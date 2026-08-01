// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/product/profile"
)

func TestSplitAuthorityIssueAndIdempotency(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	input := testRequest("operation-issue-001", ActionIssueProfile, 0, 0)

	requested, err := service.Request(requester, input)
	if err != nil {
		t.Fatal(err)
	}
	repeated, err := service.Request(requester, input)
	if err != nil || repeated != requested {
		t.Fatalf("idempotent request mismatch: %+v %v", repeated, err)
	}
	if _, err := service.Approve(requester, input.ID, "idem-self-approval", 1, 101); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("requester approval should fail, got %v", err)
	}
	if _, err := service.Approve(approverA, input.ID, "idem-approve-a", 1, 102); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(issuer, input.ID, "idem-too-early", 2, 103); !errors.Is(err, ErrInsufficientQuorum) {
		t.Fatalf("execution without quorum should fail, got %v", err)
	}
	if _, err := service.Approve(approverB, input.ID, "idem-approve-b", 2, 104); err != nil {
		t.Fatal(err)
	}
	receipt, err := service.Execute(issuer, input.ID, "idem-execute", 3, 105)
	if err != nil {
		t.Fatal(err)
	}
	if receipt.State != OperationExecuted || receipt.Revision != 4 {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	state := service.State()
	if len(PendingOutbox(state)) != 1 || len(state.Audit) != 4 ||
		state.Operations[input.ID].State != OperationExecuted {
		t.Fatalf("unexpected state: %+v", state)
	}
	if err := state.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestExecutionRoleIsolation(t *testing.T) {
	requester, approverA, approverB, issuer := testActors()
	tests := []struct {
		name       string
		action     Action
		executor   Actor
		wantDenied bool
	}{
		{"issuer-can-issue", ActionIssueProfile, issuer, false},
		{"operator-cannot-issue", ActionIssueProfile, Actor{ID: "executor-operator", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyExecute}}, true},
		{"publisher-needs-duty", ActionPublishSnapshot, Actor{ID: "executor-publisher", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyExecute}}, true},
		{"relay-role-cannot-emergency-deny", ActionEmergencyDeny, Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []Duty{DutyExecute}}, true},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			service := newTestService(t, NewMemoryStore())
			input := testRequest(fmt.Sprintf("operation-role-%03d", index), test.action, 0, 0)
			if test.action == ActionPublishSnapshot {
				input.Publication = &PublicationInput{
					Version: 1, RootVersion: 1,
					SnapshotDigest: DigestLabel("snapshot-1"),
					TargetsDigest:  DigestLabel("targets-1"),
					ValidUntil:     500,
				}
			}
			mustRequestAndApprove(t, service, requester, approverA, approverB, input)
			_, err := service.Execute(test.executor, input.ID, fmt.Sprintf("idem-role-exec-%03d", index), 3, 105)
			if test.wantDenied && !errors.Is(err, ErrUnauthorized) {
				t.Fatalf("wanted denial, got %v", err)
			}
			if !test.wantDenied && err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProfileLifecycleIsMonotonicAndRevocationTerminal(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	provider := Actor{ID: "executor-provider", AuthorityRole: profile.RoleProvider, Duties: []Duty{DutyExecute}}
	target := "profile-alpha-001"

	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-profile-issue", ActionIssueProfile, 0, 0))
	record := service.State().Profiles[target]
	if record.State != ProfileIssued || record.Generation != 1 {
		t.Fatalf("unexpected issued profile: %+v", record)
	}

	rotate := testRequest("operation-profile-rotate", ActionRotateProfile, service.State().Revision, 1)
	rotate.ExpectedArtifactDigest = record.ArtifactDigest
	rotate = sealRequestInput(rotate, requestProofProfile)
	executeApproved(t, service, requester, approverA, approverB, issuer, rotate)
	record = service.State().Profiles[target]
	if record.State != ProfileIssued || record.Generation != 2 ||
		record.ArtifactDigest != rotate.SubjectDigest {
		t.Fatalf("unexpected rotated profile: %+v", record)
	}

	revoke := testRequest("operation-profile-revoke", ActionRevokeProfile, service.State().Revision, 2)
	revoke.ExpectedArtifactDigest = record.ArtifactDigest
	revoke = sealRequestInput(revoke, requestProofRevocation)
	executeApproved(t, service, requester, approverA, approverB, provider, revoke)
	record = service.State().Profiles[target]
	if record.State != ProfileRevoked || record.Generation != 3 {
		t.Fatalf("unexpected revoked profile: %+v", record)
	}

	postRevoke := testRequest("operation-profile-post-revoke", ActionRotateProfile, service.State().Revision, 3)
	postRevoke.ExpectedArtifactDigest = record.ArtifactDigest
	postRevoke = sealRequestInput(postRevoke, requestProofProfile)
	mustRequestAndApprove(t, service, requester, approverA, approverB, postRevoke)
	if _, err := service.Execute(issuer, postRevoke.ID, "idem-post-revoke-exec", service.State().Revision, 500); !errors.Is(err, ErrConflict) {
		t.Fatalf("post-revocation rotation should fail, got %v", err)
	}
}

func TestRelayLifecycleIsMonotonicAndRevocationTerminal(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	relayActor := Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []Duty{DutyExecute}}
	target := "relay-alpha-001"

	executeApproved(t, service, requester, approverA, approverB, relayActor,
		testRequest("operation-relay-enroll", ActionEnrollRelay, service.State().Revision, 0))
	assertRelay(t, service.State(), target, RelayEnrolled, 1)

	for index, step := range []struct {
		action Action
		state  RelayState
		epoch  uint64
	}{
		{ActionPromoteRelay, RelayCanary, 2},
		{ActionPromoteRelay, RelayActive, 3},
		{ActionDrainRelay, RelayDraining, 4},
		{ActionQuarantineRelay, RelayQuarantined, 5},
		{ActionRevokeRelay, RelayRevoked, 6},
	} {
		input := testRequest(fmt.Sprintf("operation-relay-step-%03d", index), step.action, service.State().Revision, step.epoch-1)
		current := service.State().Relays[target]
		input.SubjectDigest = current.IdentityDigest
		input.ScopeDigest = current.PlanDigest
		executeApproved(t, service, requester, approverA, approverB, relayActor, input)
		assertRelay(t, service.State(), target, step.state, step.epoch)
	}

	input := testRequest("operation-relay-reactivate", ActionPromoteRelay, service.State().Revision, 6)
	input.SubjectDigest = service.State().Relays[target].IdentityDigest
	input.ScopeDigest = service.State().Relays[target].PlanDigest
	mustRequestAndApprove(t, service, requester, approverA, approverB, input)
	if _, err := service.Execute(relayActor, input.ID, "idem-reactivate-exec", service.State().Revision, 300); !errors.Is(err, ErrConflict) {
		t.Fatalf("revoked relay reactivation should fail, got %v", err)
	}
}

func TestPublicationRollbackFreezeAndEquivocationFailClosed(t *testing.T) {
	now := int64(100)
	first := Publication{
		Version: 1, RootVersion: 3,
		SnapshotDigest: DigestLabel("snapshot-one"),
		TargetsDigest:  DigestLabel("targets-one"),
		ValidUntil:     500, PublishedAt: 90,
	}
	if err := VerifyPublication(nil, first, now); err != nil {
		t.Fatal(err)
	}
	if err := VerifyPublication(&first, first, now); err != nil {
		t.Fatal(err)
	}
	rollback := first
	rollback.Version = 0
	if err := VerifyPublication(&first, rollback, now); !errors.Is(err, ErrInvalidInput) && !errors.Is(err, ErrConflict) {
		t.Fatalf("rollback should fail, got %v", err)
	}
	equivocation := first
	equivocation.TargetsDigest = DigestLabel("other-targets")
	if err := VerifyPublication(&first, equivocation, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("equivocation should fail, got %v", err)
	}
	frozen := first
	frozen.Version = 2
	frozen.PublishedAt = 95
	if err := VerifyPublication(&first, frozen, now); !errors.Is(err, ErrConflict) {
		t.Fatalf("stale hashes under a new version should fail, got %v", err)
	}
	future := first
	future.PublishedAt = now + 1
	if err := VerifyPublication(&first, future, now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("future publication should fail, got %v", err)
	}
	invalidInterval := first
	invalidInterval.ValidUntil = invalidInterval.PublishedAt
	if err := VerifyPublication(&first, invalidInterval, now); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("non-positive publication interval should fail, got %v", err)
	}
	expired := first
	expired.ValidUntil = now
	if err := VerifyPublication(&first, expired, now); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired metadata should fail, got %v", err)
	}
}

func TestPublicationWorkflowRequiresMonotonicExactVersion(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	publisher := Actor{
		ID: "executor-publisher", AuthorityRole: profile.RoleOperator,
		Duties: []Duty{DutyExecute, DutyPublish},
	}
	for version := uint64(1); version <= 2; version++ {
		input := testRequest(fmt.Sprintf("operation-publish-%03d", version), ActionPublishSnapshot, service.State().Revision, 0)
		input.Publication = &PublicationInput{
			Version: version, RootVersion: version,
			SnapshotDigest: DigestLabel(fmt.Sprintf("snapshot-%d", version)),
			TargetsDigest:  DigestLabel(fmt.Sprintf("targets-%d", version)),
			ValidUntil:     900,
		}
		executeApproved(t, service, requester, approverA, approverB, publisher, input)
	}
	if got := len(service.State().Publications); got != 2 {
		t.Fatalf("publication count=%d", got)
	}

	input := testRequest("operation-publish-skip", ActionPublishSnapshot, service.State().Revision, 0)
	input.Publication = &PublicationInput{
		Version: 4, RootVersion: 4,
		SnapshotDigest: DigestLabel("snapshot-four"),
		TargetsDigest:  DigestLabel("targets-four"),
		ValidUntil:     900,
	}
	mustRequestAndApprove(t, service, requester, approverA, approverB, input)
	if _, err := service.Execute(publisher, input.ID, "idem-publish-skip-exec", service.State().Revision, 400); !errors.Is(err, ErrConflict) {
		t.Fatalf("skipped publication version should fail, got %v", err)
	}
}

func TestPublicationIntentIsCopiedBeforeStorage(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	publisher := Actor{
		ID: "executor-publisher", AuthorityRole: profile.RoleOperator,
		Duties: []Duty{DutyExecute, DutyPublish},
	}
	publication := &PublicationInput{
		Version:        1,
		RootVersion:    1,
		SnapshotDigest: DigestLabel("snapshot-approved"),
		TargetsDigest:  DigestLabel("targets-approved"),
		ValidUntil:     900,
	}
	input := testRequest("operation-publish-copy", ActionPublishSnapshot, 0, 0)
	input.Publication = publication
	if _, err := service.Request(requester, input); err != nil {
		t.Fatal(err)
	}
	approvedTargets := publication.TargetsDigest
	publication.TargetsDigest = DigestLabel("targets-substituted")
	if got := service.State().Operations[input.ID].Publication.TargetsDigest; got != approvedTargets {
		t.Fatalf("stored intent followed caller mutation: %s", got)
	}
	if _, err := service.Approve(approverA, input.ID, "idem-publish-copy-approve-a", service.State().Revision, 101); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(approverB, input.ID, "idem-publish-copy-approve-b", service.State().Revision, 102); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(publisher, input.ID, "idem-publish-copy-execute", service.State().Revision, 103); err != nil {
		t.Fatal(err)
	}
	if got := service.State().Publications[0].TargetsDigest; got != approvedTargets {
		t.Fatalf("executed intent followed caller mutation: %s", got)
	}
}

func TestRelayTransitionRejectsIdentityOrPlanMismatch(t *testing.T) {
	for _, mismatch := range []string{"identity", "plan"} {
		t.Run(mismatch, func(t *testing.T) {
			service := newTestService(t, NewMemoryStore())
			requester, approverA, approverB, _ := testActors()
			relayActor := Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []Duty{DutyExecute}}
			executeApproved(t, service, requester, approverA, approverB, relayActor,
				testRequest("operation-relay-bind-enroll", ActionEnrollRelay, 0, 0))
			current := service.State().Relays["relay-alpha-001"]
			promote := testRequest("operation-relay-bind-promote", ActionPromoteRelay, service.State().Revision, 1)
			promote.SubjectDigest = current.IdentityDigest
			promote.ScopeDigest = current.PlanDigest
			if mismatch == "identity" {
				promote.SubjectDigest = DigestLabel("different-relay-identity")
			} else {
				promote.ScopeDigest = DigestLabel("different-relay-plan")
			}
			mustRequestAndApprove(t, service, requester, approverA, approverB, promote)
			if _, err := service.Execute(relayActor, promote.ID, "idem-relay-bind-execute", service.State().Revision, 200); !errors.Is(err, ErrConflict) {
				t.Fatalf("mismatched %s should fail, got %v", mismatch, err)
			}
			assertRelay(t, service.State(), current.ID, RelayEnrolled, 1)
		})
	}
}

func TestRecoveredStateRejectsAuthorizationAndLinkForgery(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	input := testRequest("operation-recovery-forgery", ActionIssueProfile, 0, 0)
	executeApproved(t, service, requester, approverA, approverB, issuer, input)
	base := service.State()

	tests := []struct {
		name   string
		mutate func(*State)
	}{
		{"executed-without-quorum", func(state *State) {
			operation := state.Operations[input.ID]
			operation.ApproverIDs = operation.ApproverIDs[:1]
			state.Operations[input.ID] = operation
		}},
		{"requester-overlaps-approver", func(state *State) {
			operation := state.Operations[input.ID]
			operation.ApproverIDs[0] = operation.RequesterID
			state.Operations[input.ID] = operation
		}},
		{"invalid-executed-at", func(state *State) {
			operation := state.Operations[input.ID]
			operation.ExecutedAt = 0
			state.Operations[input.ID] = operation
		}},
		{"outbox-owner-mismatch", func(state *State) {
			state.Outbox[0].OperationID = "operation-other-owner"
		}},
		{"idempotency-reference-missing", func(state *State) {
			for key, receipt := range state.Idempotency {
				receipt.OperationID = "operation-missing-reference"
				state.Idempotency[key] = receipt
				break
			}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			state := base.clone()
			test.mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("forged recovered state was accepted")
			}
		})
	}

	invalidApproved := base.Operations[input.ID]
	invalidApproved.State = OperationApproved
	invalidApproved.ApproverIDs = invalidApproved.ApproverIDs[:1]
	invalidApproved.ExecutedAt = 0
	if err := ValidateOperation(invalidApproved); err == nil {
		t.Fatal("approved operation without quorum was accepted")
	}
}

func TestDeliveredOutboxTimestampMustFollowCreation(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-delivery-timestamp", ActionIssueProfile, 0, 0))
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	event := PendingOutbox(service.State())[0]
	if applied, err := ReconcileNext(context.Background(), service, recoverer, &recordingHandler{}, event.CreatedAt+1); err != nil || !applied {
		t.Fatalf("delivery reconciliation failed: applied=%v err=%v", applied, err)
	}
	state := service.State()
	state.Outbox[0].DeliveredAt = state.Outbox[0].CreatedAt - 1
	if err := state.Validate(); err == nil {
		t.Fatal("delivery timestamp preceding creation was accepted")
	}
}

func TestOrdinaryOperationsCannotConsumeSafetyReserve(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, _, _, _ := testActors()
	ordinaryLimit := MaxOperations - ReservedSafetyOperations
	for index := 0; index < ordinaryLimit; index++ {
		input := testRequest(fmt.Sprintf("operation-capacity-%03d", index), ActionIssueProfile, service.State().Revision, 0)
		if _, err := service.Request(requester, input); err != nil {
			t.Fatalf("ordinary request %d failed early: %v", index, err)
		}
	}
	ordinary := testRequest("operation-capacity-ordinary-blocked", ActionIssueProfile, service.State().Revision, 0)
	if _, err := service.Request(requester, ordinary); !errors.Is(err, ErrConflict) {
		t.Fatalf("ordinary request consumed safety reserve: %v", err)
	}
	for index, action := range []Action{
		ActionRevokeProfile,
		ActionQuarantineRelay,
		ActionEmergencyDeny,
	} {
		input := testRequest(fmt.Sprintf("operation-capacity-safety-%03d", index), action, service.State().Revision, 1)
		if _, err := service.Request(requester, input); err != nil {
			t.Fatalf("safety request %s was starved: %v", action, err)
		}
	}
}

func TestIdempotencySaturationStillPermitsCompleteSafetyOperation(t *testing.T) {
	store := NewMemoryStore()
	service := newTestService(t, store)
	requester, approverA, approverB, _ := testActors()
	ordinary := testRequest("operation-idempotency-saturation", ActionIssueProfile, 0, 0)
	if _, err := service.Request(requester, ordinary); err != nil {
		t.Fatal(err)
	}
	state := service.State()
	receipt := state.Idempotency[ordinary.IdempotencyKey]
	ordinaryLimit := MaxIdempotencyKeys - ReservedSafetyIdempotencyKeys
	for index := len(state.Idempotency); index < ordinaryLimit; index++ {
		state.Idempotency[fmt.Sprintf("idem-saturated-%04d", index)] = receipt
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("saturated control state is invalid: %v", err)
	}
	store.state = state

	blocked := testRequest("operation-idempotency-ordinary-blocked", ActionIssueProfile, service.State().Revision, 0)
	if _, err := service.Request(requester, blocked); !errors.Is(err, ErrConflict) {
		t.Fatalf("ordinary request bypassed idempotency reserve: %v", err)
	}

	emergency := Actor{ID: "executor-emergency", AuthorityRole: profile.RoleEmergency, Duties: []Duty{DutyExecute}}
	authorityDigest := seedEmergencyAuthorityForTest(t, service, DigestLabel("provider-alpha-scope"), 99, 900)
	safety := testRequest("operation-idempotency-emergency", ActionEmergencyDeny, service.State().Revision, 0)
	safety.ExpectedArtifactDigest = authorityDigest
	safety = sealRequestInput(safety, requestProofEmergency)
	executeApproved(t, service, requester, approverA, approverB, emergency, safety)
	handler := &recordingHandler{}
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	applied, err := ReconcileNext(context.Background(), service, recoverer, handler, 500)
	if err != nil || !applied || handler.calls != 1 {
		t.Fatalf("safety operation did not complete through reconciliation: applied=%v calls=%d err=%v", applied, handler.calls, err)
	}
	if len(PendingOutbox(service.State())) != 0 {
		t.Fatal("safety outbox event remained pending")
	}
}

func TestOrdinaryExecutionCannotConsumeItsAcknowledgementCapacity(t *testing.T) {
	store := NewMemoryStore()
	service := newTestService(t, store)
	requester, approverA, approverB, issuer := testActors()
	ordinary := testRequest("operation-ack-capacity", ActionIssueProfile, 0, 0)
	mustRequestAndApprove(t, service, requester, approverA, approverB, ordinary)
	state := service.State()
	var receipt Receipt
	for _, candidate := range state.Idempotency {
		receipt = candidate
		break
	}
	ordinaryLimit := MaxIdempotencyKeys - ReservedSafetyIdempotencyKeys
	for index := len(state.Idempotency); index < ordinaryLimit-1; index++ {
		state.Idempotency[fmt.Sprintf("idem-ack-capacity-%04d", index)] = receipt
	}
	if err := state.Validate(); err != nil {
		t.Fatalf("capacity fixture is invalid: %v", err)
	}
	store.state = state

	if _, err := service.Execute(
		issuer,
		ordinary.ID,
		"idem-ack-capacity-execute",
		service.State().Revision,
		ordinary.CreatedAt+3,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("ordinary execution should preserve future acknowledgement capacity, got %v", err)
	}
	if service.State().Operations[ordinary.ID].State != OperationApproved ||
		len(PendingOutbox(service.State())) != 0 {
		t.Fatal("capacity failure partially executed the operation")
	}
}

func TestEmergencyAuthorityIsDenyOnlyMonotonicAndExpiring(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	emergency := Actor{ID: "executor-emergency", AuthorityRole: profile.RoleEmergency, Duties: []Duty{DutyExecute}}

	authorityDigest := seedEmergencyAuthorityForTest(t, service, DigestLabel("provider-alpha-scope"), 99, 900)
	input := testRequest("operation-emergency-deny", ActionEmergencyDeny, service.State().Revision, 0)
	input.ExpectedArtifactDigest = authorityDigest
	input.ExpiresAt = 180
	input = sealRequestInput(input, requestProofEmergency)
	executeApproved(t, service, requester, approverA, approverB, emergency, input)
	restriction := service.State().Restrictions[input.ScopeDigest]
	if restriction.Epoch != 1 || restriction.Narrowed || restriction.ValidUntil != 180 {
		t.Fatalf("unexpected restriction: %+v", restriction)
	}

	narrow := testRequest("operation-emergency-narrow", ActionEmergencyNarrow, service.State().Revision, 1)
	narrow.ExpectedArtifactDigest = authorityDigest
	narrow.ExpiresAt = 240
	narrow = sealRequestInput(narrow, requestProofEmergency)
	executeApproved(t, service, requester, approverA, approverB, emergency, narrow)
	restriction = service.State().Restrictions[narrow.ScopeDigest]
	if restriction.Epoch != 2 || !restriction.Narrowed {
		t.Fatalf("unexpected narrowed restriction: %+v", restriction)
	}
}

func TestJournalRepairsPartialTailBeforeLaterAppend(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.journal")
	store, err := OpenJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, store)
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-journal-001", ActionIssueProfile, 0, 0))
	expected := service.State()

	file, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteString(`{"state":{"version":"partial"`); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	actual := reopened.Snapshot()
	if actual.Revision != expected.Revision || len(actual.Audit) != len(expected.Audit) ||
		len(actual.Outbox) != len(expected.Outbox) {
		t.Fatalf("recovered state mismatch: %+v != %+v", actual, expected)
	}
	recoveredService := newTestService(t, reopened)
	rotation := testRequest("operation-journal-002", ActionRotateProfile, actual.Revision, 1)
	rotation.ExpectedArtifactDigest = actual.Profiles["profile-alpha-001"].ArtifactDigest
	rotation = sealRequestInput(rotation, requestProofProfile)
	executeApproved(t, recoveredService, requester, approverA, approverB, issuer,
		rotation)
	afterAppend := recoveredService.State()
	reopenedAgain, err := OpenJournalStore(path)
	if err != nil {
		t.Fatalf("second reopen after append failed: %v", err)
	}
	if got := reopenedAgain.Snapshot(); got.Revision != afterAppend.Revision ||
		len(got.Audit) != len(afterAppend.Audit) || len(got.Outbox) != len(afterAppend.Outbox) {
		t.Fatalf("second recovered state mismatch: %+v != %+v", got, afterAppend)
	}
}

func TestCreateJournalStoreRejectsPreexistingEmptyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.journal")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateJournalStore(path); !errors.Is(err, ErrConflict) {
		t.Fatalf("preexisting empty journal should conflict, got %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("preexisting journal was modified: %d bytes", info.Size())
	}
}

func TestJournalRejectsSymlinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.journal")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.journal")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for name, open := range map[string]func(string) (*JournalStore, error){
		"open":   OpenJournalStore,
		"create": CreateJournalStore,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := open(link); !errors.Is(err, ErrJournal) {
				t.Fatalf("symlink should be rejected, got %v", err)
			}
		})
	}
}

func TestJournalRejectsNonRegularFiles(t *testing.T) {
	dir := t.TempDir()
	for name, open := range map[string]func(string) (*JournalStore, error){
		"open":   OpenJournalStore,
		"create": CreateJournalStore,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := open(dir); !errors.Is(err, ErrJournal) {
				t.Fatalf("directory should be rejected, got %v", err)
			}
		})
	}
}

func TestJournalRejectsPathReplacementBeforeAppend(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "control-plane.journal")
	store, err := CreateJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	original := filepath.Join(dir, "original.journal")
	if err := os.Rename(path, original); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, store)
	requester, _, _, _ := testActors()
	if _, err := service.Request(requester,
		testRequest("operation-replaced-001", ActionIssueProfile, 0, 0)); !errors.Is(err, ErrJournal) {
		t.Fatalf("replacement journal should be rejected, got %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("replacement target was modified: %d bytes", info.Size())
	}
}

func TestJournalRejectsOversizedRecord(t *testing.T) {
	oversized := bytes.Repeat([]byte("x"), maxJournalRecordBytes+1)
	path := filepath.Join(t.TempDir(), "control-plane.journal")
	if err := os.WriteFile(path, oversized, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournalStore(path); !errors.Is(err, ErrJournal) {
		t.Fatalf("oversized journal record should be rejected, got %v", err)
	}
	var copied bytes.Buffer
	if err := CopyCompleteJournal(&copied, bytes.NewReader(oversized)); !errors.Is(err, ErrJournal) {
		t.Fatalf("oversized copied record should be rejected, got %v", err)
	}
}

func TestCopyCompleteJournalRequiresExactRevisionContinuity(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, _, _ := testActors()
	input := testRequest("operation-journal-continuity", ActionIssueProfile, 0, 0)
	if _, err := service.Request(requester, input); err != nil {
		t.Fatal(err)
	}
	first := service.State()
	if _, err := service.Approve(approverA, input.ID, "idem-journal-continuity-approve", first.Revision, 101); err != nil {
		t.Fatal(err)
	}
	second := service.State()
	encode := func(state State) []byte {
		t.Helper()
		hash, err := journalHash(state)
		if err != nil {
			t.Fatal(err)
		}
		raw, err := json.Marshal(journalRecord{State: state, Hash: hash})
		if err != nil {
			t.Fatal(err)
		}
		return append(raw, '\n')
	}
	firstLine := encode(first)
	secondLine := encode(second)
	tests := map[string][]byte{
		"duplicate": append(append([]byte(nil), firstLine...), firstLine...),
		"gap":       append([]byte(nil), secondLine...),
		"reorder":   append(append([]byte(nil), secondLine...), firstLine...),
	}
	for name, source := range tests {
		t.Run(name, func(t *testing.T) {
			var copied bytes.Buffer
			if err := CopyCompleteJournal(&copied, bytes.NewReader(source)); !errors.Is(err, ErrJournal) {
				t.Fatalf("invalid revision sequence should fail, got %v", err)
			}
		})
	}
}

func TestJournalTamperAndAuditTamperAreRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "control-plane.journal")
	store, err := OpenJournalStore(path)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, store)
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-tamper-001", ActionIssueProfile, 0, 0))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = bytes.Replace(raw, []byte(`"executed"`), []byte(`"rejected"`), 1)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenJournalStore(path); !errors.Is(err, ErrJournal) {
		t.Fatalf("tampered journal should fail, got %v", err)
	}

	state := service.State()
	state.Audit[0].Result = "modified"
	if err := ValidateAuditChain(state.Audit); !errors.Is(err, ErrAuditChain) {
		t.Fatalf("tampered audit should fail, got %v", err)
	}
}

func TestStateAndAuditContainNoSensitiveCanaries(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-privacy-001", ActionIssueProfile, 0, 0))
	raw, err := json.Marshal(service.State())
	if err != nil {
		t.Fatal(err)
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range []string{
		"secret-canary", "payload-canary", "destination-canary",
		"private-key-canary", "credential-canary", "token-canary",
	} {
		if strings.Contains(lower, marker) {
			t.Fatalf("sensitive canary escaped into state: %s", marker)
		}
	}
	for _, entry := range service.State().Audit {
		if !validDigest(entry.ActorDigest) || !validDigest(entry.TargetDigest) {
			t.Fatalf("audit identity was not irreversibly reduced: %+v", entry)
		}
	}
}

func TestOutboxDeliveryIsIdempotentAndRecoverable(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-outbox-001", ActionIssueProfile, 0, 0))
	pending := PendingOutbox(service.State())
	if len(pending) != 1 {
		t.Fatalf("pending=%d", len(pending))
	}
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{}
	first, err := ReconcileNext(context.Background(), service, recoverer, handler, 500)
	if err != nil || !first {
		t.Fatalf("first delivery failed: applied=%v err=%v", first, err)
	}
	second, err := ReconcileNext(context.Background(), service, recoverer, handler, 501)
	if err != nil || second {
		t.Fatalf("second delivery was not a no-op: applied=%v err=%v", second, err)
	}
	if handler.calls != 1 {
		t.Fatalf("effect was reapplied: calls=%d", handler.calls)
	}
	if len(PendingOutbox(service.State())) != 0 {
		t.Fatal("delivered event remained pending")
	}
}

func FuzzVerifyPublicationFailClosed(f *testing.F) {
	f.Add(uint64(1), uint64(1), int64(100), int64(200), "snapshot", "targets")
	f.Fuzz(func(t *testing.T, version, root uint64, now, validUntil int64, snapshot, targets string) {
		observed := Publication{
			Version: version, RootVersion: root,
			SnapshotDigest: DigestLabel(snapshot),
			TargetsDigest:  DigestLabel(targets),
			ValidUntil:     validUntil, PublishedAt: now - 1,
		}
		err := VerifyPublication(nil, observed, now)
		if err == nil {
			if version == 0 || root == 0 || now <= 0 || validUntil <= now {
				t.Fatalf("invalid publication accepted: %+v", observed)
			}
		}
	})
}

func newTestService(t *testing.T, store Store) *Service {
	t.Helper()
	service, err := NewService(store)
	if err != nil {
		t.Fatal(err)
	}
	return service
}

func testActors() (Actor, Actor, Actor, Actor) {
	return Actor{ID: "operator-requester", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRequest}},
		Actor{ID: "operator-approver-a", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyApprove}},
		Actor{ID: "operator-approver-b", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyApprove}},
		Actor{ID: "executor-issuer", AuthorityRole: profile.RoleIssuer, Duties: []Duty{DutyExecute}}
}

func testRequest(id string, action Action, revision, epoch uint64) RequestInput {
	target := "profile-alpha-001"
	if strings.Contains(string(action), "relay") {
		target = "relay-alpha-001"
	}
	resultEpoch := epoch + 1
	if action == ActionPublishSnapshot {
		resultEpoch = 0
	}
	input := RequestInput{
		ID: id, Action: action, TargetID: target,
		SubjectDigest:    DigestLabel(id + "-subject"),
		ScopeDigest:      DigestLabel("provider-alpha-scope"),
		ExpectedRevision: revision, ExpectedEpoch: epoch,
		ResultEpoch: resultEpoch,
		CreatedAt:   100, ExpiresAt: 800,
		IdempotencyKey: "idem-" + id,
	}
	if action == ActionRotateProfile || action == ActionRevokeProfile {
		input.ExpectedArtifactDigest = DigestLabel(id + "-expected-artifact")
	}
	if action == ActionEmergencyDeny || action == ActionEmergencyNarrow {
		input.AuthorityScopeDigest = input.ScopeDigest
		input.AuthorityRootDigest = DigestLabel("test-current-emergency-root")
		input.ExpectedArtifactDigest = DigestLabel("test-current-emergency-authority")
	}
	if kind, required := requiredRequestProof(action); required {
		input = sealRequestInput(input, kind)
	}
	return input
}

func seedEmergencyAuthorityForTest(
	t *testing.T,
	service *Service,
	scopeDigest string,
	validFrom, validUntil int64,
) string {
	t.Helper()
	delegationDigest := DigestLabel("test-current-emergency-authority")
	if _, err := service.store.Update(service.State().Revision, func(state *State) error {
		state.EmergencyAuthorities[scopeDigest] = EmergencyAuthorityRecord{
			ScopeDigest: scopeDigest, RootEpoch: 1, RootKeyID: "root-key-test",
			RootSetDigest:      DigestLabel("test-current-emergency-root"),
			RootKeySuiteID:     phase8TestSuiteID,
			AuthorizationEpoch: 1, DelegationDigest: delegationDigest,
			KeyID: "emergency-key-test", KeySuiteID: phase8TestSuiteID,
			ValidFrom: validFrom, ValidUntil: validUntil, UpdatedAt: validFrom,
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return delegationDigest
}

func mustRequestAndApprove(t *testing.T, service *Service, requester, approverA, approverB Actor, input RequestInput) {
	t.Helper()
	if kind, required := requiredRequestProof(input.Action); required {
		input = sealRequestInput(input, kind)
	}
	if _, err := service.Request(requester, input); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(approverA, input.ID, input.IdempotencyKey+"-approve-a", service.State().Revision, input.CreatedAt+1); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Approve(approverB, input.ID, input.IdempotencyKey+"-approve-b", service.State().Revision, input.CreatedAt+2); err != nil {
		t.Fatal(err)
	}
}

func executeApproved(t *testing.T, service *Service, requester, approverA, approverB, executor Actor, input RequestInput) {
	t.Helper()
	mustRequestAndApprove(t, service, requester, approverA, approverB, input)
	if _, err := service.Execute(executor, input.ID, input.IdempotencyKey+"-execute", service.State().Revision, input.CreatedAt+3); err != nil {
		t.Fatal(err)
	}
}

func assertRelay(t *testing.T, state State, id string, expectedState RelayState, expectedEpoch uint64) {
	t.Helper()
	relay, ok := state.Relays[id]
	if !ok || relay.State != expectedState || relay.Epoch != expectedEpoch {
		t.Fatalf("relay mismatch: %+v", relay)
	}
}
