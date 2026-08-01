// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"kurdistan/internal/product/profile"
)

type recordingHandler struct {
	calls   int
	err     error
	effects []Effect
	onApply func(Effect) error
}

func (handler *recordingHandler) Apply(_ context.Context, effect Effect) error {
	handler.calls++
	handler.effects = append(handler.effects, effect)
	if handler.onApply != nil {
		if err := handler.onApply(effect); err != nil {
			return err
		}
	}
	if handler.err != nil {
		return handler.err
	}
	if effect.EventID == "" || effect.Action == "" ||
		effect.TargetDigest == "" || effect.SubjectDigest == "" {
		return ErrConflict
	}
	return nil
}

func TestReconcileLeavesFailedEffectPendingAndAcknowledgesSuccess(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-reconcile-001", ActionIssueProfile, 0, 0))
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{err: errors.New("provider unavailable")}
	if _, err := ReconcileNext(context.Background(), service, recoverer, handler, 500); err == nil {
		t.Fatal("failed provider effect was acknowledged")
	}
	if len(PendingOutbox(service.State())) != 1 || handler.calls != 1 {
		t.Fatal("failed provider effect did not remain pending")
	}
	handler.err = nil
	applied, err := ReconcileNext(context.Background(), service, recoverer, handler, 501)
	if err != nil || !applied {
		t.Fatalf("successful reconciliation failed: %v", err)
	}
	if len(PendingOutbox(service.State())) != 0 || handler.calls != 2 {
		t.Fatal("successful effect was not acknowledged exactly once")
	}
}

func TestReconcileAuthorizesBeforeCallingEffectHandler(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-reconcile-auth", ActionIssueProfile, 0, 0))
	tests := []Actor{
		{ID: "BAD!", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}},
		{ID: "operator-auditor", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyAudit}},
	}
	for _, actor := range tests {
		handler := &recordingHandler{}
		if _, err := ReconcileNext(context.Background(), service, actor, handler, 500); !errors.Is(err, ErrUnauthorized) {
			t.Fatalf("unauthorized recoverer returned %v", err)
		}
		if handler.calls != 0 {
			t.Fatalf("unauthorized recoverer dispatched %d effects", handler.calls)
		}
	}
}

func TestReconcileEffectIsRedactedAndUsesExactEventID(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	input := testRequest("operation-reconcile-redacted", ActionIssueProfile, 0, 0)
	executeApproved(t, service, requester, approverA, approverB, issuer, input)
	event := PendingOutbox(service.State())[0]
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{}
	if applied, err := ReconcileNext(context.Background(), service, recoverer, handler, 500); err != nil || !applied {
		t.Fatalf("reconcile failed: applied=%v err=%v", applied, err)
	}
	if len(handler.effects) != 1 || handler.effects[0].EventID != event.ID ||
		handler.effects[0].TargetDigest != DigestLabel(input.TargetID) {
		t.Fatalf("unexpected redacted effect: %+v", handler.effects)
	}
	raw, err := json.Marshal(handler.effects[0])
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{input.ID, input.TargetID, requester.ID, approverA.ID, approverB.ID} {
		if strings.Contains(string(raw), secret) {
			t.Fatalf("raw identifier %q crossed effect boundary: %s", secret, raw)
		}
	}
}

func TestReconcileEffectCarriesExactExpectedArtifactDigest(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	issue := testRequest("operation-reconcile-predecessor-issue", ActionIssueProfile, 0, 0)
	executeApproved(t, service, requester, approverA, approverB, issuer, issue)
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	if applied, err := ReconcileNext(context.Background(), service, recoverer, &recordingHandler{}, 500); err != nil || !applied {
		t.Fatalf("issue reconciliation failed: applied=%v err=%v", applied, err)
	}

	currentDigest := service.State().Profiles[issue.TargetID].ArtifactDigest
	rotate := testRequest("operation-reconcile-predecessor-rotate", ActionRotateProfile, service.State().Revision, 1)
	rotate.ExpectedArtifactDigest = currentDigest
	rotate = sealRequestInput(rotate, requestProofProfile)
	executeApproved(t, service, requester, approverA, approverB, issuer, rotate)
	handler := &recordingHandler{}
	if applied, err := ReconcileNext(context.Background(), service, recoverer, handler, 501); err != nil || !applied {
		t.Fatalf("rotation reconciliation failed: applied=%v err=%v", applied, err)
	}
	if len(handler.effects) != 1 || handler.effects[0].ExpectedArtifactDigest != currentDigest {
		t.Fatalf("effect predecessor digest mismatch: %+v", handler.effects)
	}
}

func TestOutcomeCapabilityRejectsForgeryReplayCrossEventAndNewService(t *testing.T) {
	store := NewMemoryStore()
	service := newTestService(t, store)
	requester, approverA, approverB, issuer := testActors()
	for index, id := range []string{"operation-capability-a", "operation-capability-b"} {
		input := testRequest(id, ActionIssueProfile, service.State().Revision, 0)
		input.TargetID = fmt.Sprintf("profile-capability-%d", index)
		input = sealRequestInput(input, requestProofProfile)
		executeApproved(t, service, requester, approverA, approverB, issuer, input)
	}
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	state := service.State()
	first := state.Outbox[0]
	operation := state.Operations[first.OperationID]
	capability, err := service.mintEffectOutcome(first, operation, effectOutcomeDelivered)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := service.markDelivered(recoverer, effectOutcomeCapability{}, service.State().Revision, 500); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("zero capability returned %v", err)
	}
	wrongResult := capability
	wrongResult.outcome = effectOutcomeFailed
	if _, err := service.markDelivered(recoverer, wrongResult, service.State().Revision, 500); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong-result capability returned %v", err)
	}
	crossEvent := capability
	crossEvent.eventID = state.Outbox[1].ID
	if _, err := service.markDelivered(recoverer, crossEvent, service.State().Revision, 500); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-event capability returned %v", err)
	}
	reopened := newTestService(t, store)
	if _, err := reopened.markDelivered(recoverer, capability, reopened.State().Revision, 500); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale service-generation capability returned %v", err)
	}
	if _, err := service.markDelivered(recoverer, capability, service.State().Revision, 500); err != nil {
		t.Fatalf("valid capability failed: %v", err)
	}
	if _, err := service.markDelivered(recoverer, capability, service.State().Revision, 501); !errors.Is(err, ErrConflict) {
		t.Fatalf("replayed capability returned %v", err)
	}
}

func TestFailureCapabilityConsumesExactlyItsBoundAttempt(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-capability-failure", ActionIssueProfile, 0, 0))
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	state := service.State()
	event := state.Outbox[0]
	operation := state.Operations[event.OperationID]
	capability, err := service.mintEffectOutcome(event, operation, effectOutcomeFailed)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.markEffectFailed(recoverer, capability, service.State().Revision, 500); err != nil {
		t.Fatalf("valid failure capability failed: %v", err)
	}
	if got := service.State().Outbox[0].Attempts; got != 1 {
		t.Fatalf("attempts=%d, want 1", got)
	}
	if _, err := service.markEffectFailed(recoverer, capability, service.State().Revision, 501); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale-attempt capability returned %v", err)
	}
	if got := service.State().Outbox[0].Attempts; got != 1 {
		t.Fatalf("stale capability consumed another attempt: %d", got)
	}
}

func TestReconcileRetriesAcknowledgementWithoutReapplyingEffect(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-reconcile-toctou", ActionIssueProfile, 0, 0))
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{}
	handler.onApply = func(Effect) error {
		input := testRequest("operation-reconcile-revision-bump", ActionIssueProfile, service.State().Revision, 0)
		input.TargetID = "profile-revision-bump"
		input = sealRequestInput(input, requestProofProfile)
		_, err := service.Request(requester, input)
		return err
	}
	if applied, err := ReconcileNext(context.Background(), service, recoverer, handler, 500); err != nil || !applied {
		t.Fatalf("reconcile failed across revision bump: applied=%v err=%v", applied, err)
	}
	if handler.calls != 1 || len(PendingOutbox(service.State())) != 0 {
		t.Fatalf("effect reapplied or not acknowledged: calls=%d pending=%d", handler.calls, len(PendingOutbox(service.State())))
	}
}

func TestReconcileRejectsExpiredOperationBeforeDispatch(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-reconcile-expired", ActionIssueProfile, 0, 0))
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{}
	if _, err := ReconcileNext(context.Background(), service, recoverer, handler, 800); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired reconciliation returned %v", err)
	}
	if handler.calls != 0 {
		t.Fatalf("expired operation dispatched %d effects", handler.calls)
	}
}

func TestReconcilePrioritizesSafetyAndTerminallyBoundsFailures(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-reconcile-ordinary", ActionIssueProfile, 0, 0))
	authorityDigest := seedEmergencyAuthorityForTest(t, service, DigestLabel("restriction-alpha-scope"), 99, 900)
	emergency := testRequest("operation-reconcile-safety", ActionEmergencyDeny, service.State().Revision, 0)
	emergency.TargetID = "restriction-alpha-001"
	emergency.ScopeDigest = DigestLabel("restriction-alpha-scope")
	emergency.AuthorityScopeDigest = emergency.ScopeDigest
	emergency.ExpectedArtifactDigest = authorityDigest
	emergency = sealRequestInput(emergency, requestProofEmergency)
	executeApproved(t, service, requester, approverA, approverB,
		Actor{ID: "executor-emergency", AuthorityRole: profile.RoleEmergency, Duties: []Duty{DutyExecute}},
		emergency)
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	providerErr := errors.New("provider unavailable")
	handler := &recordingHandler{}
	handler.onApply = func(effect Effect) error {
		if effect.Action == ActionIssueProfile {
			return providerErr
		}
		return nil
	}
	if applied, err := ReconcileNext(context.Background(), service, recoverer, handler, 500); err != nil || !applied {
		t.Fatalf("safety event was not prioritized: applied=%v err=%v", applied, err)
	}
	if handler.effects[0].Action != ActionEmergencyDeny {
		t.Fatalf("first effect was %s, want safety", handler.effects[0].Action)
	}
	for attempt := 0; attempt < MaxEffectAttempts; attempt++ {
		if _, err := ReconcileNext(context.Background(), service, recoverer, handler, int64(501+attempt)); !errors.Is(err, providerErr) {
			t.Fatalf("failure attempt %d returned %v", attempt+1, err)
		}
	}
	state := service.State()
	if len(PendingOutbox(state)) != 0 || state.Outbox[0].Attempts != MaxEffectAttempts ||
		state.Outbox[0].FailedAt == 0 {
		t.Fatalf("ordinary failure was not terminally bounded: %+v", state.Outbox[0])
	}
	summary, err := SummarizeHealth(state)
	if err != nil || summary.FailedEffects != 1 {
		t.Fatalf("terminal effect not visible in health: %+v err=%v", summary, err)
	}
}

func TestReconcilePreservesPerTargetOrderingAcrossSafetyLane(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	relayActor := Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []Duty{DutyExecute}}
	enroll := testRequest("operation-reconcile-order-enroll", ActionEnrollRelay, 0, 0)
	executeApproved(t, service, requester, approverA, approverB, relayActor, enroll)
	relay := service.State().Relays[enroll.TargetID]
	quarantine := testRequest("operation-reconcile-order-quarantine", ActionQuarantineRelay, service.State().Revision, 1)
	quarantine.SubjectDigest = relay.IdentityDigest
	quarantine.ScopeDigest = relay.PlanDigest
	executeApproved(t, service, requester, approverA, approverB, relayActor, quarantine)
	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{}
	for now := int64(500); now < 502; now++ {
		if applied, err := ReconcileNext(context.Background(), service, recoverer, handler, now); err != nil || !applied {
			t.Fatalf("reconcile failed: applied=%v err=%v", applied, err)
		}
	}
	if len(handler.effects) != 2 ||
		handler.effects[0].Action != ActionEnrollRelay ||
		handler.effects[1].Action != ActionQuarantineRelay {
		t.Fatalf("same-target order changed: %+v", handler.effects)
	}
}

func TestReconcileUsesExactOperationOwnerAcrossTwoRelayPromotions(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	relayActor := Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []Duty{DutyExecute}}
	enroll := testRequest("operation-reconcile-relay-enroll", ActionEnrollRelay, 0, 0)
	executeApproved(t, service, requester, approverA, approverB, relayActor, enroll)
	relay := service.State().Relays[enroll.TargetID]
	for index := uint64(1); index <= 2; index++ {
		promote := testRequest(
			fmt.Sprintf("operation-reconcile-relay-promote-%d", index),
			ActionPromoteRelay,
			service.State().Revision,
			index,
		)
		promote.SubjectDigest = relay.IdentityDigest
		promote.ScopeDigest = relay.PlanDigest
		executeApproved(t, service, requester, approverA, approverB, relayActor, promote)
	}

	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	handler := &recordingHandler{}
	for index := 0; index < 3; index++ {
		applied, err := ReconcileNext(context.Background(), service, recoverer, handler, int64(500+index))
		if err != nil || !applied {
			t.Fatalf("reconciliation %d failed: applied=%v err=%v", index, applied, err)
		}
	}
	if handler.calls != 3 || len(PendingOutbox(service.State())) != 0 {
		t.Fatalf("outbox did not reconcile exactly once: calls=%d pending=%d", handler.calls, len(PendingOutbox(service.State())))
	}
}

func TestHealthSummaryIsCoarseAndValidated(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer,
		testRequest("operation-summary-001", ActionIssueProfile, 0, 0))
	summary, err := SummarizeHealth(service.State())
	if err != nil {
		t.Fatal(err)
	}
	if summary.Schema != "kurdistan-control-plane-health-v1" ||
		summary.ExecutedOperations != 1 || summary.PendingEffects != 1 ||
		summary.ContainsUserData || summary.ContainsPayloadData {
		t.Fatalf("unexpected summary: %+v", summary)
	}
}
