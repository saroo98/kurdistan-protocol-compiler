// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
	"kurdistan/production/internal/authn"
	"kurdistan/production/internal/authoritysource"
)

type deterministicTrustedTime struct {
	at       int64
	sequence uint64
}

type testAuthorityStore struct {
	controlplane.ProductionTransactionStore
	protected map[string]authoritysource.Protected
}

type staticAuthorityStore struct {
	state controlplane.State
}

func (store staticAuthorityStore) Snapshot(context.Context) (controlplane.State, error) {
	return store.state, nil
}

func (staticAuthorityStore) Execute(context.Context, controlplane.Command) (controlplane.TransactionResult, error) {
	return controlplane.TransactionResult{}, errors.New("read-only test store")
}

func (staticAuthorityStore) ExecuteAdmitted(context.Context, controlplane.Command, authoritysource.Protected) (controlplane.TransactionResult, error) {
	return controlplane.TransactionResult{}, errors.New("read-only test store")
}

func (staticAuthorityStore) ReadAuthoritySource(context.Context, string) (authoritysource.Protected, error) {
	return authoritysource.Protected{}, errors.New("read-only test store")
}

func (store *testAuthorityStore) ExecuteAdmitted(ctx context.Context, command controlplane.Command, source authoritysource.Protected) (controlplane.TransactionResult, error) {
	if source.Schema != authoritysource.Schema || source.OperationID == "" || len(source.Ciphertext) == 0 {
		return controlplane.TransactionResult{}, errors.New("missing protected source")
	}
	store.protected[source.OperationID] = source
	return store.ProductionTransactionStore.Execute(ctx, command)
}

func (store *testAuthorityStore) ReadAuthoritySource(_ context.Context, operationID string) (authoritysource.Protected, error) {
	value, ok := store.protected[operationID]
	if !ok {
		return authoritysource.Protected{}, errors.New("source missing")
	}
	return value, nil
}

type testSourceProtector struct{}

func (testSourceProtector) Protect(_ context.Context, operationID, subjectDigest string, source []byte) (authoritysource.Protected, error) {
	if operationID == "" || subjectDigest == "" || len(source) == 0 {
		return authoritysource.Protected{}, errors.New("invalid source")
	}
	digest := sha256.Sum256(source)
	return authoritysource.Protected{
		Schema: authoritysource.Schema, OperationID: operationID, SubjectDigest: subjectDigest,
		PlaintextSHA256: hex.EncodeToString(digest[:]), AADSHA256: strings.Repeat("b", 64), PlaintextBytes: len(source),
		KeyVersion: "projects/kvpn-prod-trust/locations/europe-west2/keyRings/authority/cryptoKeys/staging/cryptoKeyVersions/1",
		Nonce:      []byte("123456789012"), WrappedDEK: []byte("wrapped"), Ciphertext: append([]byte(nil), source...),
	}, nil
}

func (source *deterministicTrustedTime) Reserve(context.Context, int64) (controlplane.TrustedInstant, error) {
	source.sequence++
	return controlplane.NewTrustedInstant(source.at+int64(source.sequence), "phase16-production-test-time", source.sequence)
}

func TestProductionBackendRerunsExactIssuanceIntentAdmission(t *testing.T) {
	compatibility, err := controlplane.NewCompatibilityTransactionStore(controlplane.NewMemoryStore())
	if err != nil {
		t.Fatal(err)
	}
	store := &testAuthorityStore{ProductionTransactionStore: compatibility, protected: make(map[string]authoritysource.Protected)}
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	clock := &deterministicTrustedTime{at: spec.Now - 1}
	backend, err := NewProductionBackend(store, clock, VerifiedSourceAdmitter{Verifier: phase8issuance.NewIndependentVerifier()}, testSourceProtector{})
	if err != nil {
		t.Fatal(err)
	}
	spec.Now = 1 // the trusted source, never the HTTP client, supplies authority time
	source, err := json.Marshal(profileIntentSource{Schema: profileIntentSourceSchema, Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	result, err := backend.CreateOperation(context.Background(), authn.Identity{ActorID: "operator-requester"}, MutationRequest{
		Action: "profile.issue", OperationID: "operation-profile-intent", AuthoritySource: source,
		ExpectedRevision: 0, ExpectedEpoch: 0, IdempotencyKey: "idempotency-profile-intent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.OperationID != "operation-profile-intent" || result.Action != "profile.issue" || result.State != string(controlplane.ProductionPending) {
		t.Fatalf("unexpected operation view: %#v", result)
	}
	state, err := store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	operation := state.Operations[result.OperationID]
	if operation.Action != controlplane.ActionPrepareProfileIssue || operation.SubjectDigest == "" || len(state.Profiles) != 0 {
		t.Fatalf("unverified or prematurely issued state: %#v", operation)
	}

	for index, actorID := range []string{"operator-approver-a", "operator-approver-b"} {
		result, err = backend.ApproveOperation(context.Background(), authn.Identity{ActorID: actorID}, result.OperationID, DecisionRequest{
			ExpectedRevision: uint64(index + 1), ExpectedEpoch: operation.ResultEpoch,
			IdempotencyKey: "idempotency-approve-" + actorID,
		})
		if err != nil {
			t.Fatalf("approve %d: %v", index, err)
		}
	}
	result, err = backend.ExecuteOperation(context.Background(), authn.Identity{ActorID: "operator-executor"}, result.OperationID, DecisionRequest{
		ExpectedRevision: 3, ExpectedEpoch: operation.ResultEpoch, IdempotencyKey: "idempotency-execute-profile-intent",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.State != string(controlplane.ProductionEffectPending) {
		t.Fatalf("issuance intent did not execute: %#v", result)
	}
	state, err = store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Outbox) != 1 || state.Outbox[0].OperationID != result.OperationID || len(state.Profiles) != 0 {
		t.Fatalf("issuance intent did not create exactly one signing obligation: %#v", state)
	}

	spec.Now = 500
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	finalizationSource, err := json.Marshal(profileFinalizationSource{
		Schema: profileFinalizationSourceSchema, ParentOperationID: result.OperationID, Spec: spec, Artifact: artifact,
	})
	if err != nil {
		t.Fatal(err)
	}
	finalization, err := backend.CreateOperation(context.Background(), authn.Identity{ActorID: "operator-finalization-requester"}, MutationRequest{
		Action: "profile.issue", OperationID: "operation-profile-finalization", AuthoritySource: finalizationSource,
		ExpectedRevision: state.Revision, ExpectedEpoch: 0, IdempotencyKey: "idempotency-profile-finalization",
	})
	if err != nil {
		t.Fatal(err)
	}
	if finalization.Action != "profile.issue" || finalization.State != string(controlplane.ProductionPending) {
		t.Fatalf("exact final artifact was not admitted for independent approval: %#v", finalization)
	}
	state, err = store.Snapshot(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(state.Profiles) != 0 {
		t.Fatalf("final artifact became usable before its second dual-control operation: %#v", state.Profiles)
	}
}

func TestProductionOperationViewReflectsDurableEffectState(t *testing.T) {
	digest := strings.Repeat("a", 64)
	operation := controlplane.Operation{
		ID: "operation-state", Action: controlplane.ActionIssueProfile, TargetID: "profile-state",
		SubjectDigest: digest, State: controlplane.OperationExecuted, ResultEpoch: 1,
	}
	event := controlplane.OutboxEvent{
		ID: "outbox-state", OperationID: operation.ID, Kind: string(operation.Action), SubjectDigest: digest,
	}
	state := controlplane.NewState()
	state.Revision = 7
	state.Operations[operation.ID] = operation
	state.Outbox = []controlplane.OutboxEvent{event}

	assertState := func(want controlplane.ProductionOperationState) {
		t.Helper()
		view, err := operationView(state, operation)
		if err != nil || view.State != string(want) || view.Revision != state.Revision {
			t.Fatalf("operation state = %#v, err = %v, want %s", view, err, want)
		}
	}
	assertState(controlplane.ProductionEffectPending)

	state.Outbox[0].Attempts = 1
	assertState(controlplane.ProductionFailedRetryable)
	state.Outbox[0].Attempts = controlplane.MaxEffectAttempts
	state.Outbox[0].FailedAt = 600
	assertState(controlplane.ProductionFailedTerminal)

	state.Outbox[0].FailedAt = 0
	state.Outbox[0].DeliveredAt = 600
	assertState(controlplane.ProductionFinalized)
	operation.Action = controlplane.ActionPrepareProfileIssue
	state.Operations[operation.ID] = operation
	state.Outbox[0].Kind = string(operation.Action)
	assertState(controlplane.ProductionAnchored)
	operation.Action = controlplane.ActionPublishSnapshot
	state.Operations[operation.ID] = operation
	state.Outbox[0].Kind = string(operation.Action)
	assertState(controlplane.ProductionPublished)

	operation.State = controlplane.OperationRejected
	state.Operations[operation.ID] = operation
	assertState(controlplane.ProductionRejected)
	operation.State = controlplane.OperationApproved
	state.Operations[operation.ID] = operation
	assertState(controlplane.ProductionApproved)
	operation.State = controlplane.OperationPending
	state.Operations[operation.ID] = operation
	assertState(controlplane.ProductionPending)

	operation.State = controlplane.OperationExecuted
	state.Outbox = nil
	if _, err := operationView(state, operation); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("executed operation without durable effect returned %v", err)
	}
}

func TestProductionProfileReadFailsClosedUntilEffectDeliveryAndUsesTrustedExpiry(t *testing.T) {
	digest := strings.Repeat("b", 64)
	operation := controlplane.Operation{
		ID: "operation-profile-read", Action: controlplane.ActionIssueProfile, TargetID: "profile-read",
		SubjectDigest: digest, State: controlplane.OperationExecuted, ResultEpoch: 1, ExpiresAt: 1_000,
	}
	state := controlplane.NewState()
	state.Operations[operation.ID] = operation
	state.Profiles[operation.TargetID] = controlplane.ProfileRecord{
		ID: operation.TargetID, State: controlplane.ProfileIssued, Generation: 1,
		ArtifactDigest: digest,
	}
	state.Outbox = []controlplane.OutboxEvent{{
		ID: "outbox-profile-read", OperationID: operation.ID, Kind: string(operation.Action), SubjectDigest: digest,
	}}
	backend := &ProductionBackend{store: staticAuthorityStore{state: state}, clock: &deterministicTrustedTime{at: 699}}
	if _, err := backend.GetProfile(context.Background(), operation.TargetID); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("profile visible before delivery: %v", err)
	}

	state.Outbox[0].DeliveredAt = 700
	backend.store = staticAuthorityStore{state: state}
	view, err := backend.GetProfile(context.Background(), operation.TargetID)
	if err != nil || view.State != "ISSUED" || view.ExpirationClass != "CURRENT" {
		t.Fatalf("current profile view = %#v, err = %v", view, err)
	}

	backend.clock = &deterministicTrustedTime{at: 999}
	view, err = backend.GetProfile(context.Background(), operation.TargetID)
	if err != nil || view.State != "EXPIRED" || view.ExpirationClass != "EXPIRED" {
		t.Fatalf("expired profile view = %#v, err = %v", view, err)
	}
}

func TestVerifiedSourceAdmitterRejectsDigestAuthorityAndUnsupportedActions(t *testing.T) {
	trusted, err := controlplane.NewTrustedInstant(2_000_000_001, "phase16-production-test-time", 1)
	if err != nil {
		t.Fatal(err)
	}
	admitter := VerifiedSourceAdmitter{}
	for name, request := range map[string]MutationRequest{
		"digest-only": {
			Action: "profile.issue", OperationID: "operation-digest-only",
			AuthoritySource: json.RawMessage(`{"subject_digest":"` + strings.Repeat("a", 64) + `"}`),
			IdempotencyKey:  "idempotency-digest-only",
		},
		"unsupported-action": {
			Action: "profile.rotate", OperationID: "operation-unsupported",
			AuthoritySource: json.RawMessage(`{"schema":"unsupported"}`),
			IdempotencyKey:  "idempotency-unsupported",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := admitter.Admit(context.Background(), request, controlplane.NewMemoryStore().Snapshot(), trusted); !errors.Is(err, controlplane.ErrInvalidInput) {
				t.Fatalf("unverified source accepted: %v", err)
			}
		})
	}
}

func TestVerifiedSourceAdmitterBindsRotationIntentToDurableCurrentArtifact(t *testing.T) {
	trusted, err := controlplane.NewTrustedInstant(520, "phase16-production-test-time", 1)
	if err != nil {
		t.Fatal(err)
	}
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	spec.Now = trusted.UnixSeconds
	spec.Profile.ContentID = "content.0002"
	spec.Profile.UpdateKind = "replacement"
	spec.Profile.Generation++
	spec.MinimumGeneration = spec.Profile.Generation
	scopeDigest := controlplane.DigestLabel(spec.Profile.ProviderID + "|" + spec.Profile.LineageID + "|" + spec.Profile.RevocationScope)
	currentDigest := controlplane.DigestLabel("current-profile-artifact")
	state := controlplane.NewState()
	state.Profiles[spec.Profile.ProfileID] = controlplane.ProfileRecord{
		ID: spec.Profile.ProfileID, State: controlplane.ProfileIssued,
		Generation: spec.Profile.Generation - 1, ArtifactDigest: currentDigest,
		ScopeDigest: scopeDigest, UpdatedAt: trusted.UnixSeconds - 1,
	}
	source, err := json.Marshal(profileIntentSource{Schema: profileIntentSourceSchema, Spec: spec})
	if err != nil {
		t.Fatal(err)
	}
	input, err := (VerifiedSourceAdmitter{}).Admit(context.Background(), MutationRequest{
		Action: "profile.rotate", OperationID: "operation-profile-rotate-intent",
		AuthoritySource: source, ExpectedRevision: 0, ExpectedEpoch: spec.Profile.Generation - 1,
		IdempotencyKey: "idempotency-profile-rotate-intent",
	}, state, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != controlplane.ActionPrepareProfileRotate ||
		input.ExpectedArtifactDigest != currentDigest || input.ExpectedEpoch != spec.Profile.Generation-1 {
		t.Fatalf("rotation intent lost durable-current binding: %#v", input)
	}

	state.Profiles[spec.Profile.ProfileID] = controlplane.ProfileRecord{
		ID: spec.Profile.ProfileID, State: controlplane.ProfileIssued,
		Generation: spec.Profile.Generation - 1, ArtifactDigest: controlplane.DigestLabel("substituted-current"),
		ScopeDigest: scopeDigest, UpdatedAt: trusted.UnixSeconds - 1,
	}
	if _, err := (VerifiedSourceAdmitter{}).Admit(context.Background(), MutationRequest{
		Action: "profile.rotate", OperationID: "operation-profile-rotate-stale",
		AuthoritySource: source, ExpectedRevision: 0, ExpectedEpoch: spec.Profile.Generation - 2,
		IdempotencyKey: "idempotency-profile-rotate-stale",
	}, state, trusted); !errors.Is(err, controlplane.ErrInvalidInput) {
		t.Fatalf("stale rotation intent accepted: %v", err)
	}
}

func TestVerifiedSourceAdmitterRerunsProfileRevocationVerification(t *testing.T) {
	trusted, _ := controlplane.NewTrustedInstant(500, "phase16-production-test-time", 1)
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	issuer := phase8issuance.NewIssuer()
	verifier := phase8issuance.NewIndependentVerifier()
	artifact, err := profile.IssueOffline(spec, issuer, nil)
	if err != nil {
		t.Fatal(err)
	}
	rootKey := profile.KeyReference{KeyID: "root-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	root := profile.RootSetArtifact{Epoch: 3, ViewID: "root-view-0003", ValidFrom: 100, ValidUntil: 2_000, Keys: []profile.KeyReference{rootKey}}
	delegation := profile.IssuerDelegationArtifact{
		RootEpoch: 3, RootKeyID: rootKey.KeyID, IssuerKey: spec.IssuerKey, Scope: spec.IssuerScope,
		ValidFrom: 100, ValidUntil: 1_500, DelegationEpoch: 2, MaxProfileValiditySecs: 1_000,
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(delegation)
	if err != nil {
		t.Fatal(err)
	}
	delegationSignature, _ := issuer.Sign(rootKey, delegationPayload)
	currentRevocations := profile.RevocationSetV1{
		Version: 1, Scope: spec.Profile.RevocationScope, RootEpoch: 3, Epoch: 4,
		IssuedAt: 100, ExpiresAt: 1_000, MaxOfflineStalenessSecs: 1_000,
	}
	currentRevocationPayload, _ := profile.EncodeRevocationSetV1(currentRevocations)
	currentRevocationSignature, _ := issuer.Sign(rootKey, currentRevocationPayload)
	currentSource := activationSource{
		Artifact: artifact, Dispatch: envelope.ArtifactMetadata{Class: spec.Class, AudienceClass: spec.Audience},
		Root: root, Delegation: profile.SignedIssuerDelegationV1{Artifact: delegation, RootKey: rootKey, Payload: delegationPayload, Signature: delegationSignature},
		Revocations: profile.SignedRevocationSetV1{Set: currentRevocations, RootKey: rootKey, Payload: currentRevocationPayload, Signature: currentRevocationSignature},
		Current:     lifecycle.VerifiedState{}, ContractVersion: spec.Profile.ContractVersion,
		MinSafetyFloor: spec.Profile.RequiredSafetyFloor, MinRootEpoch: spec.Profile.RootEpoch,
		MinRevocationEpoch: spec.Profile.RevocationEpoch,
	}
	revocations := currentRevocations
	revocations.Epoch++
	revocations.RevokedContentIDs = []string{spec.Profile.ContentID}
	revocationPayload, _ := profile.EncodeRevocationSetV1(revocations)
	revocationSignature, _ := issuer.Sign(rootKey, revocationPayload)
	source, _ := json.Marshal(profileRevocationSource{
		Schema: profileRevocationSourceSchema, Current: currentSource, Root: root,
		Revocations: profile.SignedRevocationSetV1{Set: revocations, RootKey: rootKey, Payload: revocationPayload, Signature: revocationSignature},
	})
	verifiedCurrent, err := profile.VerifyActivationAdmission(activationRequest(currentSource, trusted.UnixSeconds, VerifiedSourceAdmitter{Verifier: verifier}))
	if err != nil {
		t.Fatal(err)
	}
	actual := verifiedCurrent.ExactArtifact()
	hash := sha256.Sum256(actual)
	digest := hex.EncodeToString(hash[:])
	scope := controlplane.DigestLabel(spec.Profile.ProviderID + "|" + spec.Profile.LineageID + "|" + spec.Profile.RevocationScope)
	state := controlplane.NewState()
	state.Profiles[spec.Profile.ProfileID] = controlplane.ProfileRecord{ID: spec.Profile.ProfileID, State: controlplane.ProfileIssued, Generation: spec.Profile.Generation, ArtifactDigest: digest, ScopeDigest: scope, UpdatedAt: 499}
	input, err := (VerifiedSourceAdmitter{Verifier: verifier}).Admit(context.Background(), MutationRequest{
		Action: "profile.revoke", OperationID: "operation-profile-revoke", AuthoritySource: source,
		ExpectedRevision: 0, ExpectedEpoch: spec.Profile.Generation, IdempotencyKey: "idempotency-profile-revoke",
	}, state, trusted)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != controlplane.ActionRevokeProfile || input.ExpectedArtifactDigest != digest || input.ScopeDigest != scope {
		t.Fatalf("revocation lost durable-current binding: %#v", input)
	}
	source[len(source)-2] ^= 1
	if _, err := (VerifiedSourceAdmitter{Verifier: verifier}).Admit(context.Background(), MutationRequest{
		Action: "profile.revoke", OperationID: "operation-profile-revoke-tampered", AuthoritySource: source,
		ExpectedRevision: 0, ExpectedEpoch: spec.Profile.Generation, IdempotencyKey: "idempotency-profile-revoke-tampered",
	}, state, trusted); err == nil {
		t.Fatal("tampered revocation source accepted")
	}
}
