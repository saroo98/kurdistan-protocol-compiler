// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"testing"

	"kurdistan/internal/contracts/carrier/carrierreview"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/product/strategy"
	"kurdistan/internal/testkit/phase8issuance"
)

const phase8TestSuiteID = uint16(envelope.SuiteClassicalV1)

func TestPhase8VerifiedArtifactFeedsProfileLifecycleWithoutRawRetention(t *testing.T) {
	activationRequest, profileValue := buildPhase8ActivationRequest(t)
	artifact := append([]byte(nil), activationRequest.Artifact...)
	input, inspection, err := NewVerifiedProfileIssueRequest(
		"operation-phase8-profile", activationRequest,
		0, "idem-phase8-profile",
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.TargetID != profileValue.ProfileID ||
		input.SubjectDigest == "" || inspection.ContentSHA256 == "" {
		t.Fatalf("unexpected verified request: %+v %+v", input, inspection)
	}
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer, input)
	rawState := mustMarshalState(t, service.State())
	if bytes.Contains(rawState, artifact) {
		t.Fatal("exact Phase 8 artifact entered control-plane state")
	}

	tampered := append([]byte(nil), artifact...)
	tampered[len(tampered)-1] ^= 1
	activationRequest.Artifact = tampered
	if _, _, err := NewVerifiedProfileIssueRequest(
		"operation-phase8-tamper", activationRequest,
		service.State().Revision, "idem-phase8-tamper",
	); err == nil {
		t.Fatal("tampered Phase 8 artifact entered the control plane")
	}
}

func TestVerifiedIssuanceIntentCreatesSigningObligationWithoutIssuingProfile(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	verified, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	input, inspection, err := NewVerifiedProfileIssuanceIntentRequest(
		"operation-profile-intent", verified, 0, "idem-profile-intent",
	)
	if err != nil {
		t.Fatal(err)
	}
	if inspection.Generation != spec.Profile.Generation || input.SubjectDigest != verified.SigningInputSHA256() {
		t.Fatalf("intent request lost verified authority: %#v %#v", input, inspection)
	}

	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer, input)
	state := service.State()
	if _, issued := state.Profiles[spec.Profile.ProfileID]; issued {
		t.Fatal("pre-signing approval marked a profile issued")
	}
	if len(state.Outbox) != 1 || state.Outbox[0].Kind != string(ActionPrepareProfileIssue) ||
		state.Outbox[0].SubjectDigest != verified.SigningInputSHA256() {
		t.Fatalf("missing exact signing obligation: %#v", state.Outbox)
	}
}

func TestProfileIssuanceIntentCannotBeForgedOrMutatedAfterVerification(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	verified, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	input, _, err := NewVerifiedProfileIssuanceIntentRequest(
		"operation-profile-intent-proof", verified, 0, "idem-profile-intent-proof",
	)
	if err != nil {
		t.Fatal(err)
	}
	requester, _, _, _ := testActors()

	forged := input
	forged.proof = requestProof{}
	if _, err := newTestService(t, NewMemoryStore()).Request(requester, forged); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("unverified issuance intent accepted: %v", err)
	}

	mutated := input
	mutated.ResultEpoch++
	if _, err := newTestService(t, NewMemoryStore()).Request(requester, mutated); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("mutated issuance intent accepted: %v", err)
	}
}

type successfulEffectHandler struct{}

func (successfulEffectHandler) Apply(context.Context, Effect) error { return nil }

func TestProfileFinalizationRequiresDeliveredMatchingIntentAndSecondDualControl(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	intent, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := profile.VerifyIssuedArtifact(intent, artifact, phase8issuance.NewIndependentVerifier(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepare, _, err := NewVerifiedProfileIssuanceIntentRequest(
		"operation-profile-prepare", intent, 0, "idem-profile-prepare",
	)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer, prepare)

	finalize, _, err := NewVerifiedProfileFinalizationRequest(
		"operation-profile-finalize", service.State().Operations[prepare.ID], verified,
		service.State().Revision, "idem-profile-finalize", spec.Now+10,
	)
	if err != nil {
		t.Fatal(err)
	}
	mustRequestAndApprove(t, service, requester, approverA, approverB, finalize)
	if _, err := service.Execute(
		issuer, finalize.ID, finalize.IdempotencyKey+"-execute",
		service.State().Revision, spec.Now+13,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("finalization executed before signing effect delivery: %v", err)
	}

	recoverer := Actor{ID: "operator-recoverer", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}
	if applied, err := ReconcileNext(context.Background(), service, recoverer, successfulEffectHandler{}, spec.Now+5); err != nil || !applied {
		t.Fatalf("signing effect delivery failed: applied=%v err=%v", applied, err)
	}
	if _, err := service.Execute(
		issuer, finalize.ID, finalize.IdempotencyKey+"-execute",
		service.State().Revision, spec.Now+14,
	); err != nil {
		t.Fatal(err)
	}
	record, ok := service.State().Profiles[spec.Profile.ProfileID]
	if !ok || record.ArtifactDigest != verified.ArtifactSHA256() || record.Generation != spec.Profile.Generation {
		t.Fatalf("exact verified artifact was not finalized: %#v", record)
	}
	if err := service.State().Validate(); err != nil {
		t.Fatalf("finalized state rejected: %v", err)
	}
	for name, mutate := range map[string]func(*State){
		"missing-parent": func(state *State) {
			operation := state.Operations[finalize.ID]
			operation.ParentOperationID = "operation-missing-parent"
			state.Operations[finalize.ID] = operation
		},
		"mismatched-parent-scope": func(state *State) {
			operation := state.Operations[finalize.ID]
			operation.ScopeDigest = DigestLabel("different-finalization-scope")
			state.Operations[finalize.ID] = operation
		},
	} {
		t.Run("recovered-state-rejects-"+name, func(t *testing.T) {
			state := service.State()
			mutate(&state)
			if err := state.Validate(); err == nil {
				t.Fatal("forged finalization relationship was accepted")
			}
		})
	}
}

func TestProfileRotationRequiresCurrentArtifactAndTwoStageAuthorization(t *testing.T) {
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	recoverer := Actor{ID: "operator-recoverer-rotation", AuthorityRole: profile.RoleOperator, Duties: []Duty{DutyRecover}}

	initial := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	initialIntent, err := profile.VerifyIssuanceIntent(initial)
	if err != nil {
		t.Fatal(err)
	}
	initialArtifact, err := profile.IssueOffline(initial, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	initialVerified, err := profile.VerifyIssuedArtifact(initialIntent, initialArtifact, phase8issuance.NewIndependentVerifier(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	prepareIssue, _, err := NewVerifiedProfileIssuanceIntentRequest("operation-rotation-initial-prepare", initialIntent, 0, "idem-rotation-initial-prepare")
	if err != nil {
		t.Fatal(err)
	}
	executeApproved(t, service, requester, approverA, approverB, issuer, prepareIssue)
	if applied, err := ReconcileNext(context.Background(), service, recoverer, successfulEffectHandler{}, initial.Now+5); err != nil || !applied {
		t.Fatalf("initial signing effect delivery: applied=%v err=%v", applied, err)
	}
	finalizeIssue, _, err := NewVerifiedProfileFinalizationRequest("operation-rotation-initial-finalize", service.State().Operations[prepareIssue.ID], initialVerified, service.State().Revision, "idem-rotation-initial-finalize", initial.Now+10)
	if err != nil {
		t.Fatal(err)
	}
	executeApproved(t, service, requester, approverA, approverB, issuer, finalizeIssue)
	current := service.State().Profiles[initial.Profile.ProfileID]

	replacement := initial
	replacement.Now = initial.Now + 20
	replacement.Profile.ContentID = "content.0002"
	replacement.Profile.UpdateKind = "replacement"
	replacement.Profile.Generation = initial.Profile.Generation + 1
	replacement.MinimumGeneration = replacement.Profile.Generation
	replacementIntent, err := profile.VerifyIssuanceIntent(replacement)
	if err != nil {
		t.Fatal(err)
	}
	prepareRotation, _, err := NewVerifiedProfileRotationIntentRequest(
		"operation-rotation-prepare", current, replacementIntent, service.State().Revision, "idem-rotation-prepare",
	)
	if err != nil {
		t.Fatal(err)
	}
	if prepareRotation.ExpectedArtifactDigest != current.ArtifactDigest || prepareRotation.ExpectedEpoch != current.Generation {
		t.Fatalf("rotation intent is not bound to current artifact: %#v", prepareRotation)
	}
	executeApproved(t, service, requester, approverA, approverB, issuer, prepareRotation)
	for attempt := 0; attempt < 2; attempt++ {
		if applied, err := ReconcileNext(context.Background(), service, recoverer, successfulEffectHandler{}, replacement.Now+5+int64(attempt)); err != nil || !applied {
			t.Fatalf("rotation signing effect delivery %d: applied=%v err=%v", attempt, applied, err)
		}
	}
	replacementArtifact, err := profile.IssueOffline(replacement, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	replacementVerified, err := profile.VerifyIssuedArtifact(replacementIntent, replacementArtifact, phase8issuance.NewIndependentVerifier(), nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	finalizeRotation, _, err := NewVerifiedProfileFinalizationRequest(
		"operation-rotation-finalize", service.State().Operations[prepareRotation.ID], replacementVerified,
		service.State().Revision, "idem-rotation-finalize", replacement.Now+10,
	)
	if err != nil {
		t.Fatal(err)
	}
	if finalizeRotation.Action != ActionRotateProfile || finalizeRotation.ParentOperationID != prepareRotation.ID {
		t.Fatalf("rotation finalization lost its authority chain: %#v", finalizeRotation)
	}
	executeApproved(t, service, requester, approverA, approverB, issuer, finalizeRotation)
	rotated := service.State().Profiles[replacement.Profile.ProfileID]
	if rotated.Generation != replacement.Profile.Generation || rotated.ArtifactDigest != replacementVerified.ArtifactSHA256() {
		t.Fatalf("rotation did not install exact final artifact: %#v", rotated)
	}
	if err := service.State().Validate(); err != nil {
		t.Fatalf("rotated state rejected: %v", err)
	}
}

func TestProfileIssueAndRotationBindExactLifecycleProvenanceAndTime(t *testing.T) {
	initialRequest, initialProfile := buildPhase8ActivationRequest(t)
	current, err := profile.VerifyInitialActivationAdmission(initialRequest)
	if err != nil {
		t.Fatal(err)
	}
	issue, _, err := NewVerifiedProfileIssueRequest(
		"operation-profile-provenance-issue", initialRequest, 0,
		"idem-profile-provenance-issue",
	)
	if err != nil {
		t.Fatal(err)
	}
	if issue.CreatedAt != initialRequest.Now || issue.ExpiresAt != initialProfile.ValidUntil ||
		issue.ExpectedArtifactDigest != "" {
		t.Fatalf("issue did not derive authoritative time and absent provenance: %+v", issue)
	}

	replacementProfile := initialProfile
	replacementProfile.ContentID = "content-2"
	replacementProfile.Generation = 2
	replacementProfile.UpdateKind = "replacement"
	replacementProfile.PreviousContentID = initialProfile.ContentID
	replacementRequest := resignPhase8Request(t, initialRequest, replacementProfile, current.CurrentState())

	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	executeApproved(t, service, requester, approverA, approverB, issuer, issue)
	rotation, _, err := NewVerifiedProfileRotationRequest(
		"operation-profile-provenance-rotate", current, replacementRequest,
		service.State().Revision, "idem-profile-provenance-rotate",
	)
	if err != nil {
		t.Fatal(err)
	}
	currentDigest := sha256.Sum256(current.ExactArtifact())
	if rotation.ExpectedArtifactDigest != hex.EncodeToString(currentDigest[:]) ||
		rotation.CreatedAt != replacementRequest.Now ||
		rotation.ExpiresAt != replacementProfile.ValidUntil {
		t.Fatalf("rotation did not bind exact predecessor and authority time: %+v", rotation)
	}
	executeApproved(t, service, requester, approverA, approverB, issuer, rotation)

	otherProfile := initialProfile
	otherProfile.ContentID = "content-other"
	otherRequest := resignPhase8Request(t, initialRequest, otherProfile, lifecycle.VerifiedState{})
	otherCurrent, err := profile.VerifyInitialActivationAdmission(otherRequest)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := NewVerifiedProfileRotationRequest(
		"operation-profile-wrong-current", otherCurrent, replacementRequest,
		service.State().Revision, "idem-profile-wrong-current",
	); err == nil {
		t.Fatal("replacement admitted with an opaque admission for different exact content")
	}
	if _, _, err := NewVerifiedProfileIssueRequest(
		"operation-profile-replacement-as-issue", replacementRequest,
		service.State().Revision, "idem-profile-replacement-as-issue",
	); err == nil {
		t.Fatal("replacement artifact admitted through the issue constructor")
	}

	migrationProfile := replacementProfile
	migrationProfile.ProviderID = "provider-2"
	migrationProfile.PreviousProviderID = initialProfile.ProviderID
	migrationProfile.UpdateKind = "provider-migration"
	migrationBase := initialRequest
	migrationBase.Delegation.Artifact.Scope.ProviderID = migrationProfile.ProviderID
	migrationBase.Delegation.Payload, err = profile.EncodeIssuerDelegationV1(migrationBase.Delegation.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	migrationBase.Delegation.Signature, err = phase8issuance.NewIssuer().Sign(
		migrationBase.Delegation.RootKey, migrationBase.Delegation.Payload,
	)
	if err != nil {
		t.Fatal(err)
	}
	migrationRequest := resignPhase8Request(t, migrationBase, migrationProfile, current.CurrentState())
	if _, err := profile.VerifyActivationAdmission(migrationRequest); err != nil {
		t.Fatalf("test migration must be valid Phase 8 authority: %v", err)
	}
	if _, _, err := NewVerifiedProfileRotationRequest(
		"operation-profile-migration-as-rotation", current, migrationRequest,
		service.State().Revision, "idem-profile-migration-as-rotation",
	); err == nil {
		t.Fatal("provider migration admitted through a same-scope rotation transition")
	}
}

func TestProfileOperationExpiryClampsToEveryVerifiedAuthorityBound(t *testing.T) {
	tests := []struct {
		name       string
		adjust     func(*testing.T, *profile.ActivationRequest)
		wantExpiry int64
	}{
		{
			name: "root",
			adjust: func(_ *testing.T, request *profile.ActivationRequest) {
				request.Root.ValidUntil = 700
			},
			wantExpiry: 700,
		},
		{
			name: "issuer delegation",
			adjust: func(t *testing.T, request *profile.ActivationRequest) {
				request.Delegation.Artifact.ValidUntil = 650
				var err error
				request.Delegation.Payload, err = profile.EncodeIssuerDelegationV1(request.Delegation.Artifact)
				if err != nil {
					t.Fatal(err)
				}
				request.Delegation.Signature, err = phase8issuance.NewIssuer().Sign(
					request.Delegation.RootKey, request.Delegation.Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
			},
			wantExpiry: 650,
		},
		{
			name: "revocation snapshot",
			adjust: func(t *testing.T, request *profile.ActivationRequest) {
				request.Revocations.Set.ExpiresAt = 600
				var err error
				request.Revocations.Payload, err = profile.EncodeRevocationSetV1(request.Revocations.Set)
				if err != nil {
					t.Fatal(err)
				}
				request.Revocations.Signature, err = phase8issuance.NewIssuer().Sign(
					request.Revocations.RootKey, request.Revocations.Payload,
				)
				if err != nil {
					t.Fatal(err)
				}
			},
			wantExpiry: 600,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			request, _ := buildPhase8ActivationRequest(t)
			test.adjust(t, &request)
			input, _, err := NewVerifiedProfileIssueRequest(
				"operation-profile-expiry-"+test.name, request, 0,
				"idem-profile-expiry-"+test.name,
			)
			if err != nil {
				t.Fatal(err)
			}
			if input.CreatedAt != request.Now || input.ExpiresAt != test.wantExpiry {
				t.Fatalf("derived window = [%d,%d), want [%d,%d)", input.CreatedAt, input.ExpiresAt, request.Now, test.wantExpiry)
			}
		})
	}
}

func resignPhase8Request(
	t *testing.T,
	base profile.ActivationRequest,
	profileValue envelope.CanonicalProfileV1,
	current lifecycle.VerifiedState,
) profile.ActivationRequest {
	t.Helper()
	artifact, err := profile.IssueOffline(profile.OfflineIssuanceSpec{
		Profile: profileValue, Class: base.Dispatch.Class,
		Audience: base.Dispatch.AudienceClass, Suite: envelope.SuiteClassicalV1,
		IssuerRole: profile.RoleIssuer, IssuerScope: base.Delegation.Artifact.Scope,
		IssuerKey:         base.Delegation.Artifact.IssuerKey,
		MinimumGeneration: profileValue.Generation,
		Now:               base.Now,
	}, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request := base
	request.Artifact = artifact
	request.Current = current
	return request
}

func buildPhase8ActivationRequest(t *testing.T) (profile.ActivationRequest, envelope.CanonicalProfileV1) {
	t.Helper()
	signer := phase8issuance.NewIssuer()
	rootKey := profile.KeyReference{KeyID: "root-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	issuerKey := profile.KeyReference{KeyID: "issuer-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	root := profile.RootSetArtifact{
		Epoch: 3, ViewID: "root-view-0003", ValidFrom: 100, ValidUntil: 10000,
		Keys: []profile.KeyReference{rootKey},
	}
	delegation := profile.IssuerDelegationArtifact{
		RootEpoch: 3, RootKeyID: rootKey.KeyID, IssuerKey: issuerKey,
		Scope: profile.AuthorityScope{
			ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "profiles.",
		},
		ValidFrom: 100, ValidUntil: 9000, DelegationEpoch: 2, MaxProfileValiditySecs: 1000,
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(delegation)
	if err != nil {
		t.Fatal(err)
	}
	delegationSignature, err := signer.Sign(rootKey, delegationPayload)
	if err != nil {
		t.Fatal(err)
	}
	profileValue := envelope.CanonicalProfileV1{
		ContentID: "content-1", ProfileID: "profiles.one",
		LineageID: "lineage-1", ProviderID: "provider-1",
		ContractVersion: "product-profile-admission-v1",
		RevocationScope: "revocation-1", SnapshotMode: "full-snapshot", UpdateKind: "initial",
		Generation: 1, RequiredSafetyFloor: 2,
		ValidFrom: 200, ValidUntil: 800, RootEpoch: 3, RevocationEpoch: 4,
		RelayIDs: []string{"relay-1"}, StrategyIDs: []string{"strategy-1"},
		Policy: []byte{0xa1, 0x01, 0x01},
	}
	payload, err := envelope.EncodeCanonicalProfileV1(profileValue)
	if err != nil {
		t.Fatal(err)
	}
	metadata := envelope.ArtifactMetadata{
		Class: envelope.ArtifactSignedPublic, AudienceClass: envelope.AudiencePublic,
	}
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(issuerKey.KeyID), metadata)
	if err != nil {
		t.Fatal(err)
	}
	sigStructure, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(issuerKey, sigStructure)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := envelope.BuildTaggedCOSESign1(protected, payload, signature)
	if err != nil {
		t.Fatal(err)
	}
	revocations := profile.RevocationSetV1{
		Version: 1, Scope: "revocation-1", RootEpoch: 3, Epoch: 4,
		IssuedAt: 150, ExpiresAt: 1000, MaxOfflineStalenessSecs: 500,
		RevokedIssuerKeyIDs: []string{}, RevokedContentIDs: []string{},
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(revocations)
	if err != nil {
		t.Fatal(err)
	}
	revocationSignature, err := signer.Sign(rootKey, revocationPayload)
	if err != nil {
		t.Fatal(err)
	}
	return profile.ActivationRequest{
		Artifact: artifact, Dispatch: metadata, Now: 500, Root: root,
		Delegation: profile.SignedIssuerDelegationV1{
			Artifact: delegation, RootKey: rootKey,
			Payload: delegationPayload, Signature: delegationSignature,
		},
		Revocations: profile.SignedRevocationSetV1{
			Set: revocations, RootKey: rootKey,
			Payload: revocationPayload, Signature: revocationSignature,
		},
		Verifier:        phase8issuance.NewIndependentVerifier(),
		ContractVersion: "product-profile-admission-v1",
		MinSafetyFloor:  2, MinRootEpoch: 3, MinRevocationEpoch: 4,
	}, profileValue
}

func TestPhase11RequestFeedsRelayLifecycleWithoutEndpointRetention(t *testing.T) {
	request := buildPhase11Request(t)
	plan, err := sessionplan.Build(request)
	if err != nil {
		t.Fatal(err)
	}
	input, err := NewVerifiedRelayRequest(
		"operation-phase11-relay", ActionEnrollRelay, request,
		0, 0, "idem-phase11-relay",
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.CreatedAt != request.RelayRequest.EvaluationTime || input.ExpiresAt != 300 {
		t.Fatalf("relay operation did not inherit descriptor authority time: %+v", input)
	}
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, _ := testActors()
	relayActor := Actor{ID: "executor-relay", AuthorityRole: profile.RoleRelay, Duties: []Duty{DutyExecute}}
	executeApproved(t, service, requester, approverA, approverB, relayActor, input)
	rawState := string(mustMarshalState(t, service.State()))
	if bytes.Contains([]byte(rawState), []byte(plan.EndpointReference)) {
		t.Fatal("Phase 11 endpoint reference entered control-plane state")
	}
	if service.State().Relays[plan.DescriptorID].PlanDigest != input.ScopeDigest {
		t.Fatal("relay desired state did not bind the Phase 11 plan digest")
	}

	plan.MaxFrameBytes++
	if _, err := NewRelayRequestFromPlan(
		"operation-phase11-forged", ActionEnrollRelay, plan,
		service.State().Revision, 0, "idem-phase11-forged", 100, 800,
	); err == nil {
		t.Fatal("caller-provided Phase 11 plan entered the control plane")
	}
}

func TestSignedEmergencyDenyIsRequiredAndNarrowFailsClosed(t *testing.T) {
	signer := phase8issuance.NewIssuer()
	verifier := phase8issuance.NewIndependentVerifier()
	rootKey := profile.KeyReference{KeyID: "root-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	root := profile.RootSetArtifact{
		Epoch: 3, ViewID: "root-view-0003", ValidFrom: 100, ValidUntil: 1000,
		Keys: []profile.KeyReference{rootKey},
	}
	authority := profile.EmergencyAuthorityArtifact{
		Key: profile.KeyReference{KeyID: "emergency-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)},
		Scope: profile.AuthorityScope{
			ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "profiles.",
		},
		ValidFrom: 100, ValidUntil: 900, AuthorizationEpoch: 1,
	}
	delegation := profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID, Authority: authority,
	}
	signedDelegation := signEmergencyDelegation(t, signer, rootKey, delegation)
	trusted, err := profile.VerifyEmergencyAuthorityDelegation(root, signedDelegation, verifier, 500)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, NewMemoryStore())
	rootActor := Actor{ID: "executor-root", AuthorityRole: profile.RoleRoot, Duties: []Duty{DutyExecute}}
	if _, err := service.InstallEmergencyAuthority(rootActor, trusted, service.State().Revision, 500); err != nil {
		t.Fatal(err)
	}
	action := profile.EmergencyAction{
		Kind: profile.EmergencyDeny, Scope: authority.Scope, Epoch: 1,
		ValidFrom: 200, ValidUntil: 800,
	}
	signed := signEmergencyAction(t, signer, authority, action)
	input, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-signed", trusted, signed, verifier,
		service.State().Revision, 0, "idem-emergency-signed", 500,
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != ActionEmergencyDeny || input.ResultEpoch != 1 || input.ExpiresAt != action.ValidUntil {
		t.Fatalf("unexpected emergency request: %+v", input)
	}
	requester, approverA, approverB, _ := testActors()
	emergencyActor := Actor{ID: "executor-emergency", AuthorityRole: profile.RoleEmergency, Duties: []Duty{DutyExecute}}
	executeApproved(t, service, requester, approverA, approverB, emergencyActor, input)
	if _, exists := service.State().Restrictions[input.ScopeDigest]; !exists {
		t.Fatal("equal-scope emergency deny did not execute")
	}

	narrowerDeny := action
	narrowerDeny.Scope.ProfileNamespace = "profiles.restricted."
	narrowerSigned := signEmergencyAction(t, signer, authority, narrowerDeny)
	narrowerInput, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-strictly-narrower", trusted, narrowerSigned, verifier,
		service.State().Revision, 0, "idem-emergency-strictly-narrower", 510,
	)
	if err != nil {
		t.Fatalf("strictly narrower deny was not sealed: %v", err)
	}
	if narrowerInput.ScopeDigest == narrowerInput.AuthorityScopeDigest {
		t.Fatal("strictly narrower action scope collapsed into authority scope")
	}
	executeApproved(t, service, requester, approverA, approverB, emergencyActor, narrowerInput)
	if _, exists := service.State().Restrictions[narrowerInput.ScopeDigest]; !exists {
		t.Fatal("strictly narrower emergency deny did not execute")
	}

	mutatedProof := narrowerInput
	mutatedProof.ID = "operation-emergency-mutated-proof"
	mutatedProof.TargetID = mutatedProof.ID
	mutatedProof.IdempotencyKey = "idem-emergency-mutated-proof"
	mutatedProof.ExpectedRevision = service.State().Revision
	mutatedProof.AuthorityScopeDigest = DigestLabel("wrong-authority-scope")
	if _, err := service.Request(requester, mutatedProof); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("post-seal authority-scope mutation was not rejected: %v", err)
	}

	wrongAuthorityScope := mutatedProof
	wrongAuthorityScope.ID = "operation-emergency-wrong-authority"
	wrongAuthorityScope.TargetID = wrongAuthorityScope.ID
	wrongAuthorityScope.IdempotencyKey = "idem-emergency-wrong-authority"
	wrongAuthorityScope = sealRequestInput(wrongAuthorityScope, requestProofEmergency)
	mustRequestAndApprove(t, service, requester, approverA, approverB, wrongAuthorityScope)
	beforeWrongExecution := service.State()
	if _, err := service.Execute(
		emergencyActor, wrongAuthorityScope.ID, wrongAuthorityScope.IdempotencyKey+"-execute",
		beforeWrongExecution.Revision, 513,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong authority scope reached emergency execution: %v", err)
	}
	afterWrongExecution := service.State()
	if afterWrongExecution.Revision != beforeWrongExecution.Revision ||
		afterWrongExecution.Operations[wrongAuthorityScope.ID].State != OperationApproved {
		t.Fatal("wrong authority scope failure partially mutated state")
	}

	missingAuthorityScope := narrowerInput
	missingAuthorityScope.ID = "operation-emergency-missing-authority"
	missingAuthorityScope.TargetID = missingAuthorityScope.ID
	missingAuthorityScope.IdempotencyKey = "idem-emergency-missing-authority"
	missingAuthorityScope.ExpectedRevision = service.State().Revision
	missingAuthorityScope.AuthorityScopeDigest = ""
	missingAuthorityScope = sealRequestInput(missingAuthorityScope, requestProofEmergency)
	if _, err := service.Request(requester, missingAuthorityScope); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("missing authority scope was not rejected: %v", err)
	}

	narrow := action
	narrow.Kind = profile.EmergencyNarrow
	narrow.Scope.ProfileNamespace = "profiles.restricted."
	signedNarrow := signEmergencyAction(t, signer, authority, narrow)
	if _, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-narrow", trusted, signedNarrow, verifier,
		service.State().Revision, 0, "idem-emergency-narrow", 500,
	); err == nil {
		t.Fatal("Phase 12 admitted a narrow action without a representable parent-scope proof")
	}
}

func TestEmergencyAuthorityReplacementAndRevocationRejectStaleAuthority(t *testing.T) {
	signer := phase8issuance.NewIssuer()
	verifier := phase8issuance.NewIndependentVerifier()
	rootKey := profile.KeyReference{KeyID: "root-key-0001", SuiteID: phase8TestSuiteID}
	root := profile.RootSetArtifact{
		Epoch: 3, ViewID: "root-view-0003", ValidFrom: 100, ValidUntil: 1000,
		Keys: []profile.KeyReference{rootKey},
	}
	scope := profile.AuthorityScope{
		ProviderID: "provider-1", LineageID: "lineage-1", ProfileNamespace: "profiles.",
	}
	oldAuthority := profile.EmergencyAuthorityArtifact{
		Key:   profile.KeyReference{KeyID: "emergency-key-0001", SuiteID: phase8TestSuiteID},
		Scope: scope, ValidFrom: 100, ValidUntil: 900, AuthorizationEpoch: 1,
	}
	newAuthority := oldAuthority
	newAuthority.Key.KeyID = "emergency-key-0002"
	newAuthority.AuthorizationEpoch = 2
	oldDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID, Authority: oldAuthority,
	})
	oldTrusted, err := profile.VerifyEmergencyAuthorityDelegation(root, oldDelegation, verifier, 500)
	if err != nil {
		t.Fatal(err)
	}
	oldBinding, err := oldTrusted.CurrentBinding(500)
	if err != nil {
		t.Fatal(err)
	}
	newDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID,
		PreviousDelegationSHA256: oldBinding.DelegationSHA256,
		Authority:                newAuthority,
	})
	newTrusted, err := profile.VerifyEmergencyAuthorityDelegation(root, newDelegation, verifier, 500)
	if err != nil {
		t.Fatal(err)
	}

	service := newTestService(t, NewMemoryStore())
	rootActor := Actor{ID: "executor-root", AuthorityRole: profile.RoleRoot, Duties: []Duty{DutyExecute}}
	if _, err := service.InstallEmergencyAuthority(rootActor, oldTrusted, service.State().Revision, 500); err != nil {
		t.Fatal(err)
	}
	oldAction := profile.EmergencyAction{
		Kind: profile.EmergencyDeny, Scope: scope, Epoch: 1,
		ValidFrom: 400, ValidUntil: 800,
	}
	oldSignedAction := signEmergencyAction(t, signer, oldAuthority, oldAction)
	if _, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-old-control", oldTrusted, oldSignedAction, verifier,
		service.State().Revision, 0, "idem-emergency-old-control", 500,
	); err != nil {
		t.Fatalf("current epoch-1 authority rejected before replacement: %v", err)
	}

	missingPredecessor := profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID, Authority: newAuthority,
	}
	if _, err := profile.EncodeEmergencyAuthorityDelegationV1(missingPredecessor); err == nil {
		t.Fatal("epoch-2 emergency delegation omitted its exact predecessor")
	}

	wrongPredecessorDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID,
		PreviousDelegationSHA256: DigestLabel("wrong-emergency-predecessor"),
		Authority:                newAuthority,
	})
	wrongPredecessorTrusted, err := profile.VerifyEmergencyAuthorityDelegation(root, wrongPredecessorDelegation, verifier, 500)
	if err != nil {
		t.Fatal(err)
	}
	revisionBeforeContinuityFailures := service.State().Revision
	if _, err := service.InstallEmergencyAuthority(
		rootActor, wrongPredecessorTrusted, revisionBeforeContinuityFailures, 501,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("wrong predecessor delegation was not rejected: %v", err)
	}

	conflictingRootView := root
	conflictingRootView.ViewID = "root-view-conflict"
	conflictingViewDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: conflictingRootView.Epoch, RootKeyID: rootKey.KeyID,
		PreviousDelegationSHA256: oldBinding.DelegationSHA256,
		Authority:                newAuthority,
	})
	conflictingViewTrusted, err := profile.VerifyEmergencyAuthorityDelegation(
		conflictingRootView, conflictingViewDelegation, verifier, 500,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallEmergencyAuthority(
		rootActor, conflictingViewTrusted, revisionBeforeContinuityFailures, 501,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-epoch same-key conflicting root view was not rejected: %v", err)
	}

	crossRoot := root
	crossRoot.Epoch++
	crossRoot.ViewID = "root-view-0004"
	crossRootDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: crossRoot.Epoch, RootKeyID: rootKey.KeyID,
		PreviousDelegationSHA256: oldBinding.DelegationSHA256,
		Authority:                newAuthority,
	})
	crossRootTrusted, err := profile.VerifyEmergencyAuthorityDelegation(
		crossRoot, crossRootDelegation, verifier, 500,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallEmergencyAuthority(
		rootActor, crossRootTrusted, revisionBeforeContinuityFailures, 501,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("cross-root emergency authority replacement was not rejected: %v", err)
	}
	if service.State().Revision != revisionBeforeContinuityFailures {
		t.Fatal("rejected emergency authority continuity attempts mutated state")
	}

	if _, err := service.InstallEmergencyAuthority(rootActor, newTrusted, service.State().Revision, 501); err != nil {
		t.Fatal(err)
	}
	if _, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-old-replay", oldTrusted, oldSignedAction, verifier,
		service.State().Revision, 0, "idem-emergency-old-replay", 502,
	); err == nil {
		t.Fatal("superseded emergency authority sealed a request")
	}

	sameEpochSubstitution := newAuthority
	sameEpochSubstitution.Key.KeyID = "emergency-key-substitute"
	substitutedDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID,
		PreviousDelegationSHA256: oldBinding.DelegationSHA256,
		Authority:                sameEpochSubstitution,
	})
	substitutedTrusted, err := profile.VerifyEmergencyAuthorityDelegation(root, substitutedDelegation, verifier, 502)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallEmergencyAuthority(rootActor, substitutedTrusted, service.State().Revision, 502); !errors.Is(err, ErrConflict) {
		t.Fatalf("same-epoch authority substitution was not rejected: %v", err)
	}

	newAction := oldAction
	newSignedAction := signEmergencyAction(t, signer, newAuthority, newAction)
	input, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-current", newTrusted, newSignedAction, verifier,
		service.State().Revision, 0, "idem-emergency-current", 502,
	)
	if err != nil {
		t.Fatalf("exact current replacement authority rejected: %v", err)
	}
	requester, approverA, approverB, _ := testActors()
	mustRequestAndApprove(t, service, requester, approverA, approverB, input)

	thirdAuthority := newAuthority
	thirdAuthority.Key.KeyID = "emergency-key-0003"
	thirdAuthority.AuthorizationEpoch = 3
	newBinding, err := newTrusted.CurrentBinding(503)
	if err != nil {
		t.Fatal(err)
	}
	thirdDelegation := signEmergencyDelegation(t, signer, rootKey, profile.EmergencyAuthorityDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID,
		PreviousDelegationSHA256: newBinding.DelegationSHA256,
		Authority:                thirdAuthority,
	})
	thirdTrusted, err := profile.VerifyEmergencyAuthorityDelegation(root, thirdDelegation, verifier, 503)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.InstallEmergencyAuthority(rootActor, thirdTrusted, service.State().Revision, 503); err != nil {
		t.Fatal(err)
	}
	emergencyActor := Actor{ID: "executor-emergency", AuthorityRole: profile.RoleEmergency, Duties: []Duty{DutyExecute}}
	if _, err := service.Execute(
		emergencyActor, input.ID, input.IdempotencyKey+"-execute",
		service.State().Revision, 504,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("request sealed before authority replacement executed afterward: %v", err)
	}
	if _, exists := service.State().Restrictions[input.ScopeDigest]; exists {
		t.Fatal("superseded emergency authority changed restriction state")
	}
	if service.State().Operations[input.ID].State != OperationApproved {
		t.Fatal("failed superseded-authority execution partially mutated operation state")
	}

	thirdSignedAction := signEmergencyAction(t, signer, thirdAuthority, newAction)
	thirdInput, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-third", thirdTrusted, thirdSignedAction, verifier,
		service.State().Revision, 0, "idem-emergency-third", 504,
	)
	if err != nil {
		t.Fatalf("exact current epoch-3 authority rejected: %v", err)
	}
	mustRequestAndApprove(t, service, requester, approverA, approverB, thirdInput)

	binding, err := thirdTrusted.CurrentBinding(507)
	if err != nil {
		t.Fatal(err)
	}
	revocation := profile.EmergencyAuthorityRevocationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootKey.KeyID, Scope: scope,
		PreviousAuthorizationEpoch: binding.AuthorizationEpoch,
		AuthorizationEpoch:         binding.AuthorizationEpoch + 1,
		PreviousDelegationSHA256:   binding.DelegationSHA256,
		PreviousKey:                binding.Key,
		EffectiveAt:                507,
	}
	signedRevocation := signEmergencyAuthorityRevocation(t, signer, rootKey, revocation)
	verifiedRevocation, err := profile.VerifyEmergencyAuthorityRevocation(
		root, thirdTrusted, signedRevocation, verifier, 507,
	)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := service.RevokeEmergencyAuthority(
		rootActor, verifiedRevocation, service.State().Revision, 507,
	); err != nil {
		t.Fatal(err)
	}
	if _, err := service.Execute(
		emergencyActor, thirdInput.ID, thirdInput.IdempotencyKey+"-execute",
		service.State().Revision, 508,
	); !errors.Is(err, ErrConflict) {
		t.Fatalf("request sealed before authority revocation executed afterward: %v", err)
	}
	if _, exists := service.State().Restrictions[thirdInput.ScopeDigest]; exists {
		t.Fatal("revoked emergency authority changed restriction state")
	}
	if service.State().Operations[thirdInput.ID].State != OperationApproved {
		t.Fatal("failed revoked-authority execution partially mutated operation state")
	}
	if _, err := service.NewVerifiedEmergencyRequest(
		"operation-emergency-revoked", thirdTrusted, thirdSignedAction, verifier,
		service.State().Revision, 0, "idem-emergency-revoked", 508,
	); err == nil {
		t.Fatal("revoked emergency authority sealed a request")
	}
}

func TestProfileRevocationRequiresCurrentOpaqueAdmissionAndSignedContentRevocation(t *testing.T) {
	request, profileValue := buildPhase8ActivationRequest(t)
	current, err := profile.VerifyActivationAdmission(request)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, NewMemoryStore())
	requester, approverA, approverB, issuer := testActors()
	issue, _, err := NewVerifiedProfileIssueRequest(
		"operation-profile-before-revocation", request, 0,
		"idem-profile-before-revocation",
	)
	if err != nil {
		t.Fatal(err)
	}
	executeApproved(t, service, requester, approverA, approverB, issuer, issue)
	storedArtifactDigest := service.State().Profiles[profileValue.ProfileID].ArtifactDigest

	signer := phase8issuance.NewIssuer()
	revocations := request.Revocations.Set
	revocations.Epoch++
	revocations.RevokedContentIDs = []string{profileValue.ContentID}
	payload, err := profile.EncodeRevocationSetV1(revocations)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(request.Revocations.RootKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	signed := profile.SignedRevocationSetV1{
		Set: revocations, RootKey: request.Revocations.RootKey,
		Payload: payload, Signature: signature,
	}
	input, err := NewVerifiedProfileRevocationRequest(
		"operation-profile-revocation", current, request.Root, signed,
		phase8issuance.NewIndependentVerifier(), service.State().Revision,
		"idem-profile-revocation", request.Now,
	)
	if err != nil {
		t.Fatal(err)
	}
	if input.Action != ActionRevokeProfile || input.TargetID != profileValue.ProfileID {
		t.Fatalf("unexpected revocation request: %+v", input)
	}
	providerActor := Actor{ID: "executor-provider", AuthorityRole: profile.RoleProvider, Duties: []Duty{DutyExecute}}
	executeApproved(t, service, requester, approverA, approverB, providerActor, input)
	record := service.State().Profiles[profileValue.ProfileID]
	if record.ArtifactDigest != storedArtifactDigest ||
		record.RevocationDigest != input.SubjectDigest ||
		record.State != ProfileRevoked {
		t.Fatalf("revocation lost exact stored profile provenance: %+v", record)
	}

	signed.Set.RevokedContentIDs = nil
	unsignedPayload, err := profile.EncodeRevocationSetV1(signed.Set)
	if err != nil {
		t.Fatal(err)
	}
	signed.Payload = unsignedPayload
	signed.Signature, err = signer.Sign(signed.RootKey, unsignedPayload)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewVerifiedProfileRevocationRequest(
		"operation-profile-revocation-miss", current, request.Root, signed,
		phase8issuance.NewIndependentVerifier(), 0,
		"idem-profile-revocation-miss", request.Now,
	); err == nil {
		t.Fatal("signed revocation set that omitted current content was admitted")
	}
}

func TestProtectedRequestProofRejectsGenericBypassAndMutation(t *testing.T) {
	input, err := NewVerifiedRelayRequest(
		"operation-proof-relay", ActionEnrollRelay, buildPhase11Request(t),
		0, 0, "idem-proof-relay",
	)
	if err != nil {
		t.Fatal(err)
	}
	service := newTestService(t, NewMemoryStore())
	requester, _, _, _ := testActors()

	unproved := input
	unproved.proof = requestProof{}
	if _, err := service.Request(requester, unproved); !errors.Is(err, ErrInvalidInput) {
		t.Fatalf("generic protected request bypassed provenance: %v", err)
	}

	mutations := map[string]func(*RequestInput){
		"id":                func(value *RequestInput) { value.ID = "operation-proof-mutated" },
		"action":            func(value *RequestInput) { value.Action = ActionPromoteRelay },
		"target":            func(value *RequestInput) { value.TargetID = "relay-mutated-001" },
		"subject":           func(value *RequestInput) { value.SubjectDigest = DigestLabel("mutated-subject") },
		"scope":             func(value *RequestInput) { value.ScopeDigest = DigestLabel("mutated-scope") },
		"authority scope":   func(value *RequestInput) { value.AuthorityScopeDigest = DigestLabel("mutated-authority-scope") },
		"authority root":    func(value *RequestInput) { value.AuthorityRootDigest = DigestLabel("mutated-authority-root") },
		"expected artifact": func(value *RequestInput) { value.ExpectedArtifactDigest = DigestLabel("mutated-expected") },
		"revision":          func(value *RequestInput) { value.ExpectedRevision++ },
		"expected epoch":    func(value *RequestInput) { value.ExpectedEpoch++ },
		"result epoch":      func(value *RequestInput) { value.ResultEpoch++ },
		"created":           func(value *RequestInput) { value.CreatedAt++ },
		"expires":           func(value *RequestInput) { value.ExpiresAt++ },
		"idempotency":       func(value *RequestInput) { value.IdempotencyKey = "idem-proof-mutated" },
		"publication shape": func(value *RequestInput) { value.Publication = &PublicationInput{Version: 1} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			mutated := input
			mutate(&mutated)
			if err := validateRequestProof(mutated); !errors.Is(err, ErrInvalidInput) {
				t.Fatalf("post-construction mutation retained provenance: %v", err)
			}
		})
	}
}

func signEmergencyDelegation(
	t *testing.T,
	signer profile.Signer,
	rootKey profile.KeyReference,
	delegation profile.EmergencyAuthorityDelegationArtifact,
) profile.SignedEmergencyAuthorityDelegation {
	t.Helper()
	payload, err := profile.EncodeEmergencyAuthorityDelegationV1(delegation)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rootKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	return profile.SignedEmergencyAuthorityDelegation{
		Artifact: delegation, RootKey: rootKey, Payload: payload, Signature: signature,
	}
}

func signEmergencyAction(
	t *testing.T,
	signer profile.Signer,
	authority profile.EmergencyAuthorityArtifact,
	action profile.EmergencyAction,
) profile.SignedEmergencyAction {
	t.Helper()
	payload, err := profile.EncodeEmergencyAuthorizationV1(authority, action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(authority.Key, payload)
	if err != nil {
		t.Fatal(err)
	}
	return profile.SignedEmergencyAction{
		Authority: authority, Action: action, Payload: payload, Signature: signature,
	}
}

func signEmergencyAuthorityRevocation(
	t *testing.T,
	signer profile.Signer,
	rootKey profile.KeyReference,
	revocation profile.EmergencyAuthorityRevocationArtifact,
) profile.SignedEmergencyAuthorityRevocation {
	t.Helper()
	payload, err := profile.EncodeEmergencyAuthorityRevocationV1(revocation)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rootKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	return profile.SignedEmergencyAuthorityRevocation{
		Artifact: revocation, RootKey: rootKey, Payload: payload, Signature: signature,
	}
}

func mustMarshalState(t *testing.T, state State) []byte {
	t.Helper()
	raw, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func buildPhase11Request(t *testing.T) sessionplan.Request {
	t.Helper()
	state := lifecycle.State{
		Status: lifecycle.Admitted, ProfileID: "profile-alpha-001", Scope: "scope-alpha-001",
		EvidenceReference: "evidence-alpha-001", Generation: 7,
	}
	strategyRequest := strategy.Request{
		Lifecycle: state,
		Policy: strategy.Policy{
			Version: strategy.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			MinimumSafetyFloor: 2, MinimumPrivacyFloor: 2,
			Permitted: []strategy.Candidate{{
				Family:               carrierreview.FamilyHTTPSLikeTCP,
				RequiredCapabilities: []string{"capability-alpha"},
				MinimumSafetyFloor:   2, MinimumPrivacyFloor: 2,
			}},
		},
		Client: strategy.Client{
			SupportedVersion:  strategy.Version,
			SupportedFamilies: []string{carrierreview.FamilyHTTPSLikeTCP},
			Capabilities:      []string{"capability-alpha"}, SafetyFloor: 2, PrivacyFloor: 2,
		},
	}
	selected, err := strategy.Select(strategyRequest)
	if err != nil {
		t.Fatal(err)
	}
	descriptor := relaydescriptor.Descriptor{
		Version: relaydescriptor.Version, DescriptorID: "relay-alpha-001",
		ProfileID: state.ProfileID, Scope: state.Scope, EvidenceReference: state.EvidenceReference,
		Generation: state.Generation, Family: selected.SelectedFamily, ClientID: "client-alpha-001",
		ClientCapabilities: []string{"capability-alpha"},
		EndpointReference:  "relayref:owned-relay-alpha",
		NotBefore:          100, ExpiresAt: 300,
	}
	relayRequest := relaydescriptor.Request{
		Version: relaydescriptor.Version, StrategyRequest: strategyRequest, ClaimedResult: selected,
		EvaluationTime: 200, Client: relaydescriptor.ClientBinding{ID: "client-alpha-001"},
		Policy: relaydescriptor.Policy{
			Version: relaydescriptor.Version, ProfileID: state.ProfileID, Scope: state.Scope,
			EvidenceReference: state.EvidenceReference, Generation: state.Generation,
			FallbackPolicy: strategyRequest.Policy, SelectedFamily: selected.SelectedFamily,
			ClientCapabilities:    []string{"capability-alpha"},
			AuthorizedClientIDs:   []string{"client-alpha-001"},
			AuthorizedDescriptors: []relaydescriptor.Descriptor{descriptor},
		},
		Revocation: relaydescriptor.RevocationState{
			Version: relaydescriptor.Version, Complete: true, ProfileID: state.ProfileID,
			Scope: state.Scope, EvidenceReference: state.EvidenceReference,
			Generation: state.Generation, EvaluatedAt: 200,
		},
		Descriptors: []relaydescriptor.Descriptor{descriptor},
	}
	admitted, err := relaydescriptor.Admit(relayRequest)
	if err != nil {
		t.Fatal(err)
	}
	return sessionplan.Request{
		StrategyRequest: strategyRequest, ClaimedStrategy: selected,
		RelayRequest: relayRequest, ClaimedAdmission: admitted,
		DescriptorID: descriptor.DescriptorID, DialTimeoutMs: 5_000, MaxFrameBytes: 64 << 10,
	}
}
