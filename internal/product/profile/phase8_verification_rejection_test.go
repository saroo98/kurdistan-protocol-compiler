// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
)

type verificationTestSigner struct{}

type verificationCountingVerifier struct {
	calls int
	fail  bool
}

func (verificationTestSigner) Sign(key KeyReference, message []byte) ([]byte, error) {
	return testSignature(key, message), nil
}

func (v *verificationCountingVerifier) Verify(key KeyReference, message, signature []byte) error {
	v.calls++
	if v.fail {
		return errors.New("synthetic signature failure")
	}
	return (exactVerifier{}).Verify(key, message, signature)
}

func TestVerifyOfflineWithRejectionPreservesSuccessAndFirstFailure(t *testing.T) {
	request := validVerificationOfflineRequest(t)
	legacy, legacyErr := VerifyOffline(request, exactVerifier{}, nil, nil)
	var successEvents []VerificationRejection
	detailed, detailedErr := VerifyOfflineWithRejection(request, exactVerifier{}, nil, nil, func(rejection VerificationRejection) {
		successEvents = append(successEvents, rejection)
	})
	if legacyErr != nil || detailedErr != nil || !reflect.DeepEqual(detailed, legacy) {
		t.Fatalf("success parity failed: legacy=%v detailed=%v", legacyErr, detailedErr)
	}
	if len(successEvents) != 0 {
		t.Fatalf("successful verification emitted rejection: %+v", successEvents)
	}

	request.Artifact = []byte{0xff}
	request.Suite = envelope.SuiteReservedPQV1
	_, legacyErr = VerifyOffline(request, exactVerifier{}, nil, nil)
	var failureEvents []VerificationRejection
	_, detailedErr = VerifyOfflineWithRejection(request, exactVerifier{}, nil, nil, func(rejection VerificationRejection) {
		failureEvents = append(failureEvents, rejection)
	})
	if legacyErr != ErrOfflineVerify || detailedErr != legacyErr || !errors.Is(detailedErr, ErrOfflineVerify) {
		t.Fatalf("failure parity failed: legacy=%v detailed=%v", legacyErr, detailedErr)
	}
	want := []VerificationRejection{{Stage: VerificationStageProfilePolicy, Reason: VerificationReasonIncompatible}}
	if !reflect.DeepEqual(failureEvents, want) {
		t.Fatalf("first failure = %+v, want %+v", failureEvents, want)
	}
}

func TestOfflineRejectionPredicateMapping(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*testing.T, *OfflineVerifyRequest)
		want   VerificationRejection
	}{
		{"unsupported suite", func(_ *testing.T, request *OfflineVerifyRequest) { request.Suite = envelope.SuiteReservedPQV1 }, VerificationRejection{VerificationStageProfilePolicy, VerificationReasonIncompatible}},
		{"malformed issuer key", func(_ *testing.T, request *OfflineVerifyRequest) { request.IssuerKey.KeyID = "" }, VerificationRejection{VerificationStageProfileSignature, VerificationReasonMalformed}},
		{"malformed outer object", func(_ *testing.T, request *OfflineVerifyRequest) { request.Artifact = []byte{0xff} }, VerificationRejection{VerificationStageOuter, VerificationReasonMalformed}},
		{"protected binding", func(_ *testing.T, request *OfflineVerifyRequest) { request.IssuerKey.KeyID = "issuer-key-other" }, VerificationRejection{VerificationStageOuter, VerificationReasonBindingMismatch}},
		{"signature", func(_ *testing.T, request *OfflineVerifyRequest) { request.Artifact[len(request.Artifact)-1] ^= 1 }, VerificationRejection{VerificationStageProfileSignature, VerificationReasonSignatureInvalid}},
		{"malformed issuer scope", func(_ *testing.T, request *OfflineVerifyRequest) { request.IssuerScope.ProfileNamespace = "profiles" }, VerificationRejection{VerificationStageProfilePolicy, VerificationReasonMalformed}},
		{"issuer role scope", func(_ *testing.T, request *OfflineVerifyRequest) { request.IssuerRole = RoleRoot }, VerificationRejection{VerificationStageProfilePolicy, VerificationReasonScopeMismatch}},
		{"profile time", func(_ *testing.T, request *OfflineVerifyRequest) { request.Now = 1000 }, VerificationRejection{VerificationStageProfilePolicy, VerificationReasonTimeInvalid}},
		{"profile floor", func(_ *testing.T, request *OfflineVerifyRequest) { request.MinimumGeneration++ }, VerificationRejection{VerificationStageProfilePolicy, VerificationReasonFloorRejected}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy := validVerificationOfflineRequest(t)
			tc.mutate(t, &legacy)
			_, legacyErr := VerifyOffline(legacy, exactVerifier{}, nil, nil)

			detailed := validVerificationOfflineRequest(t)
			tc.mutate(t, &detailed)
			var events []VerificationRejection
			_, detailedErr := VerifyOfflineWithRejection(detailed, exactVerifier{}, nil, nil, func(rejection VerificationRejection) { events = append(events, rejection) })
			assertLegacyErrorParity(t, legacyErr, detailedErr)
			if !reflect.DeepEqual(events, []VerificationRejection{tc.want}) {
				t.Fatalf("rejection=%+v want=%+v", events, tc.want)
			}
		})
	}
}

func TestValidateIssuerDelegationWithRejectionPreservesErrorsAndOrder(t *testing.T) {
	root := validRootSet()
	delegation := validIssuerDelegation()
	args := []string{"provider-1", "lineage-1", "kurd/profile-1"}
	if err := ValidateIssuerDelegationWithRejection(root, delegation, trustTestNow, args[0], args[1], args[2], func(rejection VerificationRejection) {
		t.Fatalf("successful delegation emitted rejection: %+v", rejection)
	}); err != nil {
		t.Fatal(err)
	}

	root.ValidUntil = trustTestNow
	delegation.RootEpoch++
	legacyErr := ValidateIssuerDelegation(root, delegation, trustTestNow, args[0], args[1], args[2])
	var events []VerificationRejection
	detailedErr := ValidateIssuerDelegationWithRejection(root, delegation, trustTestNow, args[0], args[1], args[2], func(rejection VerificationRejection) {
		events = append(events, rejection)
	})
	assertLegacyErrorParity(t, legacyErr, detailedErr)
	want := []VerificationRejection{{Stage: VerificationStageRoot, Reason: VerificationReasonTimeInvalid}}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("first failure = %+v, want %+v", events, want)
	}
}

func TestDelegationRejectionPredicateMapping(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*RootSetArtifact, *IssuerDelegationArtifact, *int64, *string, *string, *string)
		want   VerificationRejection
	}{
		{"malformed root", func(root *RootSetArtifact, _ *IssuerDelegationArtifact, _ *int64, _, _, _ *string) { root.Epoch = 0 }, VerificationRejection{VerificationStageRoot, VerificationReasonMalformed}},
		{"inactive root", func(root *RootSetArtifact, _ *IssuerDelegationArtifact, now *int64, _, _, _ *string) {
			root.ValidUntil = *now
		}, VerificationRejection{VerificationStageRoot, VerificationReasonTimeInvalid}},
		{"root mismatch", func(_ *RootSetArtifact, delegation *IssuerDelegationArtifact, _ *int64, _, _, _ *string) {
			delegation.RootEpoch++
		}, VerificationRejection{VerificationStageDelegation, VerificationReasonRootMismatch}},
		{"malformed delegation", func(_ *RootSetArtifact, delegation *IssuerDelegationArtifact, _ *int64, _, _, _ *string) {
			delegation.IssuerKey.KeyID = ""
		}, VerificationRejection{VerificationStageDelegation, VerificationReasonMalformed}},
		{"key binding", func(root *RootSetArtifact, delegation *IssuerDelegationArtifact, _ *int64, _, _, _ *string) {
			delegation.IssuerKey = root.Keys[0]
		}, VerificationRejection{VerificationStageDelegation, VerificationReasonBindingMismatch}},
		{"explicit revoked bit", func(_ *RootSetArtifact, delegation *IssuerDelegationArtifact, _ *int64, _, _, _ *string) {
			delegation.Revoked = true
		}, VerificationRejection{VerificationStageDelegation, VerificationReasonExplicitRevocation}},
		{"delegation time", func(_ *RootSetArtifact, delegation *IssuerDelegationArtifact, now *int64, _, _, _ *string) {
			delegation.ValidUntil = *now
		}, VerificationRejection{VerificationStageDelegation, VerificationReasonTimeInvalid}},
		{"delegation scope", func(_ *RootSetArtifact, _ *IssuerDelegationArtifact, _ *int64, providerID, _, _ *string) {
			*providerID = "provider-other"
		}, VerificationRejection{VerificationStageDelegation, VerificationReasonScopeMismatch}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			root := validRootSet()
			delegation := validIssuerDelegation()
			now := int64(trustTestNow)
			providerID, lineageID, profileID := "provider-1", "lineage-1", "kurd/profile-1"
			tc.mutate(&root, &delegation, &now, &providerID, &lineageID, &profileID)
			legacyErr := ValidateIssuerDelegation(root, delegation, now, providerID, lineageID, profileID)
			var events []VerificationRejection
			detailedErr := ValidateIssuerDelegationWithRejection(root, delegation, now, providerID, lineageID, profileID, func(rejection VerificationRejection) { events = append(events, rejection) })
			assertLegacyErrorParity(t, legacyErr, detailedErr)
			if !reflect.DeepEqual(events, []VerificationRejection{tc.want}) {
				t.Fatalf("rejection=%+v want=%+v", events, tc.want)
			}
		})
	}
}

func TestVerifySignedRevocationSetWithRejectionPreservesCryptoAndPrerequisites(t *testing.T) {
	request, _ := validActivationRequest(t)
	legacy, legacyErr := VerifySignedRevocationSet(request.Root, request.Revocations, exactVerifier{}, request.Now)
	var successEvents []VerificationRejection
	detailed, detailedErr := VerifySignedRevocationSetWithRejection(request.Root, request.Revocations, exactVerifier{}, request.Now, func(rejection VerificationRejection) {
		successEvents = append(successEvents, rejection)
	})
	assertLegacyErrorParity(t, legacyErr, detailedErr)
	if !reflect.DeepEqual(legacy.Set(), detailed.Set()) || !bytes.Equal(legacy.Payload(), detailed.Payload()) || len(successEvents) != 0 {
		t.Fatalf("success parity failed: events=%+v", successEvents)
	}

	request.Revocations.Set.EmergencyDenied = true
	resignRevocations(t, &request)
	verifier := &verificationCountingVerifier{fail: true}
	_, legacyErr = VerifySignedRevocationSet(request.Root, request.Revocations, verifier, request.Now)
	legacyCalls := verifier.calls
	verifier = &verificationCountingVerifier{fail: true}
	var events []VerificationRejection
	_, detailedErr = VerifySignedRevocationSetWithRejection(request.Root, request.Revocations, verifier, request.Now, func(rejection VerificationRejection) {
		events = append(events, rejection)
	})
	assertLegacyErrorParity(t, legacyErr, detailedErr)
	if legacyCalls != 1 || verifier.calls != legacyCalls {
		t.Fatalf("verifier calls: legacy=%d detailed=%d", legacyCalls, verifier.calls)
	}
	want := []VerificationRejection{{Stage: VerificationStageRevocations, Reason: VerificationReasonSignatureInvalid}}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("rejection = %+v, want %+v", events, want)
	}
}

func TestRevocationRejectionPredicateMapping(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*RootSetArtifact, *SignedRevocationSetV1, *Verifier, *int64)
		want     VerificationRejection
		wantCall int
	}{
		{"incompatible verifier", func(_ *RootSetArtifact, _ *SignedRevocationSetV1, verifier *Verifier, _ *int64) { *verifier = nil }, VerificationRejection{VerificationStageRevocations, VerificationReasonIncompatible}, 0},
		{"malformed root", func(root *RootSetArtifact, _ *SignedRevocationSetV1, _ *Verifier, _ *int64) { root.Epoch = 0 }, VerificationRejection{VerificationStageRoot, VerificationReasonMalformed}, 0},
		{"inactive root", func(root *RootSetArtifact, _ *SignedRevocationSetV1, _ *Verifier, now *int64) { root.ValidUntil = *now }, VerificationRejection{VerificationStageRoot, VerificationReasonTimeInvalid}, 0},
		{"malformed signing key", func(_ *RootSetArtifact, signed *SignedRevocationSetV1, _ *Verifier, _ *int64) {
			signed.RootKey.KeyID = ""
		}, VerificationRejection{VerificationStageRevocations, VerificationReasonMalformed}, 0},
		{"root mismatch", func(_ *RootSetArtifact, signed *SignedRevocationSetV1, _ *Verifier, _ *int64) { signed.Set.RootEpoch++ }, VerificationRejection{VerificationStageRevocations, VerificationReasonRootMismatch}, 0},
		{"canonical binding", func(_ *RootSetArtifact, signed *SignedRevocationSetV1, _ *Verifier, _ *int64) {
			signed.Payload = append(bytes.Clone(signed.Payload), 0)
		}, VerificationRejection{VerificationStageRevocations, VerificationReasonBindingMismatch}, 0},
		{"signature", func(_ *RootSetArtifact, signed *SignedRevocationSetV1, _ *Verifier, _ *int64) {
			signed.Signature[0] ^= 1
		}, VerificationRejection{VerificationStageRevocations, VerificationReasonSignatureInvalid}, 1},
		{"freshness", func(_ *RootSetArtifact, signed *SignedRevocationSetV1, _ *Verifier, now *int64) {
			signed.Set.ExpiresAt = *now
			payload, _ := EncodeRevocationSetV1(signed.Set)
			signed.Payload = payload
			signed.Signature = testSignature(signed.RootKey, payload)
		}, VerificationRejection{VerificationStageRevocations, VerificationReasonTimeInvalid}, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			request, _ := validActivationRequest(t)
			root, signed, now := request.Root, request.Revocations, request.Now
			counter := &verificationCountingVerifier{}
			var verifier Verifier = counter
			tc.mutate(&root, &signed, &verifier, &now)
			_, legacyErr := VerifySignedRevocationSet(root, signed, verifier, now)

			request, _ = validActivationRequest(t)
			counter = &verificationCountingVerifier{}
			verifier = counter
			root, signed, now = request.Root, request.Revocations, request.Now
			tc.mutate(&root, &signed, &verifier, &now)
			var events []VerificationRejection
			_, detailedErr := VerifySignedRevocationSetWithRejection(root, signed, verifier, now, func(rejection VerificationRejection) { events = append(events, rejection) })
			assertLegacyErrorParity(t, legacyErr, detailedErr)
			if counter.calls != tc.wantCall {
				t.Fatalf("verifier calls=%d want=%d", counter.calls, tc.wantCall)
			}
			if !reflect.DeepEqual(events, []VerificationRejection{tc.want}) {
				t.Fatalf("rejection=%+v want=%+v", events, tc.want)
			}
		})
	}
}

func TestActivationRejectionPreservesObserveAndStopsAtFirstFailure(t *testing.T) {
	success, _ := validActivationRequest(t)
	success.Rejected = func(rejection VerificationRejection) {
		t.Fatalf("successful activation admission emitted rejection: %+v", rejection)
	}
	if _, err := VerifyActivationAdmission(success); err != nil {
		t.Fatal(err)
	}

	legacy, _ := validActivationRequest(t)
	legacy.Revocations.Set.RevokedContentIDs = []string{"content-1"}
	resignRevocations(t, &legacy)
	legacy.Delegation.Signature[0] ^= 1
	legacyVerifier := &verificationCountingVerifier{}
	legacy.Verifier = legacyVerifier
	var legacyStages []ActivationStage
	legacy.Observe = func(stage ActivationStage) { legacyStages = append(legacyStages, stage) }
	_, legacyErr := VerifyActivationAdmission(legacy)

	detailed := legacy
	detailedVerifier := &verificationCountingVerifier{}
	detailed.Verifier = detailedVerifier
	var detailedStages []ActivationStage
	detailed.Observe = func(stage ActivationStage) { detailedStages = append(detailedStages, stage) }
	var events []VerificationRejection
	detailed.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
	_, detailedErr := VerifyActivationAdmission(detailed)
	assertLegacyErrorParity(t, legacyErr, detailedErr)
	if activationCode(legacyErr) != ActivationTrustRejected || legacyVerifier.calls != 1 || detailedVerifier.calls != legacyVerifier.calls {
		t.Fatalf("legacy result/code/calls changed: err=%v legacy_calls=%d detailed_calls=%d", legacyErr, legacyVerifier.calls, detailedVerifier.calls)
	}
	if !reflect.DeepEqual(detailedStages, legacyStages) || !reflect.DeepEqual(detailedStages, []ActivationStage{StageOuterParsed, StageSignedObjectParsed}) {
		t.Fatalf("Observe order changed: legacy=%v detailed=%v", legacyStages, detailedStages)
	}
	want := []VerificationRejection{{Stage: VerificationStageDelegation, Reason: VerificationReasonSignatureInvalid}}
	if !reflect.DeepEqual(events, want) {
		t.Fatalf("rejection = %+v, want %+v", events, want)
	}
}

func TestActivationDelegationRejectionPreservesRootPredicateOrder(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*ActivationRequest)
		want   VerificationRejection
	}{
		{
			name: "key binding precedes artifact root epoch",
			mutate: func(request *ActivationRequest) {
				request.Delegation.Artifact.RootKeyID = "root-key-other"
				request.Delegation.Artifact.RootEpoch++
			},
			want: VerificationRejection{Stage: VerificationStageDelegation, Reason: VerificationReasonBindingMismatch},
		},
		{
			name: "artifact root epoch after matching key binding",
			mutate: func(request *ActivationRequest) {
				request.Delegation.Artifact.RootEpoch++
			},
			want: VerificationRejection{Stage: VerificationStageDelegation, Reason: VerificationReasonRootMismatch},
		},
	}
	wantStages := []ActivationStage{StageOuterParsed, StageSignedObjectParsed}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy, _ := validActivationRequest(t)
			tc.mutate(&legacy)
			legacyVerifier := &verificationCountingVerifier{}
			legacy.Verifier = legacyVerifier
			var legacyStages []ActivationStage
			legacy.Observe = func(stage ActivationStage) { legacyStages = append(legacyStages, stage) }
			_, legacyErr := VerifyActivationAdmission(legacy)

			detailed, _ := validActivationRequest(t)
			tc.mutate(&detailed)
			detailedVerifier := &verificationCountingVerifier{}
			detailed.Verifier = detailedVerifier
			var detailedStages []ActivationStage
			detailed.Observe = func(stage ActivationStage) { detailedStages = append(detailedStages, stage) }
			var events []VerificationRejection
			detailed.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
			_, detailedErr := VerifyActivationAdmission(detailed)

			assertLegacyErrorParity(t, legacyErr, detailedErr)
			if activationCode(legacyErr) != ActivationTrustRejected || activationCode(detailedErr) != ActivationTrustRejected {
				t.Fatalf("legacy=%v detailed=%v", legacyErr, detailedErr)
			}
			if !reflect.DeepEqual(legacyStages, wantStages) || !reflect.DeepEqual(detailedStages, wantStages) {
				t.Fatalf("Observe legacy=%v detailed=%v want=%v", legacyStages, detailedStages, wantStages)
			}
			if legacyVerifier.calls != 0 || detailedVerifier.calls != 0 {
				t.Fatalf("verifier calls legacy=%d detailed=%d", legacyVerifier.calls, detailedVerifier.calls)
			}
			if !reflect.DeepEqual(events, []VerificationRejection{tc.want}) {
				t.Fatalf("rejection=%+v want=%+v", events, tc.want)
			}
		})
	}
}

func TestActivationRejectionClassifiesOuterAndRecipientFailures(t *testing.T) {
	cases := []struct {
		name  string
		build func(*testing.T) ActivationRequest
		want  VerificationRejection
		code  ActivationReasonCode
	}{
		{
			name: "malformed signed object",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Artifact = []byte{0xff}
				return request
			},
			want: VerificationRejection{Stage: VerificationStageOuter, Reason: VerificationReasonMalformed},
			code: ActivationInvalidArtifact,
		},
		{
			name: "opaque outer callback failure",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.UnwrapArtifact = func([]byte) ([]byte, error) { return nil, errors.New("opaque") }
				return request
			},
			want: VerificationRejection{Stage: VerificationStageOuter, Reason: VerificationReasonUnknown},
			code: ActivationTrustRejected,
		},
		{
			name: "public recipient configuration",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Resolver = fixedActivationResolver{}
				return request
			},
			want: VerificationRejection{Stage: VerificationStageRecipient, Reason: VerificationReasonIncompatible},
			code: ActivationInvalidArtifact,
		},
		{
			name: "signed object unwrap incompatible dispatch",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Dispatch = envelope.ArtifactMetadata{Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: "recipient-hint-0001", RecipientEpoch: 2}
				request.UnwrapSignedObject = func(candidate []byte) ([]byte, error) { return bytes.Clone(candidate), nil }
				return request
			},
			want: VerificationRejection{Stage: VerificationStageOuter, Reason: VerificationReasonIncompatible},
			code: ActivationInvalidArtifact,
		},
		{
			name: "recipient resolution",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				metadata := envelope.ArtifactMetadata{Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: "recipient-hint-0001", RecipientEpoch: 2}
				sealRequestHPKE(t, &request, request.Artifact, metadata)
				request.Resolver = fixedActivationResolver{err: errors.New("unavailable")}
				return request
			},
			want: VerificationRejection{Stage: VerificationStageRecipient, Reason: VerificationReasonRecipientRejected},
			code: ActivationTrustRejected,
		},
		{
			name: "recipient profile scope",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				metadata := envelope.ArtifactMetadata{Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: "recipient-hint-0001", RecipientEpoch: 2}
				signed := resignProfile(t, &request, func(profile *envelope.CanonicalProfileV1) { profile.ProviderID = "provider-other" }, metadata, request.Delegation.Artifact.IssuerKey.KeyID)
				sealRequestHPKE(t, &request, signed, metadata)
				return request
			},
			want: VerificationRejection{Stage: VerificationStageRecipient, Reason: VerificationReasonScopeMismatch},
			code: ActivationTrustRejected,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy := tc.build(t)
			_, legacyErr := VerifyActivationAdmission(legacy)
			detailed := tc.build(t)
			var events []VerificationRejection
			detailed.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
			_, detailedErr := VerifyActivationAdmission(detailed)
			assertLegacyErrorParity(t, legacyErr, detailedErr)
			if activationCode(detailedErr) != tc.code {
				t.Fatalf("code=%s want=%s err=%v", activationCode(detailedErr), tc.code, detailedErr)
			}
			if !reflect.DeepEqual(events, []VerificationRejection{tc.want}) {
				t.Fatalf("rejection=%+v want=%+v", events, tc.want)
			}
		})
	}
}

func TestActivationRejectionClassifiesTrustAndPolicyFailures(t *testing.T) {
	cases := []struct {
		name  string
		build func(*testing.T) ActivationRequest
		want  VerificationRejection
		code  ActivationReasonCode
		calls int
	}{
		{
			name: "expired root precedes delegation",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Root.ValidUntil = request.Now
				return request
			},
			want: VerificationRejection{Stage: VerificationStageRoot, Reason: VerificationReasonTimeInvalid},
			code: ActivationTrustRejected,
		},
		{
			name: "revocation canonical mismatch precedes denial",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Revocations.Set.EmergencyDenied = true
				request.Revocations.Payload = append(bytes.Clone(request.Revocations.Payload), 0)
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageRevocations, Reason: VerificationReasonBindingMismatch},
			code:  ActivationTrustRejected,
			calls: 1,
		},
		{
			name: "invalid revocation signature precedes denial",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Revocations.Set.EmergencyDenied = true
				resignRevocations(t, &request)
				request.Revocations.Signature[0] ^= 1
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageRevocations, Reason: VerificationReasonSignatureInvalid},
			code:  ActivationTrustRejected,
			calls: 2,
		},
		{
			name: "stale revocations precede denial",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Revocations.Set.EmergencyDenied = true
				request.Revocations.Set.ExpiresAt = request.Now
				resignRevocations(t, &request)
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageRevocations, Reason: VerificationReasonTimeInvalid},
			code:  ActivationTrustRejected,
			calls: 2,
		},
		{
			name: "profile signing key binding",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				resignProfile(t, &request, nil, request.Dispatch, "issuer-key-other")
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageProfileSignature, Reason: VerificationReasonBindingMismatch},
			code:  ActivationTrustRejected,
			calls: 2,
		},
		{
			name: "invalid profile signature",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Artifact[len(request.Artifact)-1] ^= 1
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageProfileSignature, Reason: VerificationReasonSignatureInvalid},
			code:  ActivationTrustRejected,
			calls: 3,
		},
		{
			name: "unsupported profile contract",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				resignProfile(t, &request, func(profile *envelope.CanonicalProfileV1) { profile.ContractVersion = "unsupported" }, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageProfilePolicy, Reason: VerificationReasonIncompatible},
			code:  ActivationPolicyRejected,
			calls: 3,
		},
		{
			name: "profile safety floor",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.MinSafetyFloor++
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageProfilePolicy, Reason: VerificationReasonFloorRejected},
			code:  ActivationPolicyRejected,
			calls: 3,
		},
		{
			name: "profile time",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				resignProfile(t, &request, func(profile *envelope.CanonicalProfileV1) { profile.ValidUntil = request.Now }, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageProfilePolicy, Reason: VerificationReasonTimeInvalid},
			code:  ActivationPolicyRejected,
			calls: 3,
		},
		{
			name: "delegation scope",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				resignProfile(t, &request, func(profile *envelope.CanonicalProfileV1) { profile.ProviderID = "provider-other" }, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageDelegation, Reason: VerificationReasonScopeMismatch},
			code:  ActivationPolicyRejected,
			calls: 3,
		},
		{
			name: "authenticated explicit denial",
			build: func(t *testing.T) ActivationRequest {
				request, _ := validActivationRequest(t)
				request.Revocations.Set.EmergencyDenied = true
				resignRevocations(t, &request)
				return request
			},
			want:  VerificationRejection{Stage: VerificationStageProfilePolicy, Reason: VerificationReasonExplicitRevocation},
			code:  ActivationPolicyRejected,
			calls: 3,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			legacy := tc.build(t)
			_, legacyErr := VerifyActivationAdmission(legacy)

			detailed := tc.build(t)
			verifier := &verificationCountingVerifier{}
			detailed.Verifier = verifier
			var events []VerificationRejection
			detailed.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
			_, detailedErr := VerifyActivationAdmission(detailed)
			assertLegacyErrorParity(t, legacyErr, detailedErr)
			if activationCode(detailedErr) != tc.code {
				t.Fatalf("code=%s want=%s err=%v", activationCode(detailedErr), tc.code, detailedErr)
			}
			if verifier.calls != tc.calls {
				t.Fatalf("verifier calls=%d want=%d", verifier.calls, tc.calls)
			}
			if !reflect.DeepEqual(events, []VerificationRejection{tc.want}) {
				t.Fatalf("rejection=%+v want=%+v", events, tc.want)
			}
		})
	}
}

func TestVerificationRejectionEnumValuesAreStable(t *testing.T) {
	stages := []VerificationStage{
		VerificationStageUnknown,
		VerificationStageOuter,
		VerificationStageRecipient,
		VerificationStageRoot,
		VerificationStageDelegation,
		VerificationStageRevocations,
		VerificationStageProfileSignature,
		VerificationStageProfilePolicy,
		VerificationStageLifecycle,
	}
	for value, stage := range stages {
		if stage != VerificationStage(value) {
			t.Fatalf("stage[%d]=%d", value, stage)
		}
	}
	reasons := []VerificationReason{
		VerificationReasonUnknown,
		VerificationReasonMalformed,
		VerificationReasonRootMismatch,
		VerificationReasonSignatureInvalid,
		VerificationReasonRecipientRejected,
		VerificationReasonBindingMismatch,
		VerificationReasonScopeMismatch,
		VerificationReasonFloorRejected,
		VerificationReasonTimeInvalid,
		VerificationReasonExplicitRevocation,
		VerificationReasonLifecycleMismatch,
		VerificationReasonIncompatible,
	}
	for value, reason := range reasons {
		if reason != VerificationReason(value) {
			t.Fatalf("reason[%d]=%d", value, reason)
		}
	}
}

func TestAdmissionRejectionClassifiesLifecycleFences(t *testing.T) {
	t.Run("replacement rejects an unowned current admission before crypto", func(t *testing.T) {
		request, _ := validActivationRequest(t)
		verifier := &verificationCountingVerifier{}
		request.Verifier = verifier
		var events []VerificationRejection
		request.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
		_, err := VerifyReplacementActivationAdmission(VerifiedActivationAdmission{}, request)
		if !errors.Is(err, ErrOfflineVerify) || verifier.calls != 0 {
			t.Fatalf("err=%v verifier calls=%d", err, verifier.calls)
		}
		want := []VerificationRejection{{Stage: VerificationStageLifecycle, Reason: VerificationReasonLifecycleMismatch}}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("rejection=%+v want=%+v", events, want)
		}
	})

	t.Run("replacement requires the next exact generation", func(t *testing.T) {
		initialRequest, _ := validActivationRequest(t)
		current, err := VerifyInitialActivationAdmission(initialRequest)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := replacementActivationRequest(t)
		request.Current = current.CurrentState()
		resignProfile(t, &request, func(profile *envelope.CanonicalProfileV1) { profile.Generation = 3 }, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)
		var events []VerificationRejection
		request.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
		_, err = VerifyReplacementActivationAdmission(current, request)
		if !errors.Is(err, ErrOfflineVerify) {
			t.Fatalf("err=%v", err)
		}
		want := []VerificationRejection{{Stage: VerificationStageLifecycle, Reason: VerificationReasonLifecycleMismatch}}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("rejection=%+v want=%+v", events, want)
		}
	})

	t.Run("equal generation requires exact authenticated epochs", func(t *testing.T) {
		initialRequest, _ := validActivationRequest(t)
		current, err := VerifyInitialActivationAdmission(initialRequest)
		if err != nil {
			t.Fatal(err)
		}
		request, _ := validActivationRequest(t)
		request.Current = current.CurrentState()
		request.Current.Receipt.RootEpoch--
		request.Current.Status = lifecycle.Admitted
		var events []VerificationRejection
		request.Rejected = func(rejection VerificationRejection) { events = append(events, rejection) }
		_, err = VerifyActivationAdmission(request)
		if activationCode(err) != ActivationPolicyRejected {
			t.Fatalf("err=%v", err)
		}
		want := []VerificationRejection{{Stage: VerificationStageLifecycle, Reason: VerificationReasonLifecycleMismatch}}
		if !reflect.DeepEqual(events, want) {
			t.Fatalf("rejection=%+v want=%+v", events, want)
		}
	})
}

func assertLegacyErrorParity(t *testing.T, legacy, detailed error) {
	t.Helper()
	if (legacy == nil) != (detailed == nil) {
		t.Fatalf("nil error parity failed: legacy=%v detailed=%v", legacy, detailed)
	}
	if legacy != nil && (legacy.Error() != detailed.Error() || errors.Is(legacy, ErrInvalidDelegation) != errors.Is(detailed, ErrInvalidDelegation) || errors.Is(legacy, ErrOfflineVerify) != errors.Is(detailed, ErrOfflineVerify)) {
		t.Fatalf("error parity failed: legacy=%#v detailed=%#v", legacy, detailed)
	}
}

func validVerificationOfflineRequest(t *testing.T) OfflineVerifyRequest {
	t.Helper()
	spec := OfflineIssuanceSpec{
		Profile: envelope.CanonicalProfileV1{
			ContentID: "content.0001", ProfileID: "profiles.one", LineageID: "lineage.0001", ProviderID: "provider.0001",
			ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.0001", SnapshotMode: "full-snapshot",
			UpdateKind: "initial", Generation: 7, RequiredSafetyFloor: 2, ValidFrom: 100, ValidUntil: 1000,
			RootEpoch: 3, RevocationEpoch: 4, RelayIDs: []string{"relay.0001"}, StrategyIDs: []string{"strategy.0001"},
			Policy: []byte{0xa1, 0x01, 0x01},
		},
		Class: envelope.ArtifactSignedPublic, Audience: envelope.AudiencePublic, Suite: envelope.SuiteClassicalV1,
		IssuerRole: RoleIssuer, IssuerScope: AuthorityScope{ProviderID: "provider.0001", LineageID: "lineage.0001", ProfileNamespace: "profiles."},
		IssuerKey: KeyReference{KeyID: "issuer-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}, MinimumGeneration: 7, Now: 500,
	}
	artifact, err := IssueOffline(spec, verificationTestSigner{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	return OfflineVerifyRequest{
		Artifact: artifact, Class: spec.Class, Audience: spec.Audience, Suite: spec.Suite, IssuerRole: spec.IssuerRole,
		IssuerScope: spec.IssuerScope, IssuerKey: spec.IssuerKey, Now: spec.Now, MinimumGeneration: spec.MinimumGeneration,
		MinimumSafetyFloor: spec.Profile.RequiredSafetyFloor, MinimumRootEpoch: spec.Profile.RootEpoch,
		MinimumRevocationEpoch: spec.Profile.RevocationEpoch,
	}
}

func mutateCopy(source []byte, mutate func([]byte)) []byte {
	cloned := bytes.Clone(source)
	mutate(cloned)
	return cloned
}
