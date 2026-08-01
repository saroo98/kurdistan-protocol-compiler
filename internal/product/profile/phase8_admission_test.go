// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"testing"

	"kurdistan/internal/product/envelope"
)

func TestVerifyActivationAdmissionRejectsRevokedContent(t *testing.T) {
	request, _ := validActivationRequest(t)
	if _, err := VerifyActivationAdmission(request); err != nil {
		t.Fatalf("valid admission rejected: %v", err)
	}

	request.Revocations.Set.RevokedContentIDs = []string{"content-1"}
	resignRevocations(t, &request)
	if _, err := VerifyActivationAdmission(request); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("revoked content admitted: %v", err)
	}
}

func TestVerifyActivationAdmissionRejectsEmergencyDeniedContent(t *testing.T) {
	request, _ := validActivationRequest(t)
	request.Revocations.Set.EmergencyDenied = true
	resignRevocations(t, &request)

	if _, err := VerifyActivationAdmission(request); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("emergency-denied content admitted: %v", err)
	}
}

func TestVerifyActivationAdmissionRejectsStaleRevocations(t *testing.T) {
	request, _ := validActivationRequest(t)
	request.Revocations.Set.ExpiresAt = request.Now
	resignRevocations(t, &request)

	if _, err := VerifyActivationAdmission(request); activationCode(err) != ActivationTrustRejected {
		t.Fatalf("stale revocation state admitted: %v", err)
	}
}

func TestVerifyActivationAdmissionRejectsLifecycleInvalidReplacement(t *testing.T) {
	request, _ := validActivationRequest(t)
	resignProfile(t, &request, func(profile *envelope.CanonicalProfileV1) {
		profile.UpdateKind = "replacement"
		profile.PreviousContentID = "content-0"
	}, request.Dispatch, request.Delegation.Artifact.IssuerKey.KeyID)

	if _, err := VerifyActivationAdmission(request); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("lifecycle-invalid replacement admitted: %v", err)
	}
}

func TestVerifyReplacementActivationAdmissionRejectsCrossLineageRebind(t *testing.T) {
	initialRequest, _ := validActivationRequest(t)
	current, err := VerifyInitialActivationAdmission(initialRequest)
	if err != nil {
		t.Fatal(err)
	}
	replacementRequest, _ := replacementActivationRequest(t)
	replacementRequest.Current = current.CurrentState()
	replacementRequest.Delegation.Artifact.Scope.LineageID = "lineage-other"
	replacementRequest.Delegation.Payload, err = EncodeIssuerDelegationV1(replacementRequest.Delegation.Artifact)
	if err != nil {
		t.Fatal(err)
	}
	replacementRequest.Delegation.Signature = testSignature(
		replacementRequest.Delegation.RootKey,
		replacementRequest.Delegation.Payload,
	)
	resignProfile(t, &replacementRequest, func(value *envelope.CanonicalProfileV1) {
		value.LineageID = "lineage-other"
	}, replacementRequest.Dispatch, replacementRequest.Delegation.Artifact.IssuerKey.KeyID)

	if _, err := VerifyReplacementActivationAdmission(current, replacementRequest); activationCode(err) != ActivationPolicyRejected {
		t.Fatalf("cross-lineage replacement admitted: %v", err)
	}
}

func TestVerifyReplacementActivationAdmissionPreservesSameLineageReplacement(t *testing.T) {
	initialRequest, _ := validActivationRequest(t)
	current, err := VerifyInitialActivationAdmission(initialRequest)
	if err != nil {
		t.Fatal(err)
	}
	replacementRequest, _ := replacementActivationRequest(t)
	replacementRequest.Current = current.CurrentState()
	if _, err := VerifyReplacementActivationAdmission(current, replacementRequest); err != nil {
		t.Fatalf("same-lineage replacement rejected: %v", err)
	}
}
