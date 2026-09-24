// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"testing"
	"unsafe"

	"kurdistan/internal/product/envelope"
)

func TestVerifiedActivationAdmissionCloneEnvelope(t *testing.T) {
	// Exercise the exact private clone backing used by the opaque admission,
	// including allocator size-class boundaries and each admitted maximum.
	for _, n := range []int{1, 7, 8, 31, 32, 255, 256, 1023, 1024, 4095, 4096, 49152, 65536, envelope.MaxSignedObjectBytes, envelope.MaxTotalInputBytes} {
		source := ActivationRecord{Artifact: make([]byte, n), SignedObject: make([]byte, n), Profile: envelope.CanonicalProfileV1{Policy: make([]byte, min(n, 65536)), RelayIDs: make([]string, min(n, 256)), StrategyIDs: make([]string, min(n, 256))}}
		copy := cloneActivationRecord(source)
		for _, v := range [][]byte{copy.Artifact, copy.SignedObject, copy.Profile.Policy} {
			if cap(v) > 2*len(v)+8 {
				t.Fatalf("byte clone exceeds charged envelope at %d", n)
			}
		}
		for _, v := range [][]string{copy.Profile.RelayIDs, copy.Profile.StrategyIDs} {
			if uint64(cap(v))*uint64(unsafe.Sizeof("")) > 2*uint64(len(v))*uint64(unsafe.Sizeof(""))+8 {
				t.Fatalf("string clone exceeds charged envelope at %d", n)
			}
		}
		destroyActivationRecord(&copy)
	}
	t.Logf("opaque value=%d activation record=%d profile=%d inspection=%d", unsafe.Sizeof(VerifiedActivationAdmission{}), unsafe.Sizeof(ActivationRecord{}), unsafe.Sizeof(envelope.CanonicalProfileV1{}), unsafe.Sizeof(RedactedInspection{}))
}

func TestVerifiedActivationAdmissionDestroyOwnedBacking(t *testing.T) {
	request, _ := validActivationRequest(t)
	borrowed := bytes.Clone(request.Artifact)
	verified, err := VerifyActivationAdmission(request)
	if err != nil {
		t.Fatal(err)
	}
	other, err := VerifyActivationAdmission(request)
	if err != nil {
		t.Fatal(err)
	}
	artifact, signed, policy := verified.record.Artifact, verified.record.SignedObject, verified.record.Profile.Policy
	destroyer, ok := any(&verified).(interface{ Destroy() })
	if !ok {
		t.Fatal("owned admission has no destruction boundary")
	}
	destroyer.Destroy()
	destroyer.Destroy()
	for _, value := range [][]byte{artifact, signed, policy} {
		if !bytes.Equal(value, make([]byte, len(value))) {
			t.Fatal("owned mutable backing survived destruction")
		}
	}
	if len(verified.ExactArtifact()) != 0 || verified.Inspection() != (RedactedInspection{}) || verified.CurrentState() != (VerifiedActivationAdmission{}).CurrentState() {
		t.Fatal("destroyed admission retains authority")
	}
	if !bytes.Equal(request.Artifact, borrowed) || !bytes.Equal(other.ExactArtifact(), borrowed) {
		t.Fatal("destruction changed caller or separate admission")
	}
}

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
