// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import "testing"

func TestEmergencyAuthorityRequiresPinnedRootDelegation(t *testing.T) {
	provider := emergencyTestProvider()
	root := validRootSet()
	delegation := EmergencyAuthorityDelegationArtifact{
		RootEpoch:                root.Epoch,
		RootKeyID:                root.Keys[0].KeyID,
		PreviousDelegationSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Authority:                validEmergencyAuthority(),
	}
	signedDelegation := signEmergencyDelegation(t, provider, root.Keys[0], delegation)
	trusted, err := VerifyEmergencyAuthorityDelegation(root, signedDelegation, provider, trustTestNow)
	if err != nil {
		t.Fatalf("valid root-bound emergency delegation rejected: %v", err)
	}

	action := EmergencyAction{
		Kind: EmergencyDeny, Scope: validScope(), Epoch: 4,
		ValidFrom: trustTestNow - 1, ValidUntil: trustTestNow + 10,
	}
	signedAction := signEmergency(t, provider, delegation.Authority, action)
	if _, err := VerifySignedEmergencyAction(trusted, signedAction, 3, trustTestNow, provider); err != nil {
		t.Fatalf("valid signed emergency action rejected: %v", err)
	}
	if _, err := VerifySignedEmergencyAction(VerifiedEmergencyAuthority{}, signedAction, 3, trustTestNow, provider); err == nil {
		t.Fatal("self-attested emergency authority admitted without root delegation")
	}
}

func TestEmergencyAuthorityRejectsEscalationAndMutation(t *testing.T) {
	provider := emergencyTestProvider()
	root := validRootSet()
	delegation := EmergencyAuthorityDelegationArtifact{
		RootEpoch:                root.Epoch,
		RootKeyID:                root.Keys[0].KeyID,
		PreviousDelegationSHA256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		Authority:                validEmergencyAuthority(),
	}
	signedDelegation := signEmergencyDelegation(t, provider, root.Keys[0], delegation)
	trusted, err := VerifyEmergencyAuthorityDelegation(root, signedDelegation, provider, trustTestNow)
	if err != nil {
		t.Fatal(err)
	}
	base := EmergencyAction{
		Kind: EmergencyDeny, Scope: validScope(), Epoch: 4,
		ValidFrom: trustTestNow - 1, ValidUntil: trustTestNow + 10,
	}

	t.Run("post-signature delegation mutation", func(t *testing.T) {
		mutated := signedDelegation
		mutated.Artifact.Authority.Scope.ProfileNamespace = "kurd/region/"
		if _, err := VerifyEmergencyAuthorityDelegation(root, mutated, provider, trustTestNow); err == nil {
			t.Fatal("mutated root delegation admitted")
		}
	})
	t.Run("delegation beyond root validity", func(t *testing.T) {
		escalated := delegation
		escalated.Authority.ValidUntil = root.ValidUntil + 1
		signed := signEmergencyDelegation(t, provider, root.Keys[0], escalated)
		if _, err := VerifyEmergencyAuthorityDelegation(root, signed, provider, trustTestNow); err == nil {
			t.Fatal("emergency delegation outliving its root admitted")
		}
	})
	t.Run("scope escalation", func(t *testing.T) {
		action := base
		action.Scope.ProfileNamespace = "kurdistan/"
		signed := signEmergency(t, provider, delegation.Authority, action)
		if _, err := VerifySignedEmergencyAction(trusted, signed, 3, trustTestNow, provider); err == nil {
			t.Fatal("scope escalation admitted")
		}
	})
	t.Run("key substitution", func(t *testing.T) {
		other := delegation.Authority
		other.Key.KeyID = "emergency-key-other"
		signed := signEmergency(t, provider, other, base)
		if _, err := VerifySignedEmergencyAction(trusted, signed, 3, trustTestNow, provider); err == nil {
			t.Fatal("untrusted emergency key admitted")
		}
	})
	t.Run("validity escalation", func(t *testing.T) {
		action := base
		action.ValidUntil = delegation.Authority.ValidUntil + 1
		signed := signEmergency(t, provider, delegation.Authority, action)
		if _, err := VerifySignedEmergencyAction(trusted, signed, 3, trustTestNow, provider); err == nil {
			t.Fatal("validity escalation admitted")
		}
	})
	t.Run("post-signature action mutation", func(t *testing.T) {
		signed := signEmergency(t, provider, delegation.Authority, base)
		signed.Action.Scope.ProfileNamespace = "kurd/other/"
		if _, err := VerifySignedEmergencyAction(trusted, signed, 3, trustTestNow, provider); err == nil {
			t.Fatal("post-signature emergency mutation admitted")
		}
	})
}

func emergencyTestProvider() *memoryKeyProvider {
	provider := newMemoryKeyProvider()
	provider.secrets["root-key-7"] = []byte("TEST-ONLY-ROOT-SECRET-32-BYTES")
	provider.secrets["emergency-key-1"] = []byte("TEST-ONLY-EMERGENCY-SECRET-32B")
	provider.secrets["emergency-key-other"] = []byte("TEST-ONLY-OTHER-EMERGENCY-KEY")
	return provider
}

func signEmergencyDelegation(
	t *testing.T,
	signer Signer,
	rootKey KeyReference,
	delegation EmergencyAuthorityDelegationArtifact,
) SignedEmergencyAuthorityDelegation {
	t.Helper()
	payload, err := EncodeEmergencyAuthorityDelegationV1(delegation)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(rootKey, payload)
	if err != nil {
		t.Fatal(err)
	}
	return SignedEmergencyAuthorityDelegation{
		Artifact: delegation, RootKey: rootKey, Payload: payload, Signature: signature,
	}
}

func signEmergency(
	t *testing.T,
	signer Signer,
	authority EmergencyAuthorityArtifact,
	action EmergencyAction,
) SignedEmergencyAction {
	t.Helper()
	payload, err := EncodeEmergencyAuthorizationV1(authority, action)
	if err != nil {
		t.Fatal(err)
	}
	signature, err := signer.Sign(authority.Key, payload)
	if err != nil {
		t.Fatal(err)
	}
	return SignedEmergencyAction{
		Authority: authority, Action: action, Payload: payload, Signature: signature,
	}
}
