// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
)

const emergencyAuthorizationVersion = uint64(1)
const emergencyAuthorityDelegationVersion = uint64(1)
const emergencyAuthorityRevocationVersion = uint64(1)

// EmergencyAuthorityDelegationArtifact binds one deny-only emergency key and
// its exact scope to the independently authenticated root set.
type EmergencyAuthorityDelegationArtifact struct {
	RootEpoch                uint64
	RootKeyID                string
	PreviousDelegationSHA256 string
	Authority                EmergencyAuthorityArtifact
}

// SignedEmergencyAuthorityDelegation carries a canonical emergency delegation
// signed by one exact key in the trusted root set.
type SignedEmergencyAuthorityDelegation struct {
	Artifact  EmergencyAuthorityDelegationArtifact
	RootKey   KeyReference
	Payload   []byte
	Signature []byte
}

// VerifiedEmergencyAuthority is an opaque root-bound emergency capability.
// Callers cannot construct one from self-attested authority fields.
type VerifiedEmergencyAuthority struct {
	root                     RootSetArtifact
	rootKey                  KeyReference
	authority                EmergencyAuthorityArtifact
	previousDelegationSHA256 string
	payload                  []byte
}

// EmergencyAuthorityBinding is the exact non-secret identity of one verified
// emergency delegation. State-owning callers must persist and compare every
// field before accepting or executing an emergency action.
type EmergencyAuthorityBinding struct {
	RootEpoch                uint64
	RootSetSHA256            string
	RootKeyID                string
	RootKeySuiteID           uint16
	AuthorizationEpoch       uint64
	PreviousDelegationSHA256 string
	DelegationSHA256         string
	Key                      KeyReference
	Scope                    AuthorityScope
	ValidFrom                int64
	ValidUntil               int64
}

// DelegationPayload returns the exact root-authenticated authority bytes for
// downstream audit binding. It does not expose key material.
func (verified VerifiedEmergencyAuthority) DelegationPayload() []byte {
	return bytes.Clone(verified.payload)
}

// CurrentBinding revalidates the opaque authority at the caller's current
// time and returns its exact durable-state identity.
func (verified VerifiedEmergencyAuthority) CurrentBinding(now int64) (EmergencyAuthorityBinding, error) {
	if validateActiveRootSet(verified.root, now) != nil ||
		validateEmergencyAuthority(verified.authority, now) != nil ||
		len(verified.payload) == 0 {
		return EmergencyAuthorityBinding{}, fmt.Errorf("%w: emergency authority is not current", ErrEmergencyAuthority)
	}
	digest := sha256.Sum256(verified.payload)
	rootSetDigest, err := emergencyRootSetSHA256(verified.root)
	if err != nil {
		return EmergencyAuthorityBinding{}, fmt.Errorf("%w: emergency root set is invalid", ErrEmergencyAuthority)
	}
	return EmergencyAuthorityBinding{
		RootEpoch:                verified.root.Epoch,
		RootSetSHA256:            rootSetDigest,
		RootKeyID:                verified.rootKey.KeyID,
		RootKeySuiteID:           verified.rootKey.SuiteID,
		AuthorizationEpoch:       verified.authority.AuthorizationEpoch,
		PreviousDelegationSHA256: verified.previousDelegationSHA256,
		DelegationSHA256:         hex.EncodeToString(digest[:]),
		Key:                      verified.authority.Key,
		Scope:                    verified.authority.Scope,
		ValidFrom:                verified.authority.ValidFrom,
		ValidUntil:               verified.authority.ValidUntil,
	}, nil
}

// EmergencyAuthorityRevocationArtifact is a separate root-authenticated,
// terminal transition for one exact current emergency delegation.
type EmergencyAuthorityRevocationArtifact struct {
	RootEpoch                  uint64
	RootKeyID                  string
	Scope                      AuthorityScope
	PreviousAuthorizationEpoch uint64
	AuthorizationEpoch         uint64
	PreviousDelegationSHA256   string
	PreviousKey                KeyReference
	EffectiveAt                int64
}

// SignedEmergencyAuthorityRevocation carries a canonical revocation signed by
// one exact key in the trusted root set.
type SignedEmergencyAuthorityRevocation struct {
	Artifact  EmergencyAuthorityRevocationArtifact
	RootKey   KeyReference
	Payload   []byte
	Signature []byte
}

// VerifiedEmergencyAuthorityRevocation is an opaque result from exact-current
// emergency authority revocation verification.
type VerifiedEmergencyAuthorityRevocation struct {
	previous           EmergencyAuthorityBinding
	authorizationEpoch uint64
	revocationSHA256   string
	effectiveAt        int64
}

// PreviousBinding returns the exact active delegation that this revocation
// terminates.
func (verified VerifiedEmergencyAuthorityRevocation) PreviousBinding() EmergencyAuthorityBinding {
	return verified.previous
}

// AuthorizationEpoch returns the exact next terminal authority epoch.
func (verified VerifiedEmergencyAuthorityRevocation) AuthorizationEpoch() uint64 {
	return verified.authorizationEpoch
}

// RevocationSHA256 returns the digest of the canonical root-signed revocation.
func (verified VerifiedEmergencyAuthorityRevocation) RevocationSHA256() string {
	return verified.revocationSHA256
}

// EffectiveAt returns the authenticated revocation effective time.
func (verified VerifiedEmergencyAuthorityRevocation) EffectiveAt() int64 {
	return verified.effectiveAt
}

// SignedEmergencyAction carries canonical authority and action bytes signed by
// the emergency authority key. Verification binds both the authority limits
// and the requested restriction.
type SignedEmergencyAction struct {
	Authority EmergencyAuthorityArtifact
	Action    EmergencyAction
	Payload   []byte
	Signature []byte
}

// VerifiedEmergencyAction is an opaque result from signed emergency
// verification.
type VerifiedEmergencyAction struct {
	authority EmergencyAuthorityArtifact
	action    EmergencyAction
}

// EncodeEmergencyAuthorityDelegationV1 returns the canonical root-signed
// representation of an emergency authority delegation.
func EncodeEmergencyAuthorityDelegationV1(delegation EmergencyAuthorityDelegationArtifact) ([]byte, error) {
	authority := delegation.Authority
	if delegation.RootEpoch == 0 || !boundedID(delegation.RootKeyID) ||
		authority.ValidFrom <= 0 || authority.ValidUntil <= authority.ValidFrom ||
		authority.AuthorizationEpoch == 0 || authority.Revoked ||
		authority.Key.validate() != nil || authority.Scope.validate() != nil {
		return nil, fmt.Errorf("%w: malformed emergency delegation", ErrEmergencyAuthority)
	}
	if (authority.AuthorizationEpoch == 1 && delegation.PreviousDelegationSHA256 != "") ||
		(authority.AuthorizationEpoch > 1 && !validSHA256(delegation.PreviousDelegationSHA256)) {
		return nil, fmt.Errorf("%w: malformed emergency delegation predecessor", ErrEmergencyAuthority)
	}
	material := map[uint64]any{
		1:  emergencyAuthorityDelegationVersion,
		2:  delegation.RootEpoch,
		3:  delegation.RootKeyID,
		4:  authority.Key.KeyID,
		5:  uint64(authority.Key.SuiteID),
		6:  encodeEmergencyScope(authority.Scope),
		7:  authority.ValidFrom,
		8:  authority.ValidUntil,
		9:  authority.AuthorizationEpoch,
		10: authority.Revoked,
	}
	if delegation.PreviousDelegationSHA256 != "" {
		material[11] = delegation.PreviousDelegationSHA256
	}
	return canonicalCBOR(material)
}

// VerifyEmergencyAuthorityDelegation verifies the exact root-set membership,
// canonical delegation bytes, root signature, scope, key separation, and
// validity window before returning an opaque emergency authority.
func VerifyEmergencyAuthorityDelegation(
	root RootSetArtifact,
	signed SignedEmergencyAuthorityDelegation,
	verifier Verifier,
	now int64,
) (VerifiedEmergencyAuthority, error) {
	delegation := signed.Artifact
	authority := delegation.Authority
	if verifier == nil || len(signed.Payload) == 0 || len(signed.Signature) == 0 ||
		validateActiveRootSet(root, now) != nil ||
		signed.RootKey.validate() != nil ||
		!rootContainsReference(root, signed.RootKey) ||
		delegation.RootEpoch != root.Epoch ||
		delegation.RootKeyID != signed.RootKey.KeyID ||
		authority.Key.KeyID == signed.RootKey.KeyID ||
		rootContains(root, authority.Key.KeyID) ||
		authority.ValidFrom < root.ValidFrom ||
		authority.ValidUntil > root.ValidUntil {
		return VerifiedEmergencyAuthority{}, fmt.Errorf("%w: invalid emergency delegation root", ErrEmergencyAuthority)
	}
	if err := validateEmergencyAuthority(authority, now); err != nil {
		return VerifiedEmergencyAuthority{}, err
	}
	canonical, err := EncodeEmergencyAuthorityDelegationV1(delegation)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return VerifiedEmergencyAuthority{}, fmt.Errorf("%w: non-canonical emergency delegation", ErrEmergencyAuthority)
	}
	if err := verifier.Verify(signed.RootKey, signed.Payload, signed.Signature); err != nil {
		return VerifiedEmergencyAuthority{}, fmt.Errorf("%w: emergency delegation signature rejected", ErrEmergencyAuthority)
	}
	return VerifiedEmergencyAuthority{
		root:                     cloneRootSet(root),
		rootKey:                  signed.RootKey,
		authority:                authority,
		previousDelegationSHA256: delegation.PreviousDelegationSHA256,
		payload:                  bytes.Clone(signed.Payload),
	}, nil
}

func emergencyRootSetSHA256(root RootSetArtifact) (string, error) {
	if err := ValidateRootSet(root); err != nil {
		return "", err
	}
	keys := make([]any, len(root.Keys))
	for index, key := range root.Keys {
		keys[index] = map[uint64]any{
			1: key.KeyID,
			2: uint64(key.SuiteID),
		}
	}
	canonical, err := canonicalCBOR(map[uint64]any{
		1: root.Epoch,
		2: root.ViewID,
		3: root.ValidFrom,
		4: root.ValidUntil,
		5: keys,
	})
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(canonical)
	return hex.EncodeToString(digest[:]), nil
}

// EncodeEmergencyAuthorityRevocationV1 returns the canonical root-signed
// representation of an exact-current terminal revocation.
func EncodeEmergencyAuthorityRevocationV1(revocation EmergencyAuthorityRevocationArtifact) ([]byte, error) {
	if revocation.RootEpoch == 0 || !boundedID(revocation.RootKeyID) ||
		revocation.Scope.validate() != nil ||
		revocation.PreviousAuthorizationEpoch == 0 ||
		revocation.AuthorizationEpoch != revocation.PreviousAuthorizationEpoch+1 ||
		!validSHA256(revocation.PreviousDelegationSHA256) ||
		revocation.PreviousKey.validate() != nil ||
		revocation.EffectiveAt <= 0 {
		return nil, fmt.Errorf("%w: malformed emergency authority revocation", ErrEmergencyAuthority)
	}
	return canonicalCBOR(map[uint64]any{
		1:  emergencyAuthorityRevocationVersion,
		2:  revocation.RootEpoch,
		3:  revocation.RootKeyID,
		4:  encodeEmergencyScope(revocation.Scope),
		5:  revocation.PreviousAuthorizationEpoch,
		6:  revocation.AuthorizationEpoch,
		7:  revocation.PreviousDelegationSHA256,
		8:  revocation.PreviousKey.KeyID,
		9:  uint64(revocation.PreviousKey.SuiteID),
		10: revocation.EffectiveAt,
	})
}

// VerifyEmergencyAuthorityRevocation verifies a terminal revocation against
// one exact current opaque emergency delegation.
func VerifyEmergencyAuthorityRevocation(
	root RootSetArtifact,
	current VerifiedEmergencyAuthority,
	signed SignedEmergencyAuthorityRevocation,
	verifier Verifier,
	now int64,
) (VerifiedEmergencyAuthorityRevocation, error) {
	if verifier == nil || len(signed.Payload) == 0 || len(signed.Signature) == 0 ||
		validateActiveRootSet(root, now) != nil ||
		!sameRootSet(current.root, root) ||
		signed.RootKey.validate() != nil ||
		!rootContainsReference(root, signed.RootKey) ||
		signed.Artifact.RootEpoch != root.Epoch ||
		signed.Artifact.RootKeyID != signed.RootKey.KeyID {
		return VerifiedEmergencyAuthorityRevocation{}, fmt.Errorf("%w: invalid emergency revocation root", ErrEmergencyAuthority)
	}
	binding, err := current.CurrentBinding(now)
	if err != nil {
		return VerifiedEmergencyAuthorityRevocation{}, err
	}
	revocation := signed.Artifact
	if binding.RootEpoch != root.Epoch ||
		revocation.Scope != binding.Scope ||
		revocation.PreviousAuthorizationEpoch != binding.AuthorizationEpoch ||
		revocation.AuthorizationEpoch != binding.AuthorizationEpoch+1 ||
		revocation.PreviousDelegationSHA256 != binding.DelegationSHA256 ||
		revocation.PreviousKey != binding.Key ||
		revocation.EffectiveAt < binding.ValidFrom ||
		revocation.EffectiveAt > now {
		return VerifiedEmergencyAuthorityRevocation{}, fmt.Errorf("%w: revocation does not match current emergency authority", ErrEmergencyAuthority)
	}
	canonical, err := EncodeEmergencyAuthorityRevocationV1(revocation)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return VerifiedEmergencyAuthorityRevocation{}, fmt.Errorf("%w: non-canonical emergency authority revocation", ErrEmergencyAuthority)
	}
	if err := verifier.Verify(signed.RootKey, signed.Payload, signed.Signature); err != nil {
		return VerifiedEmergencyAuthorityRevocation{}, fmt.Errorf("%w: emergency authority revocation signature rejected", ErrEmergencyAuthority)
	}
	digest := sha256.Sum256(signed.Payload)
	return VerifiedEmergencyAuthorityRevocation{
		previous:           binding,
		authorizationEpoch: revocation.AuthorizationEpoch,
		revocationSHA256:   hex.EncodeToString(digest[:]),
		effectiveAt:        revocation.EffectiveAt,
	}, nil
}

// EncodeEmergencyAuthorizationV1 returns the canonical signed representation
// of an emergency authority and one action under that authority.
func EncodeEmergencyAuthorizationV1(authority EmergencyAuthorityArtifact, action EmergencyAction) ([]byte, error) {
	if err := authority.Key.validate(); err != nil {
		return nil, fmt.Errorf("%w: malformed emergency key", ErrEmergencyAuthority)
	}
	if err := authority.Scope.validate(); err != nil {
		return nil, fmt.Errorf("%w: malformed authority scope", ErrEmergencyAuthority)
	}
	if err := action.Scope.validate(); err != nil {
		return nil, fmt.Errorf("%w: malformed action scope", ErrEmergencyAuthority)
	}
	return canonicalCBOR(map[uint64]any{
		1:  emergencyAuthorizationVersion,
		2:  authority.Key.KeyID,
		3:  uint64(authority.Key.SuiteID),
		4:  encodeEmergencyScope(authority.Scope),
		5:  authority.ValidFrom,
		6:  authority.ValidUntil,
		7:  authority.AuthorizationEpoch,
		8:  authority.Revoked,
		9:  string(action.Kind),
		10: encodeEmergencyScope(action.Scope),
		11: action.Epoch,
		12: action.ValidFrom,
		13: action.ValidUntil,
	})
}

// VerifySignedEmergencyAction verifies canonical encoding, signature,
// monotonicity, expiry, deny-only semantics, and strict scope reduction.
func VerifySignedEmergencyAction(
	trusted VerifiedEmergencyAuthority,
	signed SignedEmergencyAction,
	currentEpoch uint64,
	now int64,
	verifier Verifier,
) (VerifiedEmergencyAction, error) {
	if verifier == nil || len(signed.Payload) == 0 || len(signed.Signature) == 0 {
		return VerifiedEmergencyAction{}, fmt.Errorf("%w: missing signed emergency proof", ErrEmergencyAuthority)
	}
	if validateActiveRootSet(trusted.root, now) != nil ||
		trusted.authority != signed.Authority ||
		len(trusted.payload) == 0 ||
		signed.Action.ValidFrom < trusted.root.ValidFrom ||
		signed.Action.ValidUntil > trusted.root.ValidUntil {
		return VerifiedEmergencyAction{}, fmt.Errorf("%w: action does not match trusted emergency authority", ErrEmergencyAuthority)
	}
	if err := ValidateEmergencyAction(signed.Authority, currentEpoch, signed.Action, now); err != nil {
		return VerifiedEmergencyAction{}, err
	}
	canonical, err := EncodeEmergencyAuthorizationV1(signed.Authority, signed.Action)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return VerifiedEmergencyAction{}, fmt.Errorf("%w: non-canonical emergency proof", ErrEmergencyAuthority)
	}
	if err := verifier.Verify(signed.Authority.Key, signed.Payload, signed.Signature); err != nil {
		return VerifiedEmergencyAction{}, fmt.Errorf("%w: emergency signature rejected", ErrEmergencyAuthority)
	}
	return VerifiedEmergencyAction{
		authority: signed.Authority,
		action:    signed.Action,
	}, nil
}

func (verified VerifiedEmergencyAction) Authority() EmergencyAuthorityArtifact {
	return verified.authority
}

func (verified VerifiedEmergencyAction) Action() EmergencyAction {
	return verified.action
}

func cloneRootSet(root RootSetArtifact) RootSetArtifact {
	cloned := root
	cloned.Keys = append([]KeyReference(nil), root.Keys...)
	return cloned
}

func encodeEmergencyScope(scope AuthorityScope) map[uint64]any {
	return map[uint64]any{
		1: scope.ProviderID,
		2: scope.LineageID,
		3: scope.ProfileNamespace,
	}
}

func validSHA256(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if !(character >= '0' && character <= '9' || character >= 'a' && character <= 'f') {
			return false
		}
	}
	return true
}
