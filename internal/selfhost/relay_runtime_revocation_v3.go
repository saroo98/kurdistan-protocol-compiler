// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"math"
	"strings"
	"time"
	"unsafe"

	"kurdistan/internal/product/profile"
)

type relayRootIdentityV3 struct {
	public            [32]byte
	epoch             uint64
	view              string
	from, until       int64
	key               profile.KeyReference
	deployment, scope string
}

// Opaque nonsecret admitted identity. Only the same validated state load can
// create a valid subject; a caller's zero value cannot establish provenance.
type RelayRevocationSubjectV3 struct {
	valid             bool
	root              relayRootIdentityV3
	issuer            profile.KeyReference
	profile, content  string
	generation, epoch uint64
	digest            [32]byte
}

// Immutable, negative-only verified projection. It owns neither an admission
// nor private keys, payloads, signature bytes or a callback.
type RelayRevocationViewV3 struct {
	valid                       bool
	root                        relayRootIdentityV3
	epoch                       uint64
	digest                      [32]byte
	issued, expires, freshUntil int64
	emergency                   bool
	issuerCount, contentCount   int
	issuers, contents           [256]string
}

type RelayRevocationSourceV3 interface{ VerifiedRevocationsV3() *RelayRevocationViewV3 }
type RelayRevocationOrderV3 uint8

const (
	RelayRevocationInvalidV3 RelayRevocationOrderV3 = iota
	RelayRevocationDifferentRootV3
	RelayRevocationOlderV3
	RelayRevocationConflictV3
	RelayRevocationSameV3
	RelayRevocationNewerV3
)

type relayRuntimeLoadErrorV3 struct {
	cause error
	view  *RelayRevocationViewV3
}

func (e *relayRuntimeLoadErrorV3) Error() string                                 { return ErrRelayRuntimeUnavailable.Error() }
func (e *relayRuntimeLoadErrorV3) Unwrap() error                                 { return e.cause }
func (e *relayRuntimeLoadErrorV3) VerifiedRevocationsV3() *RelayRevocationViewV3 { return e.view }

func (s *RelayRuntimeSnapshotV1) VerifiedRevocationsV3() *RelayRevocationViewV3 {
	if s == nil {
		return nil
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.closed {
		return nil
	}
	return s.revocationsV3
}

func freshCutoffV3(issued, expires int64, staleness uint64) (int64, bool) {
	if issued <= 0 || expires <= issued || staleness > uint64(math.MaxInt64-issued-1) {
		return 0, false
	}
	return min(expires, issued+int64(staleness)+1), true
}

func verifiedRelayRevocationsV3(state persistedState, now time.Time) *RelayRevocationViewV3 {
	if len(state.Root.Keys) != 1 || now.Unix() <= 0 {
		return nil
	}
	cutoff, ok := freshCutoffV3(state.Revocations.IssuedAt, state.Revocations.ExpiresAt, state.Revocations.MaxOfflineStalenessSecs)
	if !ok {
		return nil
	}
	public, err := parseP256Public(state.RootPublicDER)
	if err != nil {
		return nil
	}
	verified, err := profile.VerifySignedRevocationSet(state.Root, profile.SignedRevocationSetV1{Set: state.Revocations, RootKey: state.Root.Keys[0], Payload: state.RevocationPayload, Signature: state.RevocationSig}, p256Verifier{keys: map[string]*ecdsa.PublicKey{state.Root.Keys[0].KeyID: public}}, now.Unix())
	if err != nil {
		return nil
	}
	set := verified.Set()
	if len(set.RevokedIssuerKeyIDs) > 256 || len(set.RevokedContentIDs) > 256 {
		return nil
	}
	view := &RelayRevocationViewV3{valid: true, root: relayRootIdentityV3{
		public: sha256.Sum256(state.RootPublicDER), epoch: state.Root.Epoch, view: strings.Clone(state.Root.ViewID), from: state.Root.ValidFrom, until: state.Root.ValidUntil,
		key: profile.KeyReference{KeyID: strings.Clone(state.Root.Keys[0].KeyID), SuiteID: state.Root.Keys[0].SuiteID}, deployment: strings.Clone(state.DeploymentID), scope: strings.Clone(set.Scope),
	}, epoch: set.Epoch, digest: sha256.Sum256(state.RevocationPayload), issued: set.IssuedAt, expires: set.ExpiresAt, freshUntil: cutoff, emergency: set.EmergencyDenied, issuerCount: len(set.RevokedIssuerKeyIDs), contentCount: len(set.RevokedContentIDs)}
	for i, id := range set.RevokedIssuerKeyIDs {
		view.issuers[i] = strings.Clone(id)
	}
	for i, id := range set.RevokedContentIDs {
		view.contents[i] = strings.Clone(id)
	}
	return view
}

func (v *RelayRevocationViewV3) currentV3(now time.Time) bool {
	if v == nil || !v.valid || now.IsZero() {
		return false
	}
	sec := now.Unix()
	return sec >= v.root.from && sec < v.root.until && sec >= v.issued && sec < v.expires && sec < v.freshUntil
}

func (v *RelayRevocationViewV3) CompareV3(previous *RelayRevocationViewV3) RelayRevocationOrderV3 {
	if v == nil || previous == nil || !v.valid || !previous.valid {
		return RelayRevocationInvalidV3
	}
	if v.root != previous.root {
		return RelayRevocationDifferentRootV3
	}
	if v.epoch < previous.epoch {
		return RelayRevocationOlderV3
	}
	if v.epoch > previous.epoch {
		return RelayRevocationNewerV3
	}
	if v.digest != previous.digest {
		return RelayRevocationConflictV3
	}
	return RelayRevocationSameV3
}

func (v *RelayRevocationViewV3) RevokesV3(subject RelayRevocationSubjectV3, now time.Time) bool {
	if !subject.valid || !v.currentV3(now) || v.root != subject.root || v.epoch < subject.epoch || v.epoch == subject.epoch && v.digest != subject.digest {
		return false
	}
	if v.emergency {
		return true
	}
	for _, id := range v.issuers[:v.issuerCount] {
		if id == subject.issuer.KeyID {
			return true
		}
	}
	for _, id := range v.contents[:v.contentCount] {
		if id == subject.content {
			return true
		}
	}
	return false
}

func (v *RelayRevocationViewV3) OwnedBytesV3() uint64 {
	if v == nil {
		return 0
	}
	size := uint64(unsafe.Sizeof(*v)) + rootTextBytesV3(v.root)
	for _, id := range v.issuers[:v.issuerCount] {
		size += uint64(len(id))
	}
	for _, id := range v.contents[:v.contentCount] {
		size += uint64(len(id))
	}
	return size
}
func rootTextBytesV3(root relayRootIdentityV3) uint64 {
	return uint64(len(root.view) + len(root.key.KeyID) + len(root.deployment) + len(root.scope))
}

func projectRelayServicesV3(state persistedState, record profileRecord, view *RelayRevocationViewV3, now time.Time) (string, string, time.Time, RelayRevocationSubjectV3) {
	var zero RelayRevocationSubjectV3
	if !view.currentV3(now) || state.IssuerKey != state.Delegation.IssuerKey || profile.ValidateIssuerDelegation(state.Root, state.Delegation, now.Unix(), record.Recipient.ProviderID, record.Recipient.LineageID, record.ProfileID) != nil {
		return "", "", time.Time{}, zero
	}
	until := min(record.ValidUntil, state.Delegation.ValidUntil, state.Root.ValidUntil, state.TLS.NotAfter, view.expires, view.freshUntil)
	if now.Unix() < record.CreatedAt || now.Unix() >= until {
		return "", "", time.Time{}, zero
	}
	subject := RelayRevocationSubjectV3{valid: true, root: view.root, issuer: profile.KeyReference{KeyID: strings.Clone(state.IssuerKey.KeyID), SuiteID: state.IssuerKey.SuiteID}, profile: strings.Clone(record.ProfileID), content: strings.Clone(record.ContentID), generation: record.Generation, epoch: view.epoch, digest: view.digest}
	if view.RevokesV3(subject, now) {
		return "", "", time.Time{}, zero
	}
	// Strings are exact bounded identities from validated state, independent of
	// private-key closure. Subject scalar strings may share immutable view bytes.
	return strings.Clone(record.Recipient.ProviderID), strings.Clone(record.Recipient.LineageID), time.Unix(until, 0).UTC(), subject
}
