// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"fmt"
	"slices"
)

// VerifiedRevocationSet is an opaque result from authoritative root-bound
// revocation-set verification.
type VerifiedRevocationSet struct {
	set     RevocationSetV1
	payload []byte
}

func VerifySignedRevocationSet(
	root RootSetArtifact,
	signed SignedRevocationSetV1,
	verifier Verifier,
	now int64,
) (VerifiedRevocationSet, error) {
	if verifier == nil || validateActiveRootSet(root, now) != nil ||
		signed.RootKey.validate() != nil || !rootContainsReference(root, signed.RootKey) ||
		signed.Set.RootEpoch != root.Epoch {
		return VerifiedRevocationSet{}, fmt.Errorf("%w: invalid revocation root", ErrOfflineVerify)
	}
	canonical, err := EncodeRevocationSetV1(signed.Set)
	if err != nil || !bytes.Equal(canonical, signed.Payload) ||
		verifier.Verify(signed.RootKey, signed.Payload, signed.Signature) != nil {
		return VerifiedRevocationSet{}, fmt.Errorf("%w: invalid revocation signature", ErrOfflineVerify)
	}
	if now < signed.Set.IssuedAt || now >= signed.Set.ExpiresAt ||
		uint64(now-signed.Set.IssuedAt) > signed.Set.MaxOfflineStalenessSecs {
		return VerifiedRevocationSet{}, fmt.Errorf("%w: stale revocations", ErrOfflineVerify)
	}
	return VerifiedRevocationSet{
		set:     cloneRevocationSet(signed.Set),
		payload: bytes.Clone(signed.Payload),
	}, nil
}

func (verified VerifiedRevocationSet) Set() RevocationSetV1 {
	return cloneRevocationSet(verified.set)
}

func (verified VerifiedRevocationSet) Payload() []byte {
	return bytes.Clone(verified.payload)
}

func (verified VerifiedRevocationSet) RevokesContent(contentID string) bool {
	return verified.set.EmergencyDenied ||
		slices.Contains(verified.set.RevokedContentIDs, contentID)
}

func cloneRevocationSet(set RevocationSetV1) RevocationSetV1 {
	cloned := set
	cloned.RevokedIssuerKeyIDs = slices.Clone(set.RevokedIssuerKeyIDs)
	cloned.RevokedContentIDs = slices.Clone(set.RevokedContentIDs)
	return cloned
}
