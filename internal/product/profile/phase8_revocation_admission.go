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
	return VerifySignedRevocationSetWithRejection(root, signed, verifier, now, nil)
}

func VerifySignedRevocationSetWithRejection(
	root RootSetArtifact,
	signed SignedRevocationSetV1,
	verifier Verifier,
	now int64,
	rejected VerificationRejectionSink,
) (VerifiedRevocationSet, error) {
	rejected = firstVerificationRejectionSink(rejected)
	if verifier == nil {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonIncompatible)
		return VerifiedRevocationSet{}, fmt.Errorf("%w: invalid revocation root", ErrOfflineVerify)
	}
	if validateActiveRootSetWithRejection(root, now, rejected) != nil {
		return VerifiedRevocationSet{}, fmt.Errorf("%w: invalid revocation root", ErrOfflineVerify)
	}
	if signed.RootKey.validate() != nil {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonMalformed)
		return VerifiedRevocationSet{}, fmt.Errorf("%w: invalid revocation root", ErrOfflineVerify)
	}
	if !rootContainsReference(root, signed.RootKey) || signed.Set.RootEpoch != root.Epoch {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonRootMismatch)
		return VerifiedRevocationSet{}, fmt.Errorf("%w: invalid revocation root", ErrOfflineVerify)
	}
	return verifySignedRevocationSetCore(
		signed,
		verifier,
		now,
		fmt.Errorf("%w: invalid revocation signature", ErrOfflineVerify),
		fmt.Errorf("%w: stale revocations", ErrOfflineVerify),
		rejected,
	)
}

func verifySignedRevocationSetCore(
	signed SignedRevocationSetV1,
	verifier Verifier,
	now int64,
	invalidSignature error,
	stale error,
	rejected VerificationRejectionSink,
) (VerifiedRevocationSet, error) {
	canonical, err := EncodeRevocationSetV1(signed.Set)
	if err != nil {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonMalformed)
		return VerifiedRevocationSet{}, invalidSignature
	}
	if !bytes.Equal(canonical, signed.Payload) {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonBindingMismatch)
		return VerifiedRevocationSet{}, invalidSignature
	}
	if verifier.Verify(signed.RootKey, signed.Payload, signed.Signature) != nil {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonSignatureInvalid)
		return VerifiedRevocationSet{}, invalidSignature
	}
	if now < signed.Set.IssuedAt || now >= signed.Set.ExpiresAt ||
		uint64(now-signed.Set.IssuedAt) > signed.Set.MaxOfflineStalenessSecs {
		rejectVerification(rejected, VerificationStageRevocations, VerificationReasonTimeInvalid)
		return VerifiedRevocationSet{}, stale
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
