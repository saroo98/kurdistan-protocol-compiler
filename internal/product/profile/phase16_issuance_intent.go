// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"

	"kurdistan/internal/product/envelope"
)

// VerifiedIssuanceIntent is an opaque, already-validated Phase 8 issuance
// intent. It binds the exact canonical profile payload, protected headers,
// issuer key reference, audience, artifact class, and recipient metadata before
// an HSM produces a randomized signature or sealing output.
//
// The value cannot be constructed outside this package. Production approval
// code may authorize its digest, while finalization must still verify the exact
// signed artifact through VerifyOffline.
type VerifiedIssuanceIntent struct {
	spec               OfflineIssuanceSpec
	signingInputSHA256 string
}

// VerifiedIssuedArtifact is the opaque result of verifying an exact artifact
// against an already-authorized issuance intent. It is the only value that may
// cross into Phase 16 profile finalization.
type VerifiedIssuedArtifact struct {
	exactArtifact      []byte
	artifactSHA256     string
	signingInputSHA256 string
	profileID          string
	scopeDigestInput   string
	generation         uint64
	validUntil         int64
	inspection         RedactedInspection
}

// IssuerSealedReceipt proves that the authorized signing input was signed by
// the expected issuer and that the resulting object was placed into a strict,
// canonical recipient-sealed frame. It deliberately does not claim that the
// issuer opened or decrypted the device-bound ciphertext.
type IssuerSealedReceipt struct {
	exactArtifact      []byte
	artifactSHA256     string
	signingInputSHA256 string
	profileID          string
	generation         uint64
	validUntil         int64
	inspection         RedactedInspection
}

// VerifyIssuanceIntent validates and compiles the exact signing input without
// invoking a signer or recipient sealer.
func VerifyIssuanceIntent(spec OfflineIssuanceSpec) (VerifiedIssuanceIntent, error) {
	payload, err := CompileOffline(spec)
	if err != nil {
		return VerifiedIssuanceIntent{}, ErrOfflineIssuance
	}
	metadata := issuanceMetadata(spec)
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(spec.IssuerKey.KeyID), metadata)
	if err != nil {
		return VerifiedIssuanceIntent{}, ErrOfflineIssuance
	}
	input, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		return VerifiedIssuanceIntent{}, ErrOfflineIssuance
	}
	digest := sha256.Sum256(input)
	return VerifiedIssuanceIntent{
		spec:               cloneOfflineIssuanceSpec(spec),
		signingInputSHA256: hex.EncodeToString(digest[:]),
	}, nil
}

// SigningInputSHA256 returns the exact pre-signing authorization subject.
func (verified VerifiedIssuanceIntent) SigningInputSHA256() string {
	return verified.signingInputSHA256
}

// Specification returns a defensive copy for the authorized signing worker.
func (verified VerifiedIssuanceIntent) Specification() OfflineIssuanceSpec {
	return cloneOfflineIssuanceSpec(verified.spec)
}

// Inspection returns bounded, non-secret intent metadata.
func (verified VerifiedIssuanceIntent) Inspection() RedactedInspection {
	spec := verified.spec
	return RedactedInspection{
		Class:      string(spec.Class),
		Audience:   spec.Audience,
		Suite:      spec.Suite,
		Generation: spec.Profile.Generation,
		ValidUntil: spec.Profile.ValidUntil,
		Sealed:     spec.Class != envelope.ArtifactSignedPublic,
	}
}

// VerifyIssuedArtifact reruns the independent Phase 8 verifier over the exact
// HSM-produced bytes and proves that the authenticated signed object is the
// exact canonical object authorized by intent.
func VerifyIssuedArtifact(
	intent VerifiedIssuanceIntent,
	artifact []byte,
	verifier Verifier,
	resolver RecipientResolver,
	opener OfflineRecipientOpener,
) (VerifiedIssuedArtifact, error) {
	spec := intent.spec
	verified, err := VerifyOffline(OfflineVerifyRequest{
		Artifact: artifact, Class: spec.Class, Audience: spec.Audience,
		Suite: spec.Suite, IssuerRole: spec.IssuerRole,
		IssuerScope: spec.IssuerScope, IssuerKey: spec.IssuerKey,
		Now: spec.Now, MinimumGeneration: spec.MinimumGeneration,
		MinimumSafetyFloor:     spec.Profile.RequiredSafetyFloor,
		MinimumRootEpoch:       spec.Profile.RootEpoch,
		MinimumRevocationEpoch: spec.Profile.RevocationEpoch,
	}, verifier, resolver, opener)
	if err != nil {
		return VerifiedIssuedArtifact{}, ErrOfflineVerify
	}
	expectedPayload, err := CompileOffline(spec)
	if err != nil {
		return VerifiedIssuedArtifact{}, ErrOfflineVerify
	}
	parsed, err := envelope.ParseSignedProfileOpaque(verified.ExactSignedObject)
	if err != nil || !bytes.Equal(parsed.Payload, expectedPayload) {
		return VerifiedIssuedArtifact{}, ErrOfflineVerify
	}
	signingInput, err := envelope.BuildCOSESigStructure(parsed.Protected, parsed.Payload)
	if err != nil {
		return VerifiedIssuedArtifact{}, ErrOfflineVerify
	}
	signingDigest := sha256.Sum256(signingInput)
	signingDigestText := hex.EncodeToString(signingDigest[:])
	if signingDigestText != intent.signingInputSHA256 {
		return VerifiedIssuedArtifact{}, ErrOfflineVerify
	}
	artifactDigest := sha256.Sum256(verified.ExactArtifact)
	return VerifiedIssuedArtifact{
		exactArtifact:      bytes.Clone(verified.ExactArtifact),
		artifactSHA256:     hex.EncodeToString(artifactDigest[:]),
		signingInputSHA256: signingDigestText,
		profileID:          spec.Profile.ProfileID,
		scopeDigestInput:   spec.Profile.ProviderID + "|" + spec.Profile.LineageID + "|" + spec.Profile.RevocationScope,
		generation:         spec.Profile.Generation,
		validUntil:         spec.Profile.ValidUntil,
		inspection:         InspectRedacted(verified),
	}, nil
}

// IssueOfflineChecked verifies the exact signer output before invoking the
// recipient sealer, then structurally verifies the exact sealed artifact.
// Recipient-side VerifyIssuedArtifact remains responsible for opening HPKE and
// verifying the ciphertext plaintext with the device private key.
func IssueOfflineChecked(
	intent VerifiedIssuanceIntent,
	signer Signer,
	verifier Verifier,
	sealer OfflineRecipientSealer,
) (IssuerSealedReceipt, error) {
	spec := cloneOfflineIssuanceSpec(intent.spec)
	signingInput, metadata, signed, err := signOffline(spec, signer)
	if err != nil || verifier == nil {
		return IssuerSealedReceipt{}, ErrOfflineIssuance
	}
	defer clear(signingInput)
	defer clear(signed)
	digest := sha256.Sum256(signingInput)
	signingDigest := hex.EncodeToString(digest[:])
	if signingDigest != intent.signingInputSHA256 {
		return IssuerSealedReceipt{}, ErrOfflineIssuance
	}
	verifiedSigned, err := verifyOfflineSigned(OfflineVerifyRequest{
		Class: spec.Class, Audience: spec.Audience, Suite: spec.Suite,
		IssuerRole: spec.IssuerRole, IssuerScope: spec.IssuerScope, IssuerKey: spec.IssuerKey,
		Now: spec.Now, MinimumGeneration: spec.MinimumGeneration,
		MinimumSafetyFloor: spec.Profile.RequiredSafetyFloor, MinimumRootEpoch: spec.Profile.RootEpoch,
		MinimumRevocationEpoch: spec.Profile.RevocationEpoch,
	}, metadata, signed, verifier, spec.Recipient)
	if err != nil {
		return IssuerSealedReceipt{}, ErrOfflineIssuance
	}
	expectedPayload, err := CompileOffline(spec)
	if err != nil || !bytes.Equal(verifiedSigned.Profile.Policy, spec.Profile.Policy) {
		return IssuerSealedReceipt{}, ErrOfflineIssuance
	}
	parsedSigned, err := envelope.ParseSignedProfileOpaque(verifiedSigned.ExactSignedObject)
	if err != nil || !bytes.Equal(parsedSigned.Payload, expectedPayload) {
		return IssuerSealedReceipt{}, ErrOfflineIssuance
	}
	artifact := bytes.Clone(signed)
	if spec.Class != envelope.ArtifactSignedPublic {
		if sealer == nil || spec.Recipient == nil {
			return IssuerSealedReceipt{}, ErrOfflineIssuance
		}
		outer, err := envelope.BuildSealProtected(metadata)
		if err != nil {
			return IssuerSealedReceipt{}, ErrOfflineIssuance
		}
		encapsulation, ciphertext, err := sealer.SealOffline(*spec.Recipient, outer, signed)
		if err != nil {
			return IssuerSealedReceipt{}, ErrOfflineIssuance
		}
		artifact, err = envelope.BuildSealedFrame(outer, encapsulation, ciphertext)
		if err != nil {
			return IssuerSealedReceipt{}, ErrOfflineIssuance
		}
		sealed, err := envelope.ParseSealedProfileOpaque(artifact)
		if err != nil || !bytes.Equal(sealed.ExactFrame, artifact) || !bytes.Equal(sealed.Protected, outer) ||
			!bytes.Equal(sealed.Encapsulation, encapsulation) || !bytes.Equal(sealed.Ciphertext, ciphertext) {
			return IssuerSealedReceipt{}, ErrOfflineIssuance
		}
		context, err := envelope.DecodeSealProtectedContextV1(sealed.Protected)
		if err != nil || context.SuiteID != spec.Suite || context.ContentType != envelope.SignedObjectContentType || context.Metadata != metadata {
			return IssuerSealedReceipt{}, ErrOfflineIssuance
		}
	}
	artifactDigest := sha256.Sum256(artifact)
	artifactDigestText := hex.EncodeToString(artifactDigest[:])
	return IssuerSealedReceipt{
		exactArtifact: bytes.Clone(artifact), artifactSHA256: artifactDigestText, signingInputSHA256: signingDigest,
		profileID: spec.Profile.ProfileID, generation: spec.Profile.Generation, validUntil: spec.Profile.ValidUntil,
		inspection: RedactedInspection{
			Class: string(metadata.Class), Audience: metadata.AudienceClass, ContentSHA256: artifactDigestText,
			Suite: spec.Suite, Generation: spec.Profile.Generation, ValidUntil: spec.Profile.ValidUntil,
			Sealed: spec.Class != envelope.ArtifactSignedPublic,
		},
	}, nil
}

func (verified VerifiedIssuedArtifact) ExactArtifact() []byte {
	return bytes.Clone(verified.exactArtifact)
}

func (verified VerifiedIssuedArtifact) ArtifactSHA256() string {
	return verified.artifactSHA256
}

func (verified VerifiedIssuedArtifact) SigningInputSHA256() string {
	return verified.signingInputSHA256
}

func (verified VerifiedIssuedArtifact) ProfileID() string { return verified.profileID }

func (verified VerifiedIssuedArtifact) ScopeDigestInput() string {
	return verified.scopeDigestInput
}

func (verified VerifiedIssuedArtifact) Generation() uint64 { return verified.generation }

func (verified VerifiedIssuedArtifact) ValidUntil() int64 { return verified.validUntil }

func (verified VerifiedIssuedArtifact) Inspection() RedactedInspection {
	return verified.inspection
}

func (receipt IssuerSealedReceipt) ExactArtifact() []byte {
	return bytes.Clone(receipt.exactArtifact)
}

func (receipt IssuerSealedReceipt) ArtifactSHA256() string { return receipt.artifactSHA256 }

func (receipt IssuerSealedReceipt) SigningInputSHA256() string { return receipt.signingInputSHA256 }

func (receipt IssuerSealedReceipt) ProfileID() string { return receipt.profileID }

func (receipt IssuerSealedReceipt) Generation() uint64 { return receipt.generation }

func (receipt IssuerSealedReceipt) ValidUntil() int64 { return receipt.validUntil }

func (receipt IssuerSealedReceipt) Inspection() RedactedInspection { return receipt.inspection }

func cloneOfflineIssuanceSpec(spec OfflineIssuanceSpec) OfflineIssuanceSpec {
	cloned := spec
	cloned.Profile = cloneCanonicalProfile(spec.Profile)
	if spec.Recipient != nil {
		recipient := *spec.Recipient
		cloned.Recipient = &recipient
	}
	return cloned
}
