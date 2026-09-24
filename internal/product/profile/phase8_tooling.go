// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"kurdistan/internal/product/envelope"
)

var (
	ErrOfflineIssuance = errors.New("profile: offline issuance rejected")
	ErrOfflineVerify   = errors.New("profile: offline verification rejected")
)

type OfflineIssuanceSpec struct {
	Profile           envelope.CanonicalProfileV1
	Class             envelope.ArtifactClass
	Audience          string
	Suite             envelope.SuiteID
	IssuerRole        AuthorityRole
	IssuerScope       AuthorityScope
	IssuerKey         KeyReference
	Recipient         *RecipientBinding
	MinimumGeneration uint64
	Now               int64
}

type OfflineVerifyRequest struct {
	Artifact               []byte
	Class                  envelope.ArtifactClass
	Audience               string
	Suite                  envelope.SuiteID
	IssuerRole             AuthorityRole
	IssuerScope            AuthorityScope
	IssuerKey              KeyReference
	Now                    int64
	MinimumGeneration      uint64
	MinimumSafetyFloor     uint64
	MinimumRootEpoch       uint64
	MinimumRevocationEpoch uint64
}

type OfflineVerifiedArtifact struct {
	ExactArtifact, ExactSignedObject []byte
	Profile                          envelope.CanonicalProfileV1
	Metadata                         envelope.ArtifactMetadata
	Suite                            envelope.SuiteID
}

type RedactedInspection struct {
	Class, Audience, ContentSHA256 string
	Suite                          envelope.SuiteID
	Generation                     uint64
	ValidUntil                     int64
	Sealed                         bool
}

type OfflineRecipientSealer interface {
	SealOffline(RecipientBinding, []byte, []byte) (encapsulation, ciphertext []byte, err error)
}

type OfflineRecipientOpener interface {
	OpenOffline(RecipientBinding, []byte, []byte, []byte) ([]byte, error)
}

func CompileOffline(spec OfflineIssuanceSpec) ([]byte, error) {
	if err := validateOfflineIssuance(spec); err != nil {
		return nil, err
	}
	return envelope.EncodeCanonicalProfileV1(spec.Profile)
}

func IssueOffline(spec OfflineIssuanceSpec, signer Signer, sealer OfflineRecipientSealer) ([]byte, error) {
	_, metadata, signed, err := signOffline(spec, signer)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	if spec.Class == envelope.ArtifactSignedPublic {
		return signed, nil
	}
	if sealer == nil || spec.Recipient == nil {
		return nil, ErrOfflineIssuance
	}
	outer, err := envelope.BuildSealProtected(metadata)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	enc, ciphertext, err := sealer.SealOffline(*spec.Recipient, outer, signed)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	framed, err := envelope.BuildSealedFrame(outer, enc, ciphertext)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	return framed, nil
}

func signOffline(spec OfflineIssuanceSpec, signer Signer) ([]byte, envelope.ArtifactMetadata, []byte, error) {
	payload, err := CompileOffline(spec)
	if err != nil || signer == nil {
		return nil, envelope.ArtifactMetadata{}, nil, ErrOfflineIssuance
	}
	metadata := issuanceMetadata(spec)
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(spec.IssuerKey.KeyID), metadata)
	if err != nil {
		return nil, envelope.ArtifactMetadata{}, nil, ErrOfflineIssuance
	}
	sigStructure, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		return nil, envelope.ArtifactMetadata{}, nil, ErrOfflineIssuance
	}
	signature, err := signer.Sign(spec.IssuerKey, sigStructure)
	if err != nil {
		return nil, envelope.ArtifactMetadata{}, nil, ErrOfflineIssuance
	}
	signed, err := envelope.BuildTaggedCOSESign1(protected, payload, signature)
	if err != nil {
		return nil, envelope.ArtifactMetadata{}, nil, ErrOfflineIssuance
	}
	return sigStructure, metadata, signed, nil
}

func VerifyOffline(request OfflineVerifyRequest, verifier Verifier, resolver RecipientResolver, opener OfflineRecipientOpener) (OfflineVerifiedArtifact, error) {
	return VerifyOfflineWithRejection(request, verifier, resolver, opener, nil)
}

func VerifyOfflineWithRejection(request OfflineVerifyRequest, verifier Verifier, resolver RecipientResolver, opener OfflineRecipientOpener, rejected VerificationRejectionSink) (OfflineVerifiedArtifact, error) {
	rejected = firstVerificationRejectionSink(rejected)
	metadata := envelope.ArtifactMetadata{Class: request.Class, AudienceClass: request.Audience}
	if request.Class != envelope.ArtifactSignedPublic {
		sealed, err := envelope.ParseSealedProfileOpaque(request.Artifact)
		if err != nil {
			rejectVerification(rejected, VerificationStageOuter, VerificationReasonMalformed)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		outer, err := envelope.DecodeSealProtectedContextV1(sealed.Protected)
		if err != nil {
			rejectVerification(rejected, VerificationStageOuter, VerificationReasonMalformed)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		if outer.SuiteID != request.Suite || outer.ContentType != envelope.SignedObjectContentType {
			rejectVerification(rejected, VerificationStageOuter, VerificationReasonBindingMismatch)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		metadata = outer.Metadata
		if metadata.Class != request.Class || metadata.AudienceClass != request.Audience {
			rejectVerification(rejected, VerificationStageOuter, VerificationReasonBindingMismatch)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		if resolver == nil || opener == nil {
			rejectVerification(rejected, VerificationStageRecipient, VerificationReasonRecipientRejected)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		binding, err := ResolveRecipientForMetadata(resolver, metadata)
		if err != nil {
			rejectVerification(rejected, VerificationStageRecipient, VerificationReasonRecipientRejected)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		opened, err := opener.OpenOffline(binding, sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
		if err != nil {
			rejectVerification(rejected, VerificationStageRecipient, VerificationReasonRecipientRejected)
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		return verifyOfflineSignedWithRejection(request, metadata, opened, verifier, &binding, rejected)
	}
	if err := envelope.ValidateArtifactMetadata(metadata); err != nil {
		rejectVerification(rejected, VerificationStageOuter, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	return verifyOfflineSignedWithRejection(request, metadata, request.Artifact, verifier, nil, rejected)
}

func verifyOfflineSigned(request OfflineVerifyRequest, metadata envelope.ArtifactMetadata, signed []byte, verifier Verifier, recipient *RecipientBinding) (OfflineVerifiedArtifact, error) {
	return verifyOfflineSignedWithRejection(request, metadata, signed, verifier, recipient, nil)
}

func verifyOfflineSignedWithRejection(request OfflineVerifyRequest, metadata envelope.ArtifactMetadata, signed []byte, verifier Verifier, recipient *RecipientBinding, rejected VerificationRejectionSink) (OfflineVerifiedArtifact, error) {
	if verifier == nil {
		rejectVerification(rejected, VerificationStageProfileSignature, VerificationReasonIncompatible)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if request.Suite != envelope.SuiteClassicalV1 {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonIncompatible)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if request.IssuerKey.validate() != nil {
		rejectVerification(rejected, VerificationStageProfileSignature, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	parsed, err := envelope.ParseSignedProfileOpaque(signed)
	if err != nil {
		rejectVerification(rejected, VerificationStageOuter, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	context, err := envelope.DecodeSignedProtectedContextV1(parsed.Protected)
	if err != nil {
		rejectVerification(rejected, VerificationStageOuter, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if context.SuiteID != request.Suite || context.Metadata != metadata || string(context.KeyID) != request.IssuerKey.KeyID {
		rejectVerification(rejected, VerificationStageOuter, VerificationReasonBindingMismatch)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	sigStructure, err := envelope.BuildCOSESigStructure(parsed.Protected, parsed.Payload)
	if err != nil {
		rejectVerification(rejected, VerificationStageProfileSignature, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if verifier.Verify(request.IssuerKey, sigStructure, parsed.Signature) != nil {
		rejectVerification(rejected, VerificationStageProfileSignature, VerificationReasonSignatureInvalid)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	profileValue, err := envelope.DecodeCanonicalProfileV1(parsed.Payload)
	if err != nil {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if recipient != nil && !RecipientBindingContainsProfile(*recipient, profileValue) {
		rejectVerification(rejected, VerificationStageRecipient, VerificationReasonScopeMismatch)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if AuthorizeRoleOperation(request.IssuerRole, OperationAuthenticateProfile) != nil {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonScopeMismatch)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if request.IssuerKey.SuiteID != uint16(request.Suite) {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonBindingMismatch)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if request.IssuerScope.validate() != nil {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonMalformed)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if !request.IssuerScope.contains(profileValue.ProviderID, profileValue.LineageID, profileValue.ProfileID) {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonScopeMismatch)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if request.Now < profileValue.ValidFrom || request.Now >= profileValue.ValidUntil {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonTimeInvalid)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if request.MinimumGeneration == 0 || profileValue.Generation < request.MinimumGeneration || request.MinimumSafetyFloor == 0 || profileValue.RequiredSafetyFloor < request.MinimumSafetyFloor || request.MinimumRootEpoch == 0 || profileValue.RootEpoch < request.MinimumRootEpoch || request.MinimumRevocationEpoch == 0 || profileValue.RevocationEpoch < request.MinimumRevocationEpoch {
		rejectVerification(rejected, VerificationStageProfilePolicy, VerificationReasonFloorRejected)
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	return OfflineVerifiedArtifact{ExactArtifact: bytes.Clone(request.Artifact), ExactSignedObject: bytes.Clone(parsed.ExactObject), Profile: cloneCanonicalProfile(profileValue), Metadata: metadata, Suite: request.Suite}, nil
}

func InspectRedacted(verified OfflineVerifiedArtifact) RedactedInspection {
	digest := sha256.Sum256(verified.ExactSignedObject)
	return RedactedInspection{Class: string(verified.Metadata.Class), Audience: verified.Metadata.AudienceClass, ContentSHA256: hex.EncodeToString(digest[:]), Suite: verified.Suite, Generation: verified.Profile.Generation, ValidUntil: verified.Profile.ValidUntil, Sealed: verified.Metadata.Class != envelope.ArtifactSignedPublic}
}

func validateOfflineIssuance(spec OfflineIssuanceSpec) error {
	if spec.Class == "" || spec.Audience == "" || spec.Suite == 0 || spec.MinimumGeneration == 0 || spec.Now <= 0 || spec.Profile.Generation < spec.MinimumGeneration || spec.Now < spec.Profile.ValidFrom || spec.Now >= spec.Profile.ValidUntil {
		return ErrOfflineIssuance
	}
	if envelope.ValidateSuiteID(spec.Suite) != nil || AuthorizeRoleOperation(spec.IssuerRole, OperationIssueProfile) != nil || spec.IssuerKey.validate() != nil || spec.IssuerKey.SuiteID != uint16(spec.Suite) || spec.IssuerScope.validate() != nil || !spec.IssuerScope.contains(spec.Profile.ProviderID, spec.Profile.LineageID, spec.Profile.ProfileID) {
		return ErrOfflineIssuance
	}
	metadata := issuanceMetadata(spec)
	if envelope.ValidateArtifactMetadata(metadata) != nil {
		return ErrOfflineIssuance
	}
	if spec.Class == envelope.ArtifactSignedPublic {
		if spec.Recipient != nil {
			return ErrOfflineIssuance
		}
		return nil
	}
	if spec.Recipient == nil || spec.Recipient.validate() != nil || spec.Recipient.Class != spec.Class || spec.Recipient.Epoch != metadata.RecipientEpoch || spec.Recipient.Hint != metadata.RecipientHint || !RecipientBindingContainsProfile(*spec.Recipient, spec.Profile) {
		return ErrOfflineIssuance
	}
	return nil
}

func issuanceMetadata(spec OfflineIssuanceSpec) envelope.ArtifactMetadata {
	metadata := envelope.ArtifactMetadata{Class: spec.Class, AudienceClass: spec.Audience}
	if spec.Recipient != nil {
		metadata.RecipientHint, metadata.RecipientEpoch = spec.Recipient.Hint, spec.Recipient.Epoch
	}
	return metadata
}
