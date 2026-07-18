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
	payload, err := CompileOffline(spec)
	if err != nil || signer == nil {
		return nil, ErrOfflineIssuance
	}
	metadata := issuanceMetadata(spec)
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(spec.IssuerKey.KeyID), metadata)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	sigStructure, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	signature, err := signer.Sign(spec.IssuerKey, sigStructure)
	if err != nil {
		return nil, ErrOfflineIssuance
	}
	signed, err := envelope.BuildTaggedCOSESign1(protected, payload, signature)
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

func VerifyOffline(request OfflineVerifyRequest, verifier Verifier, resolver RecipientResolver, opener OfflineRecipientOpener) (OfflineVerifiedArtifact, error) {
	metadata := envelope.ArtifactMetadata{Class: request.Class, AudienceClass: request.Audience}
	if request.Class != envelope.ArtifactSignedPublic {
		sealed, err := envelope.ParseSealedProfileOpaque(request.Artifact)
		if err != nil {
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		outer, err := envelope.DecodeSealProtectedContextV1(sealed.Protected)
		if err != nil || outer.SuiteID != request.Suite || outer.ContentType != envelope.SignedObjectContentType {
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		metadata = outer.Metadata
		if metadata.Class != request.Class || metadata.AudienceClass != request.Audience || resolver == nil || opener == nil {
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		binding, err := ResolveRecipientForMetadata(resolver, metadata)
		if err != nil {
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		opened, err := opener.OpenOffline(binding, sealed.Protected, sealed.Encapsulation, sealed.Ciphertext)
		if err != nil {
			return OfflineVerifiedArtifact{}, ErrOfflineVerify
		}
		return verifyOfflineSigned(request, metadata, opened, verifier, &binding)
	}
	if err := envelope.ValidateArtifactMetadata(metadata); err != nil {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	return verifyOfflineSigned(request, metadata, request.Artifact, verifier, nil)
}

func verifyOfflineSigned(request OfflineVerifyRequest, metadata envelope.ArtifactMetadata, signed []byte, verifier Verifier, recipient *RecipientBinding) (OfflineVerifiedArtifact, error) {
	if verifier == nil || request.Suite != envelope.SuiteClassicalV1 || request.IssuerKey.validate() != nil {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	parsed, err := envelope.ParseSignedProfileOpaque(signed)
	if err != nil {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	context, err := envelope.DecodeSignedProtectedContextV1(parsed.Protected)
	if err != nil || context.SuiteID != request.Suite || context.Metadata != metadata || string(context.KeyID) != request.IssuerKey.KeyID {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	sigStructure, err := envelope.BuildCOSESigStructure(parsed.Protected, parsed.Payload)
	if err != nil || verifier.Verify(request.IssuerKey, sigStructure, parsed.Signature) != nil {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	profileValue, err := envelope.DecodeCanonicalProfileV1(parsed.Payload)
	if err != nil {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if recipient != nil && !RecipientBindingContainsProfile(*recipient, profileValue) {
		return OfflineVerifiedArtifact{}, ErrOfflineVerify
	}
	if AuthorizeRoleOperation(request.IssuerRole, OperationAuthenticateProfile) != nil || request.IssuerKey.SuiteID != uint16(request.Suite) || request.IssuerScope.validate() != nil || !request.IssuerScope.contains(profileValue.ProviderID, profileValue.LineageID, profileValue.ProfileID) || request.Now < profileValue.ValidFrom || request.Now >= profileValue.ValidUntil || request.MinimumGeneration == 0 || profileValue.Generation < request.MinimumGeneration || request.MinimumSafetyFloor == 0 || profileValue.RequiredSafetyFloor < request.MinimumSafetyFloor || request.MinimumRootEpoch == 0 || profileValue.RootEpoch < request.MinimumRootEpoch || request.MinimumRevocationEpoch == 0 || profileValue.RevocationEpoch < request.MinimumRevocationEpoch {
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
