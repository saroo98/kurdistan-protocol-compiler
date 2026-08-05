// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package lifecycle

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/production/internal/kmsprovider"
)

var ErrIssuanceRejected = errors.New("lifecycle: issuance rejected")

type IssueRequest struct {
	Spec                   profile.OfflineIssuanceSpec
	OperationID            string
	ApprovalID             string
	TrustedSequence        uint64
	ExpectedArtifactSHA256 string
	Sealer                 profile.OfflineRecipientSealer
	Resolver               profile.RecipientResolver
	Opener                 profile.OfflineRecipientOpener
}

type IssueReceipt struct {
	Schema          string
	OperationID     string
	ArtifactSHA256  string
	Inspection      profile.RedactedInspection
	TrustedAt       int64
	TrustedSequence uint64
}

type Issuer struct{ provider *kmsprovider.Provider }

func NewIssuer(provider *kmsprovider.Provider) (*Issuer, error) {
	if provider == nil {
		return nil, ErrIssuanceRejected
	}
	return &Issuer{provider: provider}, nil
}

func (issuer *Issuer) Issue(ctx context.Context, request IssueRequest) ([]byte, IssueReceipt, error) {
	if ctx == nil || request.TrustedSequence == 0 {
		return nil, IssueReceipt{}, ErrIssuanceRejected
	}
	signingInput, err := compileSigningInput(request.Spec)
	if err != nil {
		return nil, IssueReceipt{}, ErrIssuanceRejected
	}
	signingDigest := sha256.Sum256(signingInput)
	signer, err := issuer.provider.BindContext(ctx, kmsprovider.SigningAuthorization{
		Role: kmsprovider.RoleIssuer, OperationID: request.OperationID,
		ApprovalID: request.ApprovalID, ExpectedMessageSHA256: hex.EncodeToString(signingDigest[:]),
		TrustedSequence: request.TrustedSequence,
	})
	if err != nil {
		return nil, IssueReceipt{}, ErrIssuanceRejected
	}
	artifact, err := profile.IssueOffline(request.Spec, signer, request.Sealer)
	if err != nil {
		return nil, IssueReceipt{}, ErrIssuanceRejected
	}
	artifactDigest := sha256.Sum256(artifact)
	digestText := hex.EncodeToString(artifactDigest[:])
	if request.ExpectedArtifactSHA256 != "" && request.ExpectedArtifactSHA256 != digestText {
		return nil, IssueReceipt{}, ErrIssuanceRejected
	}
	verified, err := profile.VerifyOffline(profile.OfflineVerifyRequest{
		Artifact: artifact, Class: request.Spec.Class, Audience: request.Spec.Audience,
		Suite: request.Spec.Suite, IssuerRole: request.Spec.IssuerRole,
		IssuerScope: request.Spec.IssuerScope, IssuerKey: request.Spec.IssuerKey,
		Now: request.Spec.Now, MinimumGeneration: request.Spec.MinimumGeneration,
		MinimumSafetyFloor:     request.Spec.Profile.RequiredSafetyFloor,
		MinimumRootEpoch:       request.Spec.Profile.RootEpoch,
		MinimumRevocationEpoch: request.Spec.Profile.RevocationEpoch,
	}, issuer.provider, request.Resolver, request.Opener)
	if err != nil {
		return nil, IssueReceipt{}, ErrIssuanceRejected
	}
	receipt := IssueReceipt{
		Schema: "phase16-profile-issuance-receipt-v1", OperationID: request.OperationID,
		ArtifactSHA256: digestText, Inspection: profile.InspectRedacted(verified),
		TrustedAt: request.Spec.Now, TrustedSequence: request.TrustedSequence,
	}
	return artifact, receipt, nil
}

func compileSigningInput(spec profile.OfflineIssuanceSpec) ([]byte, error) {
	payload, err := profile.CompileOffline(spec)
	if err != nil {
		return nil, ErrIssuanceRejected
	}
	metadata := envelope.ArtifactMetadata{Class: spec.Class, AudienceClass: spec.Audience}
	if spec.Recipient != nil {
		metadata.RecipientHint = spec.Recipient.Hint
		metadata.RecipientEpoch = spec.Recipient.Epoch
	}
	protected, err := envelope.BuildSignedProtectedHeaders([]byte(spec.IssuerKey.KeyID), metadata)
	if err != nil {
		return nil, ErrIssuanceRejected
	}
	input, err := envelope.BuildCOSESigStructure(protected, payload)
	if err != nil {
		return nil, ErrIssuanceRejected
	}
	return input, nil
}
