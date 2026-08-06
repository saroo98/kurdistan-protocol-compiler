//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"strings"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/backup"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/testkit/phase8issuance"
)

type internalBridgeEnvironment struct{}

type internalActivationOpener struct {
	next *phase8issuance.IndependentRecipientOpener
}

func (opener internalActivationOpener) Open(
	binding profile.RecipientBinding,
	encapsulation []byte,
	ciphertext []byte,
) ([]byte, error) {
	audience := ""
	switch binding.Class {
	case envelope.ArtifactProviderGroup:
		audience = envelope.AudienceProvisionedGroup
	case envelope.ArtifactDeviceRecipient:
		audience = envelope.AudienceProvisionedDevice
	case envelope.ArtifactEncryptedBackup:
		audience = envelope.AudienceProvisionedBackupKey
	default:
		return nil, errors.New("phase9 internal activation: invalid recipient class")
	}
	outer, err := envelope.BuildSealProtected(envelope.ArtifactMetadata{
		Class:          binding.Class,
		AudienceClass:  audience,
		RecipientHint:  binding.Hint,
		RecipientEpoch: binding.Epoch,
	})
	if err != nil {
		return nil, err
	}
	return opener.next.OpenOffline(binding, outer, encapsulation, ciphertext)
}

func newBridgeEnvironment() bridgeEnvironment { return internalBridgeEnvironment{} }

func (internalBridgeEnvironment) Verify(artifact []byte, class envelope.ArtifactClass) (profile.OfflineVerifiedArtifact, error) {
	spec := phase8issuance.ValidSpec(class)
	request := profile.OfflineVerifyRequest{
		Artifact:               artifact,
		Class:                  spec.Class,
		Audience:               spec.Audience,
		Suite:                  spec.Suite,
		IssuerRole:             profile.RoleIssuer,
		IssuerScope:            spec.IssuerScope,
		IssuerKey:              spec.IssuerKey,
		Now:                    spec.Now,
		MinimumGeneration:      spec.MinimumGeneration,
		MinimumSafetyFloor:     spec.Profile.RequiredSafetyFloor,
		MinimumRootEpoch:       spec.Profile.RootEpoch,
		MinimumRevocationEpoch: spec.Profile.RevocationEpoch,
	}
	verified, err := profile.VerifyOffline(
		request,
		phase8issuance.NewIndependentVerifier(),
		phase8issuance.NewResolver(class),
		phase8issuance.NewIndependentRecipientOpener(),
	)
	if err == nil {
		return verified, nil
	}
	return selfHostedBridgeEnvironment{}.Verify(artifact, class)
}

func (internalBridgeEnvironment) NewActivationSession(preview androidbridge.VerifyPreview) (*profile.ActivationSession, error) {
	if session, err := selfhost.NewAndroidActivationSession(preview.Verified.ExactArtifact, time.Now().UTC(), lifecycle.VerifiedState{}); err == nil {
		return session, nil
	}
	value := preview.Verified.Profile
	if value.ValidFrom >= value.ValidUntil || value.RootEpoch == 0 || value.RevocationEpoch == 0 {
		return nil, errors.New("phase9 internal activation: invalid verified profile")
	}
	now := value.ValidFrom
	if now < 500 && 500 < value.ValidUntil {
		now = 500
	}
	rootKey := profile.KeyReference{KeyID: "root-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	issuerKey := profile.KeyReference{KeyID: "issuer-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}
	namespace := value.ProfileID
	if separator := strings.LastIndex(namespace, "."); separator >= 0 {
		namespace = namespace[:separator+1]
	}
	scope := profile.AuthorityScope{
		ProviderID:       value.ProviderID,
		LineageID:        value.LineageID,
		ProfileNamespace: namespace,
	}
	root := profile.RootSetArtifact{
		Epoch:      value.RootEpoch,
		ViewID:     "phase9-internal-root",
		ValidFrom:  value.ValidFrom,
		ValidUntil: value.ValidUntil + 3600,
		Keys:       []profile.KeyReference{rootKey},
	}
	delegation := profile.IssuerDelegationArtifact{
		RootEpoch:              value.RootEpoch,
		RootKeyID:              rootKey.KeyID,
		IssuerKey:              issuerKey,
		Scope:                  scope,
		ValidFrom:              value.ValidFrom,
		ValidUntil:             value.ValidUntil + 1800,
		DelegationEpoch:        1,
		MaxProfileValiditySecs: uint64(value.ValidUntil - value.ValidFrom),
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(delegation)
	if err != nil {
		return nil, err
	}
	issuer := phase8issuance.NewIssuer()
	delegationSignature, err := issuer.Sign(rootKey, delegationPayload)
	if err != nil {
		return nil, err
	}
	revocations := profile.RevocationSetV1{
		Version:                 1,
		Scope:                   value.RevocationScope,
		RootEpoch:               value.RootEpoch,
		Epoch:                   value.RevocationEpoch,
		IssuedAt:                value.ValidFrom,
		ExpiresAt:               value.ValidUntil,
		MaxOfflineStalenessSecs: uint64(value.ValidUntil - value.ValidFrom),
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(revocations)
	if err != nil {
		return nil, err
	}
	revocationSignature, err := issuer.Sign(rootKey, revocationPayload)
	if err != nil {
		return nil, err
	}
	request := profile.ActivationRequest{
		Artifact: preview.Verified.ExactArtifact,
		Dispatch: preview.Verified.Metadata,
		Now:      now,
		Root:     root,
		Delegation: profile.SignedIssuerDelegationV1{
			Artifact:  delegation,
			RootKey:   rootKey,
			Payload:   delegationPayload,
			Signature: delegationSignature,
		},
		Revocations: profile.SignedRevocationSetV1{
			Set:       revocations,
			RootKey:   rootKey,
			Payload:   revocationPayload,
			Signature: revocationSignature,
		},
		Verifier:           phase8issuance.NewIndependentVerifier(),
		ContractVersion:    value.ContractVersion,
		MinSafetyFloor:     value.RequiredSafetyFloor,
		MinRootEpoch:       value.RootEpoch,
		MinRevocationEpoch: value.RevocationEpoch,
	}
	if preview.Verified.Metadata.Class != envelope.ArtifactSignedPublic {
		request.Resolver = phase8issuance.NewResolver(preview.Verified.Metadata.Class)
		request.Opener = internalActivationOpener{next: phase8issuance.NewIndependentRecipientOpener()}
	}
	return profile.NewActivationSession(request), nil
}

func (environment internalBridgeEnvironment) VerifyBackupRecord(record backup.Record) error {
	if record.Kind != backup.RecordNativeProfile || record.Generation == 0 || len(record.ExactBytes) == 0 {
		return errors.New("phase9 internal restore: only verified native-profile records are admitted")
	}
	request, err := androidbridge.DecodeVerifyRequest(record.ExactBytes)
	if err != nil {
		return errors.New("phase9 internal restore: malformed verify request")
	}
	preview, code := androidbridge.VerifyAndPreview(record.ExactBytes, environment)
	if code == androidbridge.CodeOK &&
		preview.Verified.Metadata.Class == request.Class &&
		preview.Verified.Profile.Generation == record.Generation {
		return nil
	}
	return errors.New("phase9 internal restore: profile verification rejected")
}
