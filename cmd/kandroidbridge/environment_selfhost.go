// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/backup"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/selfhost"
)

// selfHostedBridgeEnvironment is the release-safe first-trust verifier. It
// accepts only a self-contained, deployment-signed Kurd artifact and performs
// no network request. Trust becomes active only after the Android preview and
// transactional activation flow complete.
type selfHostedBridgeEnvironment struct{}

func (selfHostedBridgeEnvironment) Verify(artifact []byte, class envelope.ArtifactClass) (profile.OfflineVerifiedArtifact, error) {
	if class != envelope.ArtifactSignedPublic {
		return profile.OfflineVerifiedArtifact{}, errors.New("self-hosted bridge: unsupported artifact class")
	}
	return selfhost.VerifyAndroidArtifact(artifact, time.Now().UTC(), 1)
}

func (selfHostedBridgeEnvironment) VerifyWithRecipient(artifact []byte, class envelope.ArtifactClass, credentials androidbridge.RecipientCredentials) (profile.OfflineVerifiedArtifact, error) {
	defer credentials.Destroy()
	if class != envelope.ArtifactDeviceRecipient {
		return profile.OfflineVerifiedArtifact{}, errors.New("self-hosted bridge: unsupported recipient artifact class")
	}
	_, verified, err := selfhost.VerifyLiveBundleForRecipient(artifact, time.Now().UTC(), 1, credentials.Request, credentials.Private)
	return verified, err
}

func (selfHostedBridgeEnvironment) TrustPreview(artifact []byte, class envelope.ArtifactClass) (androidbridge.TrustPreview, error) {
	if class != envelope.ArtifactSignedPublic {
		return androidbridge.TrustPreview{}, errors.New("self-hosted bridge: unsupported artifact class")
	}
	verified, err := selfhost.VerifyBundle(artifact, time.Now().UTC(), 1)
	if err != nil {
		return androidbridge.TrustPreview{}, err
	}
	return androidbridge.TrustPreview{
		DeploymentFingerprint: verified.RootFingerprint,
		RelayEndpoint:         verified.Endpoint,
		AuthorityScope:        "deployment-local",
		OwnerControlled:       true,
		UpdatesEnabled:        false,
	}, nil
}

func (selfHostedBridgeEnvironment) TrustPreviewWithRecipient(artifact []byte, class envelope.ArtifactClass, credentials androidbridge.RecipientCredentials) (androidbridge.TrustPreview, error) {
	defer credentials.Destroy()
	if class != envelope.ArtifactDeviceRecipient {
		return androidbridge.TrustPreview{}, errors.New("self-hosted bridge: unsupported recipient artifact class")
	}
	verified, _, err := selfhost.VerifyLiveBundleForRecipient(artifact, time.Now().UTC(), 1, credentials.Request, credentials.Private)
	if err != nil {
		return androidbridge.TrustPreview{}, err
	}
	return androidbridge.TrustPreview{
		DeploymentFingerprint: verified.RootFingerprint,
		RelayEndpoint:         verified.Endpoint,
		AuthorityScope:        "deployment-local",
		OwnerControlled:       true,
		UpdatesEnabled:        false,
	}, nil
}

func (selfHostedBridgeEnvironment) NewActivationSession(preview androidbridge.VerifyPreview) (*profile.ActivationSession, error) {
	return selfhost.NewAndroidActivationSession(preview.Verified.ExactArtifact, time.Now().UTC(), lifecycle.VerifiedState{})
}

func (selfHostedBridgeEnvironment) NewRecipientActivationSession(preview androidbridge.VerifyPreview, credentials androidbridge.RecipientCredentials) (*profile.ActivationSession, error) {
	defer credentials.Destroy()
	return selfhost.NewAndroidLiveActivationSessionForRecipient(preview.Verified.ExactArtifact, time.Now().UTC(), lifecycle.VerifiedState{}, credentials.Request, credentials.Private)
}

func (environment selfHostedBridgeEnvironment) VerifyBackupRecord(record backup.Record) error {
	switch record.Kind {
	case backup.RecordLocalAlias:
		return verifyVersionedRecipientKeyBackupRecord(record)
	case backup.RecordNativeProfile:
		// Continue below. A profile record must be freshly verified against
		// the current self-hosted authority before restore can proceed.
	default:
		return errors.New("self-hosted restore: unsupported record kind")
	}
	if record.Generation == 0 || len(record.ExactBytes) == 0 {
		return errors.New("self-hosted restore: malformed native-profile record")
	}
	request, err := androidbridge.DecodeVerifyRequest(record.ExactBytes)
	if err != nil || request.Class != envelope.ArtifactSignedPublic {
		return errors.New("self-hosted restore: malformed verify request")
	}
	preview, code := androidbridge.VerifyAndPreview(record.ExactBytes, environment)
	if code != androidbridge.CodeOK {
		return errors.New("self-hosted restore: profile verification rejected")
	}
	defer preview.Destroy()
	if preview.Verified.Profile.Generation != record.Generation || !bytes.Equal(preview.Verified.ExactArtifact, request.Parts[0]) {
		return errors.New("self-hosted restore: record identity mismatch")
	}
	return nil
}

// verifyVersionedRecipientKeyBackupRecord admits only the v2 backup's
// canonical recipient-key envelope. backup.Restore has already validated its
// full cross-record bindings before invoking this per-record environment hook.
func verifyVersionedRecipientKeyBackupRecord(record backup.Record) error {
	if record.Generation != 0 || record.LocalID != "recipient-keys-v3" || len(record.ExactBytes) < 6 ||
		string(record.ExactBytes[:4]) != "KCK3" || record.ExactBytes[4] != 3 || record.ExactBytes[5] == 0 || record.ExactBytes[5] > 32 {
		return errors.New("restore: malformed versioned recipient-key record")
	}
	return nil
}
