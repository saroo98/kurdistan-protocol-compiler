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

func (selfHostedBridgeEnvironment) NewActivationSession(preview androidbridge.VerifyPreview) (*profile.ActivationSession, error) {
	return selfhost.NewAndroidActivationSession(preview.Verified.ExactArtifact, time.Now().UTC(), lifecycle.VerifiedState{})
}

func (environment selfHostedBridgeEnvironment) VerifyBackupRecord(record backup.Record) error {
	if record.Kind != backup.RecordNativeProfile || record.Generation == 0 || len(record.ExactBytes) == 0 {
		return errors.New("self-hosted restore: only verified native-profile records are admitted")
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
