//go:build !phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/selfhost"
)

func TestReleaseBridgeVerifiesAndStagesOwnerSelfHostedProfile(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	request, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactSignedPublic, Parts: [][]byte{issued.Artifact}})
	if err != nil {
		t.Fatal(err)
	}
	environment := newBridgeEnvironment()
	preview, code := androidbridge.VerifyAndPreview(request, environment)
	if code != androidbridge.CodeOK || !bytes.Equal(preview.Verified.ExactArtifact, issued.Artifact) {
		t.Fatalf("release verification code=%v", code)
	}
	if !preview.Trust.OwnerControlled || preview.Trust.UpdatesEnabled ||
		preview.Trust.DeploymentFingerprint == "" || preview.Trust.RelayEndpoint != "203.0.113.7:443" ||
		preview.Trust.AuthorityScope != "deployment-local" || preview.Trust.UpdateLocation != "" {
		t.Fatalf("release first-trust preview=%+v", preview.Trust)
	}
	defer preview.Destroy()
	session, err := environment.NewActivationSession(preview)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	command, ok := session.Next()
	if !ok || command.Kind != profile.ActivationCommandSnapshot || session.Submit(command, profile.ActivationCommandResult{}) != nil {
		t.Fatal("release activation did not request initial storage snapshot")
	}
	command, ok = session.Next()
	if !ok || command.Kind != profile.ActivationCommandStageCandidate || !bytes.Equal(command.Record.Artifact, issued.Artifact) {
		t.Fatal("release activation did not stage the exact owner artifact")
	}
}
