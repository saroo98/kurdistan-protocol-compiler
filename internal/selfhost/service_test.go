// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
)

func TestSelfHostedArtifactUsesAndroidActivationStateMachineWithExactOuterBytes(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_200_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	verified, err := VerifyAndroidArtifact(issued.Artifact, now.Add(2*time.Minute), 1)
	if err != nil || !bytes.Equal(verified.ExactArtifact, issued.Artifact) || verified.Profile.ContentID != issued.ContentID {
		t.Fatalf("android verification mismatch: verified=%+v err=%v", verified.Profile, err)
	}
	session, err := NewAndroidActivationSession(issued.Artifact, now.Add(2*time.Minute), lifecycle.VerifiedState{})
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	command, ok := session.Next()
	if !ok || command.Kind != profile.ActivationCommandSnapshot || session.Submit(command, profile.ActivationCommandResult{}) != nil {
		t.Fatal("activation did not request the initial snapshot")
	}
	command, ok = session.Next()
	if !ok || command.Kind != profile.ActivationCommandStageCandidate || !bytes.Equal(command.Record.Artifact, issued.Artifact) {
		t.Fatal("activation did not preserve the exact self-hosted outer artifact")
	}
	candidate := command.Record
	if err := session.Submit(command, profile.ActivationCommandResult{}); err != nil {
		t.Fatal(err)
	}
	command, _ = session.Next()
	if command.Kind != profile.ActivationCommandReopenCandidate || session.Submit(command, profile.ActivationCommandResult{Record: candidate}) != nil {
		t.Fatal("exact-byte reopen failed")
	}
	for _, kind := range []profile.ActivationCommandKind{profile.ActivationCommandMarkActivation, profile.ActivationCommandCommitMarked, profile.ActivationCommandFinalizeActivation} {
		command, ok = session.Next()
		if !ok || command.Kind != kind || session.Submit(command, profile.ActivationCommandResult{}) != nil {
			t.Fatalf("activation command %s failed", kind)
		}
	}
	record, err := session.Result()
	if err != nil || !bytes.Equal(record.Artifact, issued.Artifact) || record.Profile.ContentID != issued.ContentID {
		t.Fatalf("activation result mismatch: record=%+v err=%v", record.Profile, err)
	}
}

func TestInitializeRequiresVerifiedRecoveryBeforeIssuance(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "node")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	recoveryPath := filepath.Join(base, "offline", "owner-recovery.kurd-recovery")

	result, err := Initialize(InitOptions{
		DataDir: root, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now,
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.DeploymentID == "" || result.RootFingerprint == "" {
		t.Fatalf("initialization result is incomplete: %+v", result)
	}
	if _, err := os.Stat(recoveryPath); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateProfile(root, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now}); !errors.Is(err, ErrRecoveryUnconfirmed) {
		t.Fatalf("issuance before recovery confirmation error = %v", err)
	}
	if err := ConfirmRecovery(root, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}

	issued, err := CreateProfile(root, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	if issued.URI == "" || len(issued.Artifact) == 0 || len(issued.QRChunks) == 0 {
		t.Fatalf("issued profile is incomplete: %+v", issued)
	}
	normalized, err := envelope.NormalizeProfileIngress(envelope.ProfileIngress{Kind: envelope.IngressURI, Text: issued.URI})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(normalized, issued.Artifact) {
		t.Fatal("URI changed exact profile bytes")
	}
	verified, err := VerifyBundle(issued.Artifact, now.Add(time.Minute), 1)
	if err != nil {
		t.Fatal(err)
	}
	if verified.DeploymentID != result.DeploymentID || verified.ProfileID != issued.ProfileID || verified.Generation != 1 {
		t.Fatalf("verified profile mismatch: %+v", verified)
	}
}

func TestRecoveryRejectsWrongPassphraseAndTampering(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "node")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	recoveryPath := filepath.Join(base, "offline", "owner-recovery.kurd-recovery")
	if _, err := Initialize(InitOptions{
		DataDir: root, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(root, recoveryPath, []byte("wrong passphrase value"), now); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("wrong passphrase error = %v", err)
	}
	raw, err := os.ReadFile(recoveryPath)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	if err := os.WriteFile(recoveryPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(root, recoveryPath, passphrase, now); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("tampered recovery error = %v", err)
	}
}

func TestStoreRejectsStateTampering(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "node")
	passphrase := []byte("correct horse battery staple")
	if _, err := Initialize(InitOptions{
		DataDir: root, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: filepath.Join(base, "offline", "recovery"), RecoveryPassphrase: passphrase,
		Now: time.Unix(1_800_000_000, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, stateFileName)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)/2] ^= 1
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadStatus(root); !errors.Is(err, ErrStateCorrupt) {
		t.Fatalf("tampered state error = %v", err)
	}
}

func TestInterruptedStateWriteResidueCannotReplaceCommittedState(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, "node")
	passphrase := []byte("correct horse battery staple")
	if _, err := Initialize(InitOptions{
		DataDir: root, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: filepath.Join(base, "offline", "recovery"), RecoveryPassphrase: passphrase,
		Now: time.Unix(1_800_000_000, 0).UTC(),
	}); err != nil {
		t.Fatal(err)
	}
	before, err := LoadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, ".state-interrupted.tmp"), []byte("partial untrusted state"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := LoadStatus(root)
	if err != nil {
		t.Fatal(err)
	}
	if after != before {
		t.Fatalf("interrupted temporary write changed committed state: before=%+v after=%+v", before, after)
	}
}

func TestPolicyEndpointRoundTrip(t *testing.T) {
	encoded, err := encodePolicy("203.0.113.7:443")
	if err != nil {
		t.Fatal(err)
	}
	endpoint, err := policyEndpoint(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if endpoint != "203.0.113.7:443" {
		t.Fatalf("endpoint = %q", endpoint)
	}
}

func TestRotateRevokeAndDrainAreMonotonic(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recoveryPath := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := Initialize(InitOptions{
		DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	initial, err := CreateProfile(dataDir, CreateProfileOptions{Name: "phone", ValidFor: 48 * time.Hour, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	replacement, err := RotateProfile(dataDir, RotateProfileOptions{
		ProfileID: initial.ProfileID, RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase,
		ValidFor: 48 * time.Hour, Now: now.Add(2 * time.Minute),
	})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.ProfileID != initial.ProfileID || replacement.Generation <= initial.Generation || replacement.ContentID == initial.ContentID {
		t.Fatalf("rotation did not advance identity: initial=%+v replacement=%+v", initial, replacement)
	}
	if _, err := VerifyBundleAgainstCurrentState(dataDir, initial.Artifact, now.Add(3*time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("old profile after rotation error = %v", err)
	}
	if _, err := VerifyBundleAgainstCurrentState(dataDir, replacement.Artifact, now.Add(3*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := RevokeProfile(dataDir, RevokeProfileOptions{
		ProfileID: replacement.ProfileID, RecoveryPath: recoveryPath,
		RecoveryPassphrase: []byte("wrong passphrase value"), Now: now.Add(4 * time.Minute),
	}); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("wrong-passphrase revocation error = %v", err)
	}
	if err := RevokeProfile(dataDir, RevokeProfileOptions{
		ProfileID: replacement.ProfileID, RecoveryPath: recoveryPath,
		RecoveryPassphrase: passphrase, Now: now.Add(4 * time.Minute),
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyBundleAgainstCurrentState(dataDir, replacement.Artifact, now.Add(5*time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("revoked profile error = %v", err)
	}
	if err := SetDrained(dataDir, true, now.Add(6*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateProfile(dataDir, CreateProfileOptions{Name: "tablet", ValidFor: 24 * time.Hour, Now: now.Add(7 * time.Minute)}); !errors.Is(err, ErrDrained) {
		t.Fatalf("issuance while drained error = %v", err)
	}
	if err := SetDrained(dataDir, false, now.Add(8*time.Minute)); err != nil {
		t.Fatal(err)
	}
}

func TestDeploymentDisableRequiresRecoveryAndAdvancesRevocationEpoch(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recoveryPath := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Unix(1_800_000_000, 0).UTC()
	if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatal(err)
	}
	before, err := LoadStatus(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := SetDeploymentDisabled(dataDir, true, RecoveryActionOptions{RecoveryPath: recoveryPath, RecoveryPassphrase: []byte("wrong passphrase value"), Now: now.Add(2 * time.Minute)}); !errors.Is(err, ErrRecoveryRejected) {
		t.Fatalf("unauthorized deployment disable error = %v", err)
	}
	if err := SetDeploymentDisabled(dataDir, true, RecoveryActionOptions{RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now.Add(2 * time.Minute)}); err != nil {
		t.Fatal(err)
	}
	after, err := LoadStatus(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if after.RevocationEpoch <= before.RevocationEpoch {
		t.Fatalf("disable did not advance revocation epoch: before=%d after=%d", before.RevocationEpoch, after.RevocationEpoch)
	}
	if _, err := VerifyBundleAgainstCurrentState(dataDir, issued.Artifact, now.Add(3*time.Minute)); !errors.Is(err, ErrRollback) {
		t.Fatalf("pre-disable profile remained current: %v", err)
	}
}

func TestIssuerAndRelayRotationRevokePriorProfiles(t *testing.T) {
	for _, kind := range []string{"issuer", "relay"} {
		t.Run(kind, func(t *testing.T) {
			base := t.TempDir()
			dataDir := filepath.Join(base, "node")
			recoveryPath := filepath.Join(base, "offline", "recovery")
			passphrase := []byte("correct horse battery staple")
			now := time.Unix(1_800_000_000, 0).UTC()
			if _, err := Initialize(InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now}); err != nil {
				t.Fatal(err)
			}
			if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
				t.Fatal(err)
			}
			issued, err := CreateProfile(dataDir, CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now.Add(time.Minute)})
			if err != nil {
				t.Fatal(err)
			}
			options := RecoveryActionOptions{RecoveryPath: recoveryPath, RecoveryPassphrase: passphrase, Now: now.Add(2 * time.Minute)}
			var rotation KeyRotationResult
			if kind == "issuer" {
				rotation, err = RotateIssuer(dataDir, options)
			} else {
				rotation, err = RotateRelay(dataDir, options)
			}
			if err != nil {
				t.Fatal(err)
			}
			if rotation.Kind != kind || rotation.PreviousKeyID == rotation.CurrentKeyID || rotation.RevokedProfiles != 1 {
				t.Fatalf("rotation mismatch: %+v", rotation)
			}
			if _, err := VerifyBundleAgainstCurrentState(dataDir, issued.Artifact, now.Add(3*time.Minute)); !errors.Is(err, ErrRollback) {
				t.Fatalf("pre-rotation profile remained current: %v", err)
			}
		})
	}
}
