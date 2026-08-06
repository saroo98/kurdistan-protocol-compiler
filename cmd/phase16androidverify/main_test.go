// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/selfhost"
)

func TestExactSelfHostedProfilePassesAndroidBridgeActivation(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	now := time.Now().UTC().Add(-10 * time.Second)
	passphrase := []byte("correct horse battery staple")
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now.Add(2 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(base, "profile.kurd-profile")
	if err := os.WriteFile(artifact, issued.Artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if err := run([]string{"-artifact", artifact}, &output); err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(output.Bytes(), []byte(`"activationFinalized":true`)) {
		t.Fatalf("unexpected verifier output: %s", output.String())
	}
}

func TestAndroidVerifierRejectsMalformedArtifact(t *testing.T) {
	artifact := filepath.Join(t.TempDir(), "malformed.kurd-profile")
	if err := os.WriteFile(artifact, []byte("not a Kurd profile"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"-artifact", artifact}, &bytes.Buffer{}); err == nil {
		t.Fatal("malformed profile passed Android bridge verification")
	}
}
