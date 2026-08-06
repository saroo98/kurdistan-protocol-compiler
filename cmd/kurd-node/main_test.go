// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/selfhost"
)

func TestRunOncePublishesValidatedAuthoritySnapshot(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: time.Now().UTC()}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	var output, errorOutput bytes.Buffer
	publication := filepath.Join(base, "public", "snapshot")
	if code := run(context.Background(), []string{"run", "--data-dir", dataDir, "--publication-file", publication, "--once"}, &output, &errorOutput); code != 0 {
		t.Fatalf("run code=%d stderr=%s", code, errorOutput.String())
	}
	if output.Len() == 0 {
		t.Fatal("missing node health output")
	}
}

func TestRunOnceDoesNotRewriteAnAlreadyDeliveredRevision(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	now := time.Now().UTC()
	passphrase := []byte("correct horse battery staple")
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	publication := filepath.Join(base, "public", "snapshot")
	runOnce := func() map[string]any {
		var output, errorOutput bytes.Buffer
		if code := run(context.Background(), []string{"run", "--data-dir", dataDir, "--publication-file", publication, "--once"}, &output, &errorOutput); code != 0 {
			t.Fatalf("run code=%d stderr=%s", code, errorOutput.String())
		}
		var result map[string]any
		if err := json.Unmarshal(output.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	first := runOnce()
	before, err := os.ReadFile(publication)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(10 * time.Millisecond)
	second := runOnce()
	after, err := os.ReadFile(publication)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) || first["publicationDigest"] != second["publicationDigest"] {
		t.Fatal("an already delivered revision was rewritten")
	}
}
