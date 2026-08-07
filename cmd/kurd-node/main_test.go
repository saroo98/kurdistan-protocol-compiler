// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/selfhost"
)

func TestVersionReportsNativeLinuxDataPlane(t *testing.T) {
	var output, errorOutput bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &output, &errorOutput); code != 0 || errorOutput.Len() != 0 {
		t.Fatalf("code=%d stderr=%q", code, errorOutput.String())
	}
	var result map[string]any
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result["version"] != version || result["dataPlane"] != "NATIVE_LINUX_ONLY" {
		t.Fatalf("version=%v", result)
	}
}

func TestServeRejectsDirectLaunchWithoutSystemdActivation(t *testing.T) {
	t.Setenv("LISTEN_PID", "")
	t.Setenv("LISTEN_FDS", "")
	t.Setenv("LISTEN_FDNAMES", "")
	dataDir := filepath.Join(t.TempDir(), "node")
	control := filepath.Join(t.TempDir(), "control.sock")
	var output, errorOutput bytes.Buffer
	code := run(context.Background(), []string{"serve", "--data-dir", dataDir, "--port", "443", "--control-socket", control}, &output, &errorOutput)
	if code != 1 || output.Len() != 0 || errorOutput.String() != "kurd-node serve: unavailable\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, output.String(), errorOutput.String())
	}
	if strings.Contains(errorOutput.String(), dataDir) || strings.Contains(errorOutput.String(), control) {
		t.Fatal("serve failure exposed an owner-local path")
	}
}

func TestServeRejectsInvalidArgumentsBeforeOpeningResources(t *testing.T) {
	for _, args := range [][]string{
		{"serve"},
		{"serve", "--data-dir", t.TempDir(), "--port", "0"},
		{"serve", "--data-dir", t.TempDir(), "--port", "65536"},
		{"serve", "--data-dir", t.TempDir(), "--port", "443", "unexpected"},
	} {
		var output, errorOutput bytes.Buffer
		if code := run(context.Background(), args, &output, &errorOutput); code != 2 {
			t.Fatalf("args=%v code=%d stdout=%q stderr=%q", args, code, output.String(), errorOutput.String())
		}
	}
}

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
