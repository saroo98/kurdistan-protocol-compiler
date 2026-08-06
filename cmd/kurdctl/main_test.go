// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestCLIEndToEndUsesStdinPassphrasesAndExclusiveOutputs(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := "correct horse battery staple\n"
	call := func(args []string, input string) (int, bytes.Buffer, bytes.Buffer) {
		var stdout, stderr bytes.Buffer
		code := run(args, bytes.NewBufferString(input), &stdout, &stderr)
		return code, stdout, stderr
	}
	if code, _, stderr := call([]string{"init", "--data-dir", dataDir, "--name", "owner-node", "--endpoint", "203.0.113.7:443", "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("init code=%d stderr=%s", code, stderr.String())
	}
	if code, _, stderr := call([]string{"recovery", "confirm", "--data-dir", dataDir, "--recovery-file", recovery}, passphrase); code != 0 {
		t.Fatalf("confirm code=%d stderr=%s", code, stderr.String())
	}
	outputDir := filepath.Join(base, "profile-one")
	code, stdout, stderr := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "phone", "--valid-for", "24h", "--output-dir", outputDir}, "")
	if code != 0 {
		t.Fatalf("create code=%d stderr=%s", code, stderr.String())
	}
	var created struct {
		ProfileID string `json:"profileId"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &created); err != nil || created.ProfileID == "" {
		t.Fatalf("create output=%s err=%v", stdout.String(), err)
	}
	for _, name := range []string{"profile.kurd-profile", "profile.kurd-uri.txt", "profile-qr-1.png", "profile-qr-1.svg"} {
		if info, err := os.Stat(filepath.Join(outputDir, name)); err != nil || info.Size() == 0 {
			t.Fatalf("missing output %s: %v", name, err)
		}
	}
	if code, stdout, stderr := call([]string{"profile", "verify", "--file", filepath.Join(outputDir, "profile.kurd-profile")}, ""); code != 0 || !bytes.Contains(stdout.Bytes(), []byte(created.ProfileID)) {
		t.Fatalf("verify code=%d stdout=%s stderr=%s", code, stdout.String(), stderr.String())
	}
	if code, _, _ := call([]string{"profile", "create", "--data-dir", dataDir, "--name", "duplicate-output", "--output-dir", outputDir}, ""); code == 0 {
		t.Fatal("existing output directory was overwritten")
	}
	if code, stdout, stderr := call([]string{"profile", "show", "--data-dir", dataDir, "--id", created.ProfileID, "--reveal", "terminal"}, ""); code != 0 || !bytes.Contains(stdout.Bytes(), []byte("Chunk 1/")) {
		t.Fatalf("show code=%d stdout=%d stderr=%s", code, stdout.Len(), stderr.String())
	}
	if code, stdout, stderr := call([]string{"profile", "show", "--data-dir", dataDir, "--id", created.ProfileID, "--qr"}, ""); code != 0 || !bytes.Contains(stdout.Bytes(), []byte("Chunk 1/")) {
		t.Fatalf("show --qr code=%d stdout=%d stderr=%s", code, stdout.Len(), stderr.String())
	}
	backup := filepath.Join(base, "offline", "node.kurd-backup")
	if code, _, stderr := call([]string{"backup", "create", "--data-dir", dataDir, "--file", backup}, passphrase); code != 0 {
		t.Fatalf("backup code=%d stderr=%s", code, stderr.String())
	}
	if code, _, _ := call([]string{"profile", "revoke", "--data-dir", dataDir, "--id", created.ProfileID, "--recovery-file", recovery, "--confirm", "wrong"}, passphrase); code != 2 {
		t.Fatalf("revoke without exact confirmation code=%d", code)
	}
}

func TestCLINeverAcceptsPassphraseArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"init", "--passphrase", "secret"}, bytes.NewBufferString("correct horse battery staple\n"), &stdout, &stderr)
	if code != 2 {
		t.Fatalf("secret-bearing argument code=%d stderr=%s", code, stderr.String())
	}
}

func TestCLIHelpListsStableAdministrationInterface(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"--help"}, bytes.NewReader(nil), &stdout, &stderr)
	if code != 0 {
		t.Fatalf("help code=%d stderr=%s", code, stderr.String())
	}
	for _, command := range []string{
		"profile create",
		"profile revoke",
		"backup create",
		"restore apply",
		"upgrade apply",
		"logs export-redacted",
	} {
		if !bytes.Contains(stdout.Bytes(), []byte(command)) {
			t.Fatalf("help output missing %q:\n%s", command, stdout.String())
		}
	}
	if stderr.Len() != 0 {
		t.Fatalf("help wrote stderr: %s", stderr.String())
	}
}
