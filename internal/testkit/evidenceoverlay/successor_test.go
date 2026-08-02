// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package evidenceoverlay

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadSuccessorVerifiesPostStateAndReturnsPredecessors(t *testing.T) {
	root := t.TempDir()
	path := "ROADMAP.md"
	post := []byte("phase 15\n")
	if err := os.WriteFile(filepath.Join(root, path), post, 0o644); err != nil {
		t.Fatal(err)
	}
	postDigest := sha256.Sum256(post)
	overlay := `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"` +
		"2667320dee8453456f13e3c69928310fe5eab32f3bd95c58cdbb7b8699ad7a4e" +
		`","post_sha256":"` + hex.EncodeToString(postDigest[:]) + `"}]}`
	if err := os.MkdirAll(filepath.Join(root, "testdata", "evidence", "phase15"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, SuccessorPath), []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != "2667320dee8453456f13e3c69928310fe5eab32f3bd95c58cdbb7b8699ad7a4e" {
		t.Fatalf("predecessor = %q", got)
	}
}

func TestLoadSuccessorRejectsPostMutation(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "testdata", "evidence", "phase15"), 0o755); err != nil {
		t.Fatal(err)
	}
	overlay := `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"2667320dee8453456f13e3c69928310fe5eab32f3bd95c58cdbb7b8699ad7a4e","post_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`
	if err := os.WriteFile(filepath.Join(root, SuccessorPath), []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "ROADMAP.md"), []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuccessor(root, "phase15-production-contract-v1"); err == nil {
		t.Fatal("expected post-state mutation to fail")
	}
}
