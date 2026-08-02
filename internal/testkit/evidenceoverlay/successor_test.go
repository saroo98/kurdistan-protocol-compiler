// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package evidenceoverlay

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
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

func TestLoadSuccessorChainsPhase16IntoPhase15(t *testing.T) {
	root := t.TempDir()
	path := "ROADMAP.md"
	phase14 := strings.Repeat("1", 64)
	phase15Bytes := []byte("phase 15\n")
	phase16Bytes := []byte("phase 16\n")
	phase15Digest := sha256.Sum256(phase15Bytes)
	phase16Digest := sha256.Sum256(phase16Bytes)
	if err := os.WriteFile(filepath.Join(root, path), phase16Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16Digest[:])+`"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != phase14 {
		t.Fatalf("oldest predecessor = %q, want %q", got, phase14)
	}
}

func TestResolveCurrentSHA256UsesValidatedPredecessorOrWorkingTree(t *testing.T) {
	root := t.TempDir()
	overlaidPath := "ROADMAP.md"
	currentPath := "docs/GOVERNANCE.md"
	predecessor := strings.Repeat("2", 64)
	post := []byte("phase 15\n")
	current := []byte("current\n")
	postDigest := sha256.Sum256(post)
	currentDigest := sha256.Sum256(current)
	if err := os.WriteFile(filepath.Join(root, overlaidPath), post, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(currentPath)), current, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+predecessor+`","post_sha256":"`+hex.EncodeToString(postDigest[:])+`"}]}`)

	got, err := ResolveCurrentSHA256(root, overlaidPath)
	if err != nil {
		t.Fatal(err)
	}
	if got != predecessor {
		t.Fatalf("overlaid digest = %q, want predecessor %q", got, predecessor)
	}
	got, err = ResolveCurrentSHA256(root, currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(currentDigest[:]); got != want {
		t.Fatalf("current digest = %q, want %q", got, want)
	}
}

func writeOverlayForTest(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
