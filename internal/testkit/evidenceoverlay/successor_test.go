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

func TestLoadSuccessorAcceptsAuthenticatedDeletion(t *testing.T) {
	root := t.TempDir()
	predecessor := strings.Repeat("a", 64)
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+predecessor+`","post_evidence":"ABSENT"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre["ROADMAP.md"]; got != predecessor {
		t.Fatalf("predecessor = %q, want %q", got, predecessor)
	}
}

func TestLoadSuccessorRejectsDeletionWhenPathStillExists(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "ROADMAP.md"), []byte("still public"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+strings.Repeat("a", 64)+`","post_evidence":"ABSENT"}]}`)

	if _, err := LoadSuccessor(root, "phase15-production-contract-v1"); err == nil {
		t.Fatal("expected deletion evidence to reject an existing path")
	}
}

func TestLoadSuccessorReturnsOptionalPredecessorsWithoutLegacyBase(t *testing.T) {
	root := t.TempDir()
	predecessor := strings.Repeat("b", 64)
	writeOverlayForTest(t, root, PublicDocumentationSuccessorPath, `{"version":"public-documentation-sanitization-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+predecessor+`","post_evidence":"ABSENT"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre["ROADMAP.md"]; got != predecessor {
		t.Fatalf("predecessor = %q, want %q", got, predecessor)
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

func TestLoadSuccessorChainsProductionTrustIntoCIAndPhase15(t *testing.T) {
	root := t.TempDir()
	path := "ROADMAP.md"
	phase14 := strings.Repeat("1", 64)
	phase15Bytes := []byte("phase 15\n")
	phase16CIBytes := []byte("phase 16 CI\n")
	phase16TrustBytes := []byte("phase 16 trust\n")
	phase15Digest := sha256.Sum256(phase15Bytes)
	phase16CIDigest := sha256.Sum256(phase16CIBytes)
	phase16TrustDigest := sha256.Sum256(phase16TrustBytes)
	if err := os.WriteFile(filepath.Join(root, path), phase16TrustBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != phase14 {
		t.Fatalf("oldest predecessor = %q, want %q", got, phase14)
	}
}

func TestLoadSuccessorChainsProductionRuntimeIntoTrustCIAndPhase15(t *testing.T) {
	root := t.TempDir()
	path := "ROADMAP.md"
	phase14 := strings.Repeat("1", 64)
	phase15Bytes := []byte("phase 15\n")
	phase16CIBytes := []byte("phase 16 CI\n")
	phase16TrustBytes := []byte("phase 16 trust\n")
	phase16RuntimeBytes := []byte("phase 16 runtime\n")
	phase15Digest := sha256.Sum256(phase15Bytes)
	phase16CIDigest := sha256.Sum256(phase16CIBytes)
	phase16TrustDigest := sha256.Sum256(phase16TrustBytes)
	phase16RuntimeDigest := sha256.Sum256(phase16RuntimeBytes)
	if err := os.WriteFile(filepath.Join(root, path), phase16RuntimeBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16RuntimeSuccessorPath, `{"version":"phase16-production-runtime-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != phase14 {
		t.Fatalf("oldest predecessor = %q, want %q", got, phase14)
	}
}

func TestLoadSuccessorChainsDecentralizedAuthorityThroughEarlierLayers(t *testing.T) {
	root := t.TempDir()
	path := "ROADMAP.md"
	phase14 := strings.Repeat("1", 64)
	phase15Bytes := []byte("phase 15\n")
	phase16CIBytes := []byte("phase 16 CI\n")
	phase16TrustBytes := []byte("phase 16 trust\n")
	phase16RuntimeBytes := []byte("phase 16 runtime\n")
	decentralizedBytes := []byte("phase 16 decentralized\n")
	phase15Digest := sha256.Sum256(phase15Bytes)
	phase16CIDigest := sha256.Sum256(phase16CIBytes)
	phase16TrustDigest := sha256.Sum256(phase16TrustBytes)
	phase16RuntimeDigest := sha256.Sum256(phase16RuntimeBytes)
	decentralizedDigest := sha256.Sum256(decentralizedBytes)
	if err := os.WriteFile(filepath.Join(root, path), decentralizedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16RuntimeSuccessorPath, `{"version":"phase16-production-runtime-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16DecentralizedSuccessorPath, `{"version":"phase16-decentralized-self-hosted-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`","post_sha256":"`+hex.EncodeToString(decentralizedDigest[:])+`"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != phase14 {
		t.Fatalf("oldest predecessor = %q, want %q", got, phase14)
	}
}

func TestLoadSuccessorChainsP0RepairThroughPublicDocumentationAndEarlierLayers(t *testing.T) {
	root := t.TempDir()
	path := "ROADMAP.md"
	phase14 := strings.Repeat("1", 64)
	phase15Bytes := []byte("phase 15\n")
	phase16CIBytes := []byte("phase 16 CI\n")
	phase16TrustBytes := []byte("phase 16 trust\n")
	phase16RuntimeBytes := []byte("phase 16 runtime\n")
	decentralizedBytes := []byte("phase 16 decentralized\n")
	publicBytes := []byte("public documentation\n")
	p0Bytes := []byte("phase 16 P0 repair\n")
	phase15Digest := sha256.Sum256(phase15Bytes)
	phase16CIDigest := sha256.Sum256(phase16CIBytes)
	phase16TrustDigest := sha256.Sum256(phase16TrustBytes)
	phase16RuntimeDigest := sha256.Sum256(phase16RuntimeBytes)
	decentralizedDigest := sha256.Sum256(decentralizedBytes)
	publicDigest := sha256.Sum256(publicBytes)
	p0Digest := sha256.Sum256(p0Bytes)
	if err := os.WriteFile(filepath.Join(root, path), p0Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16RuntimeSuccessorPath, `{"version":"phase16-production-runtime-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16DecentralizedSuccessorPath, `{"version":"phase16-decentralized-self-hosted-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`","post_sha256":"`+hex.EncodeToString(decentralizedDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, PublicDocumentationSuccessorPath, `{"version":"public-documentation-sanitization-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(decentralizedDigest[:])+`","post_sha256":"`+hex.EncodeToString(publicDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16P0RepairSuccessorPath, `{"version":"phase16-p0-evidence-repair-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"`+hex.EncodeToString(publicDigest[:])+`","post_sha256":"`+hex.EncodeToString(p0Digest[:])+`"}]}`)

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
