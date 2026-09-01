// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package evidenceoverlay

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase17SuccessorOverlayUsesBoundedExpandedCardinality(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.Dir(Phase17SuccessorPath)), 0o755); err != nil {
		t.Fatal(err)
	}
	write := func(count int) {
		t.Helper()
		entries := make([]entry, count)
		for index := range entries {
			entries[index] = entry{
				Path:       fmt.Sprintf("phase17/file-%03d", index),
				PreSHA256:  strings.Repeat("a", 64),
				PostSHA256: strings.Repeat("b", 64),
			}
		}
		raw, err := json.Marshal(overlay{
			Version: "phase17-live-data-plane-v1",
			Entries: []entry{{
				Path:       "phase17/base",
				PreSHA256:  strings.Repeat("a", 64),
				PostSHA256: strings.Repeat("b", 64),
			}},
			SuccessorEntries: entries,
		})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(Phase17SuccessorPath)), raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	write(263)
	if _, err := readOverlay(root, Phase17SuccessorPath, "phase17-live-data-plane-v1"); err != nil {
		t.Fatalf("expanded Phase 17 successor inventory rejected: %v", err)
	}
	write(Phase17SuccessorEntryLimit + 1)
	if _, err := readOverlay(root, Phase17SuccessorPath, "phase17-live-data-plane-v1"); err == nil {
		t.Fatal("Phase 17 successor inventory above the bounded limit accepted")
	}
}

func TestLoadSuccessorVerifiesPostStateAndReturnsPredecessors(t *testing.T) {
	root := t.TempDir()
	path := "RZ-evidence-ref-069"
	post := []byte("phase 15\n")
	if err := os.WriteFile(filepath.Join(root, path), post, 0o644); err != nil {
		t.Fatal(err)
	}
	postDigest := sha256.Sum256(post)
	overlay := `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"` +
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
	overlay := `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"2667320dee8453456f13e3c69928310fe5eab32f3bd95c58cdbb7b8699ad7a4e","post_sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}]}`
	if err := os.WriteFile(filepath.Join(root, SuccessorPath), []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "RZ-evidence-ref-069"), []byte("mutated"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSuccessor(root, "phase15-production-contract-v1"); err == nil {
		t.Fatal("expected post-state mutation to fail")
	}
}

func TestLoadSuccessorAcceptsAuthenticatedDeletion(t *testing.T) {
	root := t.TempDir()
	predecessor := strings.Repeat("a", 64)
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+predecessor+`","post_evidence":"ABSENT"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre["RZ-evidence-ref-069"]; got != predecessor {
		t.Fatalf("predecessor = %q, want %q", got, predecessor)
	}
}

func TestLoadSuccessorRejectsDeletionWhenPathStillExists(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "RZ-evidence-ref-069"), []byte("still public"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+strings.Repeat("a", 64)+`","post_evidence":"ABSENT"}]}`)

	if _, err := LoadSuccessor(root, "phase15-production-contract-v1"); err == nil {
		t.Fatal("expected deletion evidence to reject an existing path")
	}
}

func TestLoadSuccessorReturnsOptionalPredecessorsWithoutLegacyBase(t *testing.T) {
	root := t.TempDir()
	predecessor := strings.Repeat("b", 64)
	writeOverlayForTest(t, root, PublicDocumentationSuccessorPath, `{"version":"public-documentation-sanitization-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+predecessor+`","post_evidence":"ABSENT"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre["RZ-evidence-ref-069"]; got != predecessor {
		t.Fatalf("predecessor = %q, want %q", got, predecessor)
	}
}

func TestLoadSuccessorChainsPhase16IntoPhase15(t *testing.T) {
	root := t.TempDir()
	path := "RZ-evidence-ref-069"
	phase14 := strings.Repeat("1", 64)
	phase15Bytes := []byte("phase 15\n")
	phase16Bytes := []byte("phase 16\n")
	phase15Digest := sha256.Sum256(phase15Bytes)
	phase16Digest := sha256.Sum256(phase16Bytes)
	if err := os.WriteFile(filepath.Join(root, path), phase16Bytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16Digest[:])+`"}]}`)

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
	path := "RZ-evidence-ref-069"
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
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)

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
	path := "RZ-evidence-ref-069"
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
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16RuntimeSuccessorPath, `{"version":"phase16-production-runtime-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`"}]}`)

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
	path := "RZ-evidence-ref-069"
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
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+phase14+`","post_sha256":"`+hex.EncodeToString(phase15Digest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16SuccessorPath, `{"version":"phase16-ci-release-acceleration-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase15Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16ProductionTrustSuccessorPath, `{"version":"phase16-production-trust-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase16CIDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16RuntimeSuccessorPath, `{"version":"phase16-production-runtime-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase16TrustDigest[:])+`","post_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16DecentralizedSuccessorPath, `{"version":"phase16-decentralized-self-hosted-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+hex.EncodeToString(phase16RuntimeDigest[:])+`","post_sha256":"`+hex.EncodeToString(decentralizedDigest[:])+`"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != phase14 {
		t.Fatalf("oldest predecessor = %q, want %q", got, phase14)
	}
}

func TestLoadSuccessorChainsNewestDecentralizedLFDocumentationAfterPublicLayer(t *testing.T) {
	root := t.TempDir()
	path := "docs/GITHUB_REPO_PROFILE.md"
	historical := strings.Repeat("1", 64)
	phase16Bytes := []byte("phase 16 profile\n")
	staleWindowsBytes := []byte("profile\r\n")
	canonicalCommittedBytes := []byte("profile\n")
	phase16Digest := sha256.Sum256(phase16Bytes)
	staleWindowsDigest := sha256.Sum256(staleWindowsBytes)
	canonicalCommittedDigest := sha256.Sum256(canonicalCommittedBytes)
	if err := os.MkdirAll(filepath.Join(root, "docs"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(path)), canonicalCommittedBytes, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, PublicDocumentationSuccessorPath, `{"version":"public-documentation-sanitization-v1","entries":[{"path":"`+path+`","pre_sha256":"`+hex.EncodeToString(phase16Digest[:])+`","post_sha256":"`+hex.EncodeToString(staleWindowsDigest[:])+`"}]}`)
	writeOverlayForTest(t, root, Phase16DecentralizedSuccessorPath, `{"version":"phase16-decentralized-self-hosted-v1","entries":[{"path":"`+path+`","pre_sha256":"`+historical+`","post_sha256":"`+hex.EncodeToString(phase16Digest[:])+`"}],"successor_entries":[{"path":"`+path+`","pre_sha256":"`+hex.EncodeToString(staleWindowsDigest[:])+`","post_sha256":"`+hex.EncodeToString(canonicalCommittedDigest[:])+`"}]}`)

	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	if got := pre[path]; got != historical {
		t.Fatalf("predecessor = %q, want %q", got, historical)
	}
}

func TestRepositoryDocumentationProfileUsesCanonicalLFSuccessorV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, "docs", "GITHUB_REPO_PROFILE.md"))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	if got, want := hex.EncodeToString(digest[:]), "20c9c960b20a5c8bc795419a812ce1832bad0bc35918d04fdd06f427e8b91b51"; got != want {
		t.Fatalf("documentation profile SHA-256 = %s, want canonical LF successor %s", got, want)
	}
}

func TestResolveCurrentSHA256UsesValidatedPredecessorOrWorkingTree(t *testing.T) {
	root := t.TempDir()
	overlaidPath := "RZ-evidence-ref-069"
	currentPath := "docs/GZ-evidence-ref-001"
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
	writeOverlayForTest(t, root, SuccessorPath, `{"version":"phase15-production-contract-v1","entries":[{"path":"RZ-evidence-ref-069","pre_sha256":"`+predecessor+`","post_sha256":"`+hex.EncodeToString(postDigest[:])+`"}]}`)

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

func TestResolvePhase17PredecessorSHA256StopsAtPhase16State(t *testing.T) {
	root := t.TempDir()
	overlaidPath := "internal/product/profile/phase8_tooling.go"
	currentPath := "testdata/evidence/phase8-suite-decision-matrix.json"
	phase16 := []byte("phase 16 state\n")
	phase17 := []byte("phase 17 state\n")
	current := []byte("current phase 16 evidence\n")
	phase16Digest := sha256.Sum256(phase16)
	phase17Digest := sha256.Sum256(phase17)
	currentDigest := sha256.Sum256(current)
	if err := os.MkdirAll(filepath.Join(root, "internal", "product", "profile"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(overlaidPath)), phase17, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "testdata", "evidence"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, filepath.FromSlash(currentPath)), current, 0o644); err != nil {
		t.Fatal(err)
	}
	writeOverlayForTest(t, root, Phase17SuccessorPath, `{"version":"phase17-live-data-plane-v1","entries":[{"path":"`+overlaidPath+`","pre_sha256":"`+hex.EncodeToString(phase16Digest[:])+`","post_sha256":"`+hex.EncodeToString(phase17Digest[:])+`"}]}`)

	got, err := ResolvePhase17PredecessorSHA256(root, overlaidPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(phase16Digest[:]); got != want {
		t.Fatalf("overlaid digest = %q, want Phase 16 digest %q", got, want)
	}
	got, err = ResolvePhase17PredecessorSHA256(root, currentPath)
	if err != nil {
		t.Fatal(err)
	}
	if want := hex.EncodeToString(currentDigest[:]); got != want {
		t.Fatalf("unchanged digest = %q, want current digest %q", got, want)
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

func TestRepositoryHistoricalSubjectDoesNotReadDevelopmentPostState(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	pre, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatalf("immutable historical verification must not read development post-state: %v", err)
	}
	if len(pre) == 0 {
		t.Fatal("historical verification returned no reconstructed predecessors")
	}
}

func TestRepositoryHistoricalSubjectUsesExactSanitizedMainIdentity(t *testing.T) {
	if HistoricalCommit != "c84473e28249e1d165da23a4bc9be6d4d219784a" ||
		HistoricalTree != "b29fac42992b04e072c727b79a33bcd904e5d9aa" {
		t.Fatalf("repository historical subject = %s/%s, want exact sanitized main", HistoricalCommit, HistoricalTree)
	}
}

func TestLegacyHistoricalIdentityRemainsPinnedAsProvenance(t *testing.T) {
	if LegacyHistoricalCommit != "8ef19dd57520c2930d12e81ed7769a6ec6cf3326" ||
		LegacyHistoricalTree != "3a51879991388775abffa9e3df7984d624b63852" {
		t.Fatalf("legacy provenance = %s/%s, want frozen pre-rewrite identity", LegacyHistoricalCommit, LegacyHistoricalTree)
	}
}

func TestSanitizedLineageRecordBindsPrivacySafeBoundaryMetadata(t *testing.T) {
	record := sanitizedLineageRecordV2()
	if err := validateSanitizedLineageRecord(record); err != nil {
		t.Fatal(err)
	}
	if record.LegacyFeatureCommit != "c88113fb7143a677dbb859b82fdf12cd6953f402" ||
		record.LegacyFeatureTree != "1739ccb6150fe6d9ea1403ca7c17174cfd9ef2ba" ||
		record.SanitizedFeatureCommit != "046f129ae5076d8f63f2907de5bf9e8af4a26a33" ||
		record.SanitizedFeatureTree != "3c9a2d547f709686cf00f4fd7963c0a202b1466a" ||
		record.RemovedRecordCount != 121 || record.RemovedFrameLength != 12072 ||
		record.RemovedManifestSHA256 != "c85925077c12b547b864ba25f19b64e9abd80ad5dc719036b0cb6f8e3ec1b20a" ||
		record.FeatureRecordCount != 192 || record.FeatureFrameLength != 25353 ||
		record.FeatureManifestSHA256 != "0c1b8bf49fb77774ae42714af4cbb474ae388ad48df52d09e6835c47ac874d58" {
		t.Fatalf("sanitized lineage metadata drift: %+v", record)
	}
	raw, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"docs/", ".gitignore", "ROADMAP", `C:\\Users\\`} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("lineage metadata exposed removed or local path material: %q", forbidden)
		}
	}
}

func TestSanitizedLineageRecordRejectsIdentityCountAndDigestMutations(t *testing.T) {
	for name, mutate := range map[string]func(*sanitizedLineageRecord){
		"legacy-identity":    func(r *sanitizedLineageRecord) { r.LegacyFeatureCommit = strings.Repeat("0", 40) },
		"sanitized-identity": func(r *sanitizedLineageRecord) { r.SanitizedFeatureTree = strings.Repeat("0", 40) },
		"removed-count":      func(r *sanitizedLineageRecord) { r.RemovedRecordCount-- },
		"removed-digest":     func(r *sanitizedLineageRecord) { r.RemovedManifestSHA256 = strings.Repeat("0", 64) },
		"feature-count":      func(r *sanitizedLineageRecord) { r.FeatureRecordCount-- },
		"feature-digest":     func(r *sanitizedLineageRecord) { r.FeatureManifestSHA256 = strings.Repeat("0", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			record := sanitizedLineageRecordV2()
			mutate(&record)
			if err := validateSanitizedLineageRecord(record); err == nil {
				t.Fatal("mutated sanitized lineage record accepted")
			}
		})
	}
}

func TestHistoricalFileBindsExactGitIdentityAndReturnsDefensiveBytes(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	const path = "cmd/phase17verify/artifact.go"
	file, err := ReadHistoricalFile(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if file.Commit != "c84473e28249e1d165da23a4bc9be6d4d219784a" ||
		file.Tree != "b29fac42992b04e072c727b79a33bcd904e5d9aa" || file.Path != path ||
		file.Mode != "100644" || file.Type != "blob" || file.Length != 13048 ||
		file.ObjectID != "14e2c24875e782519f5c460c4a70d34f8e89cbd6" ||
		file.SHA256 != "63f4029198490909ea682fb0552d89f896cfe45c70941942f4e1a7f6635e6e12" ||
		int64(len(file.Content)) != file.Length {
		t.Fatalf("unbound historical file metadata: %+v", file)
	}
	file.Content[0] ^= 0xff
	again, err := ReadHistoricalFile(root, path)
	if err != nil {
		t.Fatal(err)
	}
	if again.Content[0] != '/' || again.SHA256 != file.SHA256 {
		t.Fatal("caller mutation escaped into immutable cache")
	}
}

func TestHistoricalLookupNeverFallsBackToAnotherSubject(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	for _, pair := range [][2]string{
		{strings.Repeat("f", 40), HistoricalTree}, {HistoricalCommit, HistoricalCommit},
		{"HEAD", HistoricalTree}, {HistoricalCommit, "HEAD^{tree}"},
	} {
		if _, err := openHistoricalSubject(root, pair[0], pair[1]); err == nil {
			t.Fatalf("wrong or symbolic subject accepted: %v", pair)
		}
	}
	fixture := t.TempDir()
	writeOverlayForTest(t, fixture, "cmd/phase17verify/artifact.go", "shadow policy")
	if _, err := ReadHistoricalFile(fixture, "cmd/phase17verify/artifact.go"); err == nil {
		t.Fatal("similarly named fixture substituted for immutable subject")
	}
	// This is a current-development addition, absent from the pinned tree even
	// when it exists as an untracked or subsequently committed source file.
	if _, err := ReadHistoricalFile(root, "config/phase17-acceptance-registry-v2.json"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("historically absent path was read from another subject: %v", err)
	}
	for _, path := range []string{"", "../go.mod", "/go.mod", "a/../go.mod", "a\\b", "a:b", ".git/config", ".codex-private/x", "a\x00b"} {
		if _, err := ReadHistoricalFile(root, path); err == nil {
			t.Fatalf("unsafe path accepted: %q", path)
		}
	}
}

func TestRepositoryMarkerFailureCannotSelectFixtureMode(t *testing.T) {
	root := t.TempDir()
	writeOverlayForTest(t, root, ".git", "gitdir: missing-subject\n")
	writeOverlayForTest(t, root, "ROADMAP.md", "fixture that must not be read")
	if _, err := ReadSubjectFile(root, "ROADMAP.md"); err == nil {
		t.Fatal("broken immutable marker caused filesystem fallback")
	}
}

func TestStandaloneModuleFixtureRemainsMutableAndCannotBeHistoricalEvidence(t *testing.T) {
	root := t.TempDir()
	writeOverlayForTest(t, root, "go.mod", "module synthetic.example/fixture\n")
	writeOverlayForTest(t, root, "sample.txt", "first")
	for _, want := range []string{"first", "mutated"} {
		writeOverlayForTest(t, root, "sample.txt", want)
		got, err := ReadSubjectFile(root, "sample.txt")
		if err != nil || string(got) != want {
			t.Fatalf("standalone fixture mutation was not observed: %q, %v", got, err)
		}
	}
	if _, err := ReadHistoricalFile(root, "sample.txt"); err == nil {
		t.Fatal("module fixture was accepted as immutable repository evidence")
	}
}

func TestHistoricalObjectRejectsInvalidTypeLengthAndObjectIdentity(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	s, err := openHistoricalSubject(root, HistoricalCommit, HistoricalTree)
	if err != nil {
		t.Fatal(err)
	}
	const path = "cmd/phase17verify/artifact.go"
	base := s.entries[path]
	for name, mutate := range map[string]func(*HistoricalFile){
		"tree":         func(f *HistoricalFile) { f.Type = "tree" },
		"symlink":      func(f *HistoricalFile) { f.Mode = "120000" },
		"negative":     func(f *HistoricalFile) { f.Length = -1 },
		"oversize":     func(f *HistoricalFile) { f.Length = maximumObjectBytes + 1 },
		"wrong-length": func(f *HistoricalFile) { f.Length++ },
		"wrong-object": func(f *HistoricalFile) { f.ObjectID = HistoricalCommit },
	} {
		t.Run(name, func(t *testing.T) {
			entry := base
			mutate(&entry)
			s.entries[path] = entry
			if _, err := s.read(path); err == nil {
				t.Fatal("invalid object binding accepted")
			}
		})
	}
}

func TestHistoricalDirectoryIsNotAbsent(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	if state, err := SubjectState(root, "docs"); err == nil {
		t.Fatalf("directory was treated as a missing file: %s", state)
	}
}

func TestHistoricalCheckoutCRLFIsDerivedOnlyFromPinnedAttributes(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	file, err := ReadHistoricalFile(root, "android/gradlew.bat")
	if err != nil {
		t.Fatal(err)
	}
	if file.Length != 2803 || file.SHA256 != "9ca26d733ada3a45f27b2151288f54e75c9f95b287d1f82ef942ec5cc2d4f006" {
		t.Fatal("literal Git-object identity changed")
	}
	state, err := SubjectState(root, "android/gradlew.bat")
	if err != nil {
		t.Fatal(err)
	}
	if state != "fedad02c18e266ec094995a5751b7fe1eb6e74f66bf75db64fae2e50eb22c234" {
		t.Fatalf("frozen checkout projection was not reproduced: %s", state)
	}
}

func TestImmutableReconstructionCacheIsDefensiveAndFixtureMutable(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", "..", ".."))
	loads := 0
	var computed map[string]string
	compute := func() (map[string]string, error) {
		loads++
		computed = map[string]string{"synthetic": fmt.Sprint(loads)}
		return computed, nil
	}
	first, err := immutableResult(root, "test:copy-isolation", compute)
	if err != nil {
		t.Fatal(err)
	}
	first["synthetic"] = "caller mutation"
	computed["synthetic"] = "retained producer mutation"
	second, err := immutableResult(root, "test:copy-isolation", compute)
	if err != nil || loads != 1 || second["synthetic"] != "1" {
		t.Fatalf("immutable reconstruction cache: loads=%d result=%v error=%v", loads, second, err)
	}
	fixture := t.TempDir()
	for range 2 {
		if _, err := immutableResult(fixture, "test:copy-isolation", compute); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 3 {
		t.Fatal("mutable fixture reconstruction was cached")
	}
	failures := 0
	for range 2 {
		_, err := immutableResult(root, "test:errors-are-not-cached", func() (map[string]string, error) {
			failures++
			return nil, errors.New("synthetic immutable read failure")
		})
		if err == nil {
			t.Fatal("immutable reconstruction failure suppressed")
		}
	}
	if failures != 2 {
		t.Fatal("failed reconstruction was retained as a successful snapshot")
	}
}
