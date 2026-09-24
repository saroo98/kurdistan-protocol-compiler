// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package committedevidence

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"kurdistan/internal/testkit/evidenceoverlay"
)

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", "..", ".."))
}

func fixtureExpectations() []ExpectedEntry {
	return []ExpectedEntry{
		{"internal/testkit/importrules/importrules_test.go", "UNRECORDED"},
		{"docs/KZ-evidence-ref-021", "UNRECORDED"},
		{"docs/KZ-evidence-ref-013", "UNRECORDED"},
		{"docs/KZ-evidence-ref-014", "UNRECORDED"},
		{"README.md", "UNRECORDED"},
		{"internal/runtime/policy_enforcement_test.go", "UNRECORDED"},
	}
}

func TestVerifyHistoricalSetRepositoryIdentity(t *testing.T) {
	if err := VerifyHistoricalSet(repositoryRoot(t), "WO-044", fixtureExpectations()); err != nil {
		t.Fatal(err)
	}
}

// Copy only the immutable manifest closure. Removed historical paths remain
// absent, and the positive control proves successor state supplies their hashes.
func copyHistoricalFixture(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	subject, err := evidenceoverlay.OpenExactSubject(source, evidenceoverlay.HistoricalCommit, evidenceoverlay.HistoricalTree)
	if err != nil {
		t.Fatal(err)
	}
	available := map[string]bool{}
	for _, path := range subject.Paths() {
		available[path] = true
	}
	root := t.TempDir()
	required := map[string]bool{}
	manifests := []string{
		committedEvidenceManifestPathV1, evidenceoverlay.SuccessorPath,
		evidenceoverlay.Phase16SuccessorPath, evidenceoverlay.Phase16ProductionTrustSuccessorPath,
		evidenceoverlay.Phase16RuntimeSuccessorPath, evidenceoverlay.Phase16DecentralizedSuccessorPath,
		evidenceoverlay.Phase17SuccessorPath, evidenceoverlay.PublicDocumentationSuccessorPath,
	}
	var collect func(any)
	collect = func(value any) {
		switch value := value.(type) {
		case string:
			if available[value] {
				required[value] = true
			}
		case []any:
			for _, item := range value {
				collect(item)
			}
		case map[string]any:
			for _, item := range value {
				collect(item)
			}
		}
	}
	for _, path := range manifests {
		raw, err := evidenceoverlay.ReadSubjectFile(source, path)
		if err != nil {
			t.Fatal(err)
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			t.Fatal(err)
		}
		collect(value)
		required[path] = true
	}
	for path := range required {
		raw, err := evidenceoverlay.ReadSubjectFile(source, path)
		if err != nil {
			t.Fatal(err)
		}
		destination := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(destination), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(destination, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := VerifyHistoricalSet(root, "WO-044", fixtureExpectations()); err != nil {
		t.Fatalf("standalone fixture positive control: %v", err)
	}
	return root
}

func TestVerifyHistoricalSetRejectsInvalidExpectations(t *testing.T) {
	root := repositoryRoot(t)
	for _, test := range []struct {
		name, set, diagnostic string
		mutate                func([]ExpectedEntry) []ExpectedEntry
	}{
		{"path", "WO-044", "invalid expected path", func(v []ExpectedEntry) []ExpectedEntry { v[0].Path = "../outside"; return v }},
		{"pre", "WO-044", "invalid expected pre evidence", func(v []ExpectedEntry) []ExpectedEntry { v[0].PreEvidence = "bad"; return v }},
		{"set", "WO-999", "evidence entries", func(v []ExpectedEntry) []ExpectedEntry { return v }},
		{"cardinality", "WO-044", "evidence entries", func(v []ExpectedEntry) []ExpectedEntry { return v[:5] }},
		{"duplicate", "WO-044", "invalid expected path", func(v []ExpectedEntry) []ExpectedEntry { v[1] = v[0]; return v }},
		{"wrong-owned-path", "WO-044", "want path", func(v []ExpectedEntry) []ExpectedEntry { v[0].Path = "go.mod"; return v }},
		{"wrong-owned-pre", "WO-044", "want path", func(v []ExpectedEntry) []ExpectedEntry { v[0].PreEvidence = "ABSENT"; return v }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := VerifyHistoricalSet(root, "WO-044", fixtureExpectations()); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			err := VerifyHistoricalSet(root, test.set, test.mutate(fixtureExpectations()))
			if err == nil || !strings.Contains(err.Error(), test.diagnostic) {
				t.Fatalf("error=%v want %q", err, test.diagnostic)
			}
		})
	}
}

func TestVerifyHistoricalSetRejectsManifestMutationsAtIntendedStage(t *testing.T) {
	root := copyHistoricalFixture(t)
	path := filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1))
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name, diagnostic string
		mutate           func(*committedEvidenceManifestV1)
	}{
		{"schema", "invalid committed evidence manifest identity", func(v *committedEvidenceManifestV1) { v.Schema = "wrong" }},
		{"source", "invalid committed evidence manifest identity", func(v *committedEvidenceManifestV1) { v.SourceCandidate = strings.Repeat("1", 40) }},
		{"algorithm", "invalid committed evidence manifest identity", func(v *committedEvidenceManifestV1) { v.HashAlgorithm = "wrong" }},
		{"set-cardinality-bound-by-successor", "successor evidence drift", func(v *committedEvidenceManifestV1) { delete(v.Sets, "WO-040") }},
		{"set-name-bound-by-successor", "successor evidence drift", func(v *committedEvidenceManifestV1) { v.Sets["other"] = v.Sets["WO-040"]; delete(v.Sets, "WO-040") }},
		{"post-hash-bound-by-successor", "successor evidence drift", func(v *committedEvidenceManifestV1) { v.Sets["WO-044"][0].PostSHA256 = "bad" }},
		{"hash-drift-bound-by-successor", "successor evidence drift", func(v *committedEvidenceManifestV1) { v.Sets["WO-044"][0].PostSHA256 = strings.Repeat("1", 64) }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := os.WriteFile(path, original, 0600); err != nil {
				t.Fatal(err)
			}
			if err := VerifyHistoricalSet(root, "WO-044", fixtureExpectations()); err != nil {
				t.Fatalf("positive control: %v", err)
			}
			var candidate committedEvidenceManifestV1
			if err := json.Unmarshal(original, &candidate); err != nil {
				t.Fatal(err)
			}
			test.mutate(&candidate)
			raw, err := json.Marshal(candidate)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
			err = VerifyHistoricalSet(root, "WO-044", fixtureExpectations())
			if err == nil || !strings.Contains(err.Error(), test.diagnostic) {
				t.Fatalf("error=%v want %q", err, test.diagnostic)
			}
		})
	}
}

func TestVerifyHistoricalSetMissingImmutableObjectNeverUsesLiveFixture(t *testing.T) {
	root := copyHistoricalFixture(t)
	// The exact same valid live fixture becomes repository mode once .git exists.
	// Its empty object database cannot supply the frozen commit. No fallback is valid.
	command := exec.Command("git", "init", "--quiet", root)
	command.Env = append(os.Environ(), "GIT_OPTIONAL_LOCKS=0")
	if raw, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, raw)
	}
	err := VerifyHistoricalSet(root, "WO-044", fixtureExpectations())
	if err == nil || !strings.Contains(err.Error(), "immutable Git object read failed") {
		t.Fatalf("missing immutable object error=%v", err)
	}
}
