// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBuildCandidateComparisonRequiresByteIdenticalIndependentRoots(t *testing.T) {
	left := t.TempDir()
	right := t.TempDir()
	for _, root := range []string{left, right} {
		writeSubjectFixture(t, root, "PQS/product.bin", "product")
		writeSubjectFixture(t, root, "QHS/runner.bin", "runner")
	}
	comparison, err := BuildCandidateComparison(
		strings.Repeat("a", 40), strings.Repeat("b", 40), left, right,
	)
	if err != nil {
		t.Fatal(err)
	}
	if comparison.Result != "PASS" || len(comparison.Entries) != 2 || comparison.Entries[0].Path != "PQS/product.bin" {
		t.Fatalf("comparison=%+v", comparison)
	}
	raw, err := MarshalCandidateComparison(comparison)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeCandidateComparison(bytes.NewReader(raw))
	if err != nil || !equalManifestEntries(decoded.Entries, comparison.Entries) {
		t.Fatalf("decoded=%+v err=%v", decoded, err)
	}

	writeSubjectFixture(t, right, "QHS/runner.bin", "mutated")
	if _, err := BuildCandidateComparison(strings.Repeat("a", 40), strings.Repeat("b", 40), left, right); err == nil {
		t.Fatal("byte-different candidate roots compared as PASS")
	}
}

func TestBuildCandidateComparisonRejectsSymlinkAndHardlinkAmbiguity(t *testing.T) {
	left := t.TempDir()
	right := t.TempDir()
	for _, root := range []string{left, right} {
		writeSubjectFixture(t, root, "one.bin", "one")
	}
	if err := os.Symlink(filepath.Join(left, "one.bin"), filepath.Join(left, "link.bin")); err == nil {
		if _, err := BuildCandidateComparison(strings.Repeat("a", 40), strings.Repeat("b", 40), left, right); err == nil {
			t.Fatal("symlinked candidate root compared as PASS")
		}
		_ = os.Remove(filepath.Join(left, "link.bin"))
	}
	if err := os.Link(filepath.Join(left, "one.bin"), filepath.Join(left, "hard.bin")); err == nil {
		writeSubjectFixture(t, right, "hard.bin", "one")
		if _, err := BuildCandidateComparison(strings.Repeat("a", 40), strings.Repeat("b", 40), left, right); err == nil {
			t.Fatal("hardlinked candidate root compared as PASS")
		}
	}
}
