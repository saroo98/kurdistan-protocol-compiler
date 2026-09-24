// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package committedevidence interprets immutable historical evidence for tests.
// Callers supply independently owned expectations; this package supplies no caller expectation table.
package committedevidence

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"path"
	"strings"

	"kurdistan/internal/testkit/evidenceoverlay"
)

// ExpectedEntry is a caller-owned historical path/pre-evidence expectation.
type ExpectedEntry struct{ Path, PreEvidence string }

// VerifyHistoricalSet validates the manifest, historical chain and requested set.
func VerifyHistoricalSet(root, set string, want []ExpectedEntry) error {
	seen := map[string]bool{}
	for _, expected := range want {
		if !validEvidencePath(expected.Path) || seen[expected.Path] {
			return fmt.Errorf("invalid expected path %q", expected.Path)
		}
		seen[expected.Path] = true
		if expected.PreEvidence != "ABSENT" && expected.PreEvidence != "UNRECORDED" && !validHelperOwnerSHA256V1(expected.PreEvidence) {
			return fmt.Errorf("invalid expected pre evidence for %s", expected.Path)
		}
	}
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		return err
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if manifest.Schema != "kurdistan.phase1-m0.committed-sha256.v1" || manifest.HashAlgorithm != "sha256" || manifest.SourceCandidate != "68d50f3bca0f1839dd7b04a1551e5fcce47b1b71" {
		return fmt.Errorf("invalid committed evidence manifest identity: %+v", manifest)
	}
	historicalHashes, err := validateEvidenceOverlaysV1(root, manifest)
	if err != nil {
		return err
	}
	requiredSets := map[string]bool{"WO-040": true, "WO-041": true, "WO-042": true, "WO-043": true, "WO-044": true}
	if len(manifest.Sets) != len(requiredSets) {
		return fmt.Errorf("committed evidence sets=%v", manifest.Sets)
	}
	for name := range manifest.Sets {
		if !requiredSets[name] {
			return fmt.Errorf("unexpected committed evidence set %q", name)
		}
	}
	entries, ok := manifest.Sets[set]
	if !ok || len(entries) != len(want) {
		return fmt.Errorf("%s evidence entries=%v want %d", set, entries, len(want))
	}
	for i, expected := range want {
		entry := entries[i]
		if entry.Path != expected.Path || entry.PreEvidence != expected.PreEvidence {
			return fmt.Errorf("%s evidence[%d]=%+v want path=%s pre=%s", set, i, entry, expected.Path, expected.PreEvidence)
		}
		if !validEvidencePath(entry.Path) {
			return fmt.Errorf("%s invalid evidence path %q", set, entry.Path)
		}
		postBytes, err := hex.DecodeString(entry.PostSHA256)
		if err != nil || len(postBytes) != sha256.Size || entry.PostSHA256 != strings.ToLower(entry.PostSHA256) || entry.PostSHA256 == strings.Repeat("0", 64) {
			return fmt.Errorf("%s invalid post SHA-256 for %s", set, entry.Path)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			preBytes, err := hex.DecodeString(entry.PreEvidence)
			if err != nil || len(preBytes) != sha256.Size || entry.PreEvidence != strings.ToLower(entry.PreEvidence) || entry.PreEvidence == entry.PostSHA256 {
				return fmt.Errorf("%s invalid pre evidence for %s", set, entry.Path)
			}
		}
		post, present := historicalHashes[entry.Path]
		if !present {
			post, err = evidenceoverlay.ResolveCurrentSHA256(root, entry.Path)
			if err != nil {
				return err
			}
		}
		if post != entry.PostSHA256 {
			return fmt.Errorf("%s committed SHA-256 %s=%s want %s", set, entry.Path, post, entry.PostSHA256)
		}
	}
	return nil
}
func validEvidencePath(value string) bool {
	return value != "" && value != "." && value != ".." && value != committedEvidenceManifestPathV1 &&
		!strings.HasPrefix(value, "/") && !strings.HasPrefix(value, "../") &&
		!strings.ContainsAny(value, "\\:\x00\r\n\t") && path.Clean(value) == value
}
