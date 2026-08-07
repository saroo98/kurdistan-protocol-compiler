// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package evidenceoverlay validates append-only successor evidence without
// rewriting historical evidence manifests.
package evidenceoverlay

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	SuccessorPath                       = "testdata/evidence/phase15/production-contract-overlay.json"
	Phase16SuccessorPath                = "testdata/evidence/phase16/ci-release-acceleration-overlay.json"
	Phase16ProductionTrustSuccessorPath = "testdata/evidence/phase16/production-trust-overlay.json"
	Phase16RuntimeSuccessorPath         = "testdata/evidence/phase16/production-runtime-overlay.json"
	Phase16DecentralizedSuccessorPath   = "testdata/evidence/phase16/decentralized-self-hosted-overlay.json"
	Phase17SuccessorPath                = "testdata/evidence/phase17/live-data-plane-overlay.json"
	PublicDocumentationSuccessorPath    = "testdata/evidence/public-documentation-sanitization-overlay.json"
)

type overlay struct {
	Version                  string  `json:"version"`
	SelfPath                 string  `json:"self_path,omitempty"`
	SelfPreEvidence          string  `json:"self_pre_evidence,omitempty"`
	SelfPreSHA256            string  `json:"self_pre_sha256,omitempty"`
	PredecessorBindingSHA256 string  `json:"predecessor_binding_sha256,omitempty"`
	Entries                  []entry `json:"entries"`
	SuccessorEntries         []entry `json:"successor_entries,omitempty"`
}

type entry struct {
	Path         string `json:"path"`
	PreSHA256    string `json:"pre_sha256,omitempty"`
	PreEvidence  string `json:"pre_evidence,omitempty"`
	PostSHA256   string `json:"post_sha256,omitempty"`
	PostEvidence string `json:"post_evidence,omitempty"`
}

// LoadSuccessor verifies the exact current post-state and returns the
// predecessor state that the historical overlay validators must evaluate.
func LoadSuccessor(root, expectedVersion string) (map[string]string, error) {
	return LoadSuccessorAtPost(root, nil, expectedVersion)
}

// LoadSuccessorAtPost verifies the successor chain using currentAtPost for
// paths advanced by a later in-manifest overlay. This keeps the append-only
// external chain verifiable while the caller reconstructs an earlier phase.
func LoadSuccessorAtPost(root string, currentAtPost map[string]string, expectedVersion string) (map[string]string, error) {
	layers := []struct {
		path     string
		version  string
		optional bool
		entries  func(overlay) []entry
	}{
		{Phase17SuccessorPath, "phase17-live-data-plane-v1", true, func(value overlay) []entry { return value.SuccessorEntries }},
		{Phase17SuccessorPath, "phase17-live-data-plane-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16DecentralizedSuccessorPath, "phase16-decentralized-self-hosted-v1", true, func(value overlay) []entry { return value.SuccessorEntries }},
		{PublicDocumentationSuccessorPath, "public-documentation-sanitization-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16DecentralizedSuccessorPath, "phase16-decentralized-self-hosted-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16RuntimeSuccessorPath, "phase16-production-runtime-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16ProductionTrustSuccessorPath, "phase16-production-trust-v1", true, func(value overlay) []entry { return value.Entries }},
		{Phase16SuccessorPath, "phase16-ci-release-acceleration-v1", true, func(value overlay) []entry { return value.Entries }},
		{SuccessorPath, expectedVersion, false, func(value overlay) []entry { return value.Entries }},
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, digest := range currentAtPost {
		pre[path] = digest
	}
	for _, layer := range layers {
		if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(layer.path))); err != nil {
			if errors.Is(err, os.ErrNotExist) && layer.optional {
				continue
			}
			if errors.Is(err, os.ErrNotExist) && layer.path == SuccessorPath {
				return pre, nil
			}
			return nil, err
		}
		value, err := readOverlay(root, layer.path, layer.version)
		if err != nil {
			return nil, err
		}
		for index, item := range layer.entries(value) {
			observed, ok := pre[item.Path]
			if !ok {
				path := filepath.Join(root, filepath.FromSlash(item.Path))
				if item.PostEvidence == "ABSENT" {
					if _, err := os.Lstat(path); err == nil {
						return nil, fmt.Errorf("successor deletion path still exists: %s", item.Path)
					} else if !errors.Is(err, os.ErrNotExist) {
						return nil, fmt.Errorf("inspect successor deletion path %s: %w", item.Path, err)
					}
					observed = "ABSENT"
				} else {
					content, err := os.ReadFile(path)
					if err != nil {
						return nil, fmt.Errorf("read successor path %s: %w", item.Path, err)
					}
					digest := sha256.Sum256(content)
					observed = hex.EncodeToString(digest[:])
				}
			}
			if observed != postState(item) {
				return nil, fmt.Errorf("successor evidence drift in %s entry %d: %s", layer.path, index, item.Path)
			}
			pre[item.Path] = predecessor(item)
		}
	}
	return pre, nil
}

// ResolveCurrentSHA256 returns the effective current hash for a historical
// evidence validator. A validated successor overlay contributes the exact
// predecessor hash for paths it advances; all other paths are hashed from the
// working tree. This lets a new append-only overlay advance a path whose most
// recent historical owner is older than the immediately preceding phase.
func ResolveCurrentSHA256(root, path string) (string, error) {
	predecessors, err := LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return "", err
	}
	if digest, ok := predecessors[path]; ok {
		return digest, nil
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

// ResolvePhase17PredecessorSHA256 returns the hash at the Phase 17 boundary.
// It validates and unwinds only the Phase 17 overlay, leaving the established
// Phase 16 state intact. Historical generators that were already reconciled
// during Phase 16 use this boundary while Phase 17 advances their source files.
func ResolvePhase17PredecessorSHA256(root, path string) (string, error) {
	predecessors, err := loadPhase17Predecessors(root)
	if err != nil {
		return "", err
	}
	if digest, ok := predecessors[path]; ok {
		return digest, nil
	}
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func loadPhase17Predecessors(root string) (map[string]string, error) {
	overlayPath := filepath.Join(root, filepath.FromSlash(Phase17SuccessorPath))
	if _, err := os.Stat(overlayPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	value, err := readOverlay(root, Phase17SuccessorPath, "phase17-live-data-plane-v1")
	if err != nil {
		return nil, err
	}
	pre := make(map[string]string, len(value.Entries)+len(value.SuccessorEntries))
	for _, entries := range [][]entry{value.SuccessorEntries, value.Entries} {
		for index, item := range entries {
			observed, ok := pre[item.Path]
			if !ok {
				path := filepath.Join(root, filepath.FromSlash(item.Path))
				if item.PostEvidence == "ABSENT" {
					if _, err := os.Lstat(path); err == nil {
						return nil, fmt.Errorf("successor deletion path still exists: %s", item.Path)
					} else if !errors.Is(err, os.ErrNotExist) {
						return nil, fmt.Errorf("inspect successor deletion path %s: %w", item.Path, err)
					}
					observed = "ABSENT"
				} else {
					content, err := os.ReadFile(path)
					if err != nil {
						return nil, fmt.Errorf("read successor path %s: %w", item.Path, err)
					}
					digest := sha256.Sum256(content)
					observed = hex.EncodeToString(digest[:])
				}
			}
			if observed != postState(item) {
				return nil, fmt.Errorf("successor evidence drift in %s entry %d: %s", Phase17SuccessorPath, index, item.Path)
			}
			pre[item.Path] = predecessor(item)
		}
	}
	return pre, nil
}

func readOverlay(root, relative, expectedVersion string) (overlay, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
	if err != nil {
		return overlay{}, err
	}
	var value overlay
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return overlay{}, fmt.Errorf("decode successor overlay %s: %w", relative, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return overlay{}, fmt.Errorf("decode successor overlay %s: trailing JSON", relative)
	}
	if value.Version != expectedVersion || len(value.Entries) == 0 || len(value.Entries) > 128 || len(value.SuccessorEntries) > 128 {
		return overlay{}, fmt.Errorf("invalid successor overlay identity or cardinality: %s", relative)
	}
	if relative != Phase16DecentralizedSuccessorPath && relative != Phase17SuccessorPath && len(value.SuccessorEntries) != 0 {
		return overlay{}, fmt.Errorf("successor entries are only valid in %s", Phase16DecentralizedSuccessorPath)
	}
	if err := validateEntries(value.Entries, relative, "entries"); err != nil {
		return overlay{}, err
	}
	if err := validateEntries(value.SuccessorEntries, relative, "successor_entries"); err != nil {
		return overlay{}, err
	}
	return value, nil
}

func validateEntries(entries []entry, relative, field string) error {
	last := ""
	for index, item := range entries {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(item.Path)))
		if clean != item.Path || item.Path <= last || filepath.IsAbs(item.Path) || strings.HasPrefix(item.Path, "../") || strings.HasPrefix(item.Path, ".tools/") || strings.HasPrefix(item.Path, "planning/") {
			return fmt.Errorf("invalid successor overlay %s path %d in %s", field, index, relative)
		}
		if item.PostEvidence == "ABSENT" {
			if item.PostSHA256 != "" {
				return fmt.Errorf("invalid absent successor %d in %s", index, relative)
			}
		} else if item.PostEvidence != "" || !validDigest(item.PostSHA256) {
			return fmt.Errorf("invalid successor post state %d in %s", index, relative)
		}
		if item.PreEvidence == "ABSENT" {
			if item.PreSHA256 != "" {
				return fmt.Errorf("invalid absent predecessor %d in %s", index, relative)
			}
		} else if item.PreEvidence != "" || !validDigest(item.PreSHA256) {
			return fmt.Errorf("invalid existing predecessor %d in %s", index, relative)
		}
		if predecessor(item) == postState(item) {
			return fmt.Errorf("successor entry does not change state %d in %s", index, relative)
		}
		last = item.Path
	}
	return nil
}

func predecessor(item entry) string {
	if item.PreEvidence == "ABSENT" {
		return "ABSENT"
	}
	return item.PreSHA256
}

func postState(item entry) string {
	if item.PostEvidence == "ABSENT" {
		return "ABSENT"
	}
	return item.PostSHA256
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
