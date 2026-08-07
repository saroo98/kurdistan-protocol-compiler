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
	Phase16P0RepairSuccessorPath        = "testdata/evidence/phase16/p0-repair-overlay.json"
	PublicDocumentationSuccessorPath    = "testdata/evidence/public-documentation-sanitization-overlay.json"
)

type overlay struct {
	Version string  `json:"version"`
	Entries []entry `json:"entries"`
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
	layers := []struct {
		path     string
		version  string
		optional bool
	}{
		{Phase16P0RepairSuccessorPath, "phase16-p0-evidence-repair-v1", true},
		{PublicDocumentationSuccessorPath, "public-documentation-sanitization-v1", true},
		{Phase16DecentralizedSuccessorPath, "phase16-decentralized-self-hosted-v1", true},
		{Phase16RuntimeSuccessorPath, "phase16-production-runtime-v1", true},
		{Phase16ProductionTrustSuccessorPath, "phase16-production-trust-v1", true},
		{Phase16SuccessorPath, "phase16-ci-release-acceleration-v1", true},
		{SuccessorPath, expectedVersion, false},
	}
	pre := map[string]string{}
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
		for index, item := range value.Entries {
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
	if value.Version != expectedVersion || len(value.Entries) == 0 || len(value.Entries) > 128 {
		return overlay{}, fmt.Errorf("invalid successor overlay identity or cardinality: %s", relative)
	}
	last := ""
	for index, item := range value.Entries {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(item.Path)))
		if clean != item.Path || item.Path <= last || filepath.IsAbs(item.Path) || strings.HasPrefix(item.Path, "../") || strings.HasPrefix(item.Path, ".tools/") || strings.HasPrefix(item.Path, "planning/") {
			return overlay{}, fmt.Errorf("invalid successor overlay path %d in %s", index, relative)
		}
		if item.PostEvidence == "ABSENT" {
			if item.PostSHA256 != "" {
				return overlay{}, fmt.Errorf("invalid absent successor %d in %s", index, relative)
			}
		} else if item.PostEvidence != "" || !validDigest(item.PostSHA256) {
			return overlay{}, fmt.Errorf("invalid successor post state %d in %s", index, relative)
		}
		if item.PreEvidence == "ABSENT" {
			if item.PreSHA256 != "" {
				return overlay{}, fmt.Errorf("invalid absent predecessor %d in %s", index, relative)
			}
		} else if item.PreEvidence != "" || !validDigest(item.PreSHA256) {
			return overlay{}, fmt.Errorf("invalid existing predecessor %d in %s", index, relative)
		}
		if predecessor(item) == postState(item) {
			return overlay{}, fmt.Errorf("successor entry does not change state %d in %s", index, relative)
		}
		last = item.Path
	}
	return value, nil
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
