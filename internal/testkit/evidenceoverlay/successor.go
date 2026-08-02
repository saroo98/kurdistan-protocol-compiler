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

const SuccessorPath = "testdata/evidence/phase15/production-contract-overlay.json"

type overlay struct {
	Version string  `json:"version"`
	Entries []entry `json:"entries"`
}

type entry struct {
	Path        string `json:"path"`
	PreSHA256   string `json:"pre_sha256,omitempty"`
	PreEvidence string `json:"pre_evidence,omitempty"`
	PostSHA256  string `json:"post_sha256"`
}

// LoadSuccessor verifies the exact current post-state and returns the
// predecessor state that the historical overlay validators must evaluate.
func LoadSuccessor(root, expectedVersion string) (map[string]string, error) {
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(SuccessorPath)))
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return map[string]string{}, nil
		}
		return nil, err
	}
	var value overlay
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return nil, fmt.Errorf("decode successor overlay: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, errors.New("decode successor overlay: trailing JSON")
	}
	if value.Version != expectedVersion || len(value.Entries) == 0 || len(value.Entries) > 128 {
		return nil, errors.New("invalid successor overlay identity or cardinality")
	}
	pre := make(map[string]string, len(value.Entries))
	last := ""
	for index, item := range value.Entries {
		clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(item.Path)))
		if clean != item.Path || item.Path <= last || filepath.IsAbs(item.Path) || strings.HasPrefix(item.Path, "../") || strings.HasPrefix(item.Path, ".tools/") || strings.HasPrefix(item.Path, "planning/") {
			return nil, fmt.Errorf("invalid successor overlay path %d", index)
		}
		if !validDigest(item.PostSHA256) {
			return nil, fmt.Errorf("invalid successor post digest %d", index)
		}
		predecessor := item.PreSHA256
		if item.PreEvidence == "ABSENT" {
			if item.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if item.PreEvidence != "" || !validDigest(item.PreSHA256) || item.PreSHA256 == item.PostSHA256 {
			return nil, fmt.Errorf("invalid existing predecessor %d", index)
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(item.Path)))
		if err != nil {
			return nil, fmt.Errorf("read successor path %s: %w", item.Path, err)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != item.PostSHA256 {
			return nil, fmt.Errorf("successor evidence drift: %s", item.Path)
		}
		pre[item.Path] = predecessor
		last = item.Path
	}
	return pre, nil
}

func validDigest(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
