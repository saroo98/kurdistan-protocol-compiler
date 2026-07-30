// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type phase11OverlayEntryV1 struct {
	Path        string `json:"path"`
	PreSHA256   string `json:"pre_sha256"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

type phase11OverlayV1 struct {
	Version       string                  `json:"version"`
	SelfPath      string                  `json:"self_path"`
	SelfPreSHA256 string                  `json:"self_pre_sha256"`
	Paths         []string                `json:"paths"`
	Entries       []phase11OverlayEntryV1 `json:"entries"`
}

func TestPhase11LocalTransportEvidenceOverlayV1(t *testing.T) {
	root := phase11RepoRootV1(t)
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "evidence", "phase1-m0-committed-sha256.json"))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Overlays map[string]phase11OverlayV1 `json:"phase11_local_transport_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	const name = "phase11-local-transport-v1"
	overlay, ok := manifest.Overlays[name]
	if len(manifest.Overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != "testdata/evidence/phase1-m0-committed-sha256.json" ||
		!validPhase11DigestV1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 128 ||
		len(overlay.Paths) != len(overlay.Entries) {
		t.Fatal("invalid Phase 11 overlay identity or cardinality")
	}
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validPhase11DigestV1(entry.PostSHA256) {
			t.Fatalf("invalid Phase 11 overlay entry %d", index)
		}
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				t.Fatalf("invalid absent predecessor %d", index)
			}
		} else if entry.PreEvidence != "" || !validPhase11DigestV1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			t.Fatalf("invalid existing predecessor %d", index)
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		actual := sha256.Sum256(content)
		if hex.EncodeToString(actual[:]) != entry.PostSHA256 {
			t.Fatalf("Phase 11 evidence drift: %s", path)
		}
		last = path
	}
}

func phase11RepoRootV1(t *testing.T) string {
	t.Helper()
	root, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(root, "go.mod")); err == nil {
			return root
		}
		parent := filepath.Dir(root)
		if parent == root {
			t.Fatal("repository root not found")
		}
		root = parent
	}
}

func validPhase11DigestV1(value string) bool {
	if len(value) != 64 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}
