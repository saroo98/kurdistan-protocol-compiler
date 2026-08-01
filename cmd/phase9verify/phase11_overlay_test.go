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
		Phase11Overlays map[string]phase11OverlayV1 `json:"phase11_local_transport_overlays"`
		Phase12Overlays map[string]phase11OverlayV1 `json:"phase12_operator_control_plane_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	phase12Pre := validateOverlayAtPostV1(t, root, "phase12-operator-control-plane-v1", manifest.Phase12Overlays, nil)
	validateOverlayAtPostV1(t, root, "phase11-local-transport-v1", manifest.Phase11Overlays, phase12Pre)
}

func validateOverlayAtPostV1(t *testing.T, root, name string, overlays map[string]phase11OverlayV1, currentAtPost map[string]string) map[string]string {
	t.Helper()
	if name == "phase12-operator-control-plane-v1" {
		return validatePhase12OverlayAtPostV1(t, root, overlays)
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != "testdata/evidence/phase1-m0-committed-sha256.json" ||
		!validPhase11DigestV1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 128 ||
		len(overlay.Paths) != len(overlay.Entries) {
		t.Fatalf("invalid %s overlay identity or cardinality", name)
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validPhase11DigestV1(entry.PostSHA256) {
			t.Fatalf("invalid %s overlay entry %d", name, index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				t.Fatalf("invalid absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validPhase11DigestV1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			t.Fatalf("invalid existing predecessor %d", index)
		}
		actual, present := currentAtPost[path]
		if !present {
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(content)
			actual = hex.EncodeToString(digest[:])
		}
		if actual != entry.PostSHA256 {
			t.Fatalf("%s evidence drift: %s", name, path)
		}
		pre[path] = predecessor
		last = path
	}
	return pre
}

func validatePhase12OverlayAtPostV1(t *testing.T, root string, overlays map[string]phase11OverlayV1) map[string]string {
	t.Helper()
	const name = "phase12-operator-control-plane-v1"
	paths := []string{
		"ROADMAP.md",
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"cmd/koperator/evidence_test.go",
		"cmd/koperator/main.go",
		"cmd/koperator/main_test.go",
		"cmd/phase9verify/phase11_overlay_test.go",
		"docs/KIP-0087-phase12-operator-provisioning-relay-fleet.md",
		"docs/PHASE12_EVIDENCE_INDEX.md",
		"docs/safety.md",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/operator/controlplane/authority_state.go",
		"internal/operator/controlplane/controlplane_test.go",
		"internal/operator/controlplane/errors.go",
		"internal/operator/controlplane/journal.go",
		"internal/operator/controlplane/model.go",
		"internal/operator/controlplane/phase_boundaries.go",
		"internal/operator/controlplane/phase_boundaries_test.go",
		"internal/operator/controlplane/reconcile.go",
		"internal/operator/controlplane/reconcile_test.go",
		"internal/operator/controlplane/service.go",
		"internal/operator/controlplane/state.go",
		"internal/product/lifecycle/phase8_verified.go",
		"internal/product/lifecycle/phase8_verified_test.go",
		"internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_admission.go",
		"internal/product/profile/phase8_admission_test.go",
		"internal/product/profile/phase8_emergency_signed.go",
		"internal/product/profile/phase8_emergency_signed_test.go",
		"internal/product/profile/phase8_providers.go",
		"internal/product/profile/phase8_revocation_admission.go",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase12/acceptance-status.json",
		"testdata/evidence/phase8-wo807-recovery-report.json",
	}
	preHashes := map[string]string{
		"ROADMAP.md":                                         "586a5e7f377c1809eb67cfe932d996ae81703bb562f52b539935e26ccdc93e8b",
		"cmd/gate/main.go":                                   "8f0e4e86384ea012ac54f1c9f795c3a4f760b5ab6c7f4b24f3ab553cad3c96c1",
		"cmd/gate/main_test.go":                              "c2b868ec7b155ed5ae95f667181284af9672722ceea8b3c018f4dd32df2d4fdd",
		"cmd/kgen/main_test.go":                              "2fabad2630c546749cde3c0c67dd9885ffa855230c298dacb741c65ef497c846",
		"cmd/phase9verify/phase11_overlay_test.go":           "95c7e090b93beab82e673513735e6725e1f636f10244a6b37b504adc91cb3a67",
		"docs/safety.md":                                     "2846c0453c9a20d8fee0a355d339ba70f658d3f064e2dcd6ddef693d7bbb50b0",
		"internal/audit/codegen_test.go":                     "c1896696926104de33e540f207c4cc3e7f477edfddc006cfc9f279dd34e5df94",
		"internal/audit/security.go":                         "a180d1b42b37ac390a1bdf718a4c8172cafc8f14b8afd9c46c24831fe461cbe9",
		"internal/audit/security_test.go":                    "b4674dd844d0f006fe83ced7fbd6855a309e1bbd76ac1cd2fb6c8a73711a5519",
		"internal/codegen/authorization_v1_test.go":          "e2d8caf8757c35bc9e1aea7ba6c5a129d328f507d9aa54889223b83e536e4c51",
		"internal/product/lifecycle/phase8_verified.go":      "e9fd50ec54dca326be6580815153a3983555f1b31ea028e4a3c052257e7e17c6",
		"internal/product/lifecycle/phase8_verified_test.go": "7e3aad03d9af6dcec588c37225c4791cce3d38c7d0b3dfb7c69218b3ae5e5769",
		"internal/product/profile/phase8_activation.go":      "3de078f241b4bd4da039891cf19db34f30eae083363cd23ea21b393d88a3a080",
		"internal/product/profile/phase8_providers.go":       "9bf824c879fc0186de623f4c6a589a0ef2dce0cefb33b6168397363cd0a5f33c",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json":            "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json": "20b5867ab1fd0ff1aff509702021c2ccc0d529f5cd4434ad48cf74864d8b185b",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json":    "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json":               "d4987c0461d703870dcfc2a53d107537fc529cacfff0cb7ceef55343cb3722fa",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json":       "6f2c3e15819d1fd18954aa242f5283e89fa1cc6a3c3964ea9ed864ee7553f364",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json":     "2fe3a7161549f9366a7d03e3724e9ec2d341659dec8af9e74e31778a908da2f0",
		"internal/runtime/policy_enforcement_test.go":                                                 "24ee3246889bf9393bece92e0016b464c3bd252ab4cf4a10038a69c069a2af20",
		"internal/testkit/importrules/importrules_test.go":                                            "f9f719b207174e13a2a1577c8fb450412fe0c2135b301c49311311fe84863221",
		"testdata/evidence/phase8-wo807-recovery-report.json":                                         "9ab249ec04fc5c012c5ed052e6bc927bcf1ed058760e26b2bbf48c0948a81c66",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != "testdata/evidence/phase1-m0-committed-sha256.json" ||
		overlay.SelfPreSHA256 != "050dd24b449122dfd58a79df263c61a1e9cb8c83f4b038df82e7629e49d6dfc2" ||
		len(overlay.Paths) != len(paths) || len(overlay.Entries) != len(paths) {
		t.Fatalf("invalid %s overlay identity or cardinality", name)
	}
	pre := make(map[string]string, len(paths))
	for index, path := range paths {
		entry := overlay.Entries[index]
		if overlay.Paths[index] != path || entry.Path != path || !validPhase11DigestV1(entry.PostSHA256) {
			t.Fatalf("invalid %s overlay entry %d", name, index)
		}
		predecessor, existed := preHashes[path]
		if existed {
			if entry.PreEvidence != "" || entry.PreSHA256 != predecessor || entry.PreSHA256 == entry.PostSHA256 {
				t.Fatalf("invalid %s existing predecessor %d", name, index)
			}
		} else {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				t.Fatalf("invalid %s absent predecessor %d", name, index)
			}
			predecessor = "ABSENT"
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(content)
		if hex.EncodeToString(digest[:]) != entry.PostSHA256 {
			t.Fatalf("%s evidence drift: %s", name, path)
		}
		pre[path] = predecessor
	}
	return pre
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
