// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateProductionContract(t *testing.T) {
	value := validContractForTest()
	if err := validate(value); err != nil {
		t.Fatalf("validate: %v", err)
	}
	value.ReleaseDecision = "GO"
	if err := validate(value); err == nil {
		t.Fatal("expected GO contract to be rejected")
	}
}

func TestExactSetRejectsMissingAuthorityBoundary(t *testing.T) {
	if err := exactSet("prohibited action", requiredProhibited[:len(requiredProhibited)-1], requiredProhibited); err == nil {
		t.Fatal("expected missing prohibited action to fail")
	}
}

func TestValidateRejectsIncompleteCIInventory(t *testing.T) {
	value := validContractForTest()
	value.Baseline.CIJobs = value.Baseline.CIJobs[:len(value.Baseline.CIJobs)-1]
	if err := validate(value); err == nil {
		t.Fatal("expected incomplete CI job inventory to fail")
	}
}

func TestDecodeContractRejectsTrailingJSON(t *testing.T) {
	encoded, err := os.ReadFile(filepath.Join("..", "..", contractPath))
	if err != nil {
		t.Fatal(err)
	}
	encoded = append(encoded, []byte("\n{}\n")...)
	if _, err := decodeContract(encoded); err == nil || !strings.Contains(err.Error(), "trailing JSON") {
		t.Fatalf("decodeContract error = %v, want trailing JSON rejection", err)
	}
}

func TestVerifyHumanParityRejectsMismatchedBaseline(t *testing.T) {
	value := validContractForTest()
	root := t.TempDir()
	writeTestFile(t, root, "docs/PHASE15_PRODUCTION_CONTRACT.md", "baseline deadbeef release `NO_GO` API 26 API 36 arm64-v8a x86_64")
	writeTestFile(t, root, "docs/KIP-0090-phase15-production-contract-freeze.md", value.Baseline.SourceCommit+" `NO_GO`")
	if err := verifyHumanParity(root, value); err == nil {
		t.Fatal("expected human/machine baseline mismatch to fail")
	}
}

func TestVerifyPhase14ReconciliationRejectsIntegrationPending(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "docs/KIP-0089-phase14-assurance-field-release.md", "candidate integration pending")
	writeTestFile(t, root, "docs/PHASE14_EVIDENCE_INDEX.md", "integrated on main")
	writeTestFile(t, root, "docs/PHASE14_READINESS_MATRIX.md", "integrated on main")
	writeTestFile(t, root, "testdata/evidence/phase14/acceptance-status.json", `{"priorPhaseBaseline":{"integrationState":"INTEGRATED_ON_MAIN"}}`)
	if err := verifyPhase14Reconciliation(root); err == nil {
		t.Fatal("expected stale Phase 14 integration language to fail")
	}
}

func validContractForTest() contract {
	return contract{
		Schema:          "kurdistan-phase15-production-contract-v1",
		Phase:           15,
		Status:          "FROZEN_FOR_IMPLEMENTATION",
		ReleaseDecision: "NO_GO",
		Baseline: baseline{
			SourceCommit:          "1fcfeab111cf64f1295f10d788e4977ab4666a7a",
			CandidateCIRun:        "30739580424",
			MainCIRun:             "30740549679",
			CandidateCIConclusion: "SUCCESS",
			MainCIConclusion:      "SUCCESS",
			WorkflowPath:          ".github/workflows/ci.yml",
			WorkflowSHA256:        "e249f212339ca93429465db678ddd108190fd19f393b9cdc3e37976f8b280809",
			CIJobs:                append([]string(nil), requiredCIJobs...),
		},
		Android: androidContract{MinAPI: 26, TargetAPI: 36, CompileAPI: 36, ProductionABIs: []string{"arm64-v8a"}, TestOnlyABIs: []string{"x86_64"}},
		Versions: map[string]string{
			"androidBridge": "v1", "profileAdmission": "v1", "strategyRegistry": "v1",
			"relayAdmission": "v1", "diagnostics": "v1", "cryptographicSuite": "1",
		},
		AuthorizedWork: append([]string(nil), requiredAuthorized...),
		Prohibited:     append([]string(nil), requiredProhibited...),
		Privacy:        privacyContract{TelemetryDefault: "OFF", ForbiddenData: append([]string(nil), requiredForbiddenData...)},
		Limitations:    []string{"one", "two", "three"},
	}
}

func writeTestFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
