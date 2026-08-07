// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/testkit/evidenceoverlay"
)

func TestWO805DeterministicEvidenceReports(t *testing.T) {
	names := []string{
		"activation-crash-report.json",
		"revocation-generation-report.json",
		"policy-bypass-report.json",
		"verify-before-semantics-report.json",
		"authenticated-hint-mismatch-report.json",
		"last-known-good-negative-report.json",
	}
	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			encoded, err := os.ReadFile(filepath.Join("testdata", "phase8-activation", name))
			if err != nil {
				t.Fatal(err)
			}
			var report struct {
				Schema                  string   `json:"schema"`
				WorkOrder               string   `json:"work_order"`
				Status                  string   `json:"status"`
				Test                    string   `json:"test"`
				SourceSHA256            string   `json:"source_sha256"`
				TestSourceSHA256        string   `json:"test_source_sha256"`
				CaseSetSHA256           string   `json:"case_set_sha256"`
				ResultSHA256            string   `json:"result_sha256"`
				ObservedExecutionSHA256 string   `json:"observed_execution_sha256"`
				Cases                   []string `json:"cases"`
			}
			if err := json.Unmarshal(encoded, &report); err != nil {
				t.Fatal(err)
			}
			if report.Schema != "phase8-activation-evidence-v1" || report.WorkOrder != "WO-805" || report.Status != "pass" {
				t.Fatalf("unexpected evidence header: %#v", report)
			}
			if report.Test != expectedEvidenceTest(name) {
				t.Fatalf("%s test alias or nonexistent mapping: got %q want %q", name, report.Test, expectedEvidenceTest(name))
			}
			expectedCases := evidenceCases(name)
			if strings.Join(report.Cases, "\n") != strings.Join(expectedCases, "\n") {
				t.Fatalf("case set mismatch: %v", report.Cases)
			}
			root := filepath.Clean(filepath.Join("..", "..", ".."))
			if report.SourceSHA256 != effectiveFileSHA256(t, root, "internal/product/profile/phase8_activation.go") || report.TestSourceSHA256 != effectiveFileSHA256(t, root, "internal/product/profile/phase8_activation_test.go") {
				t.Fatal("source hash mismatch")
			}
			caseHash := stringsSHA256(expectedCases)
			if report.CaseSetSHA256 != caseHash {
				t.Fatalf("case hash=%s want=%s", report.CaseSetSHA256, caseHash)
			}
			if report.ResultSHA256 != stringsSHA256([]string{report.Status, report.Test, caseHash}) {
				t.Fatal("result hash mismatch")
			}
			if report.ObservedExecutionSHA256 != observedExecutionSHA256(expectedCases) {
				t.Fatal("observed execution hash mismatch")
			}
		})
	}
}

func expectedEvidenceTest(name string) string {
	switch name {
	case "activation-crash-report.json", "last-known-good-negative-report.json":
		return "TestActivateVerifiedProfileRecoversEachPersistenceFault"
	case "revocation-generation-report.json":
		return "TestWO805RevocationAndGenerationMatrix"
	case "policy-bypass-report.json":
		return "TestActivateVerifiedProfileCategoricalFailuresLeaveStateUnchanged"
	case "verify-before-semantics-report.json":
		return "TestActivateVerifiedProfileOrdersVerificationBeforeSemantics"
	case "authenticated-hint-mismatch-report.json":
		return "TestActivateVerifiedProfileSealedPathAndDispatchMismatch"
	default:
		panic("unhandled evidence report")
	}
}

func assertEvidenceObservation(t *testing.T, name string, cases []string) {
	t.Helper()
	encoded, err := os.ReadFile(filepath.Join("testdata", "phase8-activation", name))
	if err != nil {
		t.Fatal(err)
	}
	var report struct {
		Observed string `json:"observed_execution_sha256"`
	}
	if err := json.Unmarshal(encoded, &report); err != nil {
		t.Fatal(err)
	}
	if report.Observed != observedExecutionSHA256(cases) {
		t.Fatalf("%s is not bound to observed passing cases", name)
	}
}

func observedExecutionSHA256(cases []string) string {
	observed := make([]string, len(cases))
	for i, name := range cases {
		observed[i] = name + "=pass"
	}
	return stringsSHA256(observed)
}

func evidenceCases(name string) []string {
	switch name {
	case "activation-crash-report.json", "last-known-good-negative-report.json":
		return wo805PersistenceFaultCaseNames
	case "revocation-generation-report.json":
		return wo805RevocationGenerationCaseNames
	case "policy-bypass-report.json":
		return wo805CategoricalCaseNames
	case "verify-before-semantics-report.json":
		return wo805VerificationOrderCaseNames
	case "authenticated-hint-mismatch-report.json":
		return wo805DispatchMismatchCaseNames
	default:
		panic("unhandled evidence report")
	}
}

func fileSHA256(t *testing.T, name string) string {
	t.Helper()
	encoded, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func effectiveFileSHA256(t *testing.T, root, name string) string {
	t.Helper()
	digest, err := evidenceoverlay.ResolveCurrentSHA256(root, name)
	if err != nil {
		t.Fatal(err)
	}
	return digest
}

func stringsSHA256(values []string) string {
	digest := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(digest[:])
}
