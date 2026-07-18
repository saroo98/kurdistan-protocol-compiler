package profile_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/testkit/phase8issuancefixture"
)

func TestWO806FixtureReproduction(t *testing.T) {
	repoRoot, err := filepath.Abs(filepath.Join("..", "..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	generated := filepath.Join(t.TempDir(), "generated")
	if err := phase8issuancefixture.Generate(generated, repoRoot); err != nil {
		t.Fatal(err)
	}
	checked := filepath.Join("testdata", "phase8-issuance")
	entries, err := os.ReadDir(checked)
	if err != nil {
		t.Fatal(err)
	}
	generatedEntries, err := os.ReadDir(generated)
	if err != nil || len(generatedEntries) != len(entries) {
		t.Fatalf("fixture file set mismatch: checked=%d generated=%d err=%v", len(entries), len(generatedEntries), err)
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		want, _ := os.ReadFile(filepath.Join(checked, entry.Name()))
		got, _ := os.ReadFile(filepath.Join(generated, entry.Name()))
		if !bytes.Equal(got, want) {
			t.Fatalf("fixture drift: %s", entry.Name())
		}
	}
	if err := phase8issuancefixture.Generate(generated, repoRoot); err == nil {
		t.Fatal("generator overwrote existing output")
	}
	second := filepath.Join(t.TempDir(), "generated")
	if err := phase8issuancefixture.Generate(second, repoRoot); err != nil {
		t.Fatal(err)
	}
	for _, entry := range generatedEntries {
		first, _ := os.ReadFile(filepath.Join(generated, entry.Name()))
		next, _ := os.ReadFile(filepath.Join(second, entry.Name()))
		if !bytes.Equal(first, next) {
			t.Fatalf("fresh-temp generation is not deterministic: %s", entry.Name())
		}
	}
}

type wo806CaseOwner struct {
	Case string `json:"case"`
	Test string `json:"test"`
}

type wo806EvidenceReport struct {
	Schema            string           `json:"schema"`
	Test              string           `json:"test"`
	SourceSHA256      string           `json:"source_sha256"`
	TestSourceSHA256  string           `json:"test_source_sha256"`
	CaseSetSHA256     string           `json:"case_set_sha256"`
	CaseOwnerSHA256   string           `json:"case_owner_sha256"`
	ExecutionSHA256   string           `json:"execution_sha256"`
	ObservationSHA256 string           `json:"observation_sha256"`
	ResultSHA256      string           `json:"result_sha256"`
	Cases             []string         `json:"cases"`
	CaseOwners        []wo806CaseOwner `json:"case_owners"`
	Observations      []string         `json:"observations"`
}

func TestWO806EvidenceReportsBindExactTestsAndSources(t *testing.T) {
	expected := map[string]string{"fixture-reproduction-report.json": "TestWO806FixtureReproduction", "issuance-roundtrip-report.json": "TestOfflineIssuanceRoundTripsAllArtifactClasses", "production-wiring-negative-report.json": "TestWO806ProductionWiringIsolation", "offline-boundary-report.json": "TestCompileInspectAreSecretSafeAndNeverOverwrite", "issuance-negative-report.json": "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse", "redacted-inspect-report.json": "TestCompileInspectAreSecretSafeAndNeverOverwrite"}
	issuanceNegativeOwners := map[string]string{
		"wrong-role":         "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"unsupported-suite":  "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"missing-audience":   "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"stale-generation":   "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"expired":            "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"scope":              "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"recipient":          "TestOfflineIssuanceRejectsUnsafeInputsBeforeProviderUse",
		"truncation":         "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation",
		"ciphertext-tamper":  "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation",
		"wrong-header-class": "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation",
		"wrong-recipient":    "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation",
	}
	for name, testName := range expected {
		raw, err := os.ReadFile(filepath.Join("testdata", "phase8-issuance", name))
		if err != nil {
			t.Fatal(err)
		}
		var r wo806EvidenceReport
		if json.Unmarshal(raw, &r) != nil {
			t.Fatalf("invalid JSON: %s", name)
		}
		owners := map[string]string(nil)
		if name == "issuance-negative-report.json" {
			owners = issuanceNegativeOwners
		}
		if !validWO806EvidenceReport(r, testName, owners) {
			t.Fatalf("invalid %s: %#v", name, r)
		}
		if name == "issuance-negative-report.json" {
			mutated := r
			mutated.CaseOwners = append([]wo806CaseOwner(nil), r.CaseOwners...)
			mutated.CaseOwners[0].Test = "TestOfflineVerifierRejectsTamperHeadersRecipientsAndTruncation"
			if validWO806EvidenceReport(mutated, testName, issuanceNegativeOwners) {
				t.Fatal("issuance-negative report accepted a case with the wrong test owner")
			}
		}
	}
}

func validWO806EvidenceReport(r wo806EvidenceReport, expectedTest string, expectedOwners map[string]string) bool {
	caseHash, executionHash := hashWO806(r.Cases), hashWO806(r.Observations)
	resultInputs := []string{r.Test, r.SourceSHA256, r.TestSourceSHA256, caseHash, executionHash}
	if len(expectedOwners) == 0 {
		if len(r.CaseOwners) != 0 || r.CaseOwnerSHA256 != "" {
			return false
		}
	} else {
		if len(r.CaseOwners) != len(r.Cases) || len(expectedOwners) != len(r.Cases) {
			return false
		}
		for index, owner := range r.CaseOwners {
			if owner.Case != r.Cases[index] || expectedOwners[owner.Case] != owner.Test {
				return false
			}
		}
		ownerHash := hashWO806CaseOwners(r.CaseOwners)
		if r.CaseOwnerSHA256 != ownerHash {
			return false
		}
		resultInputs = append(resultInputs, ownerHash)
	}
	resultHash := hashWO806(resultInputs)
	return r.Schema == "phase8-issuance-evidence-v1" && r.Test == expectedTest && len(r.Cases) != 0 && len(r.Observations) != 0 && r.CaseSetSHA256 == caseHash && r.ObservationSHA256 == executionHash && r.ExecutionSHA256 == executionHash && r.ResultSHA256 == resultHash && len(r.SourceSHA256) == 64 && len(r.TestSourceSHA256) == 64
}

func hashWO806(values []string) string {
	digest := sha256.Sum256([]byte(strings.Join(values, "\n")))
	return hex.EncodeToString(digest[:])
}

func hashWO806CaseOwners(owners []wo806CaseOwner) string {
	values := make([]string, 0, len(owners))
	for _, owner := range owners {
		values = append(values, owner.Case+"\x00"+owner.Test)
	}
	return hashWO806(values)
}
