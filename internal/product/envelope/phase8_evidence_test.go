// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPhase8WO802EvidenceSchemas(t *testing.T) {
	t.Run("suite decision matrix", func(t *testing.T) {
		var matrix struct {
			Schema               string `json:"schema"`
			MandatorySuiteID     uint16 `json:"mandatory_suite_id"`
			AutomaticNegotiation bool   `json:"automatic_negotiation"`
			AutomaticFallback    bool   `json:"automatic_fallback"`
			Rows                 []struct {
				CandidateID            string   `json:"candidate_id"`
				Category               string   `json:"category"`
				Disposition            string   `json:"disposition"`
				OfficialSourceURL      string   `json:"official_source_url"`
				VersionOrCommit        string   `json:"version_or_commit"`
				License                string   `json:"license"`
				APIEvidence            string   `json:"api_evidence"`
				MaintenanceEvidence    string   `json:"maintenance_evidence"`
				InteropEvidence        string   `json:"interop_evidence"`
				EncodedSize            string   `json:"encoded_size"`
				TransitiveDependencies []string `json:"transitive_dependencies"`
				RemovalAnalysis        string   `json:"removal_analysis"`
				RejectionReason        string   `json:"rejection_reason"`
			} `json:"rows"`
		}
		loadEvidenceJSON(t, "phase8-suite-decision-matrix.json", &matrix)
		if matrix.Schema != "kurdistan.phase8.suite-decision-matrix.v1" || matrix.MandatorySuiteID != uint16(SuiteClassicalV1) {
			t.Fatalf("unexpected decision matrix identity: schema=%q suite=%d", matrix.Schema, matrix.MandatorySuiteID)
		}
		if matrix.AutomaticNegotiation || matrix.AutomaticFallback || len(matrix.Rows) < 10 {
			t.Fatalf("unsafe decision matrix controls: negotiation=%t fallback=%t rows=%d", matrix.AutomaticNegotiation, matrix.AutomaticFallback, len(matrix.Rows))
		}
		seen := make(map[string]string, len(matrix.Rows))
		for _, row := range matrix.Rows {
			if row.CandidateID == "" || row.Category == "" || row.Disposition == "" || row.OfficialSourceURL == "" || row.VersionOrCommit == "" || row.License == "" || row.APIEvidence == "" || row.MaintenanceEvidence == "" || row.InteropEvidence == "" || row.EncodedSize == "" || row.RemovalAnalysis == "" || row.TransitiveDependencies == nil {
				t.Fatalf("incomplete candidate row: %+v", row)
			}
			if row.Disposition != "selected" && row.RejectionReason == "" {
				t.Fatalf("non-selected candidate %q has no rejection reason", row.CandidateID)
			}
			if _, duplicate := seen[row.CandidateID]; duplicate {
				t.Fatalf("duplicate candidate ID %q", row.CandidateID)
			}
			seen[row.CandidateID] = row.Disposition
		}
		for candidate, disposition := range map[string]string{
			"cbor-fxamacker-v2.9.2":                   "selected",
			"cose-sign1-es256-narrow-rfc9052":         "selected",
			"signature-es256-go1.26.5":                "selected",
			"signature-ed25519-go1.26.5":              "rejected",
			"hpke-p256-hkdfsha256-aes256gcm-go1.26.5": "selected",
			"hpke-mlkem768-go1.26.5-draft":            "reserved-disabled",
			"hpke-mlkem768-p256-go1.26.5-draft":       "reserved-disabled",
			"cose-hpke-draft":                         "rejected",
		} {
			if seen[candidate] != disposition {
				t.Fatalf("candidate %q disposition = %q, want %q", candidate, seen[candidate], disposition)
			}
		}
	})

	t.Run("toolchain randomness", func(t *testing.T) {
		var report struct {
			Schema                  string `json:"schema"`
			StandardLibraryEvidence []struct {
				Package               string `json:"package"`
				SourceAggregateSHA256 string `json:"source_aggregate_sha256"`
				ObservedAPI           string `json:"observed_api"`
				RelevantLimit         string `json:"relevant_limit"`
			} `json:"standard_library_evidence"`
			FIPSObservation struct {
				Wording string `json:"wording"`
			} `json:"fips_observation"`
			CleanBuild struct {
				ExitCode int    `json:"exit_code"`
				Result   string `json:"result"`
			} `json:"clean_build_evidence"`
			ReferenceHost struct {
				Alias             string   `json:"alias"`
				OS                string   `json:"os"`
				OSVersion         string   `json:"os_version"`
				OSBuild           string   `json:"os_build"`
				CPUModel          string   `json:"cpu_model"`
				RAMBytes          int64    `json:"ram_bytes"`
				PrivacyExclusions []string `json:"privacy_exclusions"`
				ProbeCommands     []string `json:"probe_commands"`
			} `json:"reference_host"`
			ExecutableCases []struct {
				Case              string `json:"case"`
				Test              string `json:"test"`
				Result            string `json:"result"`
				UnexpectedAccepts int    `json:"unexpected_accepts"`
			} `json:"executable_cases"`
			HPKEEntropySource struct {
				TestLimit string `json:"test_limit"`
				Claim     string `json:"claim"`
			} `json:"hpke_entropy_source"`
			TotalUnexpectedAccepts int `json:"total_unexpected_accepts"`
		}
		loadEvidenceJSON(t, "phase8-toolchain-randomness-report.json", &report)
		if report.Schema != "kurdistan.phase8.toolchain-randomness-report.v1" || len(report.StandardLibraryEvidence) != 6 {
			t.Fatalf("unexpected toolchain report identity or package count")
		}
		for _, item := range report.StandardLibraryEvidence {
			if item.Package == "" || len(item.SourceAggregateSHA256) != 64 || item.ObservedAPI == "" || item.RelevantLimit == "" {
				t.Fatalf("incomplete standard library evidence: %+v", item)
			}
		}
		if report.CleanBuild.ExitCode != 0 || report.CleanBuild.Result != "passed" || report.TotalUnexpectedAccepts != 0 || len(report.ExecutableCases) < 5 {
			t.Fatalf("toolchain evidence not clean: build=%+v unexpected=%d cases=%d", report.CleanBuild, report.TotalUnexpectedAccepts, len(report.ExecutableCases))
		}
		for _, testCase := range report.ExecutableCases {
			if testCase.Case == "" || testCase.Test == "" || testCase.Result == "" || testCase.UnexpectedAccepts != 0 {
				t.Fatalf("invalid randomness case: %+v", testCase)
			}
		}
		if !strings.Contains(strings.ToLower(report.FIPSObservation.Wording), "not cmvp") || !strings.Contains(strings.ToLower(report.HPKEEntropySource.Claim), "not induced") {
			t.Fatal("FIPS or HPKE entropy limitation wording is not explicit")
		}
		if report.ReferenceHost.Alias != "phase8-reference-windows-amd64-01" || report.ReferenceHost.OS == "" || report.ReferenceHost.OSVersion == "" || report.ReferenceHost.OSBuild == "" || report.ReferenceHost.CPUModel == "" || report.ReferenceHost.RAMBytes <= 0 {
			t.Fatalf("incomplete privacy-safe reference host: %+v", report.ReferenceHost)
		}
		if len(report.ReferenceHost.PrivacyExclusions) < 4 || len(report.ReferenceHost.ProbeCommands) < 3 {
			t.Fatalf("reference host privacy or probe evidence incomplete: %+v", report.ReferenceHost)
		}
		for _, prohibited := range []string{"hostname=", "username=", "serial="} {
			if strings.Contains(strings.ToLower(fmt.Sprint(report.ReferenceHost)), prohibited) {
				t.Fatalf("reference host includes prohibited identity field %q", prohibited)
			}
		}
	})

	t.Run("independent regeneration lock", func(t *testing.T) {
		var report struct {
			Schema      string `json:"schema"`
			Independent struct {
				RequirementsLock       string `json:"requirements_lock"`
				RequirementsLockSHA256 string `json:"requirements_lock_sha256"`
				RuntimeVerification    struct {
					Python   string            `json:"python"`
					Packages map[string]string `json:"packages"`
					Result   string            `json:"result"`
				} `json:"runtime_verification"`
				Libraries []struct {
					Name        string `json:"name"`
					Version     string `json:"version"`
					ArtifactURL string `json:"artifact_url"`
					WheelSHA256 string `json:"wheel_sha256"`
				} `json:"libraries"`
			} `json:"independent_implementation"`
		}
		loadEvidenceJSON(t, "phase8-independent-interop-report.json", &report)
		if report.Schema != "kurdistan.phase8.independent-interop-report.v1" || report.Independent.RuntimeVerification.Python != "3.12.10" || report.Independent.RuntimeVerification.Result != "passed before fixture generation" {
			t.Fatalf("invalid independent runtime identity: %+v", report.Independent.RuntimeVerification)
		}
		for name, version := range map[string]string{"cbor2": "6.1.3", "cffi": "2.0.0", "cryptography": "46.0.7", "pycparser": "2.23", "pyhpke": "0.6.5"} {
			if report.Independent.RuntimeVerification.Packages[name] != version {
				t.Fatalf("runtime package %s = %q, want %q", name, report.Independent.RuntimeVerification.Packages[name], version)
			}
		}
		for _, library := range report.Independent.Libraries {
			if library.Name == "" || library.Version == "" || !strings.HasPrefix(library.ArtifactURL, "https://files.pythonhosted.org/packages/") || len(library.WheelSHA256) != 64 {
				t.Fatalf("incomplete hash-locked independent library: %+v", library)
			}
		}
		lockPath := filepath.Join("..", "..", "..", filepath.FromSlash(report.Independent.RequirementsLock))
		lock, err := os.ReadFile(lockPath)
		if err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(lock)
		if fmt.Sprintf("%x", digest) != report.Independent.RequirementsLockSHA256 {
			t.Fatal("independent requirements lock hash does not match report")
		}
		lockText := string(lock)
		for _, required := range []string{"--hash=sha256:", "cbor2-6.1.3", "cryptography-46.0.7", "pyhpke-0.6.5", "cffi-2.0.0", "pycparser-2.23"} {
			if !strings.Contains(lockText, required) {
				t.Fatalf("independent requirements lock missing %q", required)
			}
		}
		regenerator, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "evidence", "independent", "regenerate_phase8_interop.ps1"))
		if err != nil {
			t.Fatal(err)
		}
		for _, required := range []string{"--require-hashes", "--no-cache-dir", "--compare", "Get-FileHash", "PHASE8 INTEROP REGENERATION PASSED"} {
			if !strings.Contains(string(regenerator), required) {
				t.Fatalf("independent regenerator missing %q", required)
			}
		}
		interop, err := os.ReadFile(filepath.Join("..", "..", "..", "testdata", "evidence", "independent", "phase8_interop.py"))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(interop), `args.output.open("xb")`) || strings.Contains(string(interop), "args.output.write_bytes(") {
			t.Fatal("independent generator does not require a fresh --output path")
		}
	})

	t.Run("prohibited composition", func(t *testing.T) {
		var report struct {
			Schema          string `json:"schema"`
			ModuleInventory struct {
				UnreviewedDependencies int `json:"unreviewed_dependencies"`
				Modules                []struct {
					Path           string `json:"path"`
					Classification string `json:"classification"`
				} `json:"modules"`
			} `json:"module_inventory"`
			Prohibitions []struct {
				Name     string `json:"name"`
				Observed int    `json:"observed"`
				Evidence string `json:"evidence"`
			} `json:"prohibitions"`
			Summary struct {
				UnreviewedDependencies    int `json:"unreviewed_dependencies"`
				DraftOnlyMandatoryFormats int `json:"draft_only_mandatory_formats"`
				AutomaticDowngradePaths   int `json:"automatic_downgrade_paths"`
				ProductionKeys            int `json:"production_keys"`
			} `json:"summary"`
		}
		loadEvidenceJSON(t, "phase8-prohibited-composition-report.json", &report)
		if report.Schema != "kurdistan.phase8.prohibited-composition-report.v1" || report.ModuleInventory.UnreviewedDependencies != 0 || len(report.ModuleInventory.Modules) != 3 {
			t.Fatalf("invalid dependency inventory")
		}
		if report.Summary.UnreviewedDependencies != 0 || report.Summary.DraftOnlyMandatoryFormats != 0 || report.Summary.AutomaticDowngradePaths != 0 || report.Summary.ProductionKeys != 0 {
			t.Fatalf("prohibited composition summary is nonzero: %+v", report.Summary)
		}
		if len(report.Prohibitions) < 8 {
			t.Fatalf("prohibition coverage = %d", len(report.Prohibitions))
		}
		for _, prohibition := range report.Prohibitions {
			if prohibition.Name == "" || prohibition.Evidence == "" || prohibition.Observed != 0 {
				t.Fatalf("prohibited composition observed: %+v", prohibition)
			}
		}
	})

	goMod, err := os.ReadFile(filepath.Join("..", "..", "..", "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(goMod), "github.com/fxamacker/cbor/v2 v2.9.2") || !strings.Contains(string(goMod), "github.com/x448/float16 v0.8.4 // indirect") {
		t.Fatal("go.mod does not match the reviewed dependency inventory")
	}
}

func TestPhase8BackupConfidentialityIsRecipientKeyOnly(t *testing.T) {
	backup := ArtifactMetadata{
		Class:          ArtifactEncryptedBackup,
		AudienceClass:  AudienceProvisionedBackupKey,
		RecipientHint:  "rotating_backup_hint_01",
		RecipientEpoch: 1,
	}
	if _, err := BuildSealProtected(backup); err != nil {
		t.Fatal(err)
	}
	if _, err := BuildSealProtected(ArtifactMetadata{Class: ArtifactSignedPublic, AudienceClass: AudiencePublic}); err == nil {
		t.Fatal("public artifact entered recipient sealing")
	}
	production, err := os.ReadFile("phase8_suite.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, prohibited := range []string{"passphrase", "argon2", "scrypt", "pbkdf", "universal key", "shared key"} {
		if strings.Contains(strings.ToLower(string(production)), prohibited) {
			t.Fatalf("Phase 8 production suite contains prohibited backup path %q", prohibited)
		}
	}
}

func loadEvidenceJSON(t *testing.T, name string, destination any) {
	t.Helper()
	path := filepath.Join("..", "..", "..", "testdata", "evidence", name)
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(content, destination); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
}
