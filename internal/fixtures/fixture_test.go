// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/bytetransport"
	"kurdistan/internal/codegen"
)

func TestGenerateValidateAndCompareManifest(t *testing.T) {
	manifest, err := GenerateBytePathManifest(context.Background(), ManifestOptions{
		ProfileSeeds:   []int{12345},
		ScenarioNames:  []string{bytetransport.ScenarioSingleFlow, bytetransport.ScenarioReplay},
		BackendVersion: codegen.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(manifest.Entries) != 2 || manifest.FixtureCount != 2 {
		t.Fatalf("unexpected fixture count: %#v", manifest)
	}
	if err := ValidateManifest(manifest); err != nil {
		t.Fatal(err)
	}
	same := CompareManifests(manifest, manifest)
	if !same.Passed || same.Compared != 2 {
		t.Fatalf("same manifest compare failed: %#v", same)
	}
	changed := manifest
	changed.Entries = append([]FixtureEntry(nil), manifest.Entries...)
	changed.Entries[0].SummaryHash = "drift"
	report := CompareManifests(manifest, changed)
	if report.Passed || len(report.Changed) == 0 {
		t.Fatalf("fixture drift not detected: %#v", report)
	}
}

func TestWriteManifestRefusesOverwrite(t *testing.T) {
	manifest, err := GenerateBytePathManifest(context.Background(), ManifestOptions{
		ProfileSeeds:   []int{12345},
		ScenarioNames:  []string{bytetransport.ScenarioSingleFlow},
		BackendVersion: codegen.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := WriteManifest(path, manifest, false); err != nil {
		t.Fatal(err)
	}
	if err := WriteManifest(path, manifest, false); err != ErrRefuseOverwrite {
		t.Fatalf("overwrite error = %v, want %v", err, ErrRefuseOverwrite)
	}
	if err := WriteManifest(path, manifest, true); err != nil {
		t.Fatal(err)
	}
}

func TestMalformedCorpusRejectsSafely(t *testing.T) {
	cases := DefaultMalformedCorpus()
	if len(cases) < 20 {
		t.Fatalf("malformed corpus too small: %d", len(cases))
	}
	if err := ValidateMalformedCorpus(cases); err != nil {
		t.Fatal(err)
	}
	for _, tc := range cases {
		result := RunMalformedCase(tc)
		if tc.ExpectedReject && !result.Rejected {
			t.Fatalf("%s accepted malformed input", tc.Name)
		}
		if !result.SafeError {
			t.Fatalf("%s produced unsafe error", tc.Name)
		}
	}
}

func TestFixtureRedactionRejectsForbiddenFields(t *testing.T) {
	if !ValidateRedaction(map[string]string{"scenario": "byte_single_flow_echo"}).Passed {
		t.Fatalf("clean fixture metadata rejected")
	}
	for _, raw := range []string{
		`{"raw_payload":"x"}`,
		`{"encoded_bytes":"0102"}`,
		`{"secret":"x"}`,
		`{"payload_logged":true}`,
	} {
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			t.Fatal(err)
		}
		if ValidateRedaction(value).Passed {
			t.Fatalf("forbidden fixture metadata accepted: %s", raw)
		}
	}
}

func TestPerformanceBaselineValidates(t *testing.T) {
	baseline := DefaultPerformanceBaseline()
	if err := ValidatePerformanceBaseline(baseline); err != nil {
		t.Fatal(err)
	}
	baseline.BytePipeWriteReadMaxBucket = "exact_ns"
	if err := ValidatePerformanceBaseline(baseline); err == nil {
		t.Fatalf("invalid performance bucket accepted")
	}
}

func TestVerifyManifestDetectsDrift(t *testing.T) {
	manifest, err := GenerateBytePathManifest(context.Background(), ManifestOptions{
		ProfileSeeds:   []int{12345},
		ScenarioNames:  []string{bytetransport.ScenarioSingleFlow},
		BackendVersion: codegen.Version,
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "fixture.json")
	if err := WriteManifest(path, manifest, true); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	loaded, err := LoadManifest(path)
	if err != nil {
		t.Fatal(err)
	}
	loaded.Entries[0].SummaryHash = "drift"
	raw, err := StableJSON(loaded)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyManifest(context.Background(), path); err == nil {
		t.Fatalf("invalid drifted fixture accepted")
	}
}

func BenchmarkFixtureManifestValidation(b *testing.B) {
	manifest, err := GenerateBytePathManifest(context.Background(), ManifestOptions{
		ProfileSeeds:   []int{12345},
		ScenarioNames:  []string{bytetransport.ScenarioSingleFlow},
		BackendVersion: codegen.Version,
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateManifest(manifest); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkMalformedCorpusExecution(b *testing.B) {
	cases := DefaultMalformedCorpus()
	for i := 0; i < b.N; i++ {
		if err := ValidateMalformedCorpus(cases); err != nil {
			b.Fatal(err)
		}
	}
}
