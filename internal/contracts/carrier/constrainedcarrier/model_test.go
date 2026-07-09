// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package constrainedcarrier

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateFixtureSetCoversPrototype(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet: %v", err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatalf("ValidateFixtureSet: %v", err)
	}
	report := set.Report
	if !report.Harness.LocalOnly || report.Harness.PublicResolverBehavior || report.Harness.RealDNSQueryDefault {
		t.Fatalf("unsafe harness contract: %+v", report.Harness)
	}
	if len(report.QueryShapes) < 8 || len(report.ResponseShapes) < 7 || len(report.ControlShapes) < 6 {
		t.Fatalf("shape coverage incomplete")
	}
	if report.CapacityTruncation.OversizedMarkersRejected == 0 || report.CapacityTruncation.RawByteCountsStored {
		t.Fatalf("capacity/truncation contract incomplete")
	}
	if !report.RetryFailure.MaxRetryEnforced || !report.RetryFailure.PathHealthFeedback {
		t.Fatalf("retry/failure contract incomplete")
	}
	if report.ProfileSensitivity.DiversityScore < 0.75 || len(report.ShapeDiversityFingerprints) < 8 {
		t.Fatalf("profile-sensitive diversity too low")
	}
	if report.StreamsOpened < 4 || report.StreamResets == 0 || report.TargetErrors == 0 {
		t.Fatalf("stream reset/error evidence incomplete")
	}
	if !report.PathHealthEnforced || !report.MeasurementReviewEnforced || !report.LocalPipelineEnforced {
		t.Fatalf("integration enforcement missing")
	}
	if report.Diagnostics.UploadAllowed || report.Diagnostics.ExactQueryStored || report.Diagnostics.ResolverIPStored {
		t.Fatalf("diagnostics leaked unsafe metadata")
	}
	if report.Misuse.DetectedCount != len(RequiredMisuseNames()) {
		t.Fatalf("misuse coverage mismatch: %d", report.Misuse.DetectedCount)
	}
	if report.Parity.Conclusion != ConclusionPassed || len(report.Parity.GeneratedMarkers) == 0 {
		t.Fatalf("parity report incomplete")
	}
}

func TestValidateConfigRejectsUnsafeControls(t *testing.T) {
	cfg := DefaultConfig()
	cfg.AllowPublicResolver = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected public resolver config rejection")
	}
	cfg = DefaultConfig()
	cfg.AllowRealDNSQueryDefault = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected real DNS query default rejection")
	}
	cfg = DefaultConfig()
	cfg.AllowExactQueryPersistence = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected exact query persistence rejection")
	}
	cfg = DefaultConfig()
	cfg.AllowResolverIPPersistence = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected resolver IP persistence rejection")
	}
	cfg = DefaultConfig()
	cfg.AllowDomainDependency = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected domain dependency rejection")
	}
	cfg = DefaultConfig()
	cfg.AllowWildcardResolver = true
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("expected wildcard resolver rejection")
	}
}

func TestProfileSensitiveShapeSelectionDiffers(t *testing.T) {
	aQuery := SelectQueryShape(12345, 1, ScenarioProfileSensitiveSelection)
	bQuery := SelectQueryShape(12346, 1, ScenarioProfileSensitiveSelection)
	aResponse := SelectResponseShape(12345, 1, ScenarioProfileSensitiveSelection)
	bResponse := SelectResponseShape(12346, 1, ScenarioProfileSensitiveSelection)
	if aQuery.ShapeClass == bQuery.ShapeClass && aResponse.ShapeClass == bResponse.ShapeClass {
		t.Fatalf("profile-sensitive constrained shape selection collapsed: %s/%s", aQuery.ShapeClass, aResponse.ShapeClass)
	}
}

func TestScanForLeakRejectsUnsafeMetadata(t *testing.T) {
	cases := []any{
		map[string]string{"raw_payload": "present"},
		map[string]string{"encoded_bytes": "0102"},
		map[string]string{"host_header": "present"},
		map[string]string{"auth_tag": "present"},
		map[string]bool{"allow_public_resolver": true},
		map[string]bool{"payload_logged": true},
		map[string]bool{"secret_logged": true},
	}
	for _, tc := range cases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("expected leak rejection for %#v", tc)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Report.QueryEvents++
	newSet.FixtureHash = HashValue(reportWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != ConclusionFailed {
		t.Fatalf("expected drift failure, got %+v", report)
	}
}

func TestStableJSONRoundTrip(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := StableJSON(set)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(string(raw), "\n") {
		t.Fatal("stable JSON should end with newline")
	}
	var decoded FixtureSet
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.FixtureHash != set.FixtureHash {
		t.Fatalf("hash drift after JSON round trip")
	}
}

func FuzzScanForLeak(f *testing.F) {
	for _, seed := range []string{
		`{"scenario_bucket":"safe"}`,
		`{"raw_payload":"bad"}`,
		`{"allow_public_resolver":true}`,
		`{"payload_logged":false,"secret_logged":false}`,
	} {
		f.Add(seed)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return
		}
		_ = ScanForLeak(value)
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkShapeSelection(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = SelectQueryShape(12345+i, uint64(i%8+1), ScenarioProfileSensitiveSelection)
		_ = SelectResponseShape(12345+i, uint64(i%8+1), ScenarioProfileSensitiveSelection)
	}
}

func BenchmarkScanForLeak(b *testing.B) {
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if err := ScanForLeak(set); err != nil {
			b.Fatal(err)
		}
	}
}
