// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package constrainedcarrierreview

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateFixtureSetCoversDesignLock(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(set); err != nil {
		t.Fatal(err)
	}
	if set.BackendVersion != BackendVersion || set.Report.BackendVersion != BackendVersion {
		t.Fatalf("backend version drift: %+v", set)
	}
	if !set.Report.Scope.LocalResolverHarnessOnly || !set.Report.Scope.NoPublicResolverDefault || !set.Report.Scope.NoRealQueryDefault {
		t.Fatalf("scope did not lock local constrained carrier boundaries: %+v", set.Report.Scope)
	}
	if set.Report.ResolverHarness.PublicResolverBehavior || set.Report.ResolverHarness.ExactQueryPersisted || set.Report.ResolverHarness.WildcardResolverAllowed {
		t.Fatalf("resolver harness allows blocked behavior: %+v", set.Report.ResolverHarness)
	}
	if len(set.Report.QueryShapes) < 10 || len(set.Report.ResponseShapes) < 9 {
		t.Fatalf("shape taxonomy incomplete: %d/%d", len(set.Report.QueryShapes), len(set.Report.ResponseShapes))
	}
	if set.Report.SizeTruncation.OversizeRejectionControls == 0 || len(set.Report.SizeTruncation.TruncationBuckets) < 3 {
		t.Fatalf("size/truncation contract incomplete: %+v", set.Report.SizeTruncation)
	}
	if !set.Report.RetryFailure.PathHealthPropagation || !set.Report.RetryFailure.MeasurementReviewDiagnostics {
		t.Fatalf("retry/failure contract missing integration requirements: %+v", set.Report.RetryFailure)
	}
	if !set.Report.StreamMapping.ProfileSensitiveSelection || !set.Report.StreamMapping.BackpressureMappingRequired {
		t.Fatalf("stream mapping contract incomplete: %+v", set.Report.StreamMapping)
	}
	if !set.Report.PrivacyMeasurement.MeasurementReviewComposed || set.Report.PrivacyMeasurement.UploadAllowed || set.Report.PrivacyMeasurement.ExactQueryStored {
		t.Fatalf("privacy/measurement contract unsafe: %+v", set.Report.PrivacyMeasurement)
	}
	if set.Report.M45Contract.Decision != DecisionReady || len(set.Report.M45Contract.RequiredIntegrations) < 5 {
		t.Fatalf("M45 implementation contract incomplete: %+v", set.Report.M45Contract)
	}
	if set.Report.Misuse.DetectedCount != len(RequiredMisuseNames()) {
		t.Fatalf("misuse controls incomplete: %+v", set.Report.Misuse)
	}
	if set.Report.Parity.Conclusion != ConclusionPassed || len(set.Report.Parity.GeneratedMarkers) < 6 {
		t.Fatalf("generated parity contract incomplete: %+v", set.Report.Parity)
	}
}

func TestScanForLeakRejectsUnsafeMetadata(t *testing.T) {
	clean, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ScanForLeak(clean); err != nil {
		t.Fatalf("clean constrained carrier review fixture rejected: %v", err)
	}
	unsafeCases := []any{
		map[string]string{"raw_payload": "synthetic"},
		map[string]string{"raw_secret": "synthetic"},
		map[string]string{"resolver_address_value": "synthetic"},
		map[string]string{"exact_query_value": "synthetic"},
		map[string]string{"real_domain_value": "synthetic"},
		map[string]bool{"public_resolver_behavior": true},
		map[string]bool{"exact_query_persisted": true},
		map[string]bool{"upload_allowed": true},
	}
	for _, tc := range unsafeCases {
		if err := ScanForLeak(tc); err == nil {
			t.Fatalf("unsafe constrained carrier review metadata accepted: %#v", tc)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Report.M45Contract.Decision = "changed"
	newSet.Report.ReportHash = HashValue(reportWithoutHash(newSet.Report))
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	comparison := CompareFixtureSets(oldSet, newSet)
	if comparison.Conclusion != ConclusionFailed || len(comparison.UnexpectedDrift) == 0 {
		t.Fatalf("expected drift failure, got %+v", comparison)
	}
}

func TestStableJSONRoundTrip(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	raw := StableJSON(set)
	if !strings.Contains(string(raw), `"version": "`+Version+`"`) {
		t.Fatalf("stable JSON missing version: %s", raw)
	}
	var decoded FixtureSet
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFixtureSet(decoded); err != nil {
		t.Fatal(err)
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"query_shape_bucket":"small","payload_logged":false}`)
	f.Add(`{"raw_payload":"synthetic"}`)
	f.Fuzz(func(t *testing.T, input string) {
		_ = ScanForLeak(json.RawMessage(input))
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
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
