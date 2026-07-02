// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package httpscarrieradversary

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateFixtureSetCoversAdversaryControls(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if set.BackendVersion != BackendVersion {
		t.Fatalf("backend version = %s", set.BackendVersion)
	}
	if set.Report.Collapse.Conclusion != ConclusionPassed || !set.Report.Collapse.AcceptedProfilesNonCollapsed {
		t.Fatalf("collapse report did not prove accepted non-collapse: %+v", set.Report.Collapse)
	}
	if !set.Report.Collapse.FixedShapeDetected || !set.Report.Collapse.FixedRequestSequence || !set.Report.Collapse.FixedResponseSequence {
		t.Fatalf("fixed-shape controls were not represented: %+v", set.Report.Collapse)
	}
	if !set.Report.PaddingVariation.PaddingOnlyRejected {
		t.Fatalf("padding-only variation was not rejected")
	}
	if !set.Report.ProfileSensitivity.ProfileInputsInfluence || !set.Report.ProfileSensitivity.GeneratedProfileInfluence {
		t.Fatalf("profile sensitivity evidence missing: %+v", set.Report.ProfileSensitivity)
	}
	if !set.Report.UnsafeFallback.FallbacksRejected {
		t.Fatalf("unsafe fallback controls not rejected: %+v", set.Report.UnsafeFallback)
	}
	if set.Misuse.DetectedCount != len(requiredMisuseNames()) {
		t.Fatalf("misuse count = %d, want %d", set.Misuse.DetectedCount, len(requiredMisuseNames()))
	}
}

func TestReplayStreamBackpressureResetAndIntegrationControls(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Report.ReplayControls.DuplicateCarrierMarkersRejected == 0 ||
		set.Report.ReplayControls.ReplayedSessionMarkersRejected == 0 ||
		set.Report.ReplayControls.ProductionCryptoChanged {
		t.Fatalf("unsafe replay/control result: %+v", set.Report.ReplayControls)
	}
	if set.Report.StreamIsolation.IsolationFailures != 0 || set.Report.StreamIsolation.CrossStreamResetControls == 0 {
		t.Fatalf("stream isolation controls incomplete: %+v", set.Report.StreamIsolation)
	}
	if set.Report.Backpressure.BoundedPressureSummaries == 0 || set.Report.Backpressure.IgnoredBackpressureControls == 0 {
		t.Fatalf("backpressure controls incomplete: %+v", set.Report.Backpressure)
	}
	if set.Report.ResetError.ResetSwallowedControls == 0 || len(set.Report.ResetError.SafeErrorClasses) == 0 {
		t.Fatalf("reset/error controls incomplete: %+v", set.Report.ResetError)
	}
	if set.Report.IntegrationBypass.BypassesDetected != set.Report.IntegrationBypass.BypassesRejected ||
		!set.Report.IntegrationBypass.CarrierReviewBound ||
		!set.Report.IntegrationBypass.MeasurementReviewBound ||
		!set.Report.IntegrationBypass.PathHealthBound {
		t.Fatalf("integration bypass controls incomplete: %+v", set.Report.IntegrationBypass)
	}
}

func TestTraceHygieneAndClaimSafetyControls(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatalf("clean fixture leaked: %v", err)
	}
	for _, marker := range []string{"raw_payload", "encoded_bytes", "payload_body", "raw_secret", "public-network ready", "real https carrier support"} {
		if err := ScanForLeak(map[string]string{"bad": marker}); err == nil {
			t.Fatalf("ScanForLeak(%q) succeeded, want failure", marker)
		}
	}
	if !set.Report.PublicClaims.ClaimSafetyPassed || len(set.Report.PublicClaims.UnsafeClaimsFound) > 0 {
		t.Fatalf("public claim safety failed: %+v", set.Report.PublicClaims)
	}
}

func TestGeneratedParity(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Parity.Conclusion != ConclusionPassed || len(set.Parity.UnexpectedDifferences) != 0 {
		t.Fatalf("parity failed: %+v", set.Parity)
	}
	for _, want := range []string{"HTTPSCarrierAdversarySchemaVersion", "HTTPSCarrierAdversaryGeneratedProfileID"} {
		found := false
		for _, marker := range set.Parity.AdversarialMarkers {
			if marker == want {
				found = true
			}
		}
		if !found {
			t.Fatalf("missing generated marker %s", want)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Report.Collapse.DiversityScore = 0.01
	newSet.Report.ReportHash = HashValue(reportWithoutHash(newSet.Report))
	newSet.FixtureHash = HashValue(setWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != ConclusionFailed || len(report.UnexpectedDrift) == 0 {
		t.Fatalf("expected drift failure, got %+v", report)
	}
}

func FuzzFixtureSetJSON(f *testing.F) {
	set, err := GenerateFixtureSet()
	if err != nil {
		f.Fatal(err)
	}
	f.Add(string(StableJSON(set)))
	f.Add(`{"version":"bad"}`)
	f.Add(`{"payload_logged":true}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 1<<16 {
			t.Skip()
		}
		var set FixtureSet
		if err := json.Unmarshal([]byte(input), &set); err == nil {
			_ = ValidateFixtureSet(set)
		}
		if strings.Contains(strings.ToLower(input), "raw_secret") {
			if err := ScanForLeak(map[string]string{"input": input}); err == nil {
				t.Fatalf("raw_secret input passed hygiene scan")
			}
		}
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
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ScanForLeak(set); err != nil {
			b.Fatal(err)
		}
	}
}
