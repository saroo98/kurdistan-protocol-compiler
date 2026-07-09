// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carriercollapse

import "testing"

func TestGenerateFixtureSetCoversCollapseClasses(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Report.BackendVersion != BackendVersion {
		t.Fatalf("backend version mismatch: %s", set.Report.BackendVersion)
	}
	for _, class := range RequiredCollapseClasses() {
		if !contains(set.Report.Diversity.CollapseClassesTested, class) &&
			!contains(set.Report.SelectionCollapse.CollapseClassesTested, class) &&
			!containsMutationClass(set.Report.Mutations.Findings, class) {
			t.Fatalf("missing collapse class %s", class)
		}
	}
	if len(set.Fixtures) < 10 {
		t.Fatalf("expected reviewable fixture coverage, got %d", len(set.Fixtures))
	}
}

func TestMutationControlsDetected(t *testing.T) {
	report := BuildMutationReport()
	if report.DetectedCount != len(RequiredMutationNames()) {
		t.Fatalf("detected %d controls, want %d", report.DetectedCount, len(RequiredMutationNames()))
	}
	for _, name := range RequiredMutationNames() {
		found := false
		for _, finding := range report.Findings {
			if finding.Name == name && finding.Detected {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("missing mutation control %s", name)
		}
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Report.Diversity.DiversityScore = 0.01
	newSet.FixtureHash = HashValue(fixtureSetWithoutHash(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != ConclusionFailed {
		t.Fatalf("expected drift failure, got %s", report.Conclusion)
	}
}

func TestScanForLeakRejectsUnsafeFields(t *testing.T) {
	if err := ScanForLeak(map[string]any{"raw_payload": "blocked"}); err == nil {
		t.Fatalf("raw payload field accepted")
	}
	if err := ScanForLeak(map[string]any{"payload_logged": true}); err == nil {
		t.Fatalf("payload leakage flag accepted")
	}
	if err := ScanForLeak(map[string]any{"safe_bucket": "carrier_family_class"}); err != nil {
		t.Fatalf("safe metadata rejected: %v", err)
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"safe_bucket":"carrier"}`)
	f.Add(`{"raw_payload":"blocked"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		_ = ScanForLeak(map[string]any{"value": raw})
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareFixtureSets(b *testing.B) {
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if CompareFixtureSets(set, set).Conclusion != ConclusionPassed {
			b.Fatal("comparison failed")
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
