// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayprocess

import "testing"

func TestGenerateFixtureSetCoversArchitecture(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if len(set.Roles) < 3 {
		t.Fatalf("roles too small: %d", len(set.Roles))
	}
	if len(set.Lifecycle) < 5 {
		t.Fatalf("lifecycle contracts too small: %d", len(set.Lifecycle))
	}
	if set.M53Preconditions.Conclusion != ConclusionPassed {
		t.Fatalf("M53 preconditions not passed: %+v", set.M53Preconditions)
	}
	if set.RecommendedNextMilestone != RecommendedNextMilestone {
		t.Fatalf("unexpected next milestone: %q", set.RecommendedNextMilestone)
	}
}

func TestValidateFixtureSetRejectsUnsafeConfig(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	set.Config.AllowPublicDeploymentDefaults = true
	if err := ValidateFixtureSet(set); err == nil {
		t.Fatal("expected unsafe public deployment default to be rejected")
	}
}

func TestMisuseControlsDetected(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() error = %v", err)
	}
	if set.Misuse.DetectedCount != len(RequiredMisuseNames()) {
		t.Fatalf("misuse count = %d, want %d", set.Misuse.DetectedCount, len(RequiredMisuseNames()))
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatalf("GenerateFixtureSet() old error = %v", err)
	}
	newSet := oldSet
	newSet.BackendVersion = "0.52.1-lab"
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion == ConclusionPassed {
		t.Fatal("expected drift report to fail")
	}
}

func TestScanForLeakRejectsUnsafeFields(t *testing.T) {
	if err := ScanForLeak(map[string]string{"raw_payload": "unsafe"}); err == nil {
		t.Fatal("expected raw payload marker to fail")
	}
	if err := ScanForLeak(map[string]string{"state_class": "ready"}); err != nil {
		t.Fatalf("clean metadata failed: %v", err)
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"state_class":"ready"}`)
	f.Add(`{"raw_payload":"blocked"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		_ = ScanForLeak(map[string]string{"input": raw})
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
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	newSet, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CompareFixtureSets(oldSet, newSet)
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
