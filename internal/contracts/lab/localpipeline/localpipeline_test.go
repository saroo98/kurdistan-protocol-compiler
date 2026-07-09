// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localpipeline

import "testing"

func TestGenerateFixtureSet(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	if set.Conclusion != "passed" {
		t.Fatalf("fixture conclusion = %s", set.Conclusion)
	}
	if len(set.Scenarios) < 10 || len(set.Runs) < 10 {
		t.Fatalf("missing scenarios or runs")
	}
	if set.Boundary.Conclusion != "passed" || set.Parity.Conclusion != "passed" || set.Collapse.Conclusion != "passed" {
		t.Fatalf("unexpected report failure: %+v %+v %+v", set.Boundary, set.Parity, set.Collapse)
	}
	if err := ScanForLeak(set); err != nil {
		t.Fatal(err)
	}
}

func TestExecuteScenariosCoversPressureResetErrorAndRejection(t *testing.T) {
	set, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	var pressure, resets, errors, rejections, failovers int
	for _, run := range set.Runs {
		pressure += run.BackpressureEvents
		resets += run.TargetResets
		errors += run.TargetErrors
		rejections += run.DescriptorRejections
		failovers += run.FailoverDecisions
	}
	if pressure == 0 || resets == 0 || errors == 0 || rejections == 0 || failovers == 0 {
		t.Fatalf("missing pipeline coverage: pressure=%d resets=%d errors=%d rejections=%d failovers=%d", pressure, resets, errors, rejections, failovers)
	}
}

func TestValidationRejectsUnsafeInput(t *testing.T) {
	s := DefaultScenarios()[0]
	s.ScenarioID = ""
	if err := ValidateScenario(s); err == nil {
		t.Fatalf("missing scenario id accepted")
	}
	if err := ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		t.Fatalf("unsafe endpoint field accepted")
	}
	if err := ScanForLeak(map[string]string{"secret": "synthetic"}); err == nil {
		t.Fatalf("unsafe secret field accepted")
	}
}

func TestCompareFixtureSetsDetectsDrift(t *testing.T) {
	oldSet, err := GenerateFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	newSet := oldSet
	newSet.Runs[0].ByteFrames++
	newSet.FixtureHash = HashValue(fixtureHashInput(newSet))
	report := CompareFixtureSets(oldSet, newSet)
	if report.Conclusion != "failed" {
		t.Fatalf("expected drift failure")
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add("safe_bucket")
	f.Add("raw_payload")
	f.Fuzz(func(t *testing.T, value string) {
		_ = ScanForLeak(map[string]string{"class": value})
	})
}

func BenchmarkGenerateFixtureSet(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateFixtureSet(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanCollapse(b *testing.B) {
	set, err := GenerateFixtureSet()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(set.Runs)
	}
}
