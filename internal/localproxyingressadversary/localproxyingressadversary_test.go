// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"context"
	"testing"
)

func TestControlsFailAsExpected(t *testing.T) {
	for _, scenario := range QuickScenarios() {
		run := RunScenario(context.Background(), scenario)
		if run.Conclusion != "failed" {
			t.Fatalf("%s did not fail: %#v", scenario, run)
		}
	}
}

func TestFeatureExtractionDeterministic(t *testing.T) {
	a := RunScenario(context.Background(), ScenarioBackpressureIgnored).Features
	b := RunScenario(context.Background(), ScenarioBackpressureIgnored).Features
	if a.SummaryHash != b.SummaryHash {
		t.Fatal("feature extraction drifted")
	}
}

func BenchmarkCollapseScan(b *testing.B) {
	run := RunScenario(context.Background(), ScenarioFixedStreamMapping)
	vectors := []FeatureVector{run.Features}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(vectors, ScenarioFixedStreamMapping)
	}
}
