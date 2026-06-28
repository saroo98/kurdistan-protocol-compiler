// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

import (
	"context"
	"testing"
)

func BenchmarkProxySemScenarioRunner(b *testing.B) {
	profiles, err := GenerateProfiles(1, 1)
	if err != nil {
		b.Fatal(err)
	}
	scenario := DefaultScenario(ScenarioMixedTargets)
	for i := 0; i < b.N; i++ {
		if _, err := RunScenario(context.Background(), profiles[0], scenario); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkProxyFeatureExtraction(b *testing.B) {
	profiles, err := GenerateProfiles(1, 1)
	if err != nil {
		b.Fatal(err)
	}
	run, err := RunScenario(context.Background(), profiles[0], DefaultScenario(ScenarioMixedTargets))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractProxyFeatures(run.Events)
	}
}

func BenchmarkProxyCollapseScanner20Profiles(b *testing.B) {
	profiles, err := GenerateProfiles(1, 20)
	if err != nil {
		b.Fatal(err)
	}
	runs, err := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioMixedTargets)})
	if err != nil {
		b.Fatal(err)
	}
	thresholds := DefaultCollapseThresholds()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(ScenarioMixedTargets, runs, thresholds)
	}
}
