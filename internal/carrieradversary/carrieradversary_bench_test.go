// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrieradversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func BenchmarkCarrierFeatureExtraction(b *testing.B) {
	p, err := compiler.Generate(12101)
	if err != nil {
		b.Fatal(err)
	}
	run, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioMixedCarrierMatrix))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractFeatures(run.Events)
	}
}

func BenchmarkCarrierCollapseScanner20Profiles(b *testing.B) {
	profiles := makeProfiles(b, 20)
	runs, err := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioMixedCarrierMatrix)})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeRuns(runs, DefaultCollapseThresholds())
	}
}

func makeProfiles(b *testing.B, count int) []*ir.Profile {
	b.Helper()
	profiles := make([]*ir.Profile, 0, count)
	for seed := int64(1); seed <= int64(count); seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			b.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	return profiles
}
