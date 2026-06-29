// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func BenchmarkRuntimeFeatureExtraction(b *testing.B) {
	p, _ := compiler.Generate(1310)
	run := RunScenario(context.Background(), p, DefaultScenario(ScenarioHappyPathSession))
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractFeatures(run)
	}
}

func BenchmarkRuntimeCollapseScanner20Profiles(b *testing.B) {
	profiles := make([]*ir.Profile, 0, 20)
	for i := 0; i < 20; i++ {
		p, _ := compiler.Generate(1320 + int64(i))
		profiles = append(profiles, p)
	}
	runs := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioHappyPathSession)})
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(ScenarioHappyPathSession, runs, DefaultCollapseThresholds())
	}
}
