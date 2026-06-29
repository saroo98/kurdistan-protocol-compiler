// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapteradversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func TestAdapterAdversaryQuickScenarios(t *testing.T) {
	profiles := mustProfiles(t, 16001, 3)
	runs := RunScenarioCorpus(context.Background(), profiles, QuickScenarios())
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("quick adapter adversary failed: %+v", report)
	}
}

func TestAdapterAdversaryFailureScenarios(t *testing.T) {
	p := mustProfiles(t, 16011, 1)[0]
	for _, scenario := range []Scenario{
		DefaultScenario(ScenarioCapabilityDowngrade),
		DefaultScenario(ScenarioMalformedFlowDescriptor),
	} {
		run := RunScenario(context.Background(), p, scenario)
		if !run.Correct {
			t.Fatalf("%s expected safe failure classification: %+v", scenario.Type, run)
		}
	}
}

func TestAdapterMutantsDetected(t *testing.T) {
	for _, mode := range []string{
		mutant.ModeAdapterIgnoresBackpressure,
		mutant.ModeAdapterLeaksPayloadTrace,
		mutant.ModeAdapterAcceptsCapabilityDowngrade,
		mutant.ModeAdapterWrongResetMapping,
	} {
		profiles, err := mutant.GenerateProfiles(mode, 16100, 3)
		if err != nil {
			t.Fatal(err)
		}
		runs := RunMutantScenarioCorpus(context.Background(), mode, profiles, FullScenarios())
		report := AnalyzeRuns(runs, DefaultCollapseThresholds())
		if report.Conclusion == "passed" {
			t.Fatalf("mutant %s was not detected: %+v", mode, report)
		}
	}
}

func BenchmarkAdapterAdversaryQuick(b *testing.B) {
	profiles := mustProfiles(b, 16200, 3)
	scenarios := QuickScenarios()
	for i := 0; i < b.N; i++ {
		runs := RunScenarioCorpus(context.Background(), profiles, scenarios)
		_ = AnalyzeRuns(runs, DefaultCollapseThresholds())
	}
}

type testingFatal interface {
	Fatal(args ...any)
	Helper()
}

func mustProfiles(t testingFatal, seed int64, count int) []*ir.Profile {
	t.Helper()
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		p, err := compiler.Generate(seed + int64(i))
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	return profiles
}
