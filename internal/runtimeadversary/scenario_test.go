// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/mutant"
)

func TestRuntimeAdversaryScenarios(t *testing.T) {
	p, err := compiler.Generate(1301)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range QuickScenarios() {
		run := RunScenario(context.Background(), p, scenario)
		if !run.Correct {
			t.Fatalf("scenario %s failed: %+v", scenario.Type, run)
		}
	}
}

func TestRuntimeAdversaryFailureScenarios(t *testing.T) {
	p, err := compiler.Generate(1302)
	if err != nil {
		t.Fatal(err)
	}
	for _, kind := range []string{ScenarioCapabilityDowngrade, ScenarioProfileMismatchSession} {
		run := RunScenario(context.Background(), p, DefaultScenario(kind))
		if !run.Correct || run.Failure == "" {
			t.Fatalf("expected controlled failure for %s: %+v", kind, run)
		}
	}
}

func TestRuntimeCollapseAndMutants(t *testing.T) {
	profiles, err := mutant.GenerateProfiles(mutant.ModeRuntimePaddingOnlyDiversity, 1303, 6)
	if err != nil {
		t.Fatal(err)
	}
	runs := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioHappyPathSession)})
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Conclusion == "passed" {
		t.Fatalf("expected padding-only runtime diversity to be suspicious: %+v", report)
	}
	replayRuns := RunMutantScenarioCorpus(context.Background(), mutant.ModeRuntimeAcceptsReplay, profiles[:2], []Scenario{DefaultScenario(ScenarioReplayInjection)})
	found := false
	for _, run := range replayRuns {
		if !run.Correct {
			found = true
		}
	}
	if !found {
		t.Fatal("expected replay mutant failure")
	}
}
