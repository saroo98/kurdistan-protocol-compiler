// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"context"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/testkit/mutant"
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

func TestFaultFamilyRecurrenceV1(t *testing.T) {
	results, err := RunRealMutantCorpusV1(22016)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		mutant.ModeNoTranscriptBinding:        "transcript",
		mutant.ModeAcceptsReplay:              "security_replay",
		mutant.ModeRuntimeIgnoresBackpressure: "backpressure",
	}
	seen := map[string]bool{}
	for _, result := range results {
		category, ok := want[result.Mode]
		if !ok {
			continue
		}
		if result.Category != category || !result.UnsafeObserved || !result.DetectorRed || !result.ControlGreen || result.Count == 0 {
			t.Fatalf("representative recurrence %s=%+v", result.Mode, result)
		}
		seen[result.Mode] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("representative fault families seen=%v want=%v", seen, want)
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

func TestRuntimeCollapse(t *testing.T) {
	profiles, err := mutant.GenerateProfiles(mutant.ModeRuntimePaddingOnlyDiversity, 1303, 6)
	if err != nil {
		t.Fatal(err)
	}
	runs := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioHappyPathSession)})
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Conclusion == "passed" {
		t.Fatalf("expected padding-only runtime diversity to be suspicious: %+v", report)
	}
}
