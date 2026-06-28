// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrieradversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/mutant"
)

func TestCarrierAdversaryScenarios(t *testing.T) {
	p, err := compiler.Generate(11021)
	if err != nil {
		t.Fatal(err)
	}
	for _, scenario := range QuickScenarios() {
		t.Run(scenario.Type, func(t *testing.T) {
			run, err := RunScenario(context.Background(), p, scenario)
			if err != nil {
				t.Fatal(err)
			}
			if !run.Correct {
				t.Fatalf("scenario failed checks: %+v", run.Checks)
			}
			if len(run.Events) == 0 {
				t.Fatalf("scenario emitted no carrier trace metadata")
			}
		})
	}
}

func TestCarrierCollapseDetectsFixedMutants(t *testing.T) {
	modes := []string{
		mutant.ModeFixedCarrierFamily,
		mutant.ModeFixedEnvelopeEncoding,
		mutant.ModeFixedFlushPolicy,
		mutant.ModeFixedBatchPolicy,
		mutant.ModeFixedChunkingPolicy,
		mutant.ModePaddingOnlyCarrierDiversity,
	}
	for _, mode := range modes {
		t.Run(mode, func(t *testing.T) {
			profiles, err := mutant.GenerateProfiles(mode, 11100, 6)
			if err != nil {
				t.Fatal(err)
			}
			runs, err := RunMutantScenarioCorpus(context.Background(), mode, profiles, []Scenario{DefaultScenario(ScenarioMixedCarrierMatrix)})
			if err != nil {
				t.Fatal(err)
			}
			report := AnalyzeRuns(runs, DefaultCollapseThresholds())
			if report.Conclusion == "passed" {
				t.Fatalf("mutant not detected: %+v", report)
			}
		})
	}
}
