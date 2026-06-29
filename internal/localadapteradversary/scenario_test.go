// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapteradversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func TestLocalAdapterAdversaryQuick(t *testing.T) {
	p1, err := compiler.Generate(31)
	if err != nil {
		t.Fatal(err)
	}
	p2, err := compiler.Generate(32)
	if err != nil {
		t.Fatal(err)
	}
	runs := RunScenarioCorpus(context.Background(), []*ir.Profile{p1, p2}, QuickScenarios())
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("quick failed: %+v", report)
	}
}

func TestLocalAdapterMutantsDetected(t *testing.T) {
	modes := []string{
		mutant.ModeLocalAdapterIgnoresSourceBackpressure,
		mutant.ModeLocalAdapterAcceptsPostCloseWrite,
		mutant.ModeLocalAdapterDropsFinalChunk,
		mutant.ModeLocalAdapterDuplicatesChunk,
		mutant.ModeLocalAdapterWrongFlowStreamMapping,
		mutant.ModeLocalAdapterPayloadTraceLeak,
		mutant.ModeLocalAdapterSecretTraceLeak,
		mutant.ModeLocalAdapterPaddingOnlyDiversity,
	}
	for _, mode := range modes {
		profiles, err := mutant.GenerateProfiles(mode, 41, 4)
		if err != nil {
			t.Fatal(err)
		}
		runs := RunMutantScenarioCorpus(context.Background(), mode, profiles, []Scenario{DefaultScenario(ScenarioLargeBackpressure)})
		report := AnalyzeRuns(runs, DefaultCollapseThresholds())
		if report.Conclusion == "passed" {
			t.Fatalf("%s not detected", mode)
		}
	}
}

func BenchmarkLocalAdapterAdversaryQuick(b *testing.B) {
	p, err := compiler.Generate(33)
	if err != nil {
		b.Fatal(err)
	}
	profiles := []*ir.Profile{p}
	scenarios := QuickScenarios()
	for i := 0; i < b.N; i++ {
		_ = AnalyzeRuns(RunScenarioCorpus(context.Background(), profiles, scenarios), DefaultCollapseThresholds())
	}
}
