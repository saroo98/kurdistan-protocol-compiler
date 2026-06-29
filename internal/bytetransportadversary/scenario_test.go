// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransportadversary

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func TestByteTransportAdversaryQuick(t *testing.T) {
	ps := makeProfiles(t, 3)
	runs := RunScenarioCorpus(context.Background(), ps, QuickScenarios())
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Conclusion != "passed" {
		t.Fatalf("quick report failed: %+v", report)
	}
}

func TestByteTransportMutantsDetected(t *testing.T) {
	modes := []string{
		mutant.ModeByteTransportIgnoresBackpressure,
		mutant.ModeByteTransportReusesSequence,
		mutant.ModeByteTransportAcceptsCorruption,
		mutant.ModeByteTransportPayloadTraceLeak,
		mutant.ModeByteTransportPaddingOnlyDiversity,
	}
	ps := makeProfiles(t, 4)
	for _, mode := range modes {
		runs := RunMutantScenarioCorpus(context.Background(), mode, ps, FullScenarios())
		report := AnalyzeRuns(runs, DefaultCollapseThresholds())
		if report.Conclusion == "passed" {
			t.Fatalf("mutant %s was not detected", mode)
		}
	}
}

func makeProfiles(t *testing.T, n int) []*ir.Profile {
	t.Helper()
	out := make([]*ir.Profile, 0, n)
	for i := 0; i < n; i++ {
		p, err := compiler.Generate(int64(1 + i))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}

func BenchmarkByteTransportAdversaryQuick(b *testing.B) {
	ps := makeProfilesBench(b, 3)
	scenarios := QuickScenarios()
	for i := 0; i < b.N; i++ {
		runs := RunScenarioCorpus(context.Background(), ps, scenarios)
		_ = AnalyzeRuns(runs, DefaultCollapseThresholds())
	}
}

func makeProfilesBench(b *testing.B, n int) []*ir.Profile {
	b.Helper()
	out := make([]*ir.Profile, 0, n)
	for i := 0; i < n; i++ {
		p, err := compiler.Generate(int64(1 + i))
		if err != nil {
			b.Fatal(err)
		}
		out = append(out, p)
	}
	return out
}
