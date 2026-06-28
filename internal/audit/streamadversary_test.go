package audit

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func TestStreamAdversaryGatesPassAndDetectMutants(t *testing.T) {
	profiles := make([]*ir.Profile, 0, 8)
	for seed := int64(1300); seed < 1308; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	thresholds := DefaultThresholds()
	for _, gate := range []GateResult{
		MultiStreamAdversarialScenariosGate(context.Background(), profiles, thresholds),
		MultiStreamCollapseResistanceGate(context.Background(), profiles, thresholds),
		MultiStreamMutantDetectionGate(context.Background(), thresholds),
	} {
		if !gate.Passed {
			t.Fatalf("expected %s to pass: %+v", gate.Name, gate)
		}
	}
	fixed, err := mutant.GenerateProfiles(mutant.ModePaddingOnlyStreamDiversity, 1400, 6)
	if err != nil {
		t.Fatal(err)
	}
	if gate := MultiStreamCollapseResistanceGate(context.Background(), fixed, thresholds); gate.Passed {
		t.Fatalf("expected padding-only stream mutant to fail collapse resistance: %+v", gate)
	}
}

func TestQuickAuditIncludesStreamAdversaryGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 30
	cfg.TraceCount = 6
	cfg.Thresholds.MinInvalidInputCombinations = 3
	cfg.Thresholds.MinFrameGrammarCombinations = 3
	cfg.Thresholds.MinSchedulerCombinations = 3
	cfg.Thresholds.MinPaddingCombinations = 2
	cfg.Thresholds.MinDifferentTraceSeparationRatio = 0.4
	cfg.Thresholds.MinDifferentProfileDistance = 0.04
	report, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"multi_stream_adversarial_scenarios", "multi_stream_collapse_resistance", "multi_stream_mutant_detection"} {
		if !containsGate(report.Gates, name) {
			t.Fatalf("missing stream adversary gate %q: %v", name, sortGateNames(report.Gates))
		}
	}
}

func BenchmarkStreamAdversaryQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 12
	cfg.TraceCount = 4
	for i := 0; i < b.N; i++ {
		report, err := RunStreamAdversaryAudit(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatalf("stream adversary quick audit failed: %+v", report.Gates)
		}
	}
}
