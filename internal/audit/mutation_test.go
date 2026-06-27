package audit

import (
	"context"
	"sort"
	"testing"

	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	ktrace "kurdistan/internal/trace"
)

func TestMutantsFailExpectedGates(t *testing.T) {
	thresholds := DefaultThresholds()
	thresholds.MinFirstContactPatterns = 2
	thresholds.MinFrameGrammarCombinations = 2
	thresholds.MinSchedulerCombinations = 2
	thresholds.MinPaddingCombinations = 2
	thresholds.MinInvalidInputCombinations = 2

	tests := []struct {
		name      string
		mode      string
		assertion func(t *testing.T, profiles int, gates map[string]GateResult)
	}{
		{
			name: "fixed_first_contact",
			mode: mutant.ModeFixedFirstContact,
			assertion: func(t *testing.T, _ int, gates map[string]GateResult) {
				requireGateFail(t, gates, "black_box_trace_diversity")
				requireGateFail(t, gates, "fixed_signature")
				requireGateFail(t, gates, "adversarial_black_box_clustering")
			},
		},
		{
			name: "fixed_frame_grammar",
			mode: mutant.ModeFixedFrameGrammar,
			assertion: func(t *testing.T, _ int, gates map[string]GateResult) {
				requireGateFail(t, gates, "profile_corpus_diversity")
			},
		},
		{
			name: "cosmetic_symbols_only",
			mode: mutant.ModeCosmeticSymbolsOnly,
			assertion: func(t *testing.T, _ int, gates map[string]GateResult) {
				requireGateFail(t, gates, "profile_corpus_diversity")
			},
		},
		{
			name: "fixed_scheduler",
			mode: mutant.ModeFixedScheduler,
			assertion: func(t *testing.T, _ int, gates map[string]GateResult) {
				requireGateFail(t, gates, "profile_corpus_diversity")
			},
		},
		{
			name: "fixed_invalid_input",
			mode: mutant.ModeFixedInvalidInput,
			assertion: func(t *testing.T, _ int, gates map[string]GateResult) {
				requireGateFail(t, gates, "profile_corpus_diversity")
				requireGateFail(t, gates, "malformed_probe_behavior")
			},
		},
		{
			name: "padding_noise_only",
			mode: mutant.ModePaddingNoiseOnly,
			assertion: func(t *testing.T, _ int, gates map[string]GateResult) {
				requireGateFail(t, gates, "adversarial_black_box_clustering")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			profiles, err := mutant.GenerateProfiles(tt.mode, 1, 10)
			if err != nil {
				t.Fatal(err)
			}
			traces := mutant.TraceFixtures(tt.mode, profiles)
			gates := evaluateMutationGates(context.Background(), profiles, traces, thresholds)
			tt.assertion(t, len(profiles), gates)
		})
	}
}

func TestNormalGeneratorStillPassesMutationThresholds(t *testing.T) {
	profiles, err := diversity.GenerateProfiles(1, 30)
	if err != nil {
		t.Fatal(err)
	}
	traces, err := captureTraces(context.Background(), profiles, 8)
	if err != nil {
		t.Fatal(err)
	}
	thresholds := DefaultThresholds()
	thresholds.MinInvalidInputCombinations = 3
	thresholds.MinFrameGrammarCombinations = 3
	thresholds.MinSchedulerCombinations = 3
	thresholds.MinPaddingCombinations = 2
	thresholds.MinDifferentTraceSeparationRatio = 0.4
	thresholds.MinDifferentProfileDistance = 0.04
	gates := evaluateMutationGates(context.Background(), profiles, traces, thresholds)
	for name, gate := range gates {
		if !gate.Passed {
			t.Fatalf("normal generator gate %s failed: %+v", name, gate)
		}
	}
}

func evaluateMutationGates(ctx context.Context, profiles []*ir.Profile, traces [][]ktrace.Event, thresholds AuditThresholds) map[string]GateResult {
	summary := diversity.SummarizeCorpus(1, profiles)
	scan := ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold)
	results := []GateResult{
		ProfileCorpusDiversityGate(summary, thresholds),
		BlackBoxTraceDiversityGate(scan, thresholds),
		AdversarialBlackBoxClusteringGate(ctx, profiles, traces, thresholds),
		FixedSignatureGate(profiles, traces, thresholds),
		MalformedProbeBehaviorGate(profiles, thresholds),
	}
	out := map[string]GateResult{}
	for _, result := range results {
		out[result.Name] = result
	}
	return out
}

func requireGateFail(t *testing.T, gates map[string]GateResult, name string) {
	t.Helper()
	gate, ok := gates[name]
	if !ok {
		t.Fatalf("gate %s missing from %v", name, sortGateNamesFromMap(gates))
	}
	if gate.Passed {
		t.Fatalf("expected gate %s to fail, got pass: %+v", name, gate)
	}
}

func sortGateNamesFromMap(gates map[string]GateResult) []string {
	names := make([]string, 0, len(gates))
	for name := range gates {
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}
