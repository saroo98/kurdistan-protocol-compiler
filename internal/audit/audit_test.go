package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"kurdistan/internal/adversary"
	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/labtrace"
	ktrace "kurdistan/internal/trace"
)

func TestAuditConfigDefaults(t *testing.T) {
	quick := DefaultConfig("quick")
	if quick.ProfileCount != 100 || quick.TraceCount != 20 {
		t.Fatalf("quick defaults = %+v", quick)
	}
	full := DefaultConfig("full")
	if full.ProfileCount != 1000 || full.TraceCount != 100 {
		t.Fatalf("full defaults = %+v", full)
	}
}

func TestProfileCorpusDiversityGatePassFail(t *testing.T) {
	profiles, err := diversity.GenerateProfiles(1, 40)
	if err != nil {
		t.Fatal(err)
	}
	passSummary := diversity.SummarizeCorpus(1, profiles)
	thresholds := DefaultThresholds()
	thresholds.MinInvalidInputCombinations = 3
	if gate := ProfileCorpusDiversityGate(passSummary, thresholds); !gate.Passed {
		t.Fatalf("expected pass: %+v", gate)
	}

	failSummary := diversity.SummarizeCorpus(1, syntheticFixedSignatureProfiles(10))
	if gate := ProfileCorpusDiversityGate(failSummary, thresholds); gate.Passed {
		t.Fatalf("expected fixed corpus to fail: %+v", gate)
	}
}

func TestBlackBoxTraceDiversityGatePassFail(t *testing.T) {
	passScan := ktrace.ScanTraces([][]ktrace.Event{
		{{EventType: "first_contact", State: "a", FrameBytes: 10}, {EventType: "frame", FrameBytes: 20, PaddingBytes: 0}},
		{{EventType: "first_contact", State: "a"}, {EventType: "first_contact", State: "b", FrameBytes: 12}, {EventType: "frame", FrameBytes: 25, PaddingBytes: 3}},
		{{EventType: "first_contact", State: "x", FrameBytes: 30}, {EventType: "frame", FrameBytes: 40, PaddingBytes: 8}},
	}, 0.8)
	if gate := BlackBoxTraceDiversityGate(passScan, DefaultThresholds()); !gate.Passed {
		t.Fatalf("expected trace diversity pass: %+v", gate)
	}

	failScan := ktrace.ScanTraces(syntheticFixedSignatureTraces(5), 0.8)
	if gate := BlackBoxTraceDiversityGate(failScan, DefaultThresholds()); gate.Passed {
		t.Fatalf("expected stable traces to fail: %+v", gate)
	}
}

func TestFixedSignatureSyntheticCorpusFails(t *testing.T) {
	gate := FixedSignatureGate(syntheticFixedSignatureProfiles(8), syntheticFixedSignatureTraces(8), DefaultThresholds())
	if gate.Passed {
		t.Fatalf("expected fixed-signature gate to fail: %+v", gate)
	}
}

func TestCosmeticDifferenceGatePasses(t *testing.T) {
	if gate := CosmeticDifferenceGate(); !gate.Passed {
		t.Fatalf("expected cosmetic gate pass: %+v", gate)
	}
}

func TestSameProfileConsistencyGatePasses(t *testing.T) {
	if gate := SameProfileConsistencyGate(context.Background()); !gate.Passed {
		t.Fatalf("expected same-profile gate pass: %+v", gate)
	}
}

func TestDifferentProfileSeparationGatePasses(t *testing.T) {
	var traces [][]ktrace.Event
	for seed := int64(80); seed < 86; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		events, err := labtrace.CaptureTrace(context.Background(), p, []byte("hello kurdistan"))
		if err != nil {
			t.Fatal(err)
		}
		traces = append(traces, events)
	}
	thresholds := DefaultThresholds()
	thresholds.MinDifferentTraceSeparationRatio = 0.5
	if gate := DifferentProfileSeparationGate(traces, thresholds); !gate.Passed {
		t.Fatalf("expected separation pass: %+v", gate)
	}
}

func TestMalformedProbeBehaviorGatePassFail(t *testing.T) {
	profiles, err := diversity.GenerateProfiles(1, 40)
	if err != nil {
		t.Fatal(err)
	}
	thresholds := DefaultThresholds()
	if gate := MalformedProbeBehaviorGate(profiles, thresholds); !gate.Passed {
		t.Fatalf("expected malformed/probe pass: %+v", gate)
	}
	if gate := MalformedProbeBehaviorGate(syntheticFixedSignatureProfiles(10), thresholds); gate.Passed {
		t.Fatalf("expected malformed/probe fail: %+v", gate)
	}
}

func TestFuzzPresenceGatePasses(t *testing.T) {
	if gate := FuzzPresenceGate(); !gate.Passed {
		t.Fatalf("expected fuzz presence pass: %+v", gate)
	}
}

func TestAdversarialBlackBoxClusteringGatePassFail(t *testing.T) {
	profiles, err := diversity.GenerateProfiles(1, 16)
	if err != nil {
		t.Fatal(err)
	}
	traces, err := captureTraces(context.Background(), profiles, 8)
	if err != nil {
		t.Fatal(err)
	}
	thresholds := DefaultThresholds()
	thresholds.MinDifferentProfileDistance = 0.05
	if gate := AdversarialBlackBoxClusteringGate(context.Background(), profiles, traces, thresholds); !gate.Passed {
		t.Fatalf("expected adversarial gate pass: %+v", gate)
	}

	if gate := AdversarialBlackBoxClusteringGate(context.Background(), syntheticFixedSignatureProfiles(8), adversary.FixedProtocolTraces(8), thresholds); gate.Passed {
		t.Fatalf("expected fixed synthetic corpus to fail: %+v", gate)
	}
	if gate := AdversarialBlackBoxClusteringGate(context.Background(), syntheticFixedSignatureProfiles(8), adversary.NoisyFixedProtocolTraces(8, 1), thresholds); gate.Passed {
		t.Fatalf("expected noisy-fixed synthetic corpus to fail: %+v", gate)
	}
}

func TestAuditReportJSONSerialization(t *testing.T) {
	report := AuditReport{
		Version:      Version,
		Mode:         "quick",
		GeneratedAt:  "2026-06-27T00:00:00Z",
		ProfileCount: 1,
		TraceCount:   1,
		Gates:        []GateResult{{Name: "example", Passed: true, Severity: "required", Summary: "ok"}, {Name: "adversarial_black_box_clustering", Passed: true, Severity: "required", Summary: "ok"}},
		Conclusion:   "passed",
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded AuditReport
	if err := json.Unmarshal(raw, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Gates[0].Name != "example" {
		t.Fatalf("decoded report mismatch: %+v", decoded)
	}
}

func TestStatusRendering(t *testing.T) {
	report := AuditReport{
		Version:          Version,
		Mode:             "quick",
		GeneratedAt:      "2026-06-27T00:00:00Z",
		ProfileCount:     10,
		TraceCount:       5,
		Gates:            []GateResult{{Name: "profile_corpus_diversity", Passed: true, Severity: "required", Summary: "ok"}, {Name: "adversarial_black_box_clustering", Passed: true, Severity: "required", Summary: "ok"}},
		CorpusSummary:    map[string]any{"number_of_profiles": 10, "unique_first_contact_patterns": 4},
		BenchmarkSummary: BenchmarkSummary{TotalMillis: 12},
		Conclusion:       "passed",
	}
	status := RenderStatus(report)
	for _, want := range []string{"Kurdistan Protocol Compiler Status", "Lab-only", "profile_corpus_diversity", "adversarial_black_box_clustering", "Next Milestone"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status missing %q:\n%s", want, status)
		}
	}
}

func TestQuickAuditRunsLocalOnly(t *testing.T) {
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
	if !report.Passed() {
		t.Fatalf("quick audit did not pass: %+v", report.Gates)
	}
	if !containsGate(report.Gates, "adversarial_black_box_clustering") {
		t.Fatalf("audit report missing adversarial gate: %v", sortGateNames(report.Gates))
	}
}

func containsGate(gates []GateResult, name string) bool {
	for _, gate := range gates {
		if gate.Name == name {
			return true
		}
	}
	return false
}
