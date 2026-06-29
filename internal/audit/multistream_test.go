package audit

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/relay"
)

func TestMultiStreamGatesPassAndFail(t *testing.T) {
	profiles := mustAuditProfiles(t, 1, 12)
	gates := []GateResult{
		MultiStreamSemanticsGate(context.Background(), profiles, DefaultThresholds()),
		MultiStreamDiversityGate(profiles, DefaultThresholds()),
		MultiStreamBackpressureGate(context.Background(), profiles[:2], DefaultThresholds()),
	}
	for _, gate := range gates {
		if !gate.Passed {
			t.Fatalf("expected %s to pass: %+v", gate.Name, gate)
		}
	}
	fixed := mustAuditProfiles(t, 10, 6)
	for _, p := range fixed {
		p.GenerationHash = ""
		p.Stream.IDEncodingMode = fixed[0].Stream.IDEncodingMode
		p.Stream.PriorityPolicy = fixed[0].Stream.PriorityPolicy
		p.Stream.WindowUpdatePolicy = fixed[0].Stream.WindowUpdatePolicy
		p.Stream.ClosePolicy = fixed[0].Stream.ClosePolicy
		p.Stream.ResetPolicy = fixed[0].Stream.ResetPolicy
		p.Stream.MaxConcurrentStreams = fixed[0].Stream.MaxConcurrentStreams
	}
	if gate := MultiStreamDiversityGate(fixed, DefaultThresholds()); gate.Passed {
		t.Fatalf("expected fixed stream policies to fail diversity gate: %+v", gate)
	}
}

func TestQuickAuditIncludesMultiStreamGates(t *testing.T) {
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
	for _, name := range []string{"multi_stream_semantics", "multi_stream_diversity", "multi_stream_backpressure"} {
		if !containsGate(report.Gates, name) {
			t.Fatalf("missing gate %q: %v", name, sortGateNames(report.Gates))
		}
	}
}

func BenchmarkMultiStreamEchoFourStreams(b *testing.B) {
	p, err := compiler.Generate(80)
	if err != nil {
		b.Fatal(err)
	}
	p.GenerationHash = ""
	p.Stream.MaxConcurrentStreams = 4
	if p.Compatibility.MaxStreamCount < p.Stream.MaxConcurrentStreams {
		p.Compatibility.MaxStreamCount = p.Stream.MaxConcurrentStreams
	}
	requests := relay.DefaultMultiStreamDemoRequests(4)
	for i := 0; i < b.N; i++ {
		if _, _, err := relay.SimulateMultiStreamEcho(context.Background(), p, requests); err != nil {
			b.Fatal(err)
		}
	}
}

func mustAuditProfiles(t testing.TB, start int64, count int) []*ir.Profile {
	t.Helper()
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		p, err := compiler.Generate(start + int64(i))
		if err != nil {
			t.Fatal(err)
		}
		profiles = append(profiles, p)
	}
	return profiles
}
