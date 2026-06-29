// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"context"
	"testing"

	"kurdistan/internal/adapter"
	"kurdistan/internal/compiler"
)

func TestSourcePlanDeterminism(t *testing.T) {
	cfg := DefaultConfig("local-test")
	a, err := GenerateSourcePlan(SourceSmallBurst, 3, cfg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateSourcePlan(SourceSmallBurst, 3, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.Chunks) != len(b.Chunks) || a.Chunks[0].ByteCount != b.Chunks[0].ByteCount {
		t.Fatalf("source plan not deterministic")
	}
	cfg.DeterministicSeed++
	c, err := GenerateSourcePlan(SourceSmallBurst, 3, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if c.Chunks[0].ByteCount == a.Chunks[0].ByteCount {
		t.Fatalf("seed did not affect safe source plan")
	}
}

func TestSinkSequenceValidation(t *testing.T) {
	sink, err := NewSink(DefaultConfig("local-sink"))
	if err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(LocalSinkChunk{FlowID: "f1", Sequence: 1, ByteCount: 10}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(LocalSinkChunk{FlowID: "f1", Sequence: 1, ByteCount: 10}); err != ErrInvalidSequence {
		t.Fatalf("expected invalid sequence, got %v", err)
	}
	if err := sink.Write(LocalSinkChunk{FlowID: "f2", Sequence: 1, ByteCount: 10, Final: true}); err != nil {
		t.Fatal(err)
	}
	if err := sink.Write(LocalSinkChunk{FlowID: "f2", Sequence: 2, ByteCount: 10}); err != ErrClosedSink {
		t.Fatalf("expected closed sink, got %v", err)
	}
}

func TestMemoryPipeScenario(t *testing.T) {
	p, err := compiler.Generate(16)
	if err != nil {
		t.Fatal(err)
	}
	res, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioManySmallFlows), DefaultConfig("local-run"))
	if err != nil {
		t.Fatal(err)
	}
	if !res.Summary.Completed || res.Summary.PayloadLogged || res.Summary.SecretLogged {
		t.Fatalf("bad summary: %+v", res.Summary)
	}
	if res.Summary.RuntimeStreamsOpened == 0 || res.Summary.SinkChunks == 0 {
		t.Fatalf("runtime/sink not exercised: %+v", res.Summary)
	}
}

func TestMalformedSourceRejected(t *testing.T) {
	p, err := compiler.Generate(17)
	if err != nil {
		t.Fatal(err)
	}
	_, err = RunScenario(context.Background(), p, DefaultScenario(ScenarioMalformedSource), DefaultConfig("local-bad"))
	if err == nil {
		t.Fatalf("malformed source accepted")
	}
}

func FuzzValidateSourceChunk(f *testing.F) {
	cfg := DefaultConfig("local-fuzz")
	f.Add("flow-1", uint64(1), 10)
	f.Fuzz(func(t *testing.T, flow string, seq uint64, n int) {
		if n > MaxLocalChunkBytes*2 {
			n = MaxLocalChunkBytes * 2
		}
		_ = ValidateSourceChunk(LocalSourceChunk{FlowID: adapter.FlowID(flow), Sequence: seq, ByteCount: n}, cfg)
	})
}

func BenchmarkRunLocalAdapterScenario(b *testing.B) {
	p, err := compiler.Generate(18)
	if err != nil {
		b.Fatal(err)
	}
	cfg := DefaultConfig("local-bench")
	scenario := DefaultScenario(ScenarioManySmallFlows)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := RunScenario(context.Background(), p, scenario, cfg); err != nil {
			b.Fatal(err)
		}
	}
}
