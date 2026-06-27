package bench

import (
	"bytes"
	"context"
	"net"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/diversity"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/padding"
	"kurdistan/internal/relay"
	"kurdistan/internal/scheduler"
	ktrace "kurdistan/internal/trace"
)

func BenchmarkProfileGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := compiler.Generate(int64(i + 1)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCorpusGeneration1000(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := diversity.GenerateProfiles(int64(i*1000+1), 1000); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDiversityAnalysis100(b *testing.B) {
	profiles, err := diversity.GenerateProfiles(1, 100)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = diversity.AnalyzeProfiles(profiles)
	}
}

func BenchmarkPairwiseProfileCompare(b *testing.B) {
	a, _ := compiler.Generate(1)
	c, _ := compiler.Generate(2)
	for i := 0; i < b.N; i++ {
		_ = diversity.CompareProfileStructure(a, c)
	}
}

func BenchmarkTraceScan100(b *testing.B) {
	traces := make([][]ktrace.Event, 0, 100)
	for i := 0; i < 100; i++ {
		traces = append(traces, []ktrace.Event{
			{ProfileID: "kp", EventType: "first_contact", State: "s0", FrameBytes: 20 + i%7},
			{ProfileID: "kp", EventType: "first_contact", State: "s1", FrameBytes: 30 + i%11},
			{ProfileID: "kp", EventType: "frame", Semantic: "data", FrameBytes: 50 + i%13, PaddingBytes: i % 5, SchedulerMode: "balanced"},
		})
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold)
	}
}

func BenchmarkFrameEncodeDecode(b *testing.B) {
	p, _ := compiler.Generate(1)
	op := framing.Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: bytes.Repeat([]byte("a"), 1024)}
	b.SetBytes(int64(len(op.Payload)))
	for i := 0; i < b.N; i++ {
		frames, err := framing.EncodeOperation(p, op, int64(i))
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := framing.DecodeFrames(p, frames); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSchedulerOverhead(b *testing.B) {
	p, _ := compiler.Generate(1)
	items := []scheduler.Item{{PayloadBytes: 100, Interactive: true}, {PayloadBytes: 4096}, {PayloadBytes: 1024}}
	for i := 0; i < b.N; i++ {
		_ = scheduler.Plan(p.Scheduler, items)
	}
}

func BenchmarkPaddingOverhead(b *testing.B) {
	p, _ := compiler.Generate(1)
	engine := padding.New(p.Padding, 1)
	for i := 0; i < b.N; i++ {
		if _, err := engine.Generate(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkOneKiBRoundTrip(b *testing.B) {
	benchmarkRoundTrip(b, 1024)
}

func BenchmarkOneMiBRoundTrip(b *testing.B) {
	benchmarkRoundTrip(b, 1024*1024)
}

func benchmarkRoundTrip(b *testing.B, size int) {
	echoAddr, stopEcho := benchEcho(b)
	defer stopEcho()
	p, _ := compiler.Generate(300 + int64(size))
	serverAddr, stopServer := benchServer(b, p, echoAddr)
	defer stopServer()
	payload := bytes.Repeat([]byte("x"), size)
	b.SetBytes(int64(size))
	for i := 0; i < b.N; i++ {
		got, err := relay.ClientRoundTrip(context.Background(), p, serverAddr, payload, nil)
		if err != nil {
			b.Fatal(err)
		}
		if len(got) != len(payload) {
			b.Fatal("round trip length mismatch")
		}
	}
}

func benchEcho(b *testing.B) (string, context.CancelFunc) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = relay.ServeEcho(ctx, ln, nil) }()
	return ln.Addr().String(), cancel
}

func benchServer(b *testing.B, p *ir.Profile, target string) (string, context.CancelFunc) {
	b.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatal(err)
	}
	go func() { _ = relay.Serve(ctx, ln, target, p, nil, nil) }()
	return ln.Addr().String(), cancel
}
