package bench

import (
	"bytes"
	"context"
	"net"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/padding"
	"kurdistan/internal/relay"
	"kurdistan/internal/scheduler"
)

func BenchmarkProfileGeneration(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := compiler.Generate(int64(i + 1)); err != nil {
			b.Fatal(err)
		}
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
