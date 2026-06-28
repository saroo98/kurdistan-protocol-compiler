package relay

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
)

func BenchmarkSimulateMultiStreamEchoFour(b *testing.B) {
	p, err := compiler.Generate(901)
	if err != nil {
		b.Fatal(err)
	}
	p.GenerationHash = ""
	p.Stream.MaxConcurrentStreams = 4
	p.Stream.InitialSessionWindowBytes = p.Stream.InitialStreamWindowBytes * 4
	requests := DefaultMultiStreamDemoRequests(4)
	for i := 0; i < b.N; i++ {
		if _, _, err := SimulateMultiStreamEcho(context.Background(), p, requests); err != nil {
			b.Fatal(err)
		}
	}
}
