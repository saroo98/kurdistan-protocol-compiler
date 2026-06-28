package framing

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func BenchmarkStreamDataEncodeDecode(b *testing.B) {
	p, err := compiler.Generate(900)
	if err != nil {
		b.Fatal(err)
	}
	op := Operation{Semantic: ir.SemanticData, StreamID: 17, Sequence: 3, Offset: 128, Priority: "interactive", Payload: []byte("benchmark stream payload")}
	for i := 0; i < b.N; i++ {
		frames, err := EncodeOperation(p, op, int64(i))
		if err != nil {
			b.Fatal(err)
		}
		if _, _, err := DecodeFrames(p, frames); err != nil {
			b.Fatal(err)
		}
	}
}
