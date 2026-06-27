package framing

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func FuzzDecodeFrame(f *testing.F) {
	p, err := compiler.Generate(700)
	if err != nil {
		f.Fatal(err)
	}
	frames, err := EncodeOperation(p, Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("seed")}, 1)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(frames[0])
	f.Add([]byte{0})
	f.Add(make([]byte, p.Limits.MaxFrameBytes+1))
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = DecodeFrame(p, data)
	})
}
