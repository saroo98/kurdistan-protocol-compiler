package framing

import (
	"bytes"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestMultiStreamSemanticRoundTrips(t *testing.T) {
	p, err := compiler.Generate(200)
	if err != nil {
		t.Fatal(err)
	}
	tests := []Operation{
		{Semantic: ir.SemanticOpenStream, StreamID: 7, Sequence: 1, Priority: "interactive"},
		{Semantic: ir.SemanticData, StreamID: 7, Sequence: 2, Offset: 9, Priority: "interactive", Payload: []byte("stream payload")},
		{Semantic: ir.SemanticClose, StreamID: 7, Sequence: 3, Reason: "done"},
		{Semantic: ir.SemanticResetStream, StreamID: 9, Sequence: 1, Reason: "test-reset"},
		{Semantic: ir.SemanticWindowUpdate, StreamID: 7, Sequence: 4, CreditBytes: 4096},
		{Semantic: ir.SemanticSessionClose, Sequence: 5, Reason: "session-done"},
	}
	for _, op := range tests {
		t.Run(op.Semantic, func(t *testing.T) {
			frames, err := EncodeOperation(p, op, 1)
			if err != nil {
				t.Fatal(err)
			}
			got, _, err := DecodeFrames(p, frames)
			if err != nil {
				t.Fatal(err)
			}
			if got.Semantic != op.Semantic || got.StreamID != op.StreamID || got.Sequence != op.Sequence ||
				got.Offset != op.Offset || got.CreditBytes != op.CreditBytes || got.Priority != op.Priority ||
				got.Reason != op.Reason || !bytes.Equal(got.Payload, op.Payload) {
				t.Fatalf("round trip mismatch:\n got: %+v\nwant: %+v", got, op)
			}
		})
	}
}

func TestStreamIDEncodingVariesAcrossProfiles(t *testing.T) {
	op := Operation{Semantic: ir.SemanticData, StreamID: 17, Payload: []byte("same")}
	seen := map[string]bool{}
	for seed := int64(1); seed <= 12; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := EncodeOperation(p, op, 1)
		if err != nil {
			t.Fatal(err)
		}
		seen[string(frames[0])] = true
	}
	if len(seen) < 8 {
		t.Fatalf("stream encoding/frame variation too low: %d unique frames", len(seen))
	}
}
