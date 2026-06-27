package framing

import (
	"bytes"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	p, _ := compiler.Generate(10)
	op := Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}
	frames, err := EncodeOperation(p, op, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := DecodeFrames(p, frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, op.Payload) || got.Semantic != op.Semantic {
		t.Fatal("round trip mismatch")
	}
}

func TestProfileAEncodingDiffersFromProfileB(t *testing.T) {
	a, _ := compiler.Generate(10)
	b, _ := compiler.Generate(11)
	op := Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}
	framesA, _ := EncodeOperation(a, op, 1)
	framesB, _ := EncodeOperation(b, op, 1)
	if bytes.Equal(framesA[0], framesB[0]) {
		t.Fatal("different profiles produced same frame")
	}
}

func TestProfileABytesFailUnderProfileB(t *testing.T) {
	a, _ := compiler.Generate(10)
	b, _ := compiler.Generate(11)
	op := Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}
	framesA, _ := EncodeOperation(a, op, 1)
	if _, err := DecodeFrame(b, framesA[0]); err == nil {
		t.Fatal("profile A frame decoded under profile B")
	}
}

func TestMalformedInputDoesNotPanic(t *testing.T) {
	p, _ := compiler.Generate(10)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decode panicked: %v", r)
		}
	}()
	if _, err := DecodeFrame(p, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected malformed input error")
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	p, _ := compiler.Generate(10)
	tooBig := bytes.Repeat([]byte{1}, p.Limits.MaxFrameBytes+100)
	if _, err := DecodeFrame(p, tooBig); err == nil {
		t.Fatal("expected oversized frame to fail")
	}
}

func TestFragmentedDataReconstructs(t *testing.T) {
	p, _ := compiler.Generate(12)
	p.FrameGrammar.FragmentationMode = "fixed_size_chunks"
	p.GenerationHash = ""
	payload := bytes.Repeat([]byte("a"), 20*1024)
	frames, err := EncodeOperation(p, Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: payload}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatal("expected fragmentation")
	}
	got, _, err := DecodeFrames(p, frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatal("fragmented payload mismatch")
	}
}
