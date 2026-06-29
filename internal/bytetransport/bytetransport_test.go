// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import (
	"context"
	"strings"
	"testing"

	"kurdistan/internal/compiler"
)

func TestEncodeDecodeFrameKinds(t *testing.T) {
	cfg := DefaultConfig("test-byte")
	kinds := []ByteFrameKind{FrameData, FrameControl, FrameAck, FrameClose, FrameReset, FrameBackpressure}
	for i, kind := range kinds {
		frame := ByteFrame{SessionID: "s", StreamID: 1, Sequence: uint64(i + 1), Kind: kind, ByteCount: 32, FragmentCount: 1, MetadataClass: "test"}
		if kind == FrameReset {
			frame.Reset = true
		}
		encoded, err := EncodeFrame(cfg, frame)
		if err != nil {
			t.Fatalf("encode %s: %v", kind, err)
		}
		decoded, err := DecodeFrameBytes(cfg, encoded.Bytes)
		if err != nil {
			t.Fatalf("decode %s: %v", kind, err)
		}
		if decoded.Frame.Kind != kind || decoded.Frame.Sequence != frame.Sequence || decoded.Frame.ByteCount != frame.ByteCount {
			t.Fatalf("decoded mismatch: %+v", decoded.Frame)
		}
	}
}

func TestMalformedFramesRejected(t *testing.T) {
	cfg := DefaultConfig("malformed-byte")
	if _, err := DecodeFrameBytes(cfg, []byte{1, 2, 3}); err == nil {
		t.Fatal("truncated frame accepted")
	}
	frame := ByteFrame{SessionID: "s", StreamID: 1, Sequence: 1, Kind: FrameData, ByteCount: 16, FragmentCount: 1}
	encoded, err := EncodeFrame(cfg, frame)
	if err != nil {
		t.Fatal(err)
	}
	encoded.Bytes[1] = 99
	_, err = DecodeFrameBytes(cfg, encoded.Bytes)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("corrupt kind/checksum not rejected safely: %v", err)
	}
	if _, err := EncodeFrame(cfg, ByteFrame{SessionID: "s", StreamID: 1, Sequence: 2, Kind: "unknown", ByteCount: 1}); err == nil {
		t.Fatal("unknown kind accepted")
	}
	if _, err := EncodeFrame(cfg, ByteFrame{SessionID: "s", StreamID: 1, Sequence: 3, Kind: FrameData, ByteCount: cfg.MaxPayloadBytes + 1}); err == nil {
		t.Fatal("oversized payload accepted")
	}
}

func TestFragmentationReassembly(t *testing.T) {
	cfg := DefaultConfig("fragment-byte")
	cfg.MaxPayloadBytes = 1024
	frame := ByteFrame{SessionID: "s", StreamID: 1, Sequence: 1, Kind: FrameData, ByteCount: 2048, Final: true}
	parts, err := FragmentFrame(cfg, frame, FragmentFixed)
	if err != nil {
		t.Fatal(err)
	}
	if len(parts) < 2 {
		t.Fatalf("expected fragments, got %d", len(parts))
	}
	r, err := NewReassembler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var result DecodeResult
	for _, part := range parts {
		result, err = r.Add(part)
		if err != nil {
			t.Fatal(err)
		}
	}
	if !result.Complete || !result.Reassembled || result.Frame.ByteCount != 2048 {
		t.Fatalf("bad reassembly: %+v", result)
	}
	if _, err := r.Add(parts[0]); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Add(parts[0]); err == nil {
		t.Fatal("duplicate fragment accepted")
	}
	cfg.AllowOutOfOrder = true
	r, err = NewReassembler(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for i := len(parts) - 1; i >= 0; i-- {
		result, err = r.Add(parts[i])
		if err != nil {
			t.Fatal(err)
		}
	}
	if !result.Reassembled {
		t.Fatal("out-of-order fragments did not reassemble")
	}
}

func TestBytePipeAndSequence(t *testing.T) {
	cfg := DefaultConfig("pipe-byte")
	cfg.MaxPipeQueueDepth = 1
	pipe, err := NewBytePipe(cfg)
	if err != nil {
		t.Fatal(err)
	}
	frame := ByteFrame{SessionID: "s", StreamID: 1, Sequence: 1, Kind: FrameData, ByteCount: 32}
	encoded, err := EncodeFrame(cfg, frame)
	if err != nil {
		t.Fatal(err)
	}
	if err := pipe.Write(encoded); err != nil {
		t.Fatal(err)
	}
	if err := pipe.Write(encoded); err != ErrBackpressure {
		t.Fatalf("expected backpressure, got %v", err)
	}
	read, err := pipe.Read()
	if err != nil || read.Sequence != encoded.Sequence {
		t.Fatalf("read mismatch: %v", err)
	}
	validator := NewSequenceValidator(2)
	if err := validator.Accept(frame); err != nil {
		t.Fatal(err)
	}
	if err := validator.Accept(frame); err == nil {
		t.Fatal("duplicate sequence accepted")
	}
	if err := validator.Accept(ByteFrame{SessionID: "s", StreamID: 1, Sequence: 10, Kind: FrameData}); err == nil {
		t.Fatal("too-far future sequence accepted")
	}
}

func TestRunScenarioAndTraceHygiene(t *testing.T) {
	p, err := compiler.Generate(16)
	if err != nil {
		t.Fatal(err)
	}
	result, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioLargeFragmented), DefaultConfig("scenario-byte"))
	if err != nil {
		t.Fatal(err)
	}
	if !result.Summary.Completed || result.Summary.PayloadLogged || result.Summary.SecretLogged {
		t.Fatalf("bad summary: %+v", result.Summary)
	}
	for _, ev := range result.Events {
		if ev.PayloadHygiene == false || ev.SecretHygiene == false {
			t.Fatalf("bad hygiene event: %+v", ev)
		}
	}
}

func FuzzDecodeFrameBytes(f *testing.F) {
	cfg := DefaultConfig("fuzz-byte")
	encoded, _ := EncodeFrame(cfg, ByteFrame{SessionID: "s", StreamID: 1, Sequence: 1, Kind: FrameData, ByteCount: 8})
	f.Add(encoded.Bytes)
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > cfg.MaxFrameBytes+16 {
			raw = raw[:cfg.MaxFrameBytes+16]
		}
		_, _ = DecodeFrameBytes(cfg, raw)
	})
}

func BenchmarkEncodeDecodeFrame(b *testing.B) {
	cfg := DefaultConfig("bench-byte")
	frame := ByteFrame{SessionID: "s", StreamID: 1, Sequence: 1, Kind: FrameData, ByteCount: 1024}
	for i := 0; i < b.N; i++ {
		frame.Sequence = uint64(i + 1)
		encoded, err := EncodeFrame(cfg, frame)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := DecodeFrameBytes(cfg, encoded.Bytes); err != nil {
			b.Fatal(err)
		}
	}
}
