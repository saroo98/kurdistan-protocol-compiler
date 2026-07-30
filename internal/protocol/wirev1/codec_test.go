// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirev1

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

func testDigest() [32]byte {
	var value [32]byte
	for index := range value {
		value[index] = byte(index + 1)
	}
	return value
}

func TestCanonicalVector(t *testing.T) {
	frame := Frame{
		Type: TypeReliableData, StreamID: 7, PlanDigest: testDigest(),
		Payload: []byte("kurd-wire-v1"),
	}
	encoded, err := Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	const want = "4b55524401000500000000070000000c0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f206b7572642d776972652d7631"
	if hex.EncodeToString(encoded) != want {
		t.Fatalf("vector mismatch:\n got %x\nwant %s", encoded, want)
	}
	decoded, err := Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Type != frame.Type || decoded.StreamID != frame.StreamID ||
		decoded.PlanDigest != frame.PlanDigest || !bytes.Equal(decoded.Payload, frame.Payload) {
		t.Fatalf("round trip mismatch: %+v", decoded)
	}
}

func TestDecodeRejectsMalformedAndUnknownInputs(t *testing.T) {
	valid, err := Encode(Frame{
		Type: TypeProfileBind, PlanDigest: testDigest(), Payload: []byte{1},
	})
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func([]byte) []byte{
		func(value []byte) []byte { return value[:HeaderBytes-1] },
		func(value []byte) []byte { value[0] ^= 1; return value },
		func(value []byte) []byte { value[4]++; return value },
		func(value []byte) []byte { value[5]++; return value },
		func(value []byte) []byte { value[6] = 0xff; return value },
		func(value []byte) []byte { value[7] = 0x80; return value },
		func(value []byte) []byte { value[8+3] = 1; return value },
		func(value []byte) []byte { value[12+3]++; return value },
		func(value []byte) []byte { clear(value[16:48]); return value },
		func(value []byte) []byte { return append(value, 0) },
	}
	for index, mutate := range mutations {
		candidate := mutate(append([]byte(nil), valid...))
		if decoded, err := Decode(candidate); !errors.Is(err, ErrInvalidFrame) || !zeroFrame(decoded) {
			t.Fatalf("mutation %d accepted: frame=%+v err=%v", index, decoded, err)
		}
	}
}

func TestFrameClassRules(t *testing.T) {
	tests := []Frame{
		{Type: TypeReliableData, PlanDigest: testDigest(), Payload: []byte{1}},
		{Type: TypeReliableData, StreamID: 1, PlanDigest: testDigest()},
		{Type: TypeHeartbeat, StreamID: 1, PlanDigest: testDigest()},
		{Type: TypeHeartbeat, PlanDigest: testDigest(), Payload: []byte{1}},
		{Type: TypeClose, StreamID: 1, PlanDigest: testDigest(), Payload: []byte{1}},
		{Type: TypeClose, PlanDigest: testDigest()},
	}
	for index, frame := range tests {
		if _, err := Encode(frame); !errors.Is(err, ErrInvalidFrame) {
			t.Fatalf("case %d accepted: %v", index, err)
		}
	}
}

func TestHandshakeFinishFramesAreCanonicalControlFrames(t *testing.T) {
	for _, frameType := range []uint8{TypeClientFinish, TypeServerFinish} {
		encoded, err := Encode(Frame{Type: frameType, PlanDigest: testDigest(), Payload: []byte{1, 2, 3}})
		if err != nil {
			t.Fatalf("encode type %d: %v", frameType, err)
		}
		decoded, err := Decode(encoded)
		if err != nil {
			t.Fatalf("decode type %d: %v", frameType, err)
		}
		if decoded.Type != frameType || decoded.StreamID != 0 || !bytes.Equal(decoded.Payload, []byte{1, 2, 3}) {
			t.Fatalf("finish frame mismatch: %+v", decoded)
		}
	}
}

func FuzzDecode(f *testing.F) {
	seed, err := Encode(Frame{
		Type: TypeReliableData, StreamID: 1, PlanDigest: testDigest(), Payload: []byte("seed"),
	})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(seed)
	f.Fuzz(func(t *testing.T, input []byte) {
		frame, err := Decode(input)
		if err != nil {
			if !zeroFrame(frame) {
				t.Fatal("rejected input returned partial authority")
			}
			return
		}
		encoded, err := Encode(frame)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(encoded, input) {
			t.Fatal("accepted input was not canonical")
		}
	})
}

func zeroFrame(frame Frame) bool {
	return frame.Type == 0 && frame.Flags == 0 && frame.StreamID == 0 &&
		frame.PlanDigest == ([32]byte{}) && frame.Payload == nil
}
