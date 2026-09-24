// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package wirev1

import (
	"bytes"
	"testing"
)

func TestWireBuffersParityOwnershipAndOverlap(t *testing.T) {
	for _, size := range []int{1, 17, MaxPayloadBytes} {
		f := Frame{Type: TypeReliableData, StreamID: 2, PlanDigest: testDigest(), Payload: bytes.Repeat([]byte{7}, size)}
		want, err := Encode(f)
		if err != nil {
			t.Fatal(err)
		}
		dst := bytes.Repeat([]byte{0xaa}, len(want))
		if _, err := EncodeInto(dst[:len(dst)-1], f); err == nil || !bytes.Equal(dst, bytes.Repeat([]byte{0xaa}, len(dst))) {
			t.Fatal("short output accepted or mutated")
		}
		n, err := EncodeInto(dst, f)
		if err != nil || n != len(want) || !bytes.Equal(dst, want) {
			t.Fatal("encode parity", err)
		}
		view, err := DecodeView(dst)
		if err != nil {
			t.Fatal(err)
		}
		owned, err := Decode(dst)
		if err != nil {
			t.Fatal(err)
		}
		dst[HeaderBytes] ^= 1
		if view.Payload[0] != dst[HeaderBytes] || owned.Payload[0] != 7 || cap(view.Payload) != len(view.Payload) {
			t.Fatal("ownership contract")
		}
		copy(dst, want)
		f.Payload = dst[HeaderBytes:]
		if _, err := EncodeInto(dst, f); err != nil || !bytes.Equal(dst, want) {
			t.Fatal("exact in-place layout", err)
		}
		// Payload may overlap the header or its eventual destination. Copying payload first is safe.
		copy(dst, f.Payload)
		f.Payload = dst[:size]
		if _, err := EncodeInto(dst, f); err != nil || !bytes.Equal(dst, want) {
			t.Fatal("overlapping copy ordering", err)
		}
	}
}

func TestWireBuffersRejectAndAllocateNothing(t *testing.T) {
	f := Frame{Type: TypeReliableData, StreamID: 2, PlanDigest: testDigest(), Payload: []byte{1, 2, 3}}
	encoded, _ := Encode(f)
	dst := make([]byte, len(encoded))
	for i := 0; i < len(encoded); i++ {
		candidate := append([]byte(nil), encoded[:i]...)
		if _, err := DecodeView(candidate); err == nil {
			t.Fatal("truncation accepted")
		}
	}
	for _, i := range []int{0, 4, 5, 6, 7, 12, 16} {
		candidate := append([]byte(nil), encoded...)
		if i == 16 {
			clear(candidate[16:48])
		} else {
			candidate[i] = 0xff
		}
		if _, err := DecodeView(candidate); err == nil {
			t.Fatalf("invalid header %d", i)
		}
	}
	bad := f
	bad.Flags = 0xff
	if _, err := EncodeInto(dst, bad); err == nil || !bytes.Equal(dst, make([]byte, len(dst))) {
		t.Fatal("invalid write")
	}
	if n := testing.AllocsPerRun(100, func() {
		if _, err := EncodeInto(dst, f); err != nil {
			panic(err)
		}
		if _, err := DecodeView(encoded); err != nil {
			panic(err)
		}
	}); n != 0 {
		t.Fatalf("allocations %v", n)
	}
}
