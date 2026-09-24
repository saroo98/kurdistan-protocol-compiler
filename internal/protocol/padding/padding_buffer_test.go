// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package padding

import (
	"bytes"
	"testing"

	"kurdistan/internal/protocol/ir"
)

func TestGenerateIntoParityAndPreflight(t *testing.T) {
	for _, mode := range []string{"none", "fixed", "bounded", "inter_frame", "probabilistic"} {
		t.Run(mode, func(t *testing.T) {
			policy := ir.PaddingPolicy{Mode: mode, MinPaddingBytes: 2, MaxPaddingBytes: 16, Probability: .5}
			a, b := New(policy, 99), New(policy, 99)
			dst := bytes.Repeat([]byte{0xaa}, 16)
			if mode != "none" {
				if _, err := b.GenerateInto(dst[:15]); err == nil {
					t.Fatal("short maximum scratch accepted")
				}
				if !bytes.Equal(dst, bytes.Repeat([]byte{0xaa}, 16)) {
					t.Fatal("rejection wrote destination")
				}
			}
			for i := 0; i < 100; i++ {
				want, err := a.Generate()
				if err != nil {
					t.Fatal(err)
				}
				n, err := b.GenerateInto(dst)
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(dst[:n], want) {
					t.Fatal("RNG draw or byte parity changed")
				}
			}
			b.ResetSeed(99)
			want, _ := New(policy, 99).Generate()
			n, err := b.GenerateInto(dst)
			if err != nil || !bytes.Equal(dst[:n], want) {
				t.Fatal("reset parity")
			}
			if allocs := testing.AllocsPerRun(100, func() { _, _ = b.GenerateInto(dst) }); allocs != 0 {
				t.Fatalf("allocations %v", allocs)
			}
		})
	}
	if n, err := New(ir.PaddingPolicy{Mode: "none"}, 0).GenerateInto(nil); n != 0 || err != nil {
		t.Fatal("none requires scratch")
	}
	for _, p := range []ir.PaddingPolicy{{Mode: "fixed", MinPaddingBytes: -1, MaxPaddingBytes: 4}, {Mode: "bounded", MinPaddingBytes: 5, MaxPaddingBytes: 4}} {
		dst := bytes.Repeat([]byte{7}, 8)
		if _, err := New(p, 0).GenerateInto(dst); err == nil || !bytes.Equal(dst, bytes.Repeat([]byte{7}, 8)) {
			t.Fatal("invalid policy accepted or wrote")
		}
	}
}
