// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"testing"
)

func TestNormalizeProfileIngressSingleRawOwner(t *testing.T) {
	input := bytes.Repeat([]byte{0xa5}, 4096)
	var output []byte
	allocations := testing.AllocsPerRun(20, func() {
		var err error
		output, err = NormalizeProfileIngress(ProfileIngress{Kind: IngressFile, Bytes: input})
		if err != nil {
			panic(err)
		}
	})
	if allocations != 1 {
		t.Fatalf("raw mutable owners: allocations=%v, want one", allocations)
	}
	output[0] = 0
	if input[0] != 0xa5 {
		t.Fatal("caller buffer aliased")
	}
}

func TestNormalizeProfileIngressQRExactOwnerAndRejection(t *testing.T) {
	input := bytes.Repeat([]byte{0x7d}, 10000)
	chunks, err := EncodeQRChunks(input, 2000)
	if err != nil {
		t.Fatal(err)
	}
	output, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: chunks})
	if err != nil || !bytes.Equal(output, input) {
		t.Fatalf("QR parity: %v", err)
	}
	if cap(output) != len(output) {
		t.Fatalf("assembled owner capacity=%d want=%d", cap(output), len(output))
	}
	for _, bad := range []string{"KURD1/5/5/AAAA!", "KURD1/5/5/AB", "KURD1/5/5/AA="} {
		mutated := append([]string(nil), chunks...)
		mutated[4] = bad
		rejected, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressQRChunks, Chunks: mutated})
		if rejected != nil || !IngressErrorIs(err, IngressAmbiguousBase) {
			t.Fatalf("QR rejection: %v", err)
		}
	}
	for _, bad := range []string{"kurd://artifact/AAAA!", "kurd://artifact/AB"} {
		rejected, err := NormalizeProfileIngress(ProfileIngress{Kind: IngressURI, Text: bad})
		if rejected != nil || !IngressErrorIs(err, IngressAmbiguousBase) {
			t.Fatalf("URI rejection: %v", err)
		}
	}
}
