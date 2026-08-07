// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"bytes"
	"testing"
)

func FuzzDecodeV2(f *testing.F) {
	policy := fixturePolicyV2(f)
	encoded, err := EncodeV2(policy)
	if err == nil {
		f.Add(encoded)
	}
	f.Add([]byte{0xa2, 0x01, 0x02, 0x01, 0x02})
	f.Add([]byte{0xbf, 0x01, 0x02, 0xff})
	f.Add([]byte{0xc1, 0xa0})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		policy, err := DecodeV2(encoded)
		if err != nil {
			return
		}
		reencoded, err := EncodeV2(policy)
		if err != nil || !bytes.Equal(encoded, reencoded) {
			t.Fatalf("accepted policy did not round trip: %v", err)
		}
	})
}
