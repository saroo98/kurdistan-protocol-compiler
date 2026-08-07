// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package liveprogram

import (
	"bytes"
	"testing"
)

func FuzzDecodeV1(f *testing.F) {
	encoded, err := EncodeV1(fixtureProgramV1())
	if err == nil {
		f.Add(encoded)
	}
	f.Add([]byte{0xa2, 0x01, 0x02, 0x01, 0x02})
	f.Add([]byte{0xbf, 0x01, 0x02, 0xff})
	f.Add([]byte{0xc1, 0xa0})
	f.Fuzz(func(t *testing.T, encoded []byte) {
		program, err := DecodeV1(encoded)
		if err != nil {
			return
		}
		reencoded, err := EncodeV1(program)
		if err != nil || !bytes.Equal(encoded, reencoded) {
			t.Fatalf("accepted program did not round trip: %v", err)
		}
	})
}
