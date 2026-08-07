// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package enrollment

import (
	"bytes"
	"testing"
	"time"
)

func FuzzDecodeRequestV1(f *testing.F) {
	now := time.Unix(1_700_400_000, 0)
	request, _, err := Generate(now, time.Hour, bytes.NewReader(bytes.Repeat([]byte{0x71}, 96)))
	if err == nil {
		if encoded, encodeErr := EncodeRequestV1(request); encodeErr == nil {
			f.Add(encoded)
		}
	}
	for _, malformed := range [][]byte{
		{},
		{0xa2, 0x01, 0x01, 0x01, 0x01},
		{0xbf, 0x01, 0x01, 0xff},
		{0xc1, 0xa0},
		{0xa1, 0x18, 0x01, 0x01},
	} {
		f.Add(malformed)
	}
	f.Fuzz(func(t *testing.T, encoded []byte) {
		request, err := DecodeAndVerifyRequestV1(encoded, now)
		if err != nil {
			return
		}
		reencoded, err := EncodeRequestV1(request)
		if err != nil || !bytes.Equal(encoded, reencoded) {
			t.Fatalf("accepted request did not round trip: %v", err)
		}
	})
}
