// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"encoding/hex"
	"testing"
)

func TestServiceRecordExamplesAndBorrowedOwnership(t *testing.T) {
	c, err := NewServiceRecordCodecV1(0, 4096)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		hex       string
		direction ServiceDirectionV1
		op        ServiceOpcodeV1
		id        uint32
	}{
		{"0104000000010000", ServiceClientToRelayV1, ServiceFINV1, 1},
		{"010600000002000500070103e8", ServiceClientToRelayV1, ServiceProbeV1, 2},
		{"01020000000100020000", ServiceRelayToClientV1, ServiceOpenResultV1, 1},
	} {
		raw, _ := hex.DecodeString(tc.hex)
		v, err := c.DecodeBorrowed(raw, tc.direction, 1000)
		if err != nil || v.Opcode != tc.op || v.ID != tc.id {
			t.Fatalf("example: %+v %v", v, err)
		}
		dst := make([]byte, len(raw))
		if n, err := c.Encode(dst, v, tc.direction, 1000); err != nil || n != len(raw) || !bytes.Equal(dst, raw) {
			t.Fatalf("encode: %d %v", n, err)
		}
		if len(v.Body) != 0 {
			raw[8] ^= 1
			if v.Body[0] != raw[8] {
				t.Fatal("view did not borrow")
			}
		}
	}
}

func TestServiceRecordRejectsMalformedBeforeOutput(t *testing.T) {
	c, _ := NewServiceRecordCodecV1(8, 272)
	for _, rawHex := range []string{
		"", "0104", "0204000000010000", "0100000000010000", "0108000000010000",
		"0104000000000000", "0104000000010001", "010400000001000000", "010400000001000100",
		"01010000000100090400040101010101bb", "01010000000100090100030101010101bb",
		"0101000000010009010004010101010000", "01010000000100060200010001bb",
		"01010000000100060200014101bb", "01010000000100060200012e01bb",
		"0102000000010002000b", "010200000001000100", "0103000000010000",
		"01050000000100020000", "0105000000010002000b", "010600000001000500000103e8",
		"010600000001000500070203e8", "010600000001000500070103e7",
		"01060000000100050007017531", "0107000000010006000100000001",
		"01070000000100060000000f4241", "0107000000010006000b00000000",
	} {
		raw, _ := hex.DecodeString(rawHex)
		direction := ServiceClientToRelayV1
		if len(raw) > 1 && (raw[1] == 2 || raw[1] == 7) {
			direction = ServiceRelayToClientV1
		}
		if _, err := c.DecodeBorrowed(raw, direction, 1000); err == nil {
			t.Errorf("malformed accepted: %s", rawHex)
		}
	}
	for _, tc := range []struct {
		op        ServiceOpcodeV1
		body      []byte
		direction ServiceDirectionV1
	}{
		{ServiceOpenV1, []byte{1, 0, 4, 1, 1, 1, 1, 1, 187}, ServiceRelayToClientV1},
		{ServiceOpenResultV1, []byte{0, 0}, ServiceClientToRelayV1},
		{ServiceProbeV1, []byte{0, 7, 1, 3, 232}, ServiceRelayToClientV1},
		{ServiceProbeResultV1, []byte{0, 0, 0, 0, 0, 1}, ServiceClientToRelayV1},
		{ServiceFINV1, nil, ServiceDirectionV1(0)},
	} {
		dst := bytes.Repeat([]byte{0xaa}, 300)
		before := bytes.Clone(dst)
		if n, err := c.Encode(dst, ServiceRecordViewV1{Opcode: tc.op, ID: 1, Body: tc.body}, tc.direction, 1000); err == nil || n != 0 || !bytes.Equal(before, dst) {
			t.Fatal("direction mutated output", err)
		}
	}
	dst := bytes.Repeat([]byte{0xaa}, 7)
	if n, err := c.Encode(dst, ServiceRecordViewV1{Opcode: ServiceFINV1, ID: 1}, ServiceClientToRelayV1, 0); err == nil || n != 0 || !bytes.Equal(dst, bytes.Repeat([]byte{0xaa}, 7)) {
		t.Fatal("short output partially written")
	}
	for _, n := range []int{265, 65536} {
		if _, err := c.Encode(make([]byte, n+8), ServiceRecordViewV1{Opcode: ServiceDataV1, ID: 1, Body: make([]byte, n)}, ServiceClientToRelayV1, 0); err == nil {
			t.Fatal("oversized data")
		}
	}
}

func TestServiceRecordNativeAndSignedBounds(t *testing.T) {
	for _, b := range [][2]int{{-1, 272}, {9, 272}, {8, 271}, {8, 8<<20 + 1}} {
		if _, err := NewServiceRecordCodecV1(b[0], b[1]); err == nil {
			t.Fatal("invalid bound", b)
		}
	}
	for _, maximum := range []int{272, 4096, 8 << 20} {
		c, err := NewServiceRecordCodecV1(8, maximum)
		if err != nil {
			t.Fatal(err)
		}
		limit := maximum - 8
		if limit > 16384 {
			limit = 16384
		}
		for _, n := range []int{1, limit, limit + 1} {
			body := make([]byte, n)
			dst := make([]byte, n+8)
			count, err := c.Encode(dst, ServiceRecordViewV1{Opcode: ServiceDataV1, ID: 0xffffffff, Body: body}, ServiceRelayToClientV1, 0)
			if (err == nil) != (n <= limit) {
				t.Fatal("data boundary", n, err)
			}
			if err == nil {
				if _, err = c.DecodeBorrowed(dst[:count], ServiceRelayToClientV1, 0); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	c, _ := NewServiceRecordCodecV1(8, 4096)
	for result := uint16(0); result <= 10; result++ {
		body := []byte{byte(result >> 8), byte(result), 0, 0, 0, 0}
		if _, err := c.Encode(make([]byte, 14), ServiceRecordViewV1{Opcode: ServiceProbeResultV1, ID: 1, Body: body}, ServiceRelayToClientV1, 1000); err != nil {
			t.Fatal("result rejected", result, err)
		}
	}
	if _, err := c.Encode(make([]byte, 14), ServiceRecordViewV1{Opcode: ServiceProbeResultV1, ID: 1, Body: make([]byte, 6)}, ServiceRelayToClientV1, 0); err == nil {
		t.Fatal("success without accepted timeout")
	}
	for _, tc := range []struct {
		raw  []byte
		want ServicePayloadKindV1
	}{{nil, ServicePayloadInvalidV1}, {[]byte{1}, ServicePayloadRecordV1}, {[]byte{0x40}, ServicePayloadIPv4V1}, {[]byte{0x6f}, ServicePayloadIPv6V1}, {[]byte{0x20}, ServicePayloadInvalidV1}} {
		if got := ClassifyServicePayloadV1(tc.raw); got != tc.want {
			t.Fatal("classification", got)
		}
	}
}

func TestServiceRecordEveryBodyShapeAndOverlap(t *testing.T) {
	c, _ := NewServiceRecordCodecV1(0, 4096)
	for _, tc := range []struct {
		op        ServiceOpcodeV1
		body      []byte
		direction ServiceDirectionV1
	}{
		{ServiceOpenV1, []byte{1, 0, 4, 1, 1, 1, 1, 1, 187}, ServiceClientToRelayV1},
		{ServiceOpenV1, append([]byte{2, 0, 11}, append([]byte("example.com"), 1, 187)...), ServiceClientToRelayV1},
		{ServiceOpenV1, []byte{3, 0, 16, 0x26, 0x06, 0x47, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x11, 0x11, 1, 187}, ServiceClientToRelayV1},
		{ServiceOpenResultV1, []byte{0, 10}, ServiceRelayToClientV1},
		{ServiceDataV1, []byte{1}, ServiceClientToRelayV1},
		{ServiceFINV1, nil, ServiceRelayToClientV1},
		{ServiceResetV1, []byte{0, 1}, ServiceClientToRelayV1},
		{ServiceProbeV1, []byte{255, 255, 1, 0x75, 0x30}, ServiceClientToRelayV1},
		{ServiceProbeResultV1, []byte{0, 0, 0, 0x0f, 0x42, 0x40}, ServiceRelayToClientV1},
	} {
		raw := make([]byte, 8+len(tc.body))
		n, err := c.Encode(raw, ServiceRecordViewV1{tc.op, 1, tc.body}, tc.direction, 1000)
		if err != nil {
			t.Fatal("valid body", tc.op, err)
		}
		if _, err := c.DecodeBorrowed(raw[:n], tc.direction, 1000); err != nil {
			t.Fatal("valid decode", err)
		}
		for cut := 0; cut < len(raw); cut++ {
			if _, err := c.DecodeBorrowed(raw[:cut], tc.direction, 1000); err == nil {
				t.Fatal("truncated record")
			}
		}
		if _, err := c.DecodeBorrowed(append(bytes.Clone(raw), 0), tc.direction, 1000); err == nil {
			t.Fatal("trailing byte")
		}
		dst := bytes.Repeat([]byte{0xaa}, n-1)
		before := bytes.Clone(dst)
		if n, err := c.Encode(dst, ServiceRecordViewV1{tc.op, 1, tc.body}, tc.direction, 1000); n != 0 || err == nil || !bytes.Equal(dst, before) {
			t.Fatal("partial output")
		}
	}
	dst := make([]byte, 20)
	copy(dst, []byte("abcdefgh"))
	if _, err := c.Encode(dst, ServiceRecordViewV1{ServiceDataV1, 1, dst[:8]}, ServiceClientToRelayV1, 0); err != nil || string(dst[8:16]) != "abcdefgh" {
		t.Fatal("overlap broke body", err)
	}
}
