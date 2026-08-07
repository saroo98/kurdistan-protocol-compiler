// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import "testing"

func FuzzIPPacketV1(f *testing.F) {
	assigned4 := [4]byte{10, 89, 0, 2}
	f.Add(testIPv4PacketV1(assigned4, [4]byte{1, 1, 1, 1}, 17, []byte{1}))
	f.Add(testIPv6PacketV1([16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 6, []byte{1}))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		info, err := ValidateIPPacketV1(packet, DirectionClientV1, [4]byte{}, [16]byte{}, true, true)
		if err == nil && (info.Length != len(packet) || (info.Version != 4 && info.Version != 6)) {
			t.Fatalf("inconsistent accepted packet: %+v len=%d", info, len(packet))
		}
	})
}
