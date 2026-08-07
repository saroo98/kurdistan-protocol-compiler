// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestValidateIPPacketV1IPv4AndIPv6(t *testing.T) {
	for _, test := range []struct {
		name     string
		packet   []byte
		allowV4  bool
		allowV6  bool
		version  uint8
		protocol uint8
	}{
		{name: "ipv4 tcp", packet: testIPv4PacketV1([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, 6, []byte{1}), allowV4: true, version: 4, protocol: 6},
		{name: "ipv4 udp", packet: testIPv4PacketV1([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, 17, []byte{1, 2, 3}), allowV4: true, version: 4, protocol: 17},
		{name: "ipv4 icmp", packet: testIPv4PacketV1([4]byte{10, 89, 0, 2}, [4]byte{1, 1, 1, 1}, 1, []byte{8}), allowV4: true, version: 4, protocol: 1},
		{name: "ipv6 tcp", packet: testIPv6PacketV1([16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 6, []byte{1}), allowV6: true, version: 6, protocol: 6},
		{name: "ipv6 udp", packet: testIPv6PacketV1([16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 17, []byte{1}), allowV6: true, version: 6, protocol: 17},
		{name: "ipv6 icmp", packet: testIPv6PacketV1([16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}, 58, []byte{128}), allowV6: true, version: 6, protocol: 58},
	} {
		t.Run(test.name, func(t *testing.T) {
			info, err := ValidateIPPacketV1(test.packet, DirectionClientV1, [4]byte{}, [16]byte{}, test.allowV4, test.allowV6)
			if err != nil || info.Version != test.version || info.Protocol != test.protocol || info.Length != len(test.packet) {
				t.Fatalf("packet info=%+v err=%v", info, err)
			}
		})
	}
}

func TestValidateIPPacketV1RejectsSpoofingFragmentsAndBlockedDestinations(t *testing.T) {
	assigned := [4]byte{10, 89, 0, 2}
	wrong := testIPv4PacketV1([4]byte{10, 89, 0, 3}, [4]byte{1, 1, 1, 1}, 6, []byte{1})
	if _, err := ValidateIPPacketV1(wrong, DirectionRelayV1, assigned, [16]byte{}, true, false); !errors.Is(err, ErrPacketSource) {
		t.Fatalf("wrong source=%v", err)
	}
	fragmented := testIPv4PacketV1(assigned, [4]byte{1, 1, 1, 1}, 6, []byte{1})
	fragmented[6] = 0x20
	fragmented[10], fragmented[11] = 0, 0
	binary.BigEndian.PutUint16(fragmented[10:12], ipv4ChecksumV1(fragmented[:20]))
	if _, err := ValidateIPPacketV1(fragmented, DirectionRelayV1, assigned, [16]byte{}, true, false); !errors.Is(err, ErrPacketFragmented) {
		t.Fatalf("fragment=%v", err)
	}
	blocked := testIPv4PacketV1(assigned, [4]byte{127, 0, 0, 1}, 6, []byte{1})
	if _, err := ValidateIPPacketV1(blocked, DirectionClientV1, [4]byte{}, [16]byte{}, true, false); !errors.Is(err, ErrPacketDestination) {
		t.Fatalf("blocked=%v", err)
	}
	malformed := append([]byte(nil), wrong...)
	binary.BigEndian.PutUint16(malformed[2:4], uint16(len(malformed)+1))
	if _, err := ValidateIPPacketV1(malformed, DirectionClientV1, [4]byte{}, [16]byte{}, true, false); !errors.Is(err, ErrPacketInvalid) {
		t.Fatalf("length=%v", err)
	}
	if netip.AddrFrom4(assigned).IsUnspecified() {
		t.Fatal("bad test address")
	}
}

func TestValidateClientOutboundIPPacketV1AllowsOnlyExactTunnelGateway(t *testing.T) {
	assigned := [4]byte{10, 89, 0, 2}
	dns := testIPv4PacketV1(assigned, [4]byte{10, 89, 0, 1}, 17, []byte{1})
	if _, err := validateClientOutboundIPPacketV1(dns, assigned, [16]byte{}); err != nil {
		t.Fatalf("exact tunnel gateway rejected: %v", err)
	}
	otherPrivate := testIPv4PacketV1(assigned, [4]byte{10, 89, 0, 9}, 17, []byte{1})
	if _, err := validateClientOutboundIPPacketV1(otherPrivate, assigned, [16]byte{}); !errors.Is(err, ErrPacketDestination) {
		t.Fatalf("other private destination=%v", err)
	}
}

func TestValidateIPPacketV1RejectsFamilyProtocolChecksumAndIPv6Extensions(t *testing.T) {
	assigned4 := [4]byte{10, 89, 0, 2}
	assigned6 := [16]byte{0xfd, 0x42, 0x89, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
	public6 := [16]byte{0x20, 1, 0x48, 0x60, 0x48, 0x60, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}

	v4 := testIPv4PacketV1(assigned4, [4]byte{1, 1, 1, 1}, 6, []byte{1})
	if _, err := ValidateIPPacketV1(v4, DirectionClientV1, assigned4, assigned6, false, true); !errors.Is(err, ErrPacketFamily) {
		t.Fatalf("ipv4 family error=%v", err)
	}
	v6 := testIPv6PacketV1(assigned6, public6, 17, []byte{1})
	if _, err := ValidateIPPacketV1(v6, DirectionClientV1, assigned4, assigned6, true, false); !errors.Is(err, ErrPacketFamily) {
		t.Fatalf("ipv6 family error=%v", err)
	}

	badProtocol := testIPv4PacketV1(assigned4, [4]byte{1, 1, 1, 1}, 47, []byte{1})
	if _, err := ValidateIPPacketV1(badProtocol, DirectionClientV1, assigned4, assigned6, true, true); !errors.Is(err, ErrPacketProtocol) {
		t.Fatalf("protocol error=%v", err)
	}
	badChecksum := append([]byte(nil), v4...)
	badChecksum[10] ^= 1
	if _, err := ValidateIPPacketV1(badChecksum, DirectionClientV1, assigned4, assigned6, true, true); !errors.Is(err, ErrPacketInvalid) {
		t.Fatalf("checksum error=%v", err)
	}

	extensions := make([]byte, 9*8+1)
	for index := 0; index < 9; index++ {
		extensions[index*8] = 0
	}
	extensions[8*8] = 17
	extended := testIPv6PacketV1(assigned6, public6, 0, extensions)
	if _, err := ValidateIPPacketV1(extended, DirectionClientV1, assigned4, assigned6, true, true); !errors.Is(err, ErrPacketInvalid) {
		t.Fatalf("extension chain error=%v", err)
	}
	fragmented6 := testIPv6PacketV1(assigned6, public6, 44, make([]byte, 8))
	if _, err := ValidateIPPacketV1(fragmented6, DirectionClientV1, assigned4, assigned6, true, true); !errors.Is(err, ErrPacketFragmented) {
		t.Fatalf("ipv6 fragment error=%v", err)
	}
	multicast6 := public6
	multicast6[0] = 0xff
	if _, err := ValidateIPPacketV1(testIPv6PacketV1(assigned6, multicast6, 17, []byte{1}), DirectionClientV1, assigned4, assigned6, true, true); !errors.Is(err, ErrPacketDestination) {
		t.Fatalf("ipv6 multicast error=%v", err)
	}
	wrongSource6 := assigned6
	wrongSource6[15]++
	if _, err := ValidateIPPacketV1(testIPv6PacketV1(wrongSource6, public6, 17, []byte{1}), DirectionRelayV1, assigned4, assigned6, true, true); !errors.Is(err, ErrPacketSource) {
		t.Fatalf("ipv6 source error=%v", err)
	}
}

func testIPv4PacketV1(source, destination [4]byte, protocol byte, payload []byte) []byte {
	packet := make([]byte, 20+len(payload))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], source[:])
	copy(packet[16:20], destination[:])
	copy(packet[20:], payload)
	binary.BigEndian.PutUint16(packet[10:12], ipv4ChecksumV1(packet[:20]))
	return packet
}

func testIPv6PacketV1(source, destination [16]byte, next byte, payload []byte) []byte {
	packet := make([]byte, 40+len(payload))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(payload)))
	packet[6] = next
	packet[7] = 64
	copy(packet[8:24], source[:])
	copy(packet[24:40], destination[:])
	copy(packet[40:], payload)
	return packet
}
