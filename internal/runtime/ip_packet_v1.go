// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

type DirectionV1 uint8

const (
	DirectionClientV1 DirectionV1 = 1
	DirectionRelayV1  DirectionV1 = 2
)

var (
	ErrPacketInvalid     = errors.New("packet_invalid")
	ErrPacketFamily      = errors.New("packet_family_rejected")
	ErrPacketProtocol    = errors.New("packet_protocol_rejected")
	ErrPacketSource      = errors.New("packet_source_rejected")
	ErrPacketDestination = errors.New("packet_destination_rejected")
	ErrPacketFragmented  = errors.New("packet_fragmented")
)

type IPPacketInfoV1 struct {
	Version  uint8
	Protocol uint8
	Length   int
	source   netip.Addr
	dest     netip.Addr
}

func ValidateIPPacketV1(packet []byte, direction DirectionV1, assignedIPv4 [4]byte, assignedIPv6 [16]byte, allowIPv4, allowIPv6 bool) (IPPacketInfoV1, error) {
	if direction != DirectionClientV1 && direction != DirectionRelayV1 || len(packet) < 1 {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	switch packet[0] >> 4 {
	case 4:
		if !allowIPv4 {
			return IPPacketInfoV1{}, ErrPacketFamily
		}
		return validateIPv4PacketV1(packet, direction, assignedIPv4, netip.Addr{})
	case 6:
		if !allowIPv6 {
			return IPPacketInfoV1{}, ErrPacketFamily
		}
		return validateIPv6PacketV1(packet, direction, assignedIPv6, netip.Addr{})
	default:
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
}

func validateIPv4PacketV1(packet []byte, direction DirectionV1, assigned [4]byte, allowedDestination netip.Addr) (IPPacketInfoV1, error) {
	if len(packet) < 20 {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	headerBytes := int(packet[0]&0x0f) * 4
	if headerBytes < 20 || headerBytes > 60 || len(packet) < headerBytes || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) || ipv4ChecksumV1(packet[:headerBytes]) != 0 {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	flagsOffset := binary.BigEndian.Uint16(packet[6:8])
	if flagsOffset&0x3fff != 0 {
		return IPPacketInfoV1{}, ErrPacketFragmented
	}
	protocol := packet[9]
	if protocol != 6 && protocol != 17 && protocol != 1 {
		return IPPacketInfoV1{}, ErrPacketProtocol
	}
	var sourceBytes, destinationBytes [4]byte
	copy(sourceBytes[:], packet[12:16])
	copy(destinationBytes[:], packet[16:20])
	source := netip.AddrFrom4(sourceBytes)
	destination := netip.AddrFrom4(destinationBytes)
	if direction == DirectionRelayV1 && (assigned == [4]byte{} || sourceBytes != assigned) {
		return IPPacketInfoV1{}, ErrPacketSource
	}
	if destination != allowedDestination && blockedPacketAddressV1(destination) {
		return IPPacketInfoV1{}, ErrPacketDestination
	}
	return IPPacketInfoV1{Version: 4, Protocol: protocol, Length: len(packet), source: source, dest: destination}, nil
}

func validateIPv6PacketV1(packet []byte, direction DirectionV1, assigned [16]byte, allowedDestination netip.Addr) (IPPacketInfoV1, error) {
	if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	var sourceBytes, destinationBytes [16]byte
	copy(sourceBytes[:], packet[8:24])
	copy(destinationBytes[:], packet[24:40])
	source := netip.AddrFrom16(sourceBytes)
	destination := netip.AddrFrom16(destinationBytes)
	if direction == DirectionRelayV1 && (assigned == [16]byte{} || sourceBytes != assigned) {
		return IPPacketInfoV1{}, ErrPacketSource
	}
	if destination != allowedDestination && blockedPacketAddressV1(destination) {
		return IPPacketInfoV1{}, ErrPacketDestination
	}
	next := packet[6]
	offset := 40
	for extensions := 0; next == 0 || next == 43 || next == 60; extensions++ {
		if extensions >= 8 || offset+2 > len(packet) {
			return IPPacketInfoV1{}, ErrPacketInvalid
		}
		headerLength := (int(packet[offset+1]) + 1) * 8
		if headerLength < 8 || offset+headerLength > len(packet) || offset+headerLength > 296 {
			return IPPacketInfoV1{}, ErrPacketInvalid
		}
		next = packet[offset]
		offset += headerLength
	}
	if next == 44 {
		return IPPacketInfoV1{}, ErrPacketFragmented
	}
	if next != 6 && next != 17 && next != 58 {
		return IPPacketInfoV1{}, ErrPacketProtocol
	}
	return IPPacketInfoV1{Version: 6, Protocol: next, Length: len(packet), source: source, dest: destination}, nil
}

func validateReturnIPPacketV1(packet []byte, assignedIPv4 [4]byte, assignedIPv6 [16]byte) (IPPacketInfoV1, error) {
	if len(packet) == 0 {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	switch packet[0] >> 4 {
	case 4:
		if assignedIPv4 == [4]byte{} {
			return IPPacketInfoV1{}, ErrPacketFamily
		}
		return validateIPv4PacketV1(packet, DirectionClientV1, [4]byte{}, netip.AddrFrom4(assignedIPv4))
	case 6:
		if assignedIPv6 == [16]byte{} {
			return IPPacketInfoV1{}, ErrPacketFamily
		}
		return validateIPv6PacketV1(packet, DirectionClientV1, [16]byte{}, netip.AddrFrom16(assignedIPv6))
	default:
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
}

func validateClientOutboundIPPacketV1(packet []byte, assignedIPv4 [4]byte, assignedIPv6 [16]byte) (IPPacketInfoV1, error) {
	if len(packet) == 0 {
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
	switch packet[0] >> 4 {
	case 4:
		if assignedIPv4 == [4]byte{} {
			return IPPacketInfoV1{}, ErrPacketFamily
		}
		server := assignedIPv4
		server[3] = 1
		return validateIPv4PacketV1(packet, DirectionClientV1, [4]byte{}, netip.AddrFrom4(server))
	case 6:
		if assignedIPv6 == [16]byte{} {
			return IPPacketInfoV1{}, ErrPacketFamily
		}
		server := assignedIPv6
		server[15] = 1
		return validateIPv6PacketV1(packet, DirectionClientV1, [16]byte{}, netip.AddrFrom16(server))
	default:
		return IPPacketInfoV1{}, ErrPacketInvalid
	}
}

func blockedPacketAddressV1(address netip.Addr) bool {
	if !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsMulticast() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsPrivate() {
		return true
	}
	if address.Is4() {
		value := address.As4()
		return value == [4]byte{255, 255, 255, 255} || value[0] == 0 || (value[0] == 100 && value[1]&0xc0 == 64)
	}
	return false
}

func ipv4ChecksumV1(header []byte) uint16 {
	var sum uint32
	for index := 0; index+1 < len(header); index += 2 {
		sum += uint32(binary.BigEndian.Uint16(header[index : index+2]))
	}
	if len(header)%2 != 0 {
		sum += uint32(header[len(header)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
