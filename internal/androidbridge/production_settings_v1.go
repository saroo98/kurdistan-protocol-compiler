// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"unicode/utf8"
)

type productionAddressV1 struct {
	family uint8
	value  [16]byte
}

type productionPrefixV1 struct {
	address productionAddressV1
	bits    uint8
	encoded []byte
}

type productionSettingsV1 struct {
	selection, reconnectMaximum                                     uint8
	reconnectOnFailure, allowLAN                                    bool
	manualStrategy                                                  []byte
	ipMode, dnsMode                                                 uint8
	customPrimary, customSecondary                                  productionAddressV1
	resolverCatalog                                                 []byte
	mtu                                                             uint16
	metered                                                         bool
	routingMode                                                     uint8
	packageCount                                                    uint16
	packages                                                        [256][]byte
	excludedCount                                                   uint8
	exclusions                                                      [64]productionPrefixV1
	probeMethod, probeDisplay, probeTimeoutSeconds                  uint8
	probeTarget                                                     []byte
	expertIdleSeconds, tcpLimit, udpLimit, memoryMiB                uint16
	tunnelMode, networkMeteredPolicy, pausePolicy                   uint8
	proxySocksPort, proxyHTTPPort, proxyIdleSeconds, proxyMemoryMiB uint16
	proxyClients, proxyStreams                                      uint8
}

type productionSettingsScannerV1 struct {
	input  []byte
	offset int
	status productionStatusV1
}

func decodeProductionSettingsV1(input []byte) (productionSettingsV1, productionStatusV1) {
	if len(input) > productionSettingsMaxBytesV1 {
		return productionSettingsV1{}, productionSizeLimitV1
	}
	if len(input) < 12 || !bytes.Equal(input[:4], []byte("KPS1")) || input[4] != 1 || input[5] != 0 || input[6] != 0 || input[7] != 0 || binary.BigEndian.Uint32(input[8:12]) != uint32(len(input)) {
		return productionSettingsV1{}, productionInvalidRequestV1
	}
	s := productionSettingsScannerV1{input: input, offset: 12, status: productionSuccessV1}
	var out productionSettingsV1

	// Row 1: presentation-only fields are validated and discarded.
	if !s.closed(s.u8(), 1, 3) || !s.boolValue() || !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}

	// Row 2.
	out.selection = s.u8()
	if !s.closed(out.selection, 1, 3) {
		return productionSettingsV1{}, s.failure()
	}
	if !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	out.reconnectOnFailure = s.readBool()
	out.allowLAN = s.readBool()
	if !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	out.manualStrategy, _ = s.id(true, false)
	out.reconnectMaximum = s.u8()
	if s.status != productionSuccessV1 || out.reconnectMaximum < 1 || out.reconnectMaximum > 10 || (out.selection == 3) != (len(out.manualStrategy) != 0) {
		return productionSettingsV1{}, s.failure()
	}

	// Row 3.
	out.ipMode, out.dnsMode = s.u8(), s.u8()
	out.customPrimary = s.address(true)
	out.mtu = s.u16()
	out.metered = s.readBool()
	if !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	out.resolverCatalog, _ = s.id(true, false)
	out.customSecondary = s.address(true)
	if !s.closed(out.ipMode, 1, 4) || !s.closed(out.dnsMode, 1, 4) || out.mtu < 1280 || out.mtu > 1500 || !validProductionDNSPresenceV1(out) {
		return productionSettingsV1{}, s.failure()
	}

	// Row 4.
	out.routingMode = s.u8()
	out.packageCount = s.u16()
	if !s.closed(out.routingMode, 1, 3) || out.packageCount > 256 {
		if out.packageCount > 256 {
			s.status = productionSizeLimitV1
		}
		return productionSettingsV1{}, s.failure()
	}
	var previous []byte
	for index := 0; index < int(out.packageCount); index++ {
		value, encoded := s.packageName()
		if s.status != productionSuccessV1 || index > 0 && bytes.Compare(previous, encoded) >= 0 {
			s.invalid()
			return productionSettingsV1{}, s.failure()
		}
		out.packages[index] = value
		previous = encoded
	}
	if out.routingMode == 1 && out.packageCount != 0 || out.routingMode == 2 && out.packageCount == 0 {
		return productionSettingsV1{}, productionInvalidRequestV1
	}
	out.excludedCount = s.u8()
	if out.excludedCount > 64 {
		return productionSettingsV1{}, productionSizeLimitV1
	}
	previous = nil
	for index := 0; index < int(out.excludedCount); index++ {
		prefix := s.prefix()
		if s.status != productionSuccessV1 || index > 0 && bytes.Compare(previous, prefix.encoded) >= 0 {
			s.invalid()
			return productionSettingsV1{}, s.failure()
		}
		out.exclusions[index] = prefix
		previous = prefix.encoded
	}

	// Rows 5 and 6.
	if !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	interval := s.u16()
	if interval < 1 || interval > 168 || !s.boolValue() || !s.boolValue() || !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	out.probeMethod, out.probeDisplay = s.u8(), s.u8()
	out.probeTarget, _ = s.id(true, false)
	out.probeTimeoutSeconds = s.u8()
	if !s.closed(out.probeMethod, 1, 5) || !s.closed(out.probeDisplay, 1, 2) || out.probeTimeoutSeconds < 1 || out.probeTimeoutSeconds > 30 {
		return productionSettingsV1{}, s.failure()
	}

	// Rows 7 and 8.
	if !s.closed(s.u8(), 1, 5) || !s.closed(s.u8(), 1, 4) {
		return productionSettingsV1{}, s.failure()
	}
	out.expertIdleSeconds, out.tcpLimit, out.udpLimit, out.memoryMiB = s.u16(), s.u16(), s.u16(), s.u16()
	if out.expertIdleSeconds < 30 || out.expertIdleSeconds > 3600 || out.tcpLimit < 16 || out.tcpLimit > 4096 || out.udpLimit > 2048 || out.memoryMiB != 0 && (out.memoryMiB < 40 || out.memoryMiB > 512) {
		return productionSettingsV1{}, productionInvalidRequestV1
	}

	// Row 9 is local-only, but its complete canonical union is still checked.
	active, _ := s.id(false, false)
	favoriteCount := s.u16()
	if favoriteCount > 1024 {
		return productionSettingsV1{}, productionSizeLimitV1
	}
	previous = nil
	activeFound := len(active) == 0
	for index := 0; index < int(favoriteCount); index++ {
		value, encoded := s.id(false, true)
		if s.status != productionSuccessV1 || index > 0 && bytes.Compare(previous, encoded) >= 0 {
			s.invalid()
			return productionSettingsV1{}, s.failure()
		}
		activeFound = activeFound || bytes.Equal(active, value)
		previous = encoded
	}
	if favoriteCount == 1024 && !activeFound {
		return productionSettingsV1{}, productionSizeLimitV1
	}

	// Rows 10 and 11.
	out.tunnelMode, out.networkMeteredPolicy, out.pausePolicy = s.u8(), s.u8(), s.u8()
	if !s.closed(out.tunnelMode, 1, 3) || !s.closed(out.networkMeteredPolicy, 1, 3) || !s.closed(out.pausePolicy, 1, 2) {
		return productionSettingsV1{}, s.failure()
	}
	out.proxySocksPort, out.proxyHTTPPort = s.u16(), s.u16()
	out.proxyClients, out.proxyStreams = s.u8(), s.u8()
	out.proxyIdleSeconds, out.proxyMemoryMiB = s.u16(), s.u16()
	if out.proxySocksPort < 1024 || out.proxyHTTPPort < 1024 || out.proxySocksPort == out.proxyHTTPPort || out.proxyClients < 1 || out.proxyClients > 16 || out.proxyStreams < 1 || out.proxyStreams > 64 || out.proxyIdleSeconds < 30 || out.proxyIdleSeconds > 3600 || out.proxyMemoryMiB < 16 || out.proxyMemoryMiB > 128 {
		return productionSettingsV1{}, productionInvalidRequestV1
	}

	// Rows 12 through 14.
	if !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	retentionDays := s.u8()
	locked := s.readBool()
	mask := s.u8()
	if retentionDays < 1 || retentionDays > 30 || s.status != productionSuccessV1 || mask > 3 || locked && mask == 0 || !s.boolValue() || !s.boolValue() || !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}

	// Row 15.
	if !s.boolValue() {
		return productionSettingsV1{}, s.failure()
	}
	ruleCount := s.u16()
	if ruleCount > 256 {
		return productionSettingsV1{}, productionSizeLimitV1
	}
	previous = nil
	for index := 0; index < int(ruleCount); index++ {
		_, encoded := s.id(true, true)
		if s.status != productionSuccessV1 || index > 0 && bytes.Compare(previous, encoded) >= 0 {
			s.invalid()
			return productionSettingsV1{}, s.failure()
		}
		previous = encoded
	}
	if s.status != productionSuccessV1 || s.offset != len(input) {
		return productionSettingsV1{}, s.failure()
	}
	return out, productionSuccessV1
}

func validProductionDNSPresenceV1(value productionSettingsV1) bool {
	primary, secondary, resolver := value.customPrimary.family != 0, value.customSecondary.family != 0, len(value.resolverCatalog) != 0
	switch value.dnsMode {
	case 1, 2:
		return !primary && !secondary && !resolver
	case 3:
		return !primary && !secondary && resolver
	case 4:
		return primary && !resolver && (!secondary || value.customPrimary != value.customSecondary)
	default:
		return false
	}
}

func (s *productionSettingsScannerV1) need(length int) bool {
	if s.status != productionSuccessV1 || length < 0 || length > len(s.input)-s.offset {
		s.invalid()
		return false
	}
	return true
}

func (s *productionSettingsScannerV1) invalid() {
	if s.status == productionSuccessV1 {
		s.status = productionInvalidRequestV1
	}
}

func (s *productionSettingsScannerV1) failure() productionStatusV1 {
	if s.status == productionSuccessV1 {
		return productionInvalidRequestV1
	}
	return s.status
}

func (s *productionSettingsScannerV1) u8() uint8 {
	if !s.need(1) {
		return 0
	}
	value := s.input[s.offset]
	s.offset++
	return value
}

func (s *productionSettingsScannerV1) u16() uint16 {
	if !s.need(2) {
		return 0
	}
	value := binary.BigEndian.Uint16(s.input[s.offset : s.offset+2])
	s.offset += 2
	return value
}

func (s *productionSettingsScannerV1) readBool() bool {
	value := s.u8()
	if value > 1 {
		s.invalid()
	}
	return value == 1
}

func (s *productionSettingsScannerV1) boolValue() bool {
	_ = s.readBool()
	return s.status == productionSuccessV1
}

func (s *productionSettingsScannerV1) closed(value, first, last uint8) bool {
	if s.status != productionSuccessV1 || value < first || value > last {
		s.invalid()
		return false
	}
	return true
}

func (s *productionSettingsScannerV1) id(catalog, required bool) ([]byte, []byte) {
	start := s.offset
	length := int(s.u8())
	if s.status != productionSuccessV1 {
		return nil, nil
	}
	if length > 64 {
		s.status = productionSizeLimitV1
		return nil, nil
	}
	if required && length == 0 || !s.need(length) {
		s.invalid()
		return nil, nil
	}
	value := s.input[s.offset : s.offset+length]
	s.offset += length
	valid := validProductionLocalIDV1(value)
	if catalog {
		valid = validProductionCatalogIDV1(value)
	}
	if length != 0 && !valid {
		s.invalid()
		return nil, nil
	}
	return value, s.input[start:s.offset]
}

func validProductionCatalogIDV1(value []byte) bool {
	if len(value) < 1 || len(value) > 64 || !((value[0] >= 'a' && value[0] <= 'z') || (value[0] >= '0' && value[0] <= '9')) {
		return false
	}
	for _, character := range value[1:] {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func validProductionLocalIDV1(value []byte) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}

func (s *productionSettingsScannerV1) packageName() ([]byte, []byte) {
	start := s.offset
	length := int(s.u16())
	if s.status != productionSuccessV1 {
		return nil, nil
	}
	if length > 255 {
		s.status = productionSizeLimitV1
		return nil, nil
	}
	if length < 3 || !s.need(length) {
		s.invalid()
		return nil, nil
	}
	value := s.input[s.offset : s.offset+length]
	s.offset += length
	if !utf8.Valid(value) || !validRuntimePackage(string(value)) {
		s.invalid()
		return nil, nil
	}
	return value, s.input[start:s.offset]
}

func (s *productionSettingsScannerV1) address(optional bool) productionAddressV1 {
	family := s.u8()
	if s.status != productionSuccessV1 {
		return productionAddressV1{}
	}
	if optional && family == 0 {
		return productionAddressV1{}
	}
	length := 0
	switch family {
	case 4:
		length = 4
	case 6:
		length = 16
	default:
		s.invalid()
		return productionAddressV1{}
	}
	if !s.need(length) {
		return productionAddressV1{}
	}
	var out productionAddressV1
	out.family = family
	copy(out.value[:], s.input[s.offset:s.offset+length])
	s.offset += length
	if family == 6 {
		address := netip.AddrFrom16(out.value)
		if address.Is4In6() {
			s.invalid()
			return productionAddressV1{}
		}
	}
	return out
}

func (s *productionSettingsScannerV1) prefix() productionPrefixV1 {
	start := s.offset
	address := s.address(false)
	bits := s.u8()
	if s.status != productionSuccessV1 {
		return productionPrefixV1{}
	}
	var parsed netip.Addr
	if address.family == 4 {
		var value [4]byte
		copy(value[:], address.value[:4])
		parsed = netip.AddrFrom4(value)
	} else {
		parsed = netip.AddrFrom16(address.value)
	}
	if int(bits) > parsed.BitLen() {
		s.invalid()
		return productionPrefixV1{}
	}
	prefix := netip.PrefixFrom(parsed, int(bits))
	if prefix.Masked() != prefix {
		s.invalid()
		return productionPrefixV1{}
	}
	return productionPrefixV1{address: address, bits: bits, encoded: s.input[start:s.offset]}
}
