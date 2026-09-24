// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"unicode"
	"unicode/utf8"

	"kurdistan/internal/product/envelope"
)

const productionSnapshotMaxBytesV1 = 32768

const (
	productionCapabilityRawIPV1             uint16 = 1 << 0
	productionCapabilityProxyStreamV1       uint16 = 1 << 1
	productionCapabilityProbeActiveV1       uint16 = 1 << 2
	productionCapabilityProbeDisconnectedV1 uint16 = 1 << 3
	productionCapabilityUpdateV1            uint16 = 1 << 4
	productionCapabilityMaskV1                     = uint16(0x1f)
)

type productionSafeLabelV1 struct {
	availability uint8
	value        string
}

type productionSnapshotV1 struct {
	profileGeneration                                                      uint64
	planDigest                                                             [32]byte
	profileFingerprint, strategyFingerprint, relayFingerprint              [16]byte
	nodeLabel, pathLabel, strategyLabel                                    productionSafeLabelV1
	exitRegion                                                             uint8
	effectiveMode, effectiveIP, effectiveDNSMode                           uint8
	effectiveMTU                                                           uint16
	metered                                                                bool
	perAppMode                                                             uint8
	effectivePackageCount                                                  uint16
	clientV4, clientV6                                                     productionAddressV1
	dnsCount                                                               uint8
	dns                                                                    [2]productionAddressV1
	routeCount                                                             uint16
	routes                                                                 [256]productionPrefixV1
	signedCapabilityMask, nativeCapabilityMask, effectiveCapabilityMask    uint16
	packetMax                                                              uint32
	queuePackets, incompleteOps                                            uint16
	payloadProtocolMask                                                    uint8
	signedReconnectMax, nativeReconnectMax, effectiveAutomaticReconnectMax uint8
	fallbackAttemptMax, fallbackAttemptsUsed                               uint8
	dialTimeoutMillis, idleTimeoutMillis                                   uint32
	signedStreamMax, nativeStreamMax, effectiveStreamMax                   uint8
	nativeClientMax, effectiveClientMax                                    uint8
	signedBufferBytes, effectiveTotalBufferBytes                           uint32
	effectiveProxyIdleSeconds, signedConnectMillis                         uint16
	perDirectionQueueBytes                                                 uint32
	streamChunkMax                                                         uint16
	probeMaxConcurrent, probeMaxSamples                                    uint8
	probeMinAttemptIntervalMillis                                          uint32
	probeAttemptsPerMinute                                                 uint8
	probeMaxTotalMillis                                                    uint16
	updateMaxArtifactBytes                                                 uint32
	updateMaxTimeoutMillis                                                 uint16
	updateMinCheckIntervalSeconds                                          uint32
	rawFlowStatus                                                          uint8
	nativeTCPFlowMax, nativeUDPFlowMax                                     uint16
	effectiveTCPFlowMax, effectiveUDPFlowMax                               uint16
	effectiveFlowIdleMillis                                                uint32
	signedRawFlowCapStatus                                                 uint8
	nativeAggregateBufferMax, effectiveAggregateBufferMax                  uint32
	flowTableReservedBytes                                                 uint32
}

func encodeProductionSnapshotV1(value productionSnapshotV1, output []byte) (int, productionStatusV1) {
	size, status := validateProductionSnapshotV1(value)
	if status != productionSuccessV1 {
		return 0, status
	}
	if len(output) < size {
		return 0, productionSizeLimitV1
	}
	encoded := make([]byte, 0, size)
	encoded = append(encoded, 'K', 'P', 'N', '1', 1, 0, 0, 0, 0, 0, 0, 0)
	encoded = appendProductionSnapshotU64V1(encoded, value.profileGeneration)
	encoded = append(encoded, value.planDigest[:]...)
	encoded = append(encoded, value.profileFingerprint[:]...)
	encoded = append(encoded, value.strategyFingerprint[:]...)
	encoded = append(encoded, value.relayFingerprint[:]...)
	for _, label := range []productionSafeLabelV1{value.nodeLabel, value.pathLabel, value.strategyLabel} {
		encoded = append(encoded, label.availability)
		encoded = appendProductionSnapshotU16V1(encoded, uint16(len(label.value)))
		encoded = append(encoded, label.value...)
	}
	encoded = append(encoded, value.exitRegion, value.effectiveMode, value.effectiveIP, value.effectiveDNSMode)
	encoded = appendProductionSnapshotU16V1(encoded, value.effectiveMTU)
	encoded = append(encoded, boolByteProductionV1(value.metered), value.perAppMode)
	encoded = appendProductionSnapshotU16V1(encoded, value.effectivePackageCount)
	encoded = appendProductionSnapshotAddressV1(encoded, value.clientV4)
	encoded = appendProductionSnapshotAddressV1(encoded, value.clientV6)
	encoded = append(encoded, value.dnsCount)
	for index := 0; index < int(value.dnsCount); index++ {
		encoded = appendProductionSnapshotAddressV1(encoded, value.dns[index])
	}
	encoded = appendProductionSnapshotU16V1(encoded, value.routeCount)
	for index := 0; index < int(value.routeCount); index++ {
		encoded = appendProductionSnapshotAddressV1(encoded, value.routes[index].address)
		encoded = append(encoded, value.routes[index].bits)
	}
	encoded = appendProductionSnapshotU16V1(encoded, value.signedCapabilityMask)
	encoded = appendProductionSnapshotU16V1(encoded, value.nativeCapabilityMask)
	encoded = appendProductionSnapshotU16V1(encoded, value.effectiveCapabilityMask)
	encoded = appendProductionSnapshotU32V1(encoded, value.packetMax)
	encoded = appendProductionSnapshotU16V1(encoded, value.queuePackets)
	encoded = appendProductionSnapshotU16V1(encoded, value.incompleteOps)
	encoded = append(encoded, value.payloadProtocolMask)
	encoded = append(encoded, value.signedReconnectMax, value.nativeReconnectMax, value.effectiveAutomaticReconnectMax, value.fallbackAttemptMax, value.fallbackAttemptsUsed)
	encoded = appendProductionSnapshotU32V1(encoded, value.dialTimeoutMillis)
	encoded = appendProductionSnapshotU32V1(encoded, value.idleTimeoutMillis)
	encoded = append(encoded, value.signedStreamMax, value.nativeStreamMax, value.effectiveStreamMax, value.nativeClientMax, value.effectiveClientMax)
	encoded = appendProductionSnapshotU32V1(encoded, value.signedBufferBytes)
	encoded = appendProductionSnapshotU32V1(encoded, value.effectiveTotalBufferBytes)
	encoded = appendProductionSnapshotU16V1(encoded, value.effectiveProxyIdleSeconds)
	encoded = appendProductionSnapshotU16V1(encoded, value.signedConnectMillis)
	encoded = appendProductionSnapshotU32V1(encoded, value.perDirectionQueueBytes)
	encoded = appendProductionSnapshotU16V1(encoded, value.streamChunkMax)
	encoded = append(encoded, value.probeMaxConcurrent, value.probeMaxSamples)
	encoded = appendProductionSnapshotU32V1(encoded, value.probeMinAttemptIntervalMillis)
	encoded = append(encoded, value.probeAttemptsPerMinute)
	encoded = appendProductionSnapshotU16V1(encoded, value.probeMaxTotalMillis)
	encoded = appendProductionSnapshotU32V1(encoded, value.updateMaxArtifactBytes)
	encoded = appendProductionSnapshotU16V1(encoded, value.updateMaxTimeoutMillis)
	encoded = appendProductionSnapshotU32V1(encoded, value.updateMinCheckIntervalSeconds)
	encoded = append(encoded, value.rawFlowStatus)
	encoded = appendProductionSnapshotU16V1(encoded, value.nativeTCPFlowMax)
	encoded = appendProductionSnapshotU16V1(encoded, value.nativeUDPFlowMax)
	encoded = appendProductionSnapshotU16V1(encoded, value.effectiveTCPFlowMax)
	encoded = appendProductionSnapshotU16V1(encoded, value.effectiveUDPFlowMax)
	encoded = appendProductionSnapshotU32V1(encoded, value.effectiveFlowIdleMillis)
	encoded = append(encoded, value.signedRawFlowCapStatus)
	encoded = appendProductionSnapshotU32V1(encoded, value.nativeAggregateBufferMax)
	encoded = appendProductionSnapshotU32V1(encoded, value.effectiveAggregateBufferMax)
	encoded = appendProductionSnapshotU32V1(encoded, value.flowTableReservedBytes)
	if len(encoded) != size {
		return 0, productionInternalFailureV1
	}
	binary.BigEndian.PutUint32(encoded[8:12], uint32(size))
	copy(output[:size], encoded)
	return size, productionSuccessV1
}

func decodeProductionSnapshotV1(input []byte) (productionSnapshotV1, productionStatusV1) {
	if len(input) > productionSnapshotMaxBytesV1 {
		return productionSnapshotV1{}, productionSizeLimitV1
	}
	if len(input) < 12 || !bytes.Equal(input[:4], []byte("KPN1")) || input[4] != 1 || input[5] != 0 || input[6] != 0 || input[7] != 0 || binary.BigEndian.Uint32(input[8:12]) != uint32(len(input)) {
		return productionSnapshotV1{}, productionInvalidRequestV1
	}
	s := productionSnapshotScannerV1{input: input, offset: 12, status: productionSuccessV1}
	var value productionSnapshotV1
	value.profileGeneration = s.u64()
	s.copyFixed(value.planDigest[:])
	s.copyFixed(value.profileFingerprint[:])
	s.copyFixed(value.strategyFingerprint[:])
	s.copyFixed(value.relayFingerprint[:])
	value.nodeLabel = s.label()
	value.pathLabel = s.label()
	value.strategyLabel = s.label()
	value.exitRegion, value.effectiveMode, value.effectiveIP, value.effectiveDNSMode = s.u8(), s.u8(), s.u8(), s.u8()
	value.effectiveMTU = s.u16()
	value.metered = s.readBool()
	value.perAppMode = s.u8()
	value.effectivePackageCount = s.u16()
	value.clientV4, value.clientV6 = s.address(true), s.address(true)
	value.dnsCount = s.u8()
	if value.dnsCount > 2 {
		return productionSnapshotV1{}, productionSizeLimitV1
	}
	for index := 0; index < int(value.dnsCount); index++ {
		value.dns[index] = s.address(false)
	}
	value.routeCount = s.u16()
	if value.routeCount > 256 {
		return productionSnapshotV1{}, productionSizeLimitV1
	}
	for index := 0; index < int(value.routeCount); index++ {
		value.routes[index] = s.prefix()
	}
	value.signedCapabilityMask, value.nativeCapabilityMask, value.effectiveCapabilityMask = s.u16(), s.u16(), s.u16()
	value.packetMax, value.queuePackets, value.incompleteOps, value.payloadProtocolMask = s.u32(), s.u16(), s.u16(), s.u8()
	value.signedReconnectMax, value.nativeReconnectMax, value.effectiveAutomaticReconnectMax = s.u8(), s.u8(), s.u8()
	value.fallbackAttemptMax, value.fallbackAttemptsUsed = s.u8(), s.u8()
	value.dialTimeoutMillis, value.idleTimeoutMillis = s.u32(), s.u32()
	value.signedStreamMax, value.nativeStreamMax, value.effectiveStreamMax = s.u8(), s.u8(), s.u8()
	value.nativeClientMax, value.effectiveClientMax = s.u8(), s.u8()
	value.signedBufferBytes, value.effectiveTotalBufferBytes = s.u32(), s.u32()
	value.effectiveProxyIdleSeconds, value.signedConnectMillis = s.u16(), s.u16()
	value.perDirectionQueueBytes, value.streamChunkMax = s.u32(), s.u16()
	value.probeMaxConcurrent, value.probeMaxSamples = s.u8(), s.u8()
	value.probeMinAttemptIntervalMillis, value.probeAttemptsPerMinute, value.probeMaxTotalMillis = s.u32(), s.u8(), s.u16()
	value.updateMaxArtifactBytes, value.updateMaxTimeoutMillis, value.updateMinCheckIntervalSeconds = s.u32(), s.u16(), s.u32()
	value.rawFlowStatus = s.u8()
	value.nativeTCPFlowMax, value.nativeUDPFlowMax = s.u16(), s.u16()
	value.effectiveTCPFlowMax, value.effectiveUDPFlowMax = s.u16(), s.u16()
	value.effectiveFlowIdleMillis, value.signedRawFlowCapStatus = s.u32(), s.u8()
	value.nativeAggregateBufferMax, value.effectiveAggregateBufferMax, value.flowTableReservedBytes = s.u32(), s.u32(), s.u32()
	if s.status != productionSuccessV1 || s.offset != len(input) {
		return productionSnapshotV1{}, statusOrInvalidProductionV1(s.status)
	}
	if _, status := validateProductionSnapshotV1(value); status != productionSuccessV1 {
		return productionSnapshotV1{}, status
	}
	return value, productionSuccessV1
}

func validateProductionSnapshotV1(value productionSnapshotV1) (int, productionStatusV1) {
	if value.effectivePackageCount > 256 {
		return 0, productionSizeLimitV1
	}
	if value.profileGeneration == 0 || value.planDigest == ([32]byte{}) || value.exitRegion > 6 || value.effectiveMode < 1 || value.effectiveMode > 3 || value.effectiveIP < 2 || value.effectiveIP > 4 || value.effectiveDNSMode < 1 || value.effectiveDNSMode > 4 || value.effectiveMTU < 1280 || value.effectiveMTU > 1500 || !validProductionSnapshotPerAppV1(value.perAppMode, value.effectivePackageCount) {
		return 0, productionInvalidRequestV1
	}
	size := uint64(220)
	for _, label := range []productionSafeLabelV1{value.nodeLabel, value.pathLabel, value.strategyLabel} {
		if !validProductionSafeLabelV1(label) {
			if len(label.value) > 384 {
				return 0, productionSizeLimitV1
			}
			return 0, productionInvalidRequestV1
		}
		size += uint64(len(label.value))
	}
	for _, address := range []productionAddressV1{value.clientV4, value.clientV6} {
		length, ok := productionAddressEncodedLengthV1(address, true)
		if !ok {
			return 0, productionInvalidRequestV1
		}
		size += uint64(length - 1)
	}
	if value.dnsCount > 2 || value.routeCount > 256 {
		return 0, productionSizeLimitV1
	}
	var previous []byte
	for index := 0; index < int(value.dnsCount); index++ {
		length, ok := productionAddressEncodedLengthV1(value.dns[index], false)
		if !ok {
			return 0, productionInvalidRequestV1
		}
		encoded := productionAddressEncodingV1(value.dns[index])
		if index > 0 && bytes.Compare(previous, encoded) >= 0 {
			return 0, productionInvalidRequestV1
		}
		previous = encoded
		size += uint64(length)
	}
	previous = nil
	for index := 0; index < int(value.routeCount); index++ {
		if !validProductionPrefixValueV1(value.routes[index]) {
			return 0, productionInvalidRequestV1
		}
		encoded := append(productionAddressEncodingV1(value.routes[index].address), value.routes[index].bits)
		if index > 0 && bytes.Compare(previous, encoded) >= 0 {
			return 0, productionInvalidRequestV1
		}
		previous = encoded
		size += uint64(len(encoded))
	}
	if !validProductionSnapshotNetworkV1(value) {
		return 0, productionInvalidRequestV1
	}
	if value.signedCapabilityMask&^productionCapabilityMaskV1 != 0 || value.nativeCapabilityMask&^productionCapabilityMaskV1 != 0 || value.effectiveCapabilityMask&^productionCapabilityMaskV1 != 0 || value.effectiveCapabilityMask&^value.signedCapabilityMask != 0 || value.effectiveCapabilityMask&^value.nativeCapabilityMask != 0 || !validProductionSnapshotModeCapabilitiesV1(value) {
		return 0, productionInvalidRequestV1
	}
	if value.packetMax != uint32(value.effectiveMTU) || value.packetMax < 40 || value.queuePackets < 1 || value.queuePackets > 256 || value.incompleteOps < 1 || value.incompleteOps > 64 || value.payloadProtocolMask == 0 || value.payloadProtocolMask&^uint8(0x0f) != 0 {
		return 0, productionInvalidRequestV1
	}
	if value.signedReconnectMax == 0 || value.signedReconnectMax > 5 || value.nativeReconnectMax != 10 || value.effectiveAutomaticReconnectMax > 10 || value.effectiveAutomaticReconnectMax > value.signedReconnectMax || value.effectiveAutomaticReconnectMax > value.nativeReconnectMax || value.fallbackAttemptMax == 0 || value.fallbackAttemptMax > 5 || value.fallbackAttemptMax > value.signedReconnectMax || value.fallbackAttemptMax > value.nativeReconnectMax || value.fallbackAttemptsUsed > value.fallbackAttemptMax || value.dialTimeoutMillis == 0 || value.dialTimeoutMillis > 10000 || value.idleTimeoutMillis == 0 {
		return 0, productionInvalidRequestV1
	}
	if !validProductionSnapshotProxyV1(value) || !validProductionSnapshotProbeV1(value) || !validProductionSnapshotUpdateV1(value) {
		return 0, productionInvalidRequestV1
	}
	if value.signedRawFlowCapStatus != 0 || value.nativeAggregateBufferMax != 128<<20 || value.effectiveAggregateBufferMax < 40<<20 || value.effectiveAggregateBufferMax > value.nativeAggregateBufferMax {
		if value.nativeAggregateBufferMax > 128<<20 || value.effectiveAggregateBufferMax > 128<<20 {
			return 0, productionSizeLimitV1
		}
		return 0, productionInvalidRequestV1
	}
	switch value.rawFlowStatus {
	case 1:
		if value.effectiveMode == 3 || value.nativeTCPFlowMax != 4096 || value.nativeUDPFlowMax != 2048 || value.effectiveTCPFlowMax < 16 || value.effectiveTCPFlowMax > value.nativeTCPFlowMax || value.effectiveUDPFlowMax > value.nativeUDPFlowMax || value.effectiveFlowIdleMillis == 0 || value.effectiveFlowIdleMillis > 3600000 || value.effectiveFlowIdleMillis > value.idleTimeoutMillis || value.flowTableReservedBytes == 0 {
			return 0, productionInvalidRequestV1
		}
		if value.flowTableReservedBytes > 1<<20 || value.flowTableReservedBytes > value.effectiveAggregateBufferMax {
			return 0, productionSizeLimitV1
		}
	case 2:
		if value.effectiveMode != 3 || value.nativeTCPFlowMax != 0 || value.nativeUDPFlowMax != 0 || value.effectiveTCPFlowMax != 0 || value.effectiveUDPFlowMax != 0 || value.effectiveFlowIdleMillis != 0 || value.flowTableReservedBytes != 0 {
			return 0, productionInvalidRequestV1
		}
	default:
		return 0, productionInvalidRequestV1
	}
	if size > productionSnapshotMaxBytesV1 {
		return 0, productionSizeLimitV1
	}
	return int(size), productionSuccessV1
}

func validProductionSnapshotPerAppV1(mode uint8, count uint16) bool {
	switch mode {
	case 1:
		return count == 0
	case 2:
		return count != 0
	case 3:
		return true
	default:
		return false
	}
}

func validProductionSnapshotNetworkV1(value productionSnapshotV1) bool {
	default4 := func(prefix productionPrefixV1) bool {
		return prefix.address.family == 4 && prefix.bits == 0 && prefix.address.value == ([16]byte{})
	}
	default6 := func(prefix productionPrefixV1) bool {
		return prefix.address.family == 6 && prefix.bits == 0 && prefix.address.value == ([16]byte{})
	}
	switch value.effectiveMode {
	case 3:
		return value.clientV4.family == 0 && value.clientV6.family == 0 && value.dnsCount == 0 && value.routeCount == 0
	}
	switch value.effectiveIP {
	case 2:
		return value.clientV4.family == 4 && value.clientV6.family == 0 && value.dnsCount == 1 && value.dns[0].family == 4 && value.routeCount == 1 && default4(value.routes[0])
	case 3:
		return value.clientV4.family == 0 && value.clientV6.family == 6 && value.dnsCount == 1 && value.dns[0].family == 6 && value.routeCount == 1 && default6(value.routes[0])
	case 4:
		return value.clientV4.family == 4 && value.clientV6.family == 6 && value.dnsCount == 2 && value.dns[0].family == 4 && value.dns[1].family == 6 && value.routeCount == 2 && default4(value.routes[0]) && default6(value.routes[1])
	default:
		return false
	}
}

func validProductionSnapshotModeCapabilitiesV1(value productionSnapshotV1) bool {
	raw := value.effectiveCapabilityMask&productionCapabilityRawIPV1 != 0
	proxy := value.effectiveCapabilityMask&productionCapabilityProxyStreamV1 != 0
	switch value.effectiveMode {
	case 1:
		return raw && !proxy
	case 2:
		return raw && proxy
	case 3:
		return !raw && proxy
	default:
		return false
	}
}

func validProductionSnapshotProxyV1(value productionSnapshotV1) bool {
	active := value.effectiveCapabilityMask&productionCapabilityProxyStreamV1 != 0
	zero := value.signedStreamMax == 0 && value.nativeStreamMax == 0 && value.effectiveStreamMax == 0 && value.nativeClientMax == 0 && value.effectiveClientMax == 0 && value.signedBufferBytes == 0 && value.effectiveTotalBufferBytes == 0 && value.effectiveProxyIdleSeconds == 0 && value.signedConnectMillis == 0 && value.perDirectionQueueBytes == 0 && value.streamChunkMax == 0
	if !active {
		return zero
	}
	return value.signedStreamMax >= 1 && value.signedStreamMax <= 64 && value.nativeStreamMax >= 1 && value.nativeStreamMax <= 64 && value.effectiveStreamMax >= 1 && value.effectiveStreamMax <= value.signedStreamMax && value.effectiveStreamMax <= value.nativeStreamMax && value.nativeClientMax >= 1 && value.nativeClientMax <= 16 && value.effectiveClientMax >= 1 && value.effectiveClientMax <= value.nativeClientMax && value.signedBufferBytes >= 16<<20 && value.signedBufferBytes <= 128<<20 && value.effectiveTotalBufferBytes >= 16<<20 && value.effectiveTotalBufferBytes <= value.signedBufferBytes && value.effectiveTotalBufferBytes <= value.effectiveAggregateBufferMax && value.effectiveProxyIdleSeconds >= 30 && value.effectiveProxyIdleSeconds <= 3600 && value.signedConnectMillis >= 1000 && value.signedConnectMillis <= 30000 && value.perDirectionQueueBytes >= 1024 && value.perDirectionQueueBytes <= 65536 && value.streamChunkMax >= 1 && value.streamChunkMax <= 16384 && uint32(value.streamChunkMax) <= value.perDirectionQueueBytes
}

func validProductionSnapshotProbeV1(value productionSnapshotV1) bool {
	present := value.signedCapabilityMask&(productionCapabilityProbeActiveV1|productionCapabilityProbeDisconnectedV1) != 0
	zero := value.probeMaxConcurrent == 0 && value.probeMaxSamples == 0 && value.probeMinAttemptIntervalMillis == 0 && value.probeAttemptsPerMinute == 0 && value.probeMaxTotalMillis == 0
	if !present {
		return zero
	}
	return value.probeMaxConcurrent >= 1 && value.probeMaxConcurrent <= 4 && value.probeMaxSamples >= 1 && value.probeMaxSamples <= 10 && value.probeMinAttemptIntervalMillis >= 1000 && value.probeMinAttemptIntervalMillis <= 3600000 && value.probeAttemptsPerMinute >= 1 && value.probeAttemptsPerMinute <= 60 && value.probeMaxTotalMillis >= 1000 && value.probeMaxTotalMillis <= 30000
}

func validProductionSnapshotUpdateV1(value productionSnapshotV1) bool {
	present := value.signedCapabilityMask&productionCapabilityUpdateV1 != 0
	zero := value.updateMaxArtifactBytes == 0 && value.updateMaxTimeoutMillis == 0 && value.updateMinCheckIntervalSeconds == 0
	if !present {
		return zero
	}
	return value.updateMaxArtifactBytes >= 1 && value.updateMaxArtifactBytes <= envelope.MaxTotalInputBytes && value.updateMaxTimeoutMillis >= 1000 && value.updateMaxTimeoutMillis <= 30000 && value.updateMinCheckIntervalSeconds >= 60 && value.updateMinCheckIntervalSeconds <= 604800
}

func validProductionSafeLabelV1(label productionSafeLabelV1) bool {
	if label.availability == 0 {
		return label.value == ""
	}
	if label.availability != 1 || len(label.value) < 1 || len(label.value) > 384 || !utf8.ValidString(label.value) {
		return false
	}
	count := 0
	for index, character := range label.value {
		if character > 0xffff || !(unicode.IsLetter(character) || unicode.IsDigit(character) || character == ' ' || character == '-' || character == '_') {
			return false
		}
		if index == 0 && character == ' ' {
			return false
		}
		count++
	}
	last, _ := utf8.DecodeLastRuneInString(label.value)
	return count <= 96 && last != ' '
}

func productionAddressEncodedLengthV1(value productionAddressV1, optional bool) (int, bool) {
	if optional && value.family == 0 {
		return 1, value.value == ([16]byte{})
	}
	switch value.family {
	case 4:
		var tail [12]byte
		copy(tail[:], value.value[4:])
		return 5, tail == ([12]byte{})
	case 6:
		address := netip.AddrFrom16(value.value)
		return 17, !address.Is4In6()
	default:
		return 0, false
	}
}

func productionAddressEncodingV1(value productionAddressV1) []byte {
	length, _ := productionAddressEncodedLengthV1(value, true)
	out := make([]byte, length)
	out[0] = value.family
	if value.family == 4 {
		copy(out[1:], value.value[:4])
	} else if value.family == 6 {
		copy(out[1:], value.value[:])
	}
	return out
}

func validProductionPrefixValueV1(value productionPrefixV1) bool {
	if _, ok := productionAddressEncodedLengthV1(value.address, false); !ok {
		return false
	}
	var address netip.Addr
	if value.address.family == 4 {
		var raw [4]byte
		copy(raw[:], value.address.value[:4])
		address = netip.AddrFrom4(raw)
	} else {
		address = netip.AddrFrom16(value.address.value)
	}
	if int(value.bits) > address.BitLen() {
		return false
	}
	prefix := netip.PrefixFrom(address, int(value.bits))
	return prefix.Masked() == prefix
}

func appendProductionSnapshotU16V1(output []byte, value uint16) []byte {
	return append(output, byte(value>>8), byte(value))
}

func appendProductionSnapshotU32V1(output []byte, value uint32) []byte {
	return append(output, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func appendProductionSnapshotU64V1(output []byte, value uint64) []byte {
	return append(output, byte(value>>56), byte(value>>48), byte(value>>40), byte(value>>32), byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func appendProductionSnapshotAddressV1(output []byte, value productionAddressV1) []byte {
	return append(output, productionAddressEncodingV1(value)...)
}

func boolByteProductionV1(value bool) byte {
	if value {
		return 1
	}
	return 0
}

type productionSnapshotScannerV1 struct {
	input  []byte
	offset int
	status productionStatusV1
}

func (s *productionSnapshotScannerV1) need(length int) bool {
	if s.status != productionSuccessV1 || length < 0 || length > len(s.input)-s.offset {
		if s.status == productionSuccessV1 {
			s.status = productionInvalidRequestV1
		}
		return false
	}
	return true
}

func (s *productionSnapshotScannerV1) u8() uint8 {
	if !s.need(1) {
		return 0
	}
	value := s.input[s.offset]
	s.offset++
	return value
}

func (s *productionSnapshotScannerV1) u16() uint16 {
	if !s.need(2) {
		return 0
	}
	value := binary.BigEndian.Uint16(s.input[s.offset : s.offset+2])
	s.offset += 2
	return value
}

func (s *productionSnapshotScannerV1) u32() uint32 {
	if !s.need(4) {
		return 0
	}
	value := binary.BigEndian.Uint32(s.input[s.offset : s.offset+4])
	s.offset += 4
	return value
}

func (s *productionSnapshotScannerV1) u64() uint64 {
	if !s.need(8) {
		return 0
	}
	value := binary.BigEndian.Uint64(s.input[s.offset : s.offset+8])
	s.offset += 8
	return value
}

func (s *productionSnapshotScannerV1) copyFixed(output []byte) {
	if !s.need(len(output)) {
		return
	}
	copy(output, s.input[s.offset:s.offset+len(output)])
	s.offset += len(output)
}

func (s *productionSnapshotScannerV1) readBool() bool {
	value := s.u8()
	if value > 1 && s.status == productionSuccessV1 {
		s.status = productionInvalidRequestV1
	}
	return value == 1
}

func (s *productionSnapshotScannerV1) label() productionSafeLabelV1 {
	availability := s.u8()
	length := int(s.u16())
	if length > 384 {
		s.status = productionSizeLimitV1
		return productionSafeLabelV1{}
	}
	if !s.need(length) {
		return productionSafeLabelV1{}
	}
	value := string(s.input[s.offset : s.offset+length])
	s.offset += length
	return productionSafeLabelV1{availability: availability, value: value}
}

func (s *productionSnapshotScannerV1) address(optional bool) productionAddressV1 {
	family := s.u8()
	if optional && family == 0 {
		return productionAddressV1{}
	}
	length := 0
	if family == 4 {
		length = 4
	} else if family == 6 {
		length = 16
	} else {
		if s.status == productionSuccessV1 {
			s.status = productionInvalidRequestV1
		}
		return productionAddressV1{}
	}
	if !s.need(length) {
		return productionAddressV1{}
	}
	var value productionAddressV1
	value.family = family
	copy(value.value[:], s.input[s.offset:s.offset+length])
	s.offset += length
	if _, ok := productionAddressEncodedLengthV1(value, optional); !ok {
		s.status = productionInvalidRequestV1
	}
	return value
}

func (s *productionSnapshotScannerV1) prefix() productionPrefixV1 {
	address := s.address(false)
	bits := s.u8()
	return productionPrefixV1{address: address, bits: bits}
}
