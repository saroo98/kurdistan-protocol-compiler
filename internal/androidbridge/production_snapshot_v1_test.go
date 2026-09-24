// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"reflect"
	"testing"
)

func testSnapshotAddressV1(family uint8, raw ...byte) productionAddressV1 {
	var value productionAddressV1
	value.family = family
	copy(value.value[:], raw)
	return value
}

func testSnapshotPrefixV1(address productionAddressV1, bits uint8) productionPrefixV1 {
	return productionPrefixV1{address: address, bits: bits}
}

func productionSnapshotFixtureV1() productionSnapshotV1 {
	var value productionSnapshotV1
	value.profileGeneration = ^uint64(0)
	for index := range value.planDigest {
		value.planDigest[index] = byte(index + 1)
	}
	for index := range value.profileFingerprint {
		value.profileFingerprint[index] = byte(0x10 + index)
		value.strategyFingerprint[index] = byte(0x20 + index)
		value.relayFingerprint[index] = byte(0x30 + index)
	}
	value.nodeLabel = productionSafeLabelV1{availability: 1, value: "Node 1"}
	value.pathLabel = productionSafeLabelV1{}
	value.strategyLabel = productionSafeLabelV1{availability: 1, value: "Kurd_TCP"}
	value.exitRegion = 1
	value.effectiveMode, value.effectiveIP, value.effectiveDNSMode = 2, 4, 1
	value.effectiveMTU, value.metered, value.perAppMode, value.effectivePackageCount = 1280, true, 2, 2
	value.clientV4 = testSnapshotAddressV1(4, 10, 77, 0, 2)
	value.clientV6 = testSnapshotAddressV1(6, 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2)
	value.dnsCount = 2
	value.dns[0] = testSnapshotAddressV1(4, 10, 77, 0, 1)
	value.dns[1] = testSnapshotAddressV1(6, 0x20, 1, 0xdb, 8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1)
	value.routeCount = 2
	value.routes[0] = testSnapshotPrefixV1(testSnapshotAddressV1(4, 0, 0, 0, 0), 0)
	value.routes[1] = testSnapshotPrefixV1(testSnapshotAddressV1(6), 0)
	value.signedCapabilityMask, value.nativeCapabilityMask, value.effectiveCapabilityMask = 0x1f, 0x1f, 0x1f
	value.packetMax, value.queuePackets, value.incompleteOps, value.payloadProtocolMask = 1280, 100, 64, 0x0c
	value.signedReconnectMax, value.nativeReconnectMax, value.effectiveAutomaticReconnectMax = 3, 10, 2
	value.fallbackAttemptMax, value.fallbackAttemptsUsed = 2, 0
	value.dialTimeoutMillis, value.idleTimeoutMillis = 5000, 30000
	value.signedStreamMax, value.nativeStreamMax, value.effectiveStreamMax = 16, 64, 8
	value.nativeClientMax, value.effectiveClientMax = 16, 4
	value.signedBufferBytes, value.effectiveTotalBufferBytes = 32<<20, 32<<20
	value.effectiveProxyIdleSeconds, value.signedConnectMillis = 300, 5000
	value.perDirectionQueueBytes, value.streamChunkMax = 65536, 16384
	value.probeMaxConcurrent, value.probeMaxSamples = 4, 10
	value.probeMinAttemptIntervalMillis, value.probeAttemptsPerMinute, value.probeMaxTotalMillis = 1000, 60, 30000
	value.updateMaxArtifactBytes, value.updateMaxTimeoutMillis, value.updateMinCheckIntervalSeconds = 1<<20, 30000, 60
	value.rawFlowStatus = 1
	value.nativeTCPFlowMax, value.nativeUDPFlowMax = 4096, 2048
	value.effectiveTCPFlowMax, value.effectiveUDPFlowMax = 256, 128
	value.effectiveFlowIdleMillis, value.signedRawFlowCapStatus = 30000, 0
	value.nativeAggregateBufferMax, value.effectiveAggregateBufferMax, value.flowTableReservedBytes = 128<<20, 80<<20, 65536
	return value
}

func appendSnapshotU16V1(out []byte, value uint16) []byte {
	return append(out, byte(value>>8), byte(value))
}

func appendSnapshotU32V1(out []byte, value uint32) []byte {
	return append(out, byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func appendSnapshotU64V1(out []byte, value uint64) []byte {
	return append(out, byte(value>>56), byte(value>>48), byte(value>>40), byte(value>>32), byte(value>>24), byte(value>>16), byte(value>>8), byte(value))
}

func appendSnapshotAddressV1(out []byte, value productionAddressV1, optional bool) []byte {
	out = append(out, value.family)
	if value.family == 4 {
		return append(out, value.value[:4]...)
	}
	if value.family == 6 {
		return append(out, value.value[:]...)
	}
	if optional && value.family == 0 {
		return out
	}
	panic("invalid fixture address")
}

func productionSnapshotGoldenV1(value productionSnapshotV1) []byte {
	out := make([]byte, 12)
	copy(out[:4], "KPN1")
	out[4] = 1
	out = appendSnapshotU64V1(out, value.profileGeneration)
	out = append(out, value.planDigest[:]...)
	out = append(out, value.profileFingerprint[:]...)
	out = append(out, value.strategyFingerprint[:]...)
	out = append(out, value.relayFingerprint[:]...)
	for _, label := range []productionSafeLabelV1{value.nodeLabel, value.pathLabel, value.strategyLabel} {
		out = append(out, label.availability)
		out = appendSnapshotU16V1(out, uint16(len([]byte(label.value))))
		out = append(out, []byte(label.value)...)
	}
	out = append(out, value.exitRegion, value.effectiveMode, value.effectiveIP, value.effectiveDNSMode)
	out = appendSnapshotU16V1(out, value.effectiveMTU)
	if value.metered {
		out = append(out, 1)
	} else {
		out = append(out, 0)
	}
	out = append(out, value.perAppMode)
	out = appendSnapshotU16V1(out, value.effectivePackageCount)
	out = appendSnapshotAddressV1(out, value.clientV4, true)
	out = appendSnapshotAddressV1(out, value.clientV6, true)
	out = append(out, value.dnsCount)
	for index := 0; index < int(value.dnsCount); index++ {
		out = appendSnapshotAddressV1(out, value.dns[index], false)
	}
	out = appendSnapshotU16V1(out, value.routeCount)
	for index := 0; index < int(value.routeCount); index++ {
		out = appendSnapshotAddressV1(out, value.routes[index].address, false)
		out = append(out, value.routes[index].bits)
	}
	out = appendSnapshotU16V1(out, value.signedCapabilityMask)
	out = appendSnapshotU16V1(out, value.nativeCapabilityMask)
	out = appendSnapshotU16V1(out, value.effectiveCapabilityMask)
	out = appendSnapshotU32V1(out, value.packetMax)
	out = appendSnapshotU16V1(out, value.queuePackets)
	out = appendSnapshotU16V1(out, value.incompleteOps)
	out = append(out, value.payloadProtocolMask)
	out = append(out, value.signedReconnectMax, value.nativeReconnectMax, value.effectiveAutomaticReconnectMax, value.fallbackAttemptMax, value.fallbackAttemptsUsed)
	out = appendSnapshotU32V1(out, value.dialTimeoutMillis)
	out = appendSnapshotU32V1(out, value.idleTimeoutMillis)
	out = append(out, value.signedStreamMax, value.nativeStreamMax, value.effectiveStreamMax, value.nativeClientMax, value.effectiveClientMax)
	out = appendSnapshotU32V1(out, value.signedBufferBytes)
	out = appendSnapshotU32V1(out, value.effectiveTotalBufferBytes)
	out = appendSnapshotU16V1(out, value.effectiveProxyIdleSeconds)
	out = appendSnapshotU16V1(out, value.signedConnectMillis)
	out = appendSnapshotU32V1(out, value.perDirectionQueueBytes)
	out = appendSnapshotU16V1(out, value.streamChunkMax)
	out = append(out, value.probeMaxConcurrent, value.probeMaxSamples)
	out = appendSnapshotU32V1(out, value.probeMinAttemptIntervalMillis)
	out = append(out, value.probeAttemptsPerMinute)
	out = appendSnapshotU16V1(out, value.probeMaxTotalMillis)
	out = appendSnapshotU32V1(out, value.updateMaxArtifactBytes)
	out = appendSnapshotU16V1(out, value.updateMaxTimeoutMillis)
	out = appendSnapshotU32V1(out, value.updateMinCheckIntervalSeconds)
	out = append(out, value.rawFlowStatus)
	out = appendSnapshotU16V1(out, value.nativeTCPFlowMax)
	out = appendSnapshotU16V1(out, value.nativeUDPFlowMax)
	out = appendSnapshotU16V1(out, value.effectiveTCPFlowMax)
	out = appendSnapshotU16V1(out, value.effectiveUDPFlowMax)
	out = appendSnapshotU32V1(out, value.effectiveFlowIdleMillis)
	out = append(out, value.signedRawFlowCapStatus)
	out = appendSnapshotU32V1(out, value.nativeAggregateBufferMax)
	out = appendSnapshotU32V1(out, value.effectiveAggregateBufferMax)
	out = appendSnapshotU32V1(out, value.flowTableReservedBytes)
	binary.BigEndian.PutUint32(out[8:12], uint32(len(out)))
	return out
}

func TestProductionSnapshotV1IndependentAllElevenRowGolden(t *testing.T) {
	value := productionSnapshotFixtureV1()
	want := productionSnapshotGoldenV1(value)
	output := bytes.Repeat([]byte{0xa5}, productionSnapshotMaxBytesV1)
	written, status := encodeProductionSnapshotV1(value, output)
	if status != productionSuccessV1 || written != len(want) || !bytes.Equal(output[:written], want) {
		t.Fatalf("encode: written=%d status=%d", written, status)
	}
	decoded, status := decodeProductionSnapshotV1(want)
	if status != productionSuccessV1 || decoded.profileGeneration != ^uint64(0) || decoded.planDigest != value.planDigest || decoded.effectiveMode != 2 || decoded.effectiveIP != 4 || decoded.dnsCount != 2 || decoded.routeCount != 2 || decoded.signedCapabilityMask != 0x1f || decoded.packetMax != 1280 || decoded.signedReconnectMax != 3 || decoded.effectiveStreamMax != 8 || decoded.probeMaxConcurrent != 4 || decoded.updateMaxArtifactBytes != 1<<20 || decoded.rawFlowStatus != 1 || decoded.effectiveAggregateBufferMax != 80<<20 {
		t.Fatalf("decode lost one or more rows: status=%d value=%+v", status, decoded)
	}
	if got := reflect.VisibleFields(reflect.TypeOf(decoded)); len(got) == 0 {
		t.Fatal("snapshot surface unavailable")
	} else {
		for _, field := range got {
			forbidden := map[string]bool{"request": true, "endpoint": true, "packages": true, "selectors": true, "policy": true, "owner": true, "token": true}
			if forbidden[field.Name] {
				t.Fatalf("decoded snapshot exposes forbidden field %q", field.Name)
			}
		}
	}
}

func TestProductionSnapshotV1FailureIsAtomic(t *testing.T) {
	valid := productionSnapshotFixtureV1()
	for name, test := range map[string]struct {
		mutate func(*productionSnapshotV1)
		status productionStatusV1
	}{
		"zero-generation":      {func(v *productionSnapshotV1) { v.profileGeneration = 0 }, productionInvalidRequestV1},
		"zero-digest":          {func(v *productionSnapshotV1) { v.planDigest = [32]byte{} }, productionInvalidRequestV1},
		"unknown-mask":         {func(v *productionSnapshotV1) { v.nativeCapabilityMask = 0x20 }, productionInvalidRequestV1},
		"effective-not-subset": {func(v *productionSnapshotV1) { v.signedCapabilityMask &^= 2 }, productionInvalidRequestV1},
		"tun-without-raw":      {func(v *productionSnapshotV1) { v.effectiveCapabilityMask &^= 1 }, productionInvalidRequestV1},
		"wrong-client-family":  {func(v *productionSnapshotV1) { v.clientV4.family = 6 }, productionInvalidRequestV1},
		"wrong-dns-family":     {func(v *productionSnapshotV1) { v.dns[0].family = 6 }, productionInvalidRequestV1},
		"wrong-route-family":   {func(v *productionSnapshotV1) { v.routes[0].address.family = 6 }, productionInvalidRequestV1},
		"missing-dual-family":  {func(v *productionSnapshotV1) { v.clientV6 = productionAddressV1{} }, productionInvalidRequestV1},
		"absent-proxy-nonzero": {func(v *productionSnapshotV1) {
			v.signedCapabilityMask &^= 2
			v.nativeCapabilityMask &^= 2
			v.effectiveCapabilityMask &^= 2
		}, productionInvalidRequestV1},
		"unsupported-raw-status": {func(v *productionSnapshotV1) { v.rawFlowStatus = 0 }, productionInvalidRequestV1},
		"fake-signed-raw-cap":    {func(v *productionSnapshotV1) { v.signedRawFlowCapStatus = 1 }, productionInvalidRequestV1},
		"flow-reserve-over":      {func(v *productionSnapshotV1) { v.flowTableReservedBytes = (1 << 20) + 1 }, productionSizeLimitV1},
		"aggregate-over":         {func(v *productionSnapshotV1) { v.nativeAggregateBufferMax = (128 << 20) + 1 }, productionSizeLimitV1},
		"untrimmed-label":        {func(v *productionSnapshotV1) { v.nodeLabel.value = " Node" }, productionInvalidRequestV1},
		"control-label":          {func(v *productionSnapshotV1) { v.nodeLabel.value = "Node\n" }, productionInvalidRequestV1},
		"supplementary-label":    {func(v *productionSnapshotV1) { v.nodeLabel.value = "Node😀" }, productionInvalidRequestV1},
	} {
		t.Run(name, func(t *testing.T) {
			value := valid
			test.mutate(&value)
			output := bytes.Repeat([]byte{0x5a}, productionSnapshotMaxBytesV1)
			before := append([]byte(nil), output...)
			written, status := encodeProductionSnapshotV1(value, output)
			if written != 0 || status != test.status || !bytes.Equal(output, before) {
				t.Fatalf("written=%d status=%d mutated=%v", written, status, !bytes.Equal(output, before))
			}
		})
	}
	tooSmall := bytes.Repeat([]byte{0x5a}, len(productionSnapshotGoldenV1(valid))-1)
	before := append([]byte(nil), tooSmall...)
	if written, status := encodeProductionSnapshotV1(valid, tooSmall); written != 0 || status != productionSizeLimitV1 || !bytes.Equal(tooSmall, before) {
		t.Fatalf("small output: written=%d status=%d", written, status)
	}
}

func TestProductionSnapshotV1RejectsImpossibleLimitsAndPerAppMetadata(t *testing.T) {
	for name, test := range map[string]struct {
		mutate func(*productionSnapshotV1)
		status productionStatusV1
	}{
		"reconnect-ceilings": {func(value *productionSnapshotV1) {
			value.signedReconnectMax = 255
			value.nativeReconnectMax = 255
			value.fallbackAttemptMax = 255
		}, productionInvalidRequestV1},
		"native-reconnect-not-exact": {func(value *productionSnapshotV1) {
			value.nativeReconnectMax = 9
		}, productionInvalidRequestV1},
		"flow-idle-exceeds-session": {func(value *productionSnapshotV1) {
			value.effectiveFlowIdleMillis = 3600000
		}, productionInvalidRequestV1},
		"proxy-buffer-below-minimum": {func(value *productionSnapshotV1) {
			value.effectiveTotalBufferBytes = 1
		}, productionInvalidRequestV1},
		"all-with-package-count": {func(value *productionSnapshotV1) {
			value.perAppMode = 1
		}, productionInvalidRequestV1},
		"include-without-package": {func(value *productionSnapshotV1) {
			value.effectivePackageCount = 0
		}, productionInvalidRequestV1},
		"package-count-over-limit": {func(value *productionSnapshotV1) {
			value.effectivePackageCount = 257
		}, productionSizeLimitV1},
	} {
		t.Run(name, func(t *testing.T) {
			value := productionSnapshotFixtureV1()
			test.mutate(&value)
			output := bytes.Repeat([]byte{0x5a}, productionSnapshotMaxBytesV1)
			before := append([]byte(nil), output...)
			if written, status := encodeProductionSnapshotV1(value, output); written != 0 || status != test.status || !bytes.Equal(output, before) {
				t.Fatalf("encode: written=%d status=%d mutated=%v", written, status, !bytes.Equal(output, before))
			}
			input := productionSnapshotGoldenV1(value)
			if decoded, status := decodeProductionSnapshotV1(input); status != test.status || !reflect.DeepEqual(decoded, productionSnapshotV1{}) {
				t.Fatalf("decode: status=%d value=%+v", status, decoded)
			}
		})
	}

	excludeEmpty := productionSnapshotFixtureV1()
	excludeEmpty.perAppMode = 3
	excludeEmpty.effectivePackageCount = 0
	output := make([]byte, productionSnapshotMaxBytesV1)
	written, status := encodeProductionSnapshotV1(excludeEmpty, output)
	if status != productionSuccessV1 || written == 0 {
		t.Fatalf("encode EXCLUDE empty: written=%d status=%d", written, status)
	}
	if decoded, status := decodeProductionSnapshotV1(output[:written]); status != productionSuccessV1 || decoded.perAppMode != 3 || decoded.effectivePackageCount != 0 {
		t.Fatalf("decode EXCLUDE empty: status=%d value=%+v", status, decoded)
	}
}

func TestProductionSnapshotV1RejectsMalformedBytesAndProxyOnlyRawClaims(t *testing.T) {
	valid := productionSnapshotGoldenV1(productionSnapshotFixtureV1())
	for length := 0; length < len(valid); length++ {
		value, status := decodeProductionSnapshotV1(valid[:length])
		if status != productionInvalidRequestV1 || !reflect.DeepEqual(value, productionSnapshotV1{}) {
			t.Fatalf("truncation %d: status=%d value=%+v", length, status, value)
		}
	}
	for name, mutate := range map[string]func([]byte){
		"magic":    func(v []byte) { v[0] ^= 1 },
		"version":  func(v []byte) { v[4] = 2 },
		"reserved": func(v []byte) { v[7] = 1 },
		"total":    func(v []byte) { binary.BigEndian.PutUint32(v[8:12], uint32(len(v)-1)) },
	} {
		t.Run(name, func(t *testing.T) {
			input := append([]byte(nil), valid...)
			mutate(input)
			if value, status := decodeProductionSnapshotV1(input); status != productionInvalidRequestV1 || !reflect.DeepEqual(value, productionSnapshotV1{}) {
				t.Fatalf("status=%d value=%+v", status, value)
			}
		})
	}
	trailing := append(append([]byte(nil), valid...), 0)
	binary.BigEndian.PutUint32(trailing[8:12], uint32(len(trailing)))
	if value, status := decodeProductionSnapshotV1(trailing); status != productionInvalidRequestV1 || !reflect.DeepEqual(value, productionSnapshotV1{}) {
		t.Fatalf("trailing: status=%d value=%+v", status, value)
	}
	over := make([]byte, productionSnapshotMaxBytesV1+1)
	if value, status := decodeProductionSnapshotV1(over); status != productionSizeLimitV1 || !reflect.DeepEqual(value, productionSnapshotV1{}) {
		t.Fatalf("oversize: status=%d value=%+v", status, value)
	}

	proxyOnly := productionSnapshotFixtureV1()
	proxyOnly.effectiveMode = 3
	proxyOnly.effectiveIP = 2
	proxyOnly.clientV4, proxyOnly.clientV6 = productionAddressV1{}, productionAddressV1{}
	proxyOnly.dnsCount, proxyOnly.routeCount = 0, 0
	proxyOnly.effectiveCapabilityMask &^= 1
	proxyOnly.rawFlowStatus = 2
	proxyOnly.nativeTCPFlowMax, proxyOnly.nativeUDPFlowMax = 0, 0
	proxyOnly.effectiveTCPFlowMax, proxyOnly.effectiveUDPFlowMax = 0, 0
	proxyOnly.effectiveFlowIdleMillis, proxyOnly.flowTableReservedBytes = 0, 0
	if _, status := encodeProductionSnapshotV1(proxyOnly, make([]byte, productionSnapshotMaxBytesV1)); status != productionSuccessV1 {
		t.Fatalf("valid proxy-only snapshot rejected: %d", status)
	}
	proxyOnly.effectiveTCPFlowMax = 1
	if _, status := encodeProductionSnapshotV1(proxyOnly, make([]byte, productionSnapshotMaxBytesV1)); status != productionInvalidRequestV1 {
		t.Fatalf("proxy-only raw claim accepted: %d", status)
	}
}
