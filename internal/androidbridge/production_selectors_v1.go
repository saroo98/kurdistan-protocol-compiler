// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
	"slices"
	"strconv"

	"kurdistan/internal/product/runtimepolicy"
)

const productionSelectorsMaxBytesV1 = 512

var (
	productionStrategyCatalogIDV1 = []byte("strategy-kurd-tls13-tcp")
	productionStrategyNativeIDV1  = "strategy.kurd-tls13-tcp"
)

type productionSelectorSetV1 struct {
	profileGeneration uint64
	planDigest        [32]byte
	strategyCount     uint8
	strategyIDs       [1][]byte
	probeCount        uint8
	probeIDs          [16][]byte
}

func (value productionSelectorSetV1) matches(generation uint64, digest [32]byte) bool {
	return value.profileGeneration != 0 && value.profileGeneration == generation && value.planDigest == digest && digest != ([32]byte{})
}

func encodeProductionSelectorsV1(value productionSelectorSetV1, output []byte) (int, productionStatusV1) {
	size, status := validateProductionSelectorsV1(value)
	if status != productionSuccessV1 {
		return 0, status
	}
	if len(output) < size {
		return 0, productionSizeLimitV1
	}
	encoded := make([]byte, size)
	defer clear(encoded)
	copy(encoded[:4], "KPA1")
	encoded[4], encoded[5] = 1, 1
	binary.BigEndian.PutUint32(encoded[8:12], uint32(size))
	binary.BigEndian.PutUint64(encoded[12:20], value.profileGeneration)
	copy(encoded[20:52], value.planDigest[:])
	offset := 52
	encoded[offset] = value.strategyCount
	offset++
	for index := 0; index < int(value.strategyCount); index++ {
		offset = appendProductionSelectorIDV1(encoded, offset, value.strategyIDs[index])
	}
	encoded[offset] = value.probeCount
	offset++
	for index := 0; index < int(value.probeCount); index++ {
		offset = appendProductionSelectorIDV1(encoded, offset, value.probeIDs[index])
	}
	copy(output[:size], encoded)
	return size, productionSuccessV1
}

func appendProductionSelectorIDV1(output []byte, offset int, value []byte) int {
	output[offset] = byte(len(value))
	offset++
	copy(output[offset:], value)
	return offset + len(value)
}

func validateProductionSelectorsV1(value productionSelectorSetV1) (int, productionStatusV1) {
	if value.profileGeneration == 0 || value.planDigest == ([32]byte{}) {
		return 0, productionInvalidRequestV1
	}
	if value.strategyCount > 1 || value.probeCount > 16 {
		return 0, productionSizeLimitV1
	}
	size := uint64(54)
	var previous []byte
	for index := 0; index < int(value.strategyCount); index++ {
		id := value.strategyIDs[index]
		if len(id) > 64 {
			return 0, productionSizeLimitV1
		}
		if !bytes.Equal(id, productionStrategyCatalogIDV1) {
			return 0, productionInvalidRequestV1
		}
		size += uint64(1 + len(id))
	}
	for index := 0; index < int(value.probeCount); index++ {
		id := value.probeIDs[index]
		if !validProductionCatalogIDV1(id) {
			if len(id) > 64 {
				return 0, productionSizeLimitV1
			}
			return 0, productionInvalidRequestV1
		}
		if _, ok := parseProductionProbeSelectorV1(id); !ok {
			return 0, productionInvalidRequestV1
		}
		if index > 0 && (len(previous) > len(id) || len(previous) == len(id) && bytes.Compare(previous, id) >= 0) {
			return 0, productionInvalidRequestV1
		}
		previous = id
		size += uint64(1 + len(id))
	}
	if size > productionSelectorsMaxBytesV1 {
		return 0, productionSizeLimitV1
	}
	return int(size), productionSuccessV1
}

func decodeProductionSelectorsV1(input []byte) (productionSelectorSetV1, productionStatusV1) {
	if len(input) > productionSelectorsMaxBytesV1 {
		return productionSelectorSetV1{}, productionSizeLimitV1
	}
	if len(input) < 54 || !bytes.Equal(input[:4], []byte("KPA1")) || input[4] != 1 || input[5] != 1 || input[6] != 0 || input[7] != 0 || binary.BigEndian.Uint32(input[8:12]) != uint32(len(input)) {
		return productionSelectorSetV1{}, productionInvalidRequestV1
	}
	var value productionSelectorSetV1
	value.profileGeneration = binary.BigEndian.Uint64(input[12:20])
	copy(value.planDigest[:], input[20:52])
	offset := 52
	value.strategyCount = input[offset]
	offset++
	if value.strategyCount > 1 {
		return productionSelectorSetV1{}, productionSizeLimitV1
	}
	readID := func() ([]byte, []byte, productionStatusV1) {
		if offset >= len(input) {
			return nil, nil, productionInvalidRequestV1
		}
		start := offset
		length := int(input[offset])
		offset++
		if length > 64 {
			return nil, nil, productionSizeLimitV1
		}
		if length == 0 || length > len(input)-offset {
			return nil, nil, productionInvalidRequestV1
		}
		id := input[offset : offset+length]
		offset += length
		return id, input[start:offset], productionSuccessV1
	}
	for index := 0; index < int(value.strategyCount); index++ {
		id, _, status := readID()
		if status != productionSuccessV1 || !bytes.Equal(id, productionStrategyCatalogIDV1) {
			return productionSelectorSetV1{}, statusOrInvalidProductionV1(status)
		}
		value.strategyIDs[index] = id
	}
	if offset >= len(input) {
		return productionSelectorSetV1{}, productionInvalidRequestV1
	}
	value.probeCount = input[offset]
	offset++
	if value.probeCount > 16 {
		return productionSelectorSetV1{}, productionSizeLimitV1
	}
	var previous []byte
	for index := 0; index < int(value.probeCount); index++ {
		id, encoded, status := readID()
		if status != productionSuccessV1 {
			return productionSelectorSetV1{}, status
		}
		if !validProductionCatalogIDV1(id) || index > 0 && bytes.Compare(previous, encoded) >= 0 {
			return productionSelectorSetV1{}, productionInvalidRequestV1
		}
		if _, ok := parseProductionProbeSelectorV1(id); !ok {
			return productionSelectorSetV1{}, productionInvalidRequestV1
		}
		value.probeIDs[index] = id
		previous = encoded
	}
	if offset != len(input) {
		return productionSelectorSetV1{}, productionInvalidRequestV1
	}
	if _, status := validateProductionSelectorsV1(value); status != productionSuccessV1 {
		return productionSelectorSetV1{}, status
	}
	return value, productionSuccessV1
}

func statusOrInvalidProductionV1(status productionStatusV1) productionStatusV1 {
	if status == productionSuccessV1 {
		return productionInvalidRequestV1
	}
	return status
}

func productionStrategyCatalogV1(native string, signed []string) ([]byte, bool) {
	if native != productionStrategyNativeIDV1 || !slices.Contains(signed, productionStrategyNativeIDV1) {
		return nil, false
	}
	return append([]byte(nil), productionStrategyCatalogIDV1...), true
}

func productionStrategyNativeV1(catalog []byte, signed []string) (string, bool) {
	if !bytes.Equal(catalog, productionStrategyCatalogIDV1) || !slices.Contains(signed, productionStrategyNativeIDV1) {
		return "", false
	}
	return productionStrategyNativeIDV1, true
}

func productionProbeCatalogV1(target uint16, targets []runtimepolicy.ProbeTargetV1, mode uint8) ([]byte, bool) {
	if !productionProbeTargetAdmittedV1(target, targets, mode) {
		return nil, false
	}
	return []byte("probe-" + strconv.FormatUint(uint64(target), 10)), true
}

func productionProbeTargetV1(selector []byte, targets []runtimepolicy.ProbeTargetV1, mode uint8) (uint16, bool) {
	target, ok := parseProductionProbeSelectorV1(selector)
	if !ok || !productionProbeTargetAdmittedV1(target, targets, mode) {
		return 0, false
	}
	return target, true
}

func parseProductionProbeSelectorV1(selector []byte) (uint16, bool) {
	const prefix = "probe-"
	if len(selector) <= len(prefix) || !bytes.HasPrefix(selector, []byte(prefix)) {
		return 0, false
	}
	digits := string(selector[len(prefix):])
	if digits[0] == '0' && len(digits) != 1 {
		return 0, false
	}
	for index := range len(digits) {
		if digits[index] < '0' || digits[index] > '9' {
			return 0, false
		}
	}
	parsed, err := strconv.ParseUint(digits, 10, 16)
	if err != nil || parsed == 0 || prefix+strconv.FormatUint(parsed, 10) != string(selector) {
		return 0, false
	}
	return uint16(parsed), true
}

func productionProbeTargetAdmittedV1(target uint16, targets []runtimepolicy.ProbeTargetV1, mode uint8) bool {
	if target == 0 || mode < 1 || mode > 2 {
		return false
	}
	for _, candidate := range targets {
		if candidate.ID == target && len(candidate.Methods) == 1 && candidate.Methods[0] == 1 && slices.Contains(candidate.Modes, mode) {
			return true
		}
	}
	return false
}
