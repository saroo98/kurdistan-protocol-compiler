// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"encoding/binary"
)

const (
	productionSettingsMaxBytesV1  = 196608
	productionOpenMaxBytesV1      = 2721575
	productionRecipientMaxBytesV1 = 512
	productionPrivateMaxBytesV1   = 128
)

type productionOpenViewV1 struct {
	purpose                                                          uint8
	settings, verify, activation, recipientRequest, recipientPrivate []byte
}

func decodeProductionOpenV1(input []byte) (productionOpenViewV1, productionStatusV1) {
	if len(input) > productionOpenMaxBytesV1 {
		return productionOpenViewV1{}, productionSizeLimitV1
	}
	if len(input) < 32 || !bytes.Equal(input[:4], []byte("KPO1")) || input[4] != 1 || input[5] < 1 || input[5] > 2 || input[6] != 0 || input[7] != 0 || binary.BigEndian.Uint32(input[8:12]) != uint32(len(input)) || binary.BigEndian.Uint32(input[28:32]) != 0 {
		return productionOpenViewV1{}, productionInvalidRequestV1
	}
	lengths := [5]uint64{
		uint64(binary.BigEndian.Uint32(input[12:16])),
		uint64(binary.BigEndian.Uint32(input[16:20])),
		uint64(binary.BigEndian.Uint32(input[20:24])),
		uint64(binary.BigEndian.Uint16(input[24:26])),
		uint64(binary.BigEndian.Uint16(input[26:28])),
	}
	limits := [5]uint64{productionSettingsMaxBytesV1, MaxVerifyRequestBytes, MaxBridgeResultBytes, productionRecipientMaxBytesV1, productionPrivateMaxBytesV1}
	var total uint64 = 32
	for index, length := range lengths {
		if length == 0 {
			return productionOpenViewV1{}, productionInvalidRequestV1
		}
		if length > limits[index] {
			return productionOpenViewV1{}, productionSizeLimitV1
		}
		if ^uint64(0)-total < length {
			return productionOpenViewV1{}, productionInvalidRequestV1
		}
		total += length
	}
	if total != uint64(len(input)) || total > productionOpenMaxBytesV1 {
		return productionOpenViewV1{}, productionInvalidRequestV1
	}
	offset := 32
	next := func(length uint64) []byte {
		end := offset + int(length)
		value := input[offset:end]
		offset = end
		return value
	}
	return productionOpenViewV1{
		purpose:          input[5],
		settings:         next(lengths[0]),
		verify:           next(lengths[1]),
		activation:       next(lengths[2]),
		recipientRequest: next(lengths[3]),
		recipientPrivate: next(lengths[4]),
	}, productionSuccessV1
}
