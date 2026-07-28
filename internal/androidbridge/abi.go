// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package androidbridge owns the versioned, bounded, process-neutral Android
// bridge contract. It contains no JNI or Android dependencies.
package androidbridge

import (
	"encoding/binary"
	"errors"

	"kurdistan/internal/product/diagnosticexport"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/relaydescriptor"
	"kurdistan/internal/product/strategy"
)

const (
	ABIVersion           = "kurd-android-bridge-v1"
	GoCoreVersion        = "kurd-go-core-phase9-v1"
	ProfileSchemaVersion = profile.Version
	DiagnosticSchema     = diagnosticexport.Version
	MaxABIInfoBytes      = 512
	MaxBridgeHandles     = 64
	// MaxBridgeResultBytes accommodates one maximum-sized opaque artifact plus
	// a bounded activation-record envelope. Preview and diagnostic responses
	// have substantially smaller independent limits.
	MaxBridgeResultBytes  = envelope.MaxTotalInputBytes + 64*1024
	abiInfoEncoding       = 1
	abiInfoFieldCount     = 7
	abiInfoMagic          = "KVAB"
	abiInfoFixedHeaderLen = 8
)

type ErrorCode int32

const (
	CodeOK ErrorCode = iota
	CodeInvalidArgument
	CodeSizeLimit
	CodeInvalidHandle
	CodeWrongHandleType
	CodeAlreadyClosed
	CodeCancelled
	CodeTrustUnavailable
	CodeVerificationRejected
	CodePolicyRejected
	CodeStorageFailure
	CodeRecoveryRequired
	CodeQuarantined
	CodeIncompatible
	CodeInternalFailure
)

type ABIInfo struct {
	BridgeVersion       string
	GoCoreVersion       string
	ProfileSchema       string
	CryptoSuite         uint16
	StrategyRegistry    string
	RelaySchema         string
	DiagnosticSchema    string
	MaxInputBytes       uint32
	MaxQRChunks         uint16
	MaxQRChunkChars     uint16
	MaxResultBytes      uint32
	MaxConcurrentHandle uint16
}

func CurrentABIInfo() ABIInfo {
	return ABIInfo{
		BridgeVersion:       ABIVersion,
		GoCoreVersion:       GoCoreVersion,
		ProfileSchema:       ProfileSchemaVersion,
		CryptoSuite:         uint16(envelope.SuiteClassicalV1),
		StrategyRegistry:    strategy.Version,
		RelaySchema:         relaydescriptor.Version,
		DiagnosticSchema:    DiagnosticSchema,
		MaxInputBytes:       uint32(envelope.MaxTotalInputBytes),
		MaxQRChunks:         uint16(envelope.MaxIngressQRChunks),
		MaxQRChunkChars:     uint16(envelope.MaxIngressChunkChars),
		MaxResultBytes:      MaxBridgeResultBytes,
		MaxConcurrentHandle: MaxBridgeHandles,
	}
}

// EncodeABIInfo emits a compact length-delimited binary handshake. Fields are
// fixed-order and bounded; no JSON or platform object crosses the ABI.
func EncodeABIInfo(info ABIInfo) ([]byte, error) {
	fields := []string{
		info.BridgeVersion,
		info.GoCoreVersion,
		info.ProfileSchema,
		info.StrategyRegistry,
		info.RelaySchema,
		info.DiagnosticSchema,
	}
	size := abiInfoFixedHeaderLen + 2 + 4 + 2 + 2 + 4 + 2
	for _, field := range fields {
		if len(field) == 0 || len(field) > 255 {
			return nil, errors.New("androidbridge: invalid ABI field")
		}
		size += 1 + len(field)
	}
	if info.CryptoSuite == 0 || info.MaxInputBytes == 0 ||
		info.MaxQRChunks == 0 || info.MaxQRChunkChars == 0 ||
		info.MaxResultBytes == 0 || info.MaxConcurrentHandle == 0 ||
		size > MaxABIInfoBytes {
		return nil, errors.New("androidbridge: invalid ABI bounds")
	}
	out := make([]byte, size)
	copy(out[:4], abiInfoMagic)
	out[4] = abiInfoEncoding
	out[5] = abiInfoFieldCount
	binary.BigEndian.PutUint16(out[6:8], uint16(size))
	offset := abiInfoFixedHeaderLen
	for _, field := range fields {
		out[offset] = byte(len(field))
		offset++
		copy(out[offset:], field)
		offset += len(field)
	}
	binary.BigEndian.PutUint16(out[offset:], info.CryptoSuite)
	offset += 2
	binary.BigEndian.PutUint32(out[offset:], info.MaxInputBytes)
	offset += 4
	binary.BigEndian.PutUint16(out[offset:], info.MaxQRChunks)
	offset += 2
	binary.BigEndian.PutUint16(out[offset:], info.MaxQRChunkChars)
	offset += 2
	binary.BigEndian.PutUint32(out[offset:], info.MaxResultBytes)
	offset += 4
	binary.BigEndian.PutUint16(out[offset:], info.MaxConcurrentHandle)
	return out, nil
}

func DecodeABIInfo(encoded []byte) (ABIInfo, error) {
	if len(encoded) < abiInfoFixedHeaderLen || len(encoded) > MaxABIInfoBytes ||
		string(encoded[:4]) != abiInfoMagic || encoded[4] != abiInfoEncoding ||
		encoded[5] != abiInfoFieldCount || int(binary.BigEndian.Uint16(encoded[6:8])) != len(encoded) {
		return ABIInfo{}, errors.New("androidbridge: invalid ABI header")
	}
	offset := abiInfoFixedHeaderLen
	fields := make([]string, abiInfoFieldCount-1)
	for index := range fields {
		if offset >= len(encoded) {
			return ABIInfo{}, errors.New("androidbridge: truncated ABI field")
		}
		length := int(encoded[offset])
		offset++
		if length == 0 || offset+length > len(encoded) {
			return ABIInfo{}, errors.New("androidbridge: invalid ABI field")
		}
		fields[index] = string(encoded[offset : offset+length])
		offset += length
	}
	const scalarBytes = 2 + 4 + 2 + 2 + 4 + 2
	if len(encoded)-offset != scalarBytes {
		return ABIInfo{}, errors.New("androidbridge: invalid ABI scalar tail")
	}
	info := ABIInfo{
		BridgeVersion:       fields[0],
		GoCoreVersion:       fields[1],
		ProfileSchema:       fields[2],
		StrategyRegistry:    fields[3],
		RelaySchema:         fields[4],
		DiagnosticSchema:    fields[5],
		CryptoSuite:         binary.BigEndian.Uint16(encoded[offset:]),
		MaxInputBytes:       binary.BigEndian.Uint32(encoded[offset+2:]),
		MaxQRChunks:         binary.BigEndian.Uint16(encoded[offset+6:]),
		MaxQRChunkChars:     binary.BigEndian.Uint16(encoded[offset+8:]),
		MaxResultBytes:      binary.BigEndian.Uint32(encoded[offset+10:]),
		MaxConcurrentHandle: binary.BigEndian.Uint16(encoded[offset+14:]),
	}
	reencoded, err := EncodeABIInfo(info)
	if err != nil || len(reencoded) != len(encoded) {
		return ABIInfo{}, errors.New("androidbridge: non-canonical ABI info")
	}
	for index := range encoded {
		if encoded[index] != reencoded[index] {
			return ABIInfo{}, errors.New("androidbridge: non-canonical ABI info")
		}
	}
	return info, nil
}
