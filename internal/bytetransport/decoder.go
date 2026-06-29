// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import (
	"encoding/binary"
	"fmt"
)

func DecodeFrameBytes(cfg ByteTransportConfig, raw []byte) (DecodeResult, error) {
	if err := ValidateConfig(cfg); err != nil {
		return rejectResult("", err), err
	}
	if len(raw) < 3+2+2+8+8+4+2+2+4+4 {
		err := fmt.Errorf("%w: truncated", ErrMalformedBytes)
		return rejectResult("truncated", err), err
	}
	if len(raw) > cfg.MaxFrameBytes {
		err := fmt.Errorf("%w: encoded size", ErrFrameTooLarge)
		return rejectResult("oversized", err), err
	}
	if raw[0] != byteFrameVersion {
		err := fmt.Errorf("%w: version", ErrMalformedBytes)
		return rejectResult("version", err), err
	}
	want := binary.BigEndian.Uint32(raw[len(raw)-4:])
	if checksum(raw[:len(raw)-4]) != want {
		err := fmt.Errorf("%w: checksum", ErrChecksumMismatch)
		return rejectResult("checksum", err), err
	}
	offset := 1
	kind, ok := kindFromCode(raw[offset])
	offset++
	if !ok {
		err := fmt.Errorf("%w: unknown kind", ErrInvalidFrame)
		return rejectResult("unknown_kind", err), err
	}
	flags := raw[offset]
	offset++
	fragIndex, ok := readU16(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: fragment index", ErrMalformedBytes)
		return rejectResult("fragment_index", err), err
	}
	fragCount, ok := readU16(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: fragment count", ErrMalformedBytes)
		return rejectResult("fragment_count", err), err
	}
	streamID, ok := readU64(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: stream id", ErrMalformedBytes)
		return rejectResult("stream_id", err), err
	}
	sequence, ok := readU64(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: sequence", ErrMalformedBytes)
		return rejectResult("sequence", err), err
	}
	byteCount, ok := readU32(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: byte count", ErrMalformedBytes)
		return rejectResult("byte_count", err), err
	}
	meta, ok := readString(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: metadata", ErrMalformedBytes)
		return rejectResult("metadata", err), err
	}
	session, ok := readString(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: session", ErrMalformedBytes)
		return rejectResult("session", err), err
	}
	payloadLen, ok := readU32(raw, &offset)
	if !ok {
		err := fmt.Errorf("%w: payload length", ErrMalformedBytes)
		return rejectResult("payload_length", err), err
	}
	if payloadLen != byteCount || int(payloadLen) > cfg.MaxPayloadBytes {
		err := fmt.Errorf("%w: payload length", ErrPayloadTooLarge)
		return rejectResult("payload_length", err), err
	}
	if offset+int(payloadLen)+4 != len(raw) {
		err := fmt.Errorf("%w: trailing or truncated payload", ErrMalformedBytes)
		return rejectResult("payload_bounds", err), err
	}
	frame := ByteFrame{
		SessionID:     session,
		StreamID:      streamID,
		Sequence:      sequence,
		Kind:          kind,
		FragmentIndex: int(fragIndex),
		FragmentCount: int(fragCount),
		ByteCount:     int(byteCount),
		Final:         flags&1 != 0,
		Reset:         flags&2 != 0,
		MetadataClass: meta,
		ChecksumClass: "fnv32a",
	}
	if err := ValidateFrame(cfg, frame); err != nil {
		return rejectResult("validate", err), err
	}
	return DecodeResult{Frame: frame, Complete: frame.FragmentCount <= 1}, nil
}

func rejectResult(reason string, err error) DecodeResult {
	if reason == "" && err != nil {
		reason = err.Error()
	}
	return DecodeResult{Rejected: true, RejectReason: reason}
}

func readU16(raw []byte, offset *int) (uint16, bool) {
	if *offset+2 > len(raw) {
		return 0, false
	}
	value := binary.BigEndian.Uint16(raw[*offset : *offset+2])
	*offset += 2
	return value, true
}

func readU32(raw []byte, offset *int) (uint32, bool) {
	if *offset+4 > len(raw) {
		return 0, false
	}
	value := binary.BigEndian.Uint32(raw[*offset : *offset+4])
	*offset += 4
	return value, true
}

func readU64(raw []byte, offset *int) (uint64, bool) {
	if *offset+8 > len(raw) {
		return 0, false
	}
	value := binary.BigEndian.Uint64(raw[*offset : *offset+8])
	*offset += 8
	return value, true
}

func readString(raw []byte, offset *int) (string, bool) {
	n, ok := readU16(raw, offset)
	if !ok || int(n) > 128 || *offset+int(n) > len(raw) {
		return "", false
	}
	value := string(raw[*offset : *offset+int(n)])
	*offset += int(n)
	return value, true
}
