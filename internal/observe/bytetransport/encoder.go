// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

const byteFrameVersion byte = 1

func EncodeFrame(cfg ByteTransportConfig, frame ByteFrame) (EncodedFrame, error) {
	if frame.SessionID == "" {
		frame.SessionID = cfg.RuntimeID
	}
	if frame.FragmentCount == 0 {
		frame.FragmentCount = 1
	}
	if err := ValidateFrame(cfg, frame); err != nil {
		return EncodedFrame{}, err
	}
	kindCode, ok := kindCode(frame.Kind)
	if !ok {
		return EncodedFrame{}, fmt.Errorf("%w: kind", ErrInvalidFrame)
	}
	buf := bytes.Buffer{}
	buf.WriteByte(byteFrameVersion)
	buf.WriteByte(kindCode)
	flags := byte(0)
	if frame.Final {
		flags |= 1
	}
	if frame.Reset {
		flags |= 2
	}
	buf.WriteByte(flags)
	writeU16(&buf, uint16(frame.FragmentIndex))
	writeU16(&buf, uint16(frame.FragmentCount))
	writeU64(&buf, frame.StreamID)
	writeU64(&buf, frame.Sequence)
	writeU32(&buf, uint32(frame.ByteCount))
	writeString(&buf, frame.MetadataClass)
	writeString(&buf, frame.SessionID)
	payload := deterministicPayload(cfg.DeterministicSeed, frame.Sequence, frame.ByteCount)
	writeU32(&buf, uint32(len(payload)))
	buf.Write(payload)
	sum := checksum(buf.Bytes())
	writeU32(&buf, sum)
	raw := buf.Bytes()
	if len(raw) > cfg.MaxFrameBytes {
		return EncodedFrame{}, fmt.Errorf("%w: encoded size", ErrFrameTooLarge)
	}
	return EncodedFrame{Sequence: frame.Sequence, Kind: frame.Kind, ByteCount: frame.ByteCount, FragmentIndex: frame.FragmentIndex, FragmentCount: frame.FragmentCount, Bytes: raw}, nil
}

func writeU16(buf *bytes.Buffer, value uint16) {
	_ = binary.Write(buf, binary.BigEndian, value)
}

func writeU32(buf *bytes.Buffer, value uint32) {
	_ = binary.Write(buf, binary.BigEndian, value)
}

func writeU64(buf *bytes.Buffer, value uint64) {
	_ = binary.Write(buf, binary.BigEndian, value)
}

func writeString(buf *bytes.Buffer, value string) {
	writeU16(buf, uint16(len(value)))
	buf.WriteString(value)
}

func kindCode(kind ByteFrameKind) (byte, bool) {
	switch kind {
	case FrameData:
		return 1, true
	case FrameControl:
		return 2, true
	case FrameAck:
		return 3, true
	case FrameClose:
		return 4, true
	case FrameReset:
		return 5, true
	case FrameBackpressure:
		return 6, true
	default:
		return 0, false
	}
}

func kindFromCode(code byte) (ByteFrameKind, bool) {
	switch code {
	case 1:
		return FrameData, true
	case 2:
		return FrameControl, true
	case 3:
		return FrameAck, true
	case 4:
		return FrameClose, true
	case 5:
		return FrameReset, true
	case 6:
		return FrameBackpressure, true
	default:
		return "", false
	}
}
