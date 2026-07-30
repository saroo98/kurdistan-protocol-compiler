// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package wirev1 defines the canonical outer envelope for Kurd wire major 1.
// Payload authentication remains owned by the existing Kurd runtime.
package wirev1

import (
	"encoding/binary"
	"errors"
)

const (
	MajorVersion    uint8 = 1
	MinorVersion    uint8 = 0
	HeaderBytes           = 48
	MaxControlBytes       = 64 << 10
	MaxPayloadBytes       = 1 << 20
)

const (
	TypeClientHello  uint8 = 1
	TypeServerHello  uint8 = 2
	TypeProfileBind  uint8 = 3
	TypeEngineReady  uint8 = 4
	TypeReliableData uint8 = 5
	TypeHeartbeat    uint8 = 6
	TypeClose        uint8 = 7
	TypeClientFinish uint8 = 8
	TypeServerFinish uint8 = 9
)

const (
	FlagCritical uint8 = 1 << 0
	knownFlags         = FlagCritical
)

var ErrInvalidFrame = errors.New("wirev1: invalid frame")

var magic = [4]byte{'K', 'U', 'R', 'D'}

type Frame struct {
	Type       uint8
	Flags      uint8
	StreamID   uint32
	PlanDigest [32]byte
	Payload    []byte
}

func Encode(frame Frame) ([]byte, error) {
	if err := validate(frame); err != nil {
		return nil, err
	}
	out := make([]byte, HeaderBytes+len(frame.Payload))
	copy(out[0:4], magic[:])
	out[4] = MajorVersion
	out[5] = MinorVersion
	out[6] = frame.Type
	out[7] = frame.Flags
	binary.BigEndian.PutUint32(out[8:12], frame.StreamID)
	binary.BigEndian.PutUint32(out[12:16], uint32(len(frame.Payload)))
	copy(out[16:48], frame.PlanDigest[:])
	copy(out[HeaderBytes:], frame.Payload)
	return out, nil
}

func Decode(encoded []byte) (Frame, error) {
	if len(encoded) < HeaderBytes || len(encoded) > HeaderBytes+MaxPayloadBytes ||
		string(encoded[0:4]) != string(magic[:]) ||
		encoded[4] != MajorVersion || encoded[5] != MinorVersion {
		return Frame{}, ErrInvalidFrame
	}
	length := binary.BigEndian.Uint32(encoded[12:16])
	if int64(length)+HeaderBytes != int64(len(encoded)) {
		return Frame{}, ErrInvalidFrame
	}
	frame := Frame{
		Type: encoded[6], Flags: encoded[7],
		StreamID: binary.BigEndian.Uint32(encoded[8:12]),
		Payload:  append([]byte(nil), encoded[HeaderBytes:]...),
	}
	copy(frame.PlanDigest[:], encoded[16:48])
	if err := validate(frame); err != nil {
		clear(frame.Payload)
		return Frame{}, err
	}
	return frame, nil
}

func validate(frame Frame) error {
	if !knownType(frame.Type) || frame.Flags&^knownFlags != 0 ||
		frame.PlanDigest == ([32]byte{}) || len(frame.Payload) > MaxPayloadBytes {
		return ErrInvalidFrame
	}
	switch frame.Type {
	case TypeReliableData:
		if frame.StreamID == 0 || len(frame.Payload) == 0 {
			return ErrInvalidFrame
		}
	case TypeHeartbeat:
		if frame.StreamID != 0 || len(frame.Payload) != 0 {
			return ErrInvalidFrame
		}
	default:
		if frame.StreamID != 0 || len(frame.Payload) == 0 || len(frame.Payload) > MaxControlBytes {
			return ErrInvalidFrame
		}
	}
	return nil
}

func knownType(value uint8) bool {
	return value >= TypeClientHello && value <= TypeServerFinish
}
