// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package wirev1

import "encoding/binary"

// EncodeInto writes a complete record into dst after validating capacity.
// Payload may overlap dst: memmove-style copy runs before the header write,
// including when Payload already occupies dst[HeaderBytes:]. Borrow exclusively.
func EncodeInto(dst []byte, frame Frame) (int, error) {
	if err := validate(frame); err != nil {
		return 0, err
	}
	n := HeaderBytes + len(frame.Payload)
	if len(dst) < n {
		return 0, ErrInvalidFrame
	}
	writeFrame(dst[:n], frame)
	return n, nil
}

func writeFrame(out []byte, frame Frame) {
	copy(out[HeaderBytes:], frame.Payload)
	copy(out[0:4], magic[:])
	out[4], out[5], out[6], out[7] = MajorVersion, MinorVersion, frame.Type, frame.Flags
	binary.BigEndian.PutUint32(out[8:12], frame.StreamID)
	binary.BigEndian.PutUint32(out[12:16], uint32(len(frame.Payload)))
	copy(out[16:48], frame.PlanDigest[:])
}

// DecodeView returns an exact-capacity borrowed payload. Keep encoded immutable
// and alive until the returned view's consumer has finished. Decode owns a copy.
func DecodeView(encoded []byte) (Frame, error) {
	if len(encoded) < HeaderBytes || len(encoded) > HeaderBytes+MaxPayloadBytes || string(encoded[:4]) != string(magic[:]) || encoded[4] != MajorVersion || encoded[5] != MinorVersion {
		return Frame{}, ErrInvalidFrame
	}
	length := binary.BigEndian.Uint32(encoded[12:16])
	if int64(length)+HeaderBytes != int64(len(encoded)) {
		return Frame{}, ErrInvalidFrame
	}
	frame := Frame{Type: encoded[6], Flags: encoded[7], StreamID: binary.BigEndian.Uint32(encoded[8:12]), Payload: encoded[HeaderBytes:len(encoded):len(encoded)]}
	copy(frame.PlanDigest[:], encoded[16:48])
	if err := validate(frame); err != nil {
		return Frame{}, err
	}
	return frame, nil
}
