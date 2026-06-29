// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "fmt"

type ByteFrameKind string

const (
	FrameData         ByteFrameKind = "data"
	FrameControl      ByteFrameKind = "control"
	FrameAck          ByteFrameKind = "ack"
	FrameClose        ByteFrameKind = "close"
	FrameReset        ByteFrameKind = "reset"
	FrameBackpressure ByteFrameKind = "backpressure"
)

type ByteFrame struct {
	SessionID     string        `json:"session_id"`
	StreamID      uint64        `json:"stream_id"`
	Sequence      uint64        `json:"sequence"`
	Kind          ByteFrameKind `json:"kind"`
	FragmentIndex int           `json:"fragment_index"`
	FragmentCount int           `json:"fragment_count"`
	ByteCount     int           `json:"byte_count"`
	Final         bool          `json:"final"`
	Reset         bool          `json:"reset"`
	MetadataClass string        `json:"metadata_class"`
	ChecksumClass string        `json:"checksum_class"`
}

type EncodedFrame struct {
	Sequence      uint64        `json:"sequence"`
	Kind          ByteFrameKind `json:"kind"`
	ByteCount     int           `json:"byte_count"`
	FragmentIndex int           `json:"fragment_index"`
	FragmentCount int           `json:"fragment_count"`
	Bytes         []byte        `json:"-"`
}

type DecodeResult struct {
	Frame        ByteFrame `json:"frame"`
	Complete     bool      `json:"complete"`
	Reassembled  bool      `json:"reassembled"`
	Rejected     bool      `json:"rejected"`
	RejectReason string    `json:"reject_reason,omitempty"`
}

func ValidateFrame(cfg ByteTransportConfig, frame ByteFrame) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	if frame.SessionID == "" {
		frame.SessionID = cfg.RuntimeID
	}
	if len(frame.SessionID) > 128 || len(frame.MetadataClass) > 128 {
		return fmt.Errorf("%w: metadata too large", ErrInvalidFrame)
	}
	if !knownKind(frame.Kind) {
		return fmt.Errorf("%w: unknown kind", ErrInvalidFrame)
	}
	if frame.Sequence == 0 {
		return fmt.Errorf("%w: sequence", ErrInvalidFrame)
	}
	if frame.ByteCount < 0 || frame.ByteCount > cfg.MaxPayloadBytes {
		return fmt.Errorf("%w: byte count", ErrPayloadTooLarge)
	}
	if frame.FragmentCount < 0 || frame.FragmentCount > cfg.MaxFragments {
		return fmt.Errorf("%w: fragment count", ErrInvalidFrame)
	}
	if frame.FragmentCount == 0 {
		frame.FragmentCount = 1
	}
	if frame.FragmentIndex < 0 || frame.FragmentIndex >= frame.FragmentCount {
		return fmt.Errorf("%w: fragment index", ErrInvalidFrame)
	}
	if frame.Kind == FrameReset && !frame.Reset {
		return fmt.Errorf("%w: reset flag", ErrInvalidFrame)
	}
	return nil
}

func knownKind(kind ByteFrameKind) bool {
	switch kind {
	case FrameData, FrameControl, FrameAck, FrameClose, FrameReset, FrameBackpressure:
		return true
	default:
		return false
	}
}
