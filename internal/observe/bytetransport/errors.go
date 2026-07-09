// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "errors"

var (
	ErrInvalidConfig      = errors.New("byte transport invalid config")
	ErrInvalidFrame       = errors.New("byte transport invalid frame")
	ErrFrameTooLarge      = errors.New("byte transport frame too large")
	ErrPayloadTooLarge    = errors.New("byte transport payload too large")
	ErrMalformedBytes     = errors.New("byte transport malformed bytes")
	ErrChecksumMismatch   = errors.New("byte transport checksum mismatch")
	ErrSequenceRejected   = errors.New("byte transport sequence rejected")
	ErrBackpressure       = errors.New("byte transport backpressure")
	ErrPipeClosed         = errors.New("byte transport pipe closed")
	ErrPipeReset          = errors.New("byte transport pipe reset")
	ErrReassemblyRejected = errors.New("byte transport reassembly rejected")
)
