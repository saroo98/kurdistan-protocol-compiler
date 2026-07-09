// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package stream

import "errors"

var (
	ErrInvalidConfig        = errors.New("invalid stream session config")
	ErrUnknownStream        = errors.New("unknown stream")
	ErrMaxConcurrentStreams = errors.New("max concurrent streams exceeded")
	ErrStreamClosed         = errors.New("stream is closed")
	ErrBackpressure         = errors.New("flow-control backpressure")
)
