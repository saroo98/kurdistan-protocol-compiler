// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import "errors"

var (
	ErrInvalidSourceChunk = errors.New("invalid local source chunk")
	ErrInvalidSequence    = errors.New("invalid local sequence")
	ErrClosedSink         = errors.New("local sink is closed")
	ErrLocalBackpressure  = errors.New("local adapter backpressure")
)
