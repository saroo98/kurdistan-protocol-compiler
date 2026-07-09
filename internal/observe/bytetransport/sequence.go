// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

import "fmt"

type SequenceValidator struct {
	last     map[string]uint64
	closed   map[string]bool
	maxAhead uint64
}

func NewSequenceValidator(maxAhead uint64) *SequenceValidator {
	if maxAhead == 0 {
		maxAhead = 1024
	}
	return &SequenceValidator{last: map[string]uint64{}, closed: map[string]bool{}, maxAhead: maxAhead}
}

func (v *SequenceValidator) Accept(frame ByteFrame) error {
	if v == nil {
		return fmt.Errorf("%w: nil validator", ErrSequenceRejected)
	}
	key := fmt.Sprintf("%s/%d", frame.SessionID, frame.StreamID)
	if v.closed[key] && frame.Kind != FrameClose && frame.Kind != FrameReset {
		return fmt.Errorf("%w: terminal stream", ErrSequenceRejected)
	}
	last := v.last[key]
	if frame.Sequence <= last {
		return fmt.Errorf("%w: duplicate or old", ErrSequenceRejected)
	}
	if last != 0 && frame.Sequence-last > v.maxAhead {
		return fmt.Errorf("%w: too far future", ErrSequenceRejected)
	}
	v.last[key] = frame.Sequence
	if frame.Kind == FrameClose || frame.Kind == FrameReset || frame.Final {
		v.closed[key] = true
	}
	return nil
}
