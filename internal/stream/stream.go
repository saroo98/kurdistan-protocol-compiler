// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package stream

import "bytes"

type State string

const (
	StateIdle             State = "idle"
	StateOpen             State = "open"
	StateHalfClosedLocal  State = "half-closed-local"
	StateHalfClosedRemote State = "half-closed-remote"
	StateClosed           State = "closed"
	StateReset            State = "reset"
)

type Stream struct {
	ID           uint32
	Priority     string
	State        State
	windowBytes  int
	pendingBytes int
	blocked      bool
	buffer       bytes.Buffer
	resetReason  string
}

func (s *Stream) WindowBytes() int {
	if s == nil {
		return 0
	}
	return s.windowBytes
}

func (s *Stream) PendingBytes() int {
	if s == nil {
		return 0
	}
	return s.pendingBytes
}

func (s *Stream) Blocked() bool {
	return s != nil && s.blocked
}
