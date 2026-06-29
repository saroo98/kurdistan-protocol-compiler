// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/security"
)

type LinkFrame struct {
	Direction     string                  `json:"direction"`
	SessionID     string                  `json:"session_id"`
	Sequence      uint64                  `json:"sequence"`
	EnvelopeKind  string                  `json:"envelope_kind"`
	ByteCount     int                     `json:"byte_count"`
	MetadataClass string                  `json:"metadata_class,omitempty"`
	Envelope      security.SecureEnvelope `json:"-"`
}

type MemoryLink struct {
	MaxQueueDepth int
	closed        bool
	failNext      bool
	clientServer  []LinkFrame
	serverClient  []LinkFrame
}

func NewMemoryLink(maxQueueDepth int) *MemoryLink {
	if maxQueueDepth <= 0 {
		maxQueueDepth = 64
	}
	return &MemoryLink{MaxQueueDepth: maxQueueDepth}
}

func (l *MemoryLink) Send(frame LinkFrame) error {
	if l == nil {
		return fmt.Errorf("%w: nil link", ErrLinkFailure)
	}
	if l.closed {
		return ErrLinkClosed
	}
	if l.failNext {
		l.failNext = false
		return ErrLinkFailure
	}
	if frame.Direction == "" {
		return fmt.Errorf("%w: missing direction", ErrLinkFailure)
	}
	q := &l.clientServer
	if frame.Direction == "server_to_client" {
		q = &l.serverClient
	}
	if len(*q) >= l.MaxQueueDepth {
		return ErrLinkQueueFull
	}
	*q = append(*q, frame)
	return nil
}

func (l *MemoryLink) Deliver(direction string) (LinkFrame, error) {
	if l == nil {
		return LinkFrame{}, fmt.Errorf("%w: nil link", ErrLinkFailure)
	}
	q := &l.clientServer
	if direction == "server_to_client" {
		q = &l.serverClient
	}
	if len(*q) == 0 {
		return LinkFrame{}, fmt.Errorf("%w: empty queue", ErrLinkFailure)
	}
	frame := (*q)[0]
	*q = (*q)[1:]
	return frame, nil
}

func (l *MemoryLink) Close() {
	if l != nil {
		l.closed = true
	}
}

func (l *MemoryLink) InjectFailure() {
	if l != nil {
		l.failNext = true
	}
}

func (l *MemoryLink) QueueDepth(direction string) int {
	if l == nil {
		return 0
	}
	if direction == "server_to_client" {
		return len(l.serverClient)
	}
	return len(l.clientServer)
}
