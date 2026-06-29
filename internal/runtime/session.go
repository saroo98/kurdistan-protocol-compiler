// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/security"
	kstream "kurdistan/internal/stream"
)

type Session struct {
	ID              string
	RuntimeID       string
	Role            Role
	State           SessionState
	SecurityContext security.SecurityContext
	KeySchedule     security.KeySchedule
	Capabilities    security.CapabilitySet
	StreamSession   *kstream.Session
	Events          []Event
	CloseReason     string
	FailureReason   string
}

func NewSession(id, runtimeID string, role Role) (*Session, error) {
	if id == "" {
		return nil, fmt.Errorf("%w: missing session id", ErrLifecycle)
	}
	if err := ValidateRole(role); err != nil {
		return nil, err
	}
	return &Session{ID: id, RuntimeID: runtimeID, Role: role, State: SessionNew}, nil
}

func (s *Session) BeginNegotiation() error { return s.transition(SessionNegotiating, "") }
func (s *Session) BeginSecuring() error    { return s.transition(SessionSecuring, "") }
func (s *Session) MarkOpen() error         { return s.transition(SessionOpen, "") }
func (s *Session) Drain(reason string) error {
	return s.transition(SessionDraining, reason)
}
func (s *Session) Close(reason string) error {
	if s.State == SessionClosed {
		return nil
	}
	if s.State == SessionOpen {
		if err := s.Drain(reason); err != nil {
			return err
		}
	}
	if s.State == SessionDraining {
		return s.transition(SessionClosed, reason)
	}
	if s.State == SessionNew || s.State == SessionNegotiating || s.State == SessionSecuring {
		return s.transition(SessionFailed, "close_before_open")
	}
	return nil
}
func (s *Session) Fail(reason string) error {
	if terminalState(s.State) {
		return nil
	}
	return s.transition(SessionFailed, reason)
}
