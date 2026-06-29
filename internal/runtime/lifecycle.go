// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import "fmt"

func (s *Session) transition(to SessionState, reason string) error {
	if s == nil {
		return fmt.Errorf("%w: nil session", ErrLifecycle)
	}
	if terminalState(s.State) {
		if s.State == SessionClosed && to == SessionClosed {
			return nil
		}
		return fmt.Errorf("%w: terminal state %s", ErrLifecycle, s.State)
	}
	if !validTransition(s.State, to) {
		return fmt.Errorf("%w: %s to %s", ErrLifecycle, s.State, to)
	}
	from := s.State
	s.State = to
	if to == SessionFailed {
		s.FailureReason = reason
	}
	if to == SessionClosed || to == SessionDraining {
		s.CloseReason = reason
	}
	s.Events = append(s.Events, Event{
		RuntimeRole:   s.Role,
		RuntimeID:     s.RuntimeID,
		SessionID:     s.ID,
		State:         s.State,
		Transition:    string(from) + "->" + string(to),
		FailureReason: safeReason(s.FailureReason),
		CloseReason:   safeReason(s.CloseReason),
	})
	return nil
}

func validTransition(from, to SessionState) bool {
	switch from {
	case SessionNew:
		return to == SessionNegotiating || to == SessionFailed
	case SessionNegotiating:
		return to == SessionSecuring || to == SessionFailed
	case SessionSecuring:
		return to == SessionOpen || to == SessionFailed
	case SessionOpen:
		return to == SessionDraining || to == SessionClosed || to == SessionFailed
	case SessionDraining:
		return to == SessionClosed || to == SessionFailed
	default:
		return false
	}
}

func safeReason(reason string) string {
	if reason == "" {
		return ""
	}
	if len(reason) > 64 {
		return reason[:64]
	}
	return reason
}
