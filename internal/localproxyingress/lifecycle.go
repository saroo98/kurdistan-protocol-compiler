// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

type requestLifecycle struct {
	opened bool
	closed bool
	reset  bool
	failed bool
}

func (l *requestLifecycle) apply(event SyntheticIngressEvent) error {
	if l.closed || l.reset || l.failed {
		if event.Kind == RequestEventClose && l.closed {
			return ErrLifecycleViolation
		}
		return ErrLifecycleViolation
	}
	switch event.Kind {
	case RequestEventOpen:
		if l.opened {
			return ErrLifecycleViolation
		}
		l.opened = true
	case RequestEventData, RequestEventBackpress:
		if !l.opened {
			return ErrLifecycleViolation
		}
	case RequestEventClose:
		if !l.opened {
			return ErrLifecycleViolation
		}
		l.closed = true
	case RequestEventReset:
		if !l.opened {
			return ErrLifecycleViolation
		}
		l.reset = true
	case RequestEventTargetErr:
		if !l.opened {
			return ErrLifecycleViolation
		}
		l.failed = true
	default:
		return ErrInvalidEvent
	}
	return nil
}

func (l requestLifecycle) finalState() string {
	switch {
	case l.reset:
		return "reset"
	case l.failed:
		return "failed"
	case l.closed:
		return "closed"
	case l.opened:
		return "accepted"
	default:
		return "rejected"
	}
}
