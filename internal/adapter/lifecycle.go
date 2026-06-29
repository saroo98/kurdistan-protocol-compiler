// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import "fmt"

func (f *Flow) Transition(next FlowState, caps AdapterCapabilities) error {
	if f == nil {
		return fmt.Errorf("%w: nil flow", ErrInvalidFlow)
	}
	if f.State == next && (next == FlowClosed || next == FlowReset) {
		return nil
	}
	if f.Terminal() {
		return fmt.Errorf("%w: %s is terminal", ErrInvalidTransition, f.State)
	}
	valid := false
	switch f.State {
	case FlowNew:
		valid = next == FlowOpening || next == FlowReset || next == FlowFailed
	case FlowOpening:
		valid = next == FlowOpen || next == FlowReset || next == FlowFailed
	case FlowOpen:
		valid = next == FlowHalfClosed || next == FlowDraining || next == FlowClosed || next == FlowReset || next == FlowFailed
	case FlowHalfClosed:
		valid = next == FlowDraining || next == FlowClosed || next == FlowReset || next == FlowFailed
	case FlowDraining:
		valid = next == FlowClosed || next == FlowReset || next == FlowFailed
	}
	if next == FlowHalfClosed && !caps.SupportsHalfClose {
		return fmt.Errorf("%w: half-close capability missing", ErrCapabilityMismatch)
	}
	if next == FlowReset && !caps.SupportsReset {
		return fmt.Errorf("%w: reset capability missing", ErrCapabilityMismatch)
	}
	if !valid {
		return fmt.Errorf("%w: %s to %s", ErrInvalidTransition, f.State, next)
	}
	f.State = next
	f.Events++
	return nil
}

func (f *Flow) Open(caps AdapterCapabilities) error {
	if err := f.Transition(FlowOpening, caps); err != nil {
		return err
	}
	return f.Transition(FlowOpen, caps)
}

func (f *Flow) Close(caps AdapterCapabilities) error {
	if f == nil {
		return fmt.Errorf("%w: nil flow", ErrInvalidFlow)
	}
	if f.State == FlowClosed {
		return nil
	}
	if f.State == FlowReset || f.State == FlowFailed {
		return nil
	}
	return f.Transition(FlowClosed, caps)
}

func (f *Flow) Reset(caps AdapterCapabilities, _ string) error {
	if f == nil {
		return fmt.Errorf("%w: nil flow", ErrInvalidFlow)
	}
	if f.State == FlowReset {
		return nil
	}
	if f.State == FlowClosed || f.State == FlowFailed {
		return nil
	}
	return f.Transition(FlowReset, caps)
}

func (f *Flow) Fail(caps AdapterCapabilities, _ string) error {
	if f == nil {
		return fmt.Errorf("%w: nil flow", ErrInvalidFlow)
	}
	if f.State == FlowFailed {
		return nil
	}
	if f.State == FlowClosed || f.State == FlowReset {
		return nil
	}
	return f.Transition(FlowFailed, caps)
}
