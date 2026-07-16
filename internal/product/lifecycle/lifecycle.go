// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package lifecycle defines a pure, monotonic profile lifecycle state machine.
package lifecycle

import "errors"

type Status string

const (
	Absent     Status = "absent"
	Admitted   Status = "admitted"
	Superseded Status = "superseded"
	Revoked    Status = "revoked"
	Disabled   Status = "disabled"
)

type Action string

const (
	Admit     Action = "admit"
	Supersede Action = "supersede"
	Revoke    Action = "revoke"
	Disable   Action = "disable"
)

type State struct {
	Status                              Status
	ProfileID, Scope, EvidenceReference string
	Generation                          uint64
}
type Decision struct {
	Action                              Action
	ProfileID, Scope, EvidenceReference string
	Generation                          uint64
}

func Apply(current State, d Decision) (State, error) {
	original := current
	if !knownStatus(current.Status) {
		return original, errors.New("lifecycle: unknown current status")
	}
	if !knownAction(d.Action) {
		return original, errors.New("lifecycle: unknown action")
	}
	if current.Status == "" {
		current.Status = Absent
	}
	if current.Status == Absent && (current.ProfileID != "" || current.Scope != "" || current.EvidenceReference != "" || current.Generation != 0) {
		return original, errors.New("lifecycle: malformed absent state")
	}
	if d.Generation == 0 || d.ProfileID == "" || d.Scope == "" || d.EvidenceReference == "" {
		return current, errors.New("lifecycle: partial decision")
	}
	if current.Status != Absent && (d.ProfileID != current.ProfileID || d.Scope != current.Scope) {
		return current, errors.New("lifecycle: over-scoped or mismatched decision")
	}
	if d.Generation < current.Generation {
		return current, errors.New("lifecycle: stale decision")
	}
	if d.Generation == current.Generation {
		if d.ProfileID == current.ProfileID && d.Scope == current.Scope && d.EvidenceReference == current.EvidenceReference && statusFor(d.Action, current.Status) == current.Status {
			return current, nil
		}
		return current, errors.New("lifecycle: conflicting equal-generation decision")
	}
	next := State{ProfileID: d.ProfileID, Scope: d.Scope, EvidenceReference: d.EvidenceReference, Generation: d.Generation}
	switch d.Action {
	case Admit:
		if current.Status == Admitted {
			return current, errors.New("lifecycle: admitted profile must be superseded before replacement")
		}
		next.Status = Admitted
	case Supersede:
		if current.Status != Admitted {
			return current, errors.New("lifecycle: only an admitted profile can be superseded")
		}
		next.Status = Superseded
	case Revoke:
		next.Status = Revoked
	case Disable:
		next.Status = Disabled
	default:
		panic("lifecycle: known action was not handled")
	}
	return next, nil
}

func knownStatus(s Status) bool {
	switch s {
	case "", Absent, Admitted, Superseded, Revoked, Disabled:
		return true
	default:
		return false
	}
}

func knownAction(a Action) bool {
	switch a {
	case Admit, Supersede, Revoke, Disable:
		return true
	default:
		return false
	}
}

func statusFor(a Action, current Status) Status {
	switch a {
	case Admit:
		return Admitted
	case Supersede:
		return Superseded
	case Revoke:
		return Revoked
	case Disable:
		return Disabled
	}
	return current
}
