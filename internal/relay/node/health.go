// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package node

import "sync"

type HealthState string

const (
	HealthStarting HealthState = "STARTING"
	HealthReady    HealthState = "READY"
	HealthDraining HealthState = "DRAINING"
	HealthDisabled HealthState = "DISABLED"
	HealthDegraded HealthState = "DEGRADED"
	HealthStopping HealthState = "STOPPING"
)

type HealthRequirements struct {
	Listener, Tunnel, VerifiedState, TLSIdentity, RelayIdentity, DNS bool
}

type HealthSnapshot struct {
	State             HealthState
	AcceptingSessions bool
	Missing           uint8
}

type HealthMachine struct {
	mu           sync.RWMutex
	requirements HealthRequirements
	drained      bool
	disabled     bool
	stopping     bool
	updated      bool
}

func NewHealthMachine() *HealthMachine { return &HealthMachine{} }

func (health *HealthMachine) Update(requirements HealthRequirements) {
	if health == nil {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	if !health.stopping {
		health.requirements = requirements
		health.updated = true
	}
}

func (health *HealthMachine) SetDrain(drained bool) {
	if health == nil {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	if !health.stopping {
		health.drained = drained
	}
}

func (health *HealthMachine) SetDisabled(disabled bool) {
	if health == nil {
		return
	}
	health.mu.Lock()
	defer health.mu.Unlock()
	if !health.stopping {
		health.disabled = disabled
	}
}

func (health *HealthMachine) Stop() {
	if health == nil {
		return
	}
	health.mu.Lock()
	health.stopping = true
	health.mu.Unlock()
}

func (health *HealthMachine) Snapshot() HealthSnapshot {
	if health == nil {
		return HealthSnapshot{State: HealthDisabled}
	}
	health.mu.RLock()
	defer health.mu.RUnlock()
	missing := missingRequirementsV1(health.requirements)
	snapshot := HealthSnapshot{State: HealthStarting, Missing: missing}
	switch {
	case health.stopping:
		snapshot.State = HealthStopping
	case health.disabled:
		snapshot.State = HealthDisabled
	case health.drained:
		snapshot.State = HealthDraining
	case !health.updated:
		snapshot.State = HealthStarting
	case missing > 0:
		snapshot.State = HealthDegraded
	default:
		snapshot.State = HealthReady
		snapshot.AcceptingSessions = true
	}
	return snapshot
}

func missingRequirementsV1(requirements HealthRequirements) uint8 {
	var missing uint8
	for _, available := range []bool{requirements.Listener, requirements.Tunnel, requirements.VerifiedState, requirements.TLSIdentity, requirements.RelayIdentity, requirements.DNS} {
		if !available {
			missing++
		}
	}
	return missing
}
