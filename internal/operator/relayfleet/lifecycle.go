// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import "fmt"

type LifecycleTransition struct {
	RelayID       string `json:"relay_id"`
	Tick          int    `json:"tick"`
	OldState      string `json:"old_state"`
	NewState      string `json:"new_state"`
	ReasonBucket  string `json:"reason_bucket"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

func CanTransition(from, to RelayState) bool {
	switch from {
	case RelayProvisioned:
		return to == RelayActive
	case RelayActive:
		return to == RelayCooling || to == RelayRotating || to == RelayMigrating || to == RelayQuarantined || to == RelayRetired || to == RelayBurned
	case RelayCooling:
		return to == RelayActive
	case RelayRotating:
		return to == RelayActive
	case RelayMigrating:
		return to == RelayActive
	case RelayQuarantined:
		return to == RelayRetired
	case RelayRetired, RelayBurned:
		return false
	default:
		return false
	}
}

func TransitionRelay(relay SyntheticRelay, to RelayState, tick int, policy FleetPolicy) (SyntheticRelay, LifecycleTransition, error) {
	if !supportedState(to) || !CanTransition(relay.State, to) {
		return relay, LifecycleTransition{}, ErrInvalidTransition
	}
	if relay.State == RelayBurned && to == RelayMigrating {
		return relay, LifecycleTransition{}, ErrInvalidTransition
	}
	if relay.State == RelayCooling && tick-relay.ActivatedAtTick < policy.CoolingPeriodTicks {
		return relay, LifecycleTransition{}, ErrInvalidTransition
	}
	old := relay.State
	relay.State = to
	if to == RelayRetired || to == RelayBurned {
		relay.RetiredAtTick = tick
	}
	if to == RelayActive {
		relay.ActivatedAtTick = tick
	}
	if to == RelayRotating {
		relay.RotationCount++
	}
	if to == RelayMigrating {
		relay.MigrationCount++
	}
	return relay, LifecycleTransition{
		RelayID:      string(relay.RelayID),
		Tick:         tick,
		OldState:     string(old),
		NewState:     string(to),
		ReasonBucket: "policy_" + string(to),
	}, nil
}

func ReplayLifecycle(fleet RelayFleet, transitions []LifecycleTransition) (RelayFleet, error) {
	relays := map[RelayID]SyntheticRelay{}
	for _, relay := range fleet.Relays {
		relays[relay.RelayID] = relay
	}
	for _, transition := range transitions {
		id := RelayID(transition.RelayID)
		relay, ok := relays[id]
		if !ok {
			return fleet, fmt.Errorf("%w: unknown relay", ErrInvalidTransition)
		}
		next, _, err := TransitionRelay(relay, RelayState(transition.NewState), transition.Tick, fleet.Policy)
		if err != nil {
			return fleet, err
		}
		relays[id] = next
	}
	for i := range fleet.Relays {
		fleet.Relays[i] = relays[fleet.Relays[i].RelayID]
	}
	if activeRelayCount(fleet.Relays) > fleet.Policy.MaxActiveRelays {
		return fleet, ErrInvalidFleet
	}
	fleet.FleetHash = FleetHash(fleet)
	return fleet, nil
}

func LifecycleGolden(fleet RelayFleet) []LifecycleTransition {
	events := []LifecycleTransition{}
	for i, relay := range fleet.Relays {
		if i >= 6 {
			break
		}
		switch relay.State {
		case RelayProvisioned:
			events = append(events, LifecycleTransition{RelayID: string(relay.RelayID), Tick: i + 1, OldState: string(RelayProvisioned), NewState: string(RelayActive), ReasonBucket: "initial_activation"})
		case RelayCooling:
			events = append(events, LifecycleTransition{RelayID: string(relay.RelayID), Tick: relay.ActivatedAtTick + fleet.Policy.CoolingPeriodTicks, OldState: string(RelayCooling), NewState: string(RelayActive), ReasonBucket: "cooling_complete"})
		case RelayRotating:
			events = append(events, LifecycleTransition{RelayID: string(relay.RelayID), Tick: i + 8, OldState: string(RelayRotating), NewState: string(RelayActive), ReasonBucket: "rotation_complete"})
		case RelayMigrating:
			events = append(events, LifecycleTransition{RelayID: string(relay.RelayID), Tick: i + 9, OldState: string(RelayMigrating), NewState: string(RelayActive), ReasonBucket: "migration_complete"})
		case RelayQuarantined:
			events = append(events, LifecycleTransition{RelayID: string(relay.RelayID), Tick: i + 10, OldState: string(RelayQuarantined), NewState: string(RelayRetired), ReasonBucket: "quarantine_retire"})
		}
	}
	return events
}
