// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import "fmt"

type ChurnEvent struct {
	EventID        string `json:"event_id"`
	Tick           int    `json:"tick"`
	RelayID        string `json:"relay_id"`
	EventType      string `json:"event_type"`
	OldState       string `json:"old_state"`
	NewState       string `json:"new_state"`
	OldProfileSeed int    `json:"old_profile_seed"`
	NewProfileSeed int    `json:"new_profile_seed"`
	ReasonBucket   string `json:"reason_bucket"`
	PayloadLogged  bool   `json:"payload_logged"`
	SecretLogged   bool   `json:"secret_logged"`
}

func GenerateChurnSchedule(fleet RelayFleet) []ChurnEvent {
	events := []ChurnEvent{}
	if fleet.Policy.ChurnMode == ChurnControlNoChurn {
		return events
	}
	for i, relay := range fleet.Relays {
		if relay.RelayClass == RelayClassControl && fleet.Policy.ChurnMode != ChurnControlOverChurn {
			continue
		}
		if terminalState(relay.State) {
			continue
		}
		reason := churnReason(fleet.Policy.ChurnMode, relay)
		if reason == "" {
			continue
		}
		tick := (i + 1) * fleet.Policy.RotationIntervalTicks
		newSeed := relay.ProfileSeed + 1000 + i
		if fleet.Policy.ChurnMode == ChurnControlOverChurn {
			tick = i + 1
		}
		events = append(events, ChurnEvent{
			EventID:        "churn_" + safeHash(fmt.Sprintf("%s:%d:%s", relay.RelayID, tick, reason))[:12],
			Tick:           tick,
			RelayID:        string(relay.RelayID),
			EventType:      "profile_refresh",
			OldState:       string(relay.State),
			NewState:       string(RelayRotating),
			OldProfileSeed: relay.ProfileSeed,
			NewProfileSeed: newSeed,
			ReasonBucket:   reason,
		})
		if len(events) >= fleet.Policy.MaxActiveRelays {
			break
		}
	}
	return events
}

func churnReason(mode string, relay SyntheticRelay) string {
	switch mode {
	case ChurnFixedInterval:
		return "fixed_interval"
	case ChurnRiskThreshold:
		if relay.BurnRiskBucket == RiskHigh || relay.BurnRiskBucket == RiskCritical {
			return "risk_threshold"
		}
	case ChurnObservationCount:
		if relay.ObservationCount >= 4 {
			return "observation_count"
		}
	case ChurnProfileReuse:
		return "profile_reuse"
	case ChurnMixedPolicy:
		if relay.BurnRiskBucket == RiskHigh || relay.BurnRiskBucket == RiskCritical {
			return "risk_threshold"
		}
		if relay.ObservationCount >= 4 {
			return "observation_count"
		}
		return "interval_bucket"
	case ChurnControlOverChurn:
		return "over_churn_control"
	}
	return ""
}
