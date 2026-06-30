// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import "fmt"

type MigrationEvent struct {
	EventID                string `json:"event_id"`
	Tick                   int    `json:"tick"`
	SourceRelayID          string `json:"source_relay_id"`
	TargetRelayID          string `json:"target_relay_id"`
	OldProfileSeed         int    `json:"old_profile_seed"`
	NewProfileSeed         int    `json:"new_profile_seed"`
	OldWirePolicyHash      string `json:"old_wire_policy_hash"`
	NewWirePolicyHash      string `json:"new_wire_policy_hash"`
	SessionContinuityClass string `json:"session_continuity_class"`
	MigrationResult        string `json:"migration_result"`
	ReasonBucket           string `json:"reason_bucket"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
}

func GenerateMigrationEvents(fleet RelayFleet) []MigrationEvent {
	if !fleet.Policy.MigrationEnabled || fleet.Policy.MigrationMode == MigrationNone {
		return nil
	}
	events := []MigrationEvent{}
	active := activeRelays(fleet.Relays)
	if len(active) < 2 {
		return events
	}
	for i := 0; i+1 < len(active) && len(events) < max(1, fleet.Policy.MaxActiveRelays/2); i += 2 {
		source := active[i]
		target := active[i+1]
		reason := migrationReason(fleet.Policy.MigrationMode, source)
		result := "semantic_continuity_preserved"
		if fleet.Policy.MigrationMode == MigrationControlBroken {
			result = "broken_migration_control"
		}
		events = append(events, MigrationEvent{
			EventID:                "migration_" + safeHash(fmt.Sprintf("%s:%s:%d", source.RelayID, target.RelayID, i))[:12],
			Tick:                   20 + i,
			SourceRelayID:          string(source.RelayID),
			TargetRelayID:          string(target.RelayID),
			OldProfileSeed:         source.ProfileSeed,
			NewProfileSeed:         target.ProfileSeed,
			OldWirePolicyHash:      source.WirePolicyHash,
			NewWirePolicyHash:      target.WirePolicyHash,
			SessionContinuityClass: "session_boundary_safe",
			MigrationResult:        result,
			ReasonBucket:           reason,
		})
	}
	return events
}

func ValidateMigrationEvent(fleet RelayFleet, event MigrationEvent) error {
	source, sourceOK := relayByID(fleet, RelayID(event.SourceRelayID))
	target, targetOK := relayByID(fleet, RelayID(event.TargetRelayID))
	if !sourceOK || !targetOK || source.RelayID == target.RelayID {
		return ErrInvalidReport
	}
	if source.State == RelayBurned || target.State == RelayRetired || target.State == RelayBurned {
		return ErrInvalidReport
	}
	if event.PayloadLogged || event.SecretLogged {
		return ErrTraceLeak
	}
	return ScanForLeak(event)
}

func migrationReason(mode string, relay SyntheticRelay) string {
	switch mode {
	case MigrationGracefulProfile:
		return "graceful_profile"
	case MigrationRelayToRelay:
		return "relay_to_relay"
	case MigrationRiskTriggered:
		if relay.BurnRiskBucket == RiskHigh || relay.BurnRiskBucket == RiskCritical {
			return "risk_triggered"
		}
		return "rotation_bucket"
	case MigrationSessionBoundary:
		return "session_boundary"
	case MigrationControlBroken:
		return "broken_control"
	default:
		return "none"
	}
}

func activeRelays(relays []SyntheticRelay) []SyntheticRelay {
	out := []SyntheticRelay{}
	for _, relay := range relays {
		if relay.State == RelayActive {
			out = append(out, relay)
		}
	}
	return out
}

func relayByID(fleet RelayFleet, id RelayID) (SyntheticRelay, bool) {
	for _, relay := range fleet.Relays {
		if relay.RelayID == id {
			return relay, true
		}
	}
	return SyntheticRelay{}, false
}
