// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

type RelayFleetVersion string
type RelayID string
type RelayState string
type RelayClass string

const (
	Version          RelayFleetVersion = "relayfleet-v1"
	FixedGeneratedAt                   = "2026-06-30T00:00:00Z"

	RelayProvisioned RelayState = "provisioned"
	RelayActive      RelayState = "active"
	RelayCooling     RelayState = "cooling"
	RelayRotating    RelayState = "rotating"
	RelayMigrating   RelayState = "migrating"
	RelayQuarantined RelayState = "quarantined"
	RelayRetired     RelayState = "retired"
	RelayBurned      RelayState = "burned"

	RelayClassGenerated RelayClass = "generated"
	RelayClassBaseline  RelayClass = "baseline"
	RelayClassControl   RelayClass = "control"

	RiskLow      = "low"
	RiskMedium   = "medium"
	RiskHigh     = "high"
	RiskCritical = "critical"
	RiskUnknown  = "unknown"
)

type SyntheticRelay struct {
	RelayID          RelayID    `json:"relay_id"`
	RelayClass       RelayClass `json:"relay_class"`
	State            RelayState `json:"state"`
	ProfileID        string     `json:"profile_id"`
	ProfileSeed      int        `json:"profile_seed"`
	WirePolicyHash   string     `json:"wire_policy_hash"`
	SelectedFamily   string     `json:"selected_family"`
	SyntheticHostID  string     `json:"synthetic_host_id"`
	CreatedAtTick    int        `json:"created_at_tick"`
	ActivatedAtTick  int        `json:"activated_at_tick"`
	RetiredAtTick    int        `json:"retired_at_tick,omitempty"`
	ObservationCount int        `json:"observation_count"`
	MigrationCount   int        `json:"migration_count"`
	RotationCount    int        `json:"rotation_count"`
	BurnRiskBucket   string     `json:"burn_risk_bucket"`
	PayloadLogged    bool       `json:"payload_logged"`
	SecretLogged     bool       `json:"secret_logged"`
}

func terminalState(state RelayState) bool {
	return state == RelayRetired || state == RelayBurned
}

func supportedState(state RelayState) bool {
	switch state {
	case RelayProvisioned, RelayActive, RelayCooling, RelayRotating, RelayMigrating, RelayQuarantined, RelayRetired, RelayBurned:
		return true
	default:
		return false
	}
}

func supportedClass(class RelayClass) bool {
	switch class {
	case RelayClassGenerated, RelayClassBaseline, RelayClassControl:
		return true
	default:
		return false
	}
}
