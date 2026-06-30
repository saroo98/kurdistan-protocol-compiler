// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

const (
	AssignOneProfilePerRelay  = "one_profile_per_relay"
	AssignProfileRotation     = "profile_rotation"
	AssignFamilyRotation      = "family_rotation"
	AssignWirePolicyRotation  = "wire_policy_rotation"
	AssignRiskAwareRefresh    = "risk_aware_profile_refresh"
	AssignControlFixedProfile = "control_fixed_profile"
	AssignControlPaddingOnly  = "control_padding_only_profile"
	ChurnFixedInterval        = "fixed_interval_churn"
	ChurnRiskThreshold        = "risk_threshold_churn"
	ChurnObservationCount     = "observation_count_churn"
	ChurnProfileReuse         = "profile_reuse_churn"
	ChurnMixedPolicy          = "mixed_policy_churn"
	ChurnControlNoChurn       = "control_no_churn"
	ChurnControlOverChurn     = "control_over_churn"
	MigrationNone             = "no_migration"
	MigrationGracefulProfile  = "graceful_profile_migration"
	MigrationRelayToRelay     = "relay_to_relay_migration"
	MigrationRiskTriggered    = "risk_triggered_migration"
	MigrationSessionBoundary  = "session_boundary_migration"
	MigrationControlBroken    = "control_broken_migration"
)

type FleetPolicy struct {
	Name                    string `json:"name"`
	AssignmentMode          string `json:"assignment_mode"`
	ChurnMode               string `json:"churn_mode"`
	MigrationMode           string `json:"migration_mode"`
	MaxActiveRelays         int    `json:"max_active_relays"`
	MaxObservationsPerRelay int    `json:"max_observations_per_relay"`
	MaxHostRiskBucket       string `json:"max_host_risk_bucket"`
	ProfileReuseLimit       int    `json:"profile_reuse_limit"`
	WirePolicyReuseLimit    int    `json:"wire_policy_reuse_limit"`
	RotationIntervalTicks   int    `json:"rotation_interval_ticks"`
	CoolingPeriodTicks      int    `json:"cooling_period_ticks"`
	MigrationEnabled        bool   `json:"migration_enabled"`
	RiskAwareRefreshEnabled bool   `json:"risk_aware_refresh_enabled"`
}

type Options struct {
	RelayCount       int
	ProfileSeeds     []int
	Policy           FleetPolicy
	IncludeControls  bool
	GeneratedBackend bool
}

func DefaultPolicy() FleetPolicy {
	return FleetPolicy{
		Name:                    "synthetic_fleet_default",
		AssignmentMode:          AssignRiskAwareRefresh,
		ChurnMode:               ChurnMixedPolicy,
		MigrationMode:           MigrationRiskTriggered,
		MaxActiveRelays:         6,
		MaxObservationsPerRelay: 9,
		MaxHostRiskBucket:       RiskHigh,
		ProfileReuseLimit:       2,
		WirePolicyReuseLimit:    2,
		RotationIntervalTicks:   4,
		CoolingPeriodTicks:      2,
		MigrationEnabled:        true,
		RiskAwareRefreshEnabled: true,
	}
}

func DefaultOptions() Options {
	return Options{
		RelayCount:      6,
		ProfileSeeds:    []int{12345, 12346, 12347, 12348, 12349, 12350, 12351, 12352},
		Policy:          DefaultPolicy(),
		IncludeControls: true,
	}
}

func FullOptions() Options {
	policy := DefaultPolicy()
	policy.MaxActiveRelays = 20
	policy.ProfileReuseLimit = 3
	policy.WirePolicyReuseLimit = 3
	seeds := make([]int, 30)
	for i := range seeds {
		seeds[i] = 12345 + i
	}
	return Options{RelayCount: 20, ProfileSeeds: seeds, Policy: policy, IncludeControls: true}
}

func AssignmentModes() []string {
	return []string{AssignOneProfilePerRelay, AssignProfileRotation, AssignFamilyRotation, AssignWirePolicyRotation, AssignRiskAwareRefresh, AssignControlFixedProfile, AssignControlPaddingOnly}
}

func ChurnModes() []string {
	return []string{ChurnFixedInterval, ChurnRiskThreshold, ChurnObservationCount, ChurnProfileReuse, ChurnMixedPolicy, ChurnControlNoChurn, ChurnControlOverChurn}
}

func MigrationModes() []string {
	return []string{MigrationNone, MigrationGracefulProfile, MigrationRelayToRelay, MigrationRiskTriggered, MigrationSessionBoundary, MigrationControlBroken}
}

func NormalizeOptions(opts Options) Options {
	def := DefaultOptions()
	if opts.RelayCount == 0 {
		opts.RelayCount = def.RelayCount
	}
	if len(opts.ProfileSeeds) == 0 {
		opts.ProfileSeeds = def.ProfileSeeds
	}
	if opts.Policy.Name == "" {
		opts.Policy = def.Policy
	}
	return opts
}

func ValidatePolicy(policy FleetPolicy) error {
	if policy.Name == "" || policy.MaxActiveRelays <= 0 || policy.MaxActiveRelays > 128 {
		return ErrInvalidPolicy
	}
	if policy.MaxObservationsPerRelay <= 0 || policy.MaxObservationsPerRelay > 10_000 {
		return ErrInvalidPolicy
	}
	if policy.ProfileReuseLimit <= 0 || policy.WirePolicyReuseLimit <= 0 {
		return ErrInvalidPolicy
	}
	if policy.RotationIntervalTicks <= 0 || policy.CoolingPeriodTicks <= 0 {
		return ErrInvalidPolicy
	}
	if !contains(AssignmentModes(), policy.AssignmentMode) || !contains(ChurnModes(), policy.ChurnMode) || !contains(MigrationModes(), policy.MigrationMode) {
		return ErrInvalidPolicy
	}
	if !contains([]string{RiskLow, RiskMedium, RiskHigh, RiskCritical, RiskUnknown}, policy.MaxHostRiskBucket) {
		return ErrInvalidPolicy
	}
	return nil
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
