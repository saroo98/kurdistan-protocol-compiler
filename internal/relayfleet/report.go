// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

type FleetCollapseReport struct {
	FleetID                string   `json:"fleet_id"`
	RelayCount             int      `json:"relay_count"`
	ActiveRelays           int      `json:"active_relays"`
	UniqueProfileSeeds     int      `json:"unique_profile_seeds"`
	UniqueWirePolicyHashes int      `json:"unique_wire_policy_hashes"`
	UniqueFamilies         int      `json:"unique_families"`
	ChurnEvents            int      `json:"churn_events"`
	MigrationEvents        int      `json:"migration_events"`
	HighRiskRelays         int      `json:"high_risk_relays"`
	SuspiciousMetrics      []string `json:"suspicious_metrics,omitempty"`
	DiversityScore         float64  `json:"diversity_score"`
	PayloadLogged          bool     `json:"payload_logged"`
	SecretLogged           bool     `json:"secret_logged"`
	Conclusion             string   `json:"conclusion"`
}

type FleetParityReport struct {
	ComparedFleets        int      `json:"compared_fleets"`
	ComparedRelays        int      `json:"compared_relays"`
	LifecycleMatches      int      `json:"lifecycle_matches"`
	AssignmentMatches     int      `json:"assignment_matches"`
	ChurnMatches          int      `json:"churn_matches"`
	MigrationMatches      int      `json:"migration_matches"`
	RiskBucketMatches     int      `json:"risk_bucket_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type RelayFleetComparisonReport struct {
	Version         string   `json:"version"`
	OldRelays       int      `json:"old_relays"`
	NewRelays       int      `json:"new_relays"`
	Added           int      `json:"added"`
	Removed         int      `json:"removed"`
	Changed         int      `json:"changed"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func ScanCollapse(fleet RelayFleet, assignment ProfileAssignmentReport, churn []ChurnEvent, migrations []MigrationEvent, risk BurnRiskReport) FleetCollapseReport {
	seeds := map[int]bool{}
	policies := map[string]bool{}
	families := map[string]bool{}
	report := FleetCollapseReport{FleetID: fleet.FleetID, RelayCount: len(fleet.Relays), ChurnEvents: len(churn), MigrationEvents: len(migrations), Conclusion: "passed"}
	for _, relay := range fleet.Relays {
		seeds[relay.ProfileSeed] = true
		policies[relay.WirePolicyHash] = true
		families[relay.SelectedFamily] = true
		if relay.State == RelayActive {
			report.ActiveRelays++
		}
		if relay.BurnRiskBucket == RiskHigh || relay.BurnRiskBucket == RiskCritical {
			report.HighRiskRelays++
		}
		if relay.State == RelayBurned && relay.RelayClass != RelayClassControl {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "burned_relay_in_generated_fleet")
		}
		report.PayloadLogged = report.PayloadLogged || relay.PayloadLogged
		report.SecretLogged = report.SecretLogged || relay.SecretLogged
	}
	report.UniqueProfileSeeds = len(seeds)
	report.UniqueWirePolicyHashes = len(policies)
	report.UniqueFamilies = len(families)
	report.DiversityScore = diversityScore(report.UniqueProfileSeeds, report.UniqueWirePolicyHashes, report.UniqueFamilies, report.RelayCount)
	if assignment.ProfileReuseViolations > 0 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "profile_reuse_limit_exceeded")
	}
	if assignment.PolicyReuseViolations > 0 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "wire_policy_reuse_limit_exceeded")
	}
	if report.UniqueProfileSeeds <= 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "same_profile_seed_across_fleet")
	}
	if report.UniqueWirePolicyHashes <= 2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "same_wire_policy_hash_across_fleet")
	}
	if report.UniqueFamilies <= 1 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "same_selected_family_across_fleet")
	}
	if len(churn) == 0 && risk.HighRiskRelays+risk.CriticalRiskRelays > 0 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "no_churn_despite_high_risk")
	}
	if len(churn) > report.RelayCount*2 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "over_churn_no_stable_active")
	}
	if fleet.Policy.MigrationEnabled && len(migrations) == 0 {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "migration_events_ignored")
	}
	if report.PayloadLogged || report.SecretLogged {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "trace_hygiene_failed")
	}
	onlyControls := true
	for _, relay := range fleet.Relays {
		if relay.RelayClass != RelayClassControl {
			onlyControls = false
			break
		}
	}
	if len(report.SuspiciousMetrics) > 0 && !onlyControls {
		report.Conclusion = "failed"
	}
	return report
}

func CompareFleets(interpreted, generated RelayFleetSummary) FleetParityReport {
	report := FleetParityReport{ComparedFleets: 2, ComparedRelays: len(interpreted.Fleet.Relays), Conclusion: "passed"}
	if len(interpreted.Fleet.Relays) == len(generated.Fleet.Relays) {
		report.LifecycleMatches = len(interpreted.Fleet.Relays)
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "relay_count")
	}
	if interpreted.Assignment.UniqueProfileSeeds == generated.Assignment.UniqueProfileSeeds && interpreted.Assignment.UniqueWirePolicyHashes == generated.Assignment.UniqueWirePolicyHashes {
		report.AssignmentMatches = len(interpreted.Fleet.Relays)
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "assignment")
	}
	if len(interpreted.ChurnEvents) == len(generated.ChurnEvents) {
		report.ChurnMatches = len(interpreted.ChurnEvents)
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "churn_count")
	}
	if len(interpreted.MigrationEvents) == len(generated.MigrationEvents) {
		report.MigrationMatches = len(interpreted.MigrationEvents)
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "migration_count")
	}
	if interpreted.BurnRisk.HighRiskRelays+interpreted.BurnRisk.CriticalRiskRelays == generated.BurnRisk.HighRiskRelays+generated.BurnRisk.CriticalRiskRelays {
		report.RiskBucketMatches = len(interpreted.Fleet.Relays)
	} else {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "risk_buckets")
	}
	report.PayloadLogged = interpreted.PayloadLogged || generated.PayloadLogged
	report.SecretLogged = interpreted.SecretLogged || generated.SecretLogged
	if len(report.UnexpectedDifferences) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func diversityScore(seeds, policies, families, relays int) float64 {
	if relays == 0 {
		return 0
	}
	return (float64(seeds) + float64(policies) + float64(families)) / float64(relays*3)
}
