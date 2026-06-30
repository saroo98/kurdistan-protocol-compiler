// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

type ProfileAssignmentReport struct {
	RelayCount             int    `json:"relay_count"`
	AssignedProfiles       int    `json:"assigned_profiles"`
	UniqueProfileSeeds     int    `json:"unique_profile_seeds"`
	UniqueWirePolicyHashes int    `json:"unique_wire_policy_hashes"`
	UniqueSelectedFamilies int    `json:"unique_selected_families"`
	ProfileReuseViolations int    `json:"profile_reuse_violations"`
	PolicyReuseViolations  int    `json:"policy_reuse_violations"`
	RiskTriggeredRefreshes int    `json:"risk_triggered_refreshes"`
	PayloadLogged          bool   `json:"payload_logged"`
	SecretLogged           bool   `json:"secret_logged"`
	Conclusion             string `json:"conclusion"`
}

func AnalyzeProfileAssignment(fleet RelayFleet) ProfileAssignmentReport {
	seedCounts := map[int]int{}
	policyCounts := map[string]int{}
	families := map[string]bool{}
	assigned := 0
	refreshes := 0
	report := ProfileAssignmentReport{RelayCount: len(fleet.Relays), Conclusion: "passed"}
	for _, relay := range fleet.Relays {
		if relay.ProfileSeed != 0 && relay.ProfileID != "" {
			assigned++
			seedCounts[relay.ProfileSeed]++
		}
		if relay.WirePolicyHash != "" {
			policyCounts[relay.WirePolicyHash]++
		}
		if relay.SelectedFamily != "" {
			families[relay.SelectedFamily] = true
		}
		if fleet.Policy.RiskAwareRefreshEnabled && (relay.BurnRiskBucket == RiskHigh || relay.BurnRiskBucket == RiskCritical) && relay.RotationCount > 0 {
			refreshes++
		}
		report.PayloadLogged = report.PayloadLogged || relay.PayloadLogged
		report.SecretLogged = report.SecretLogged || relay.SecretLogged
	}
	for _, count := range seedCounts {
		if count > fleet.Policy.ProfileReuseLimit {
			report.ProfileReuseViolations += count - fleet.Policy.ProfileReuseLimit
		}
	}
	for _, count := range policyCounts {
		if count > fleet.Policy.WirePolicyReuseLimit {
			report.PolicyReuseViolations += count - fleet.Policy.WirePolicyReuseLimit
		}
	}
	report.AssignedProfiles = assigned
	report.UniqueProfileSeeds = len(seedCounts)
	report.UniqueWirePolicyHashes = len(policyCounts)
	report.UniqueSelectedFamilies = len(families)
	report.RiskTriggeredRefreshes = refreshes
	if assigned != len(fleet.Relays) || report.ProfileReuseViolations > 0 || report.PolicyReuseViolations > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
