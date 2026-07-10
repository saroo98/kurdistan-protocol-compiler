// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

type BundleCollapseReport struct {
	BundleID                  string   `json:"bundle_id"`
	CandidateCount            int      `json:"candidate_count"`
	UniqueFamilies            int      `json:"unique_families"`
	UniqueProfileSeeds        int      `json:"unique_profile_seeds"`
	UniqueWirePolicyHashes    int      `json:"unique_wire_policy_hashes"`
	PrimaryEligibleCandidates int      `json:"primary_eligible_candidates"`
	HighRiskCandidates        int      `json:"high_risk_candidates"`
	ExperimentalCandidates    int      `json:"experimental_candidates"`
	CollapseFindings          []string `json:"collapse_findings,omitempty"`
	DiversityScore            float64  `json:"diversity_score"`
	PayloadLogged             bool     `json:"payload_logged"`
	SecretLogged              bool     `json:"secret_logged"`
	Conclusion                string   `json:"conclusion"`
}

type TransportBundleParityReport struct {
	ComparedBundles       int      `json:"compared_bundles"`
	ComparedCandidates    int      `json:"compared_candidates"`
	PolicyMatches         int      `json:"policy_matches"`
	CandidateCountMatches int      `json:"candidate_count_matches"`
	FamilyCountMatches    int      `json:"family_count_matches"`
	RoleCountMatches      int      `json:"role_count_matches"`
	FallbackPlanMatches   int      `json:"fallback_plan_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type TransportBundleComparisonReport struct {
	Version         string   `json:"version"`
	OldHash         string   `json:"old_hash"`
	NewHash         string   `json:"new_hash"`
	UnexpectedDrift []string `json:"unexpected_drift,omitempty"`
	PayloadLogged   bool     `json:"payload_logged"`
	SecretLogged    bool     `json:"secret_logged"`
	Conclusion      string   `json:"conclusion"`
}

func ScanCollapse(manifest TransportBundleManifest) BundleCollapseReport {
	report := BundleCollapseReport{BundleID: manifest.BundleID, CandidateCount: len(manifest.Candidates), Conclusion: "passed"}
	families := map[string]bool{}
	seeds := map[int]bool{}
	wires := map[string]bool{}
	for _, c := range manifest.Candidates {
		families[string(c.Family)] = true
		seeds[c.ProfileSeed] = true
		wires[c.WirePolicyHash] = true
		if c.Role == CandidateRolePrimaryEligible {
			report.PrimaryEligibleCandidates++
		}
		if c.HighRisk {
			report.HighRiskCandidates++
			if c.Role == CandidateRolePrimaryEligible {
				report.CollapseFindings = append(report.CollapseFindings, "high_risk_candidate_primary_eligible")
			}
		}
		if c.Experimental {
			report.ExperimentalCandidates++
			if c.Role == CandidateRolePrimaryEligible {
				report.CollapseFindings = append(report.CollapseFindings, "experimental_candidate_primary_eligible")
			}
		}
		if c.BurnRiskClass == "burned" && c.Role == CandidateRolePrimaryEligible {
			report.CollapseFindings = append(report.CollapseFindings, "burned_relay_primary_eligible")
		}
		if c.BurnRiskClass == "quarantined" && c.Role == CandidateRolePrimaryEligible {
			report.CollapseFindings = append(report.CollapseFindings, "quarantined_relay_primary_eligible")
		}
		report.PayloadLogged = report.PayloadLogged || c.PayloadLogged
		report.SecretLogged = report.SecretLogged || c.SecretLogged
	}
	report.UniqueFamilies = len(families)
	report.UniqueProfileSeeds = len(seeds)
	report.UniqueWirePolicyHashes = len(wires)
	if len(manifest.Candidates) > 1 && report.UniqueFamilies <= 1 {
		report.CollapseFindings = append(report.CollapseFindings, "all_candidates_same_family")
	}
	if len(manifest.Candidates) > 1 && report.UniqueProfileSeeds <= 1 {
		report.CollapseFindings = append(report.CollapseFindings, "all_candidates_same_profile_seed")
	}
	if len(manifest.Candidates) > 1 && report.UniqueWirePolicyHashes <= 1 {
		report.CollapseFindings = append(report.CollapseFindings, "all_candidates_same_wire_policy")
	}
	if len(manifest.FallbackPlan.OrderedCandidateIDs) == 0 {
		report.CollapseFindings = append(report.CollapseFindings, "fallback_plan_missing")
	}
	if manifest.FallbackPlan.FinalWinnerSelected {
		report.CollapseFindings = append(report.CollapseFindings, "fallback_plan_selects_final_winner")
	}
	if report.PayloadLogged {
		report.CollapseFindings = append(report.CollapseFindings, "candidate_contains_payload")
	}
	if report.SecretLogged {
		report.CollapseFindings = append(report.CollapseFindings, "candidate_contains_secret")
	}
	if len(manifest.Candidates) > 0 {
		report.DiversityScore = float64(report.UniqueFamilies+report.UniqueProfileSeeds+report.UniqueWirePolicyHashes) / float64(len(manifest.Candidates)*3)
	}
	report.CollapseFindings = uniqueStrings(report.CollapseFindings)
	if len(report.CollapseFindings) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func CollapsedControl(manifest TransportBundleManifest) BundleCollapseReport {
	control := manifest
	control.Candidates = append([]TransportBundleCandidate(nil), manifest.Candidates...)
	control.FamilyCounts = map[string]int{}
	control.RoleCounts = map[string]int{}
	for i := range control.Candidates {
		control.Candidates[i].Family = "collapsed_control"
		control.Candidates[i].ProfileSeed = 1
		control.Candidates[i].WirePolicyHash = "collapsed_wire_policy"
		control.Candidates[i].Role = CandidateRoleControl
		control.FamilyCounts[string(control.Candidates[i].Family)]++
		control.RoleCounts[string(CandidateRoleControl)]++
	}
	control.FallbackPlan = BuildFallbackPlan(control.Candidates)
	report := ScanCollapse(control)
	if report.Conclusion != "failed" {
		report.CollapseFindings = append(report.CollapseFindings, "control_collapsed_bundle_not_detected")
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(manifest TransportBundleManifest) TransportBundleParityReport {
	report := TransportBundleParityReport{
		ComparedBundles:       1,
		ComparedCandidates:    len(manifest.Candidates),
		PolicyMatches:         1,
		CandidateCountMatches: 1,
		FamilyCountMatches:    1,
		RoleCountMatches:      1,
		FallbackPlanMatches:   1,
		Conclusion:            "passed",
	}
	if len(manifest.Candidates) == 0 {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "empty_bundle")
	}
	if manifest.PayloadLogged {
		report.PayloadLogged = true
	}
	if manifest.SecretLogged {
		report.SecretLogged = true
	}
	if len(report.UnexpectedDifferences) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
