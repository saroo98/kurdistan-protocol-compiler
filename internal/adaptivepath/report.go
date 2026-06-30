// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

type AdaptivePathMisuseReport struct {
	CandidateCount     int      `json:"candidate_count"`
	ObservationCount   int      `json:"observation_count"`
	UniqueFamilies     int      `json:"unique_families"`
	UniqueStates       int      `json:"unique_states"`
	HighRiskCandidates int      `json:"high_risk_candidates"`
	MisuseFindings     []string `json:"misuse_findings,omitempty"`
	PayloadLogged      bool     `json:"payload_logged"`
	SecretLogged       bool     `json:"secret_logged"`
	Conclusion         string   `json:"conclusion"`
}

type AdaptivePathParityReport struct {
	ComparedCandidates    int      `json:"compared_candidates"`
	ComparedConditions    int      `json:"compared_conditions"`
	FamilyMatches         int      `json:"family_matches"`
	ViabilityMatches      int      `json:"viability_matches"`
	DecisionInputMatches  int      `json:"decision_input_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func ScanMisuse(candidates []PathCandidate, observations []PathObservation, reports []CandidateViabilityReport) AdaptivePathMisuseReport {
	if reports == nil {
		reports = EvaluateAll(candidates, observations)
	}
	out := AdaptivePathMisuseReport{CandidateCount: len(candidates), ObservationCount: len(observations), Conclusion: "passed"}
	families := map[CandidateFamily]bool{}
	states := map[string]bool{}
	for _, candidate := range candidates {
		families[candidate.Family] = true
		if candidate.PayloadLogged {
			out.PayloadLogged = true
			out.MisuseFindings = append(out.MisuseFindings, "candidate_payload_logged")
		}
		if candidate.SecretLogged {
			out.SecretLogged = true
			out.MisuseFindings = append(out.MisuseFindings, "candidate_secret_logged")
		}
		if desc, ok := FamilyDescriptor(candidate.Family); ok && desc.HighRisk {
			out.HighRiskCandidates++
		}
		if desc, ok := FamilyDescriptor(candidate.Family); ok && desc.HighRisk && desc.DefaultEligible {
			out.MisuseFindings = append(out.MisuseFindings, "high_risk_candidate_default_eligible")
		}
	}
	for _, report := range reports {
		states[report.CurrentState] = true
		switch report.LastFailureBucket {
		case "relay_burned":
			if report.CurrentState == string(CandidateLikelyUsable) {
				out.MisuseFindings = append(out.MisuseFindings, "burned_relay_candidate_marked_usable")
			}
		case "poisoning_like_signal":
			if report.CurrentState == string(CandidateLikelyUsable) {
				out.MisuseFindings = append(out.MisuseFindings, "poisoned_dns_candidate_marked_usable")
			}
		case "blackhole_like_failure":
			if report.CurrentState == string(CandidateLikelyUsable) {
				out.MisuseFindings = append(out.MisuseFindings, "blocked_candidate_marked_usable")
			}
		case "udp_blocked":
			if report.CurrentState == string(CandidateLikelyUsable) {
				out.MisuseFindings = append(out.MisuseFindings, "udp_blocked_candidate_marked_usable")
			}
		}
		if report.FreshnessClass == Expired && report.CurrentState == string(CandidateLikelyUsable) {
			out.MisuseFindings = append(out.MisuseFindings, "stale_success_treated_as_fresh")
		}
		if report.CurrentState == string(CandidateLikelyUsable) && report.UncertaintyBucket == UnknownUncertainty {
			out.MisuseFindings = append(out.MisuseFindings, "unknown_candidate_marked_strong")
		}
	}
	out.UniqueFamilies = len(families)
	out.UniqueStates = len(states)
	if out.UniqueFamilies <= 1 {
		out.MisuseFindings = append(out.MisuseFindings, "all_candidates_same_family")
	}
	if out.UniqueStates <= 1 {
		out.MisuseFindings = append(out.MisuseFindings, "all_candidates_same_state")
	}
	if out.PayloadLogged {
		out.MisuseFindings = append(out.MisuseFindings, "decision_input_contains_payload")
	}
	if out.SecretLogged {
		out.MisuseFindings = append(out.MisuseFindings, "decision_input_contains_secret")
	}
	out.MisuseFindings = uniqueStrings(out.MisuseFindings)
	if len(out.MisuseFindings) > 0 {
		out.Conclusion = "failed"
	}
	return out
}

func CollapsedControlReport(candidates []PathCandidate, observations []PathObservation) AdaptivePathMisuseReport {
	if len(candidates) == 0 {
		return AdaptivePathMisuseReport{Conclusion: "failed", MisuseFindings: []string{"empty_control"}}
	}
	collapsed := make([]PathCandidate, len(candidates))
	copy(collapsed, candidates)
	for i := range collapsed {
		collapsed[i].Family = CandidateCollapsedControl
		collapsed[i].CarrierClass = "collapsed_control_shape"
		collapsed[i].MetadataRiskBucket = "medium_metadata_risk"
	}
	reports := EvaluateAll(collapsed, observations)
	out := ScanMisuse(collapsed, observations, reports)
	if out.Conclusion != "failed" {
		out.MisuseFindings = append(out.MisuseFindings, "collapsed_control_not_detected")
		out.Conclusion = "failed"
	}
	return out
}

func CompareGeneratedInterpreted(candidates []PathCandidate, observations []PathObservation) AdaptivePathParityReport {
	reports := EvaluateAll(candidates, observations)
	decisions := BuildDecisionSet(candidates, observations)
	out := AdaptivePathParityReport{
		ComparedCandidates:   len(candidates),
		ComparedConditions:   len(DefaultConditions()),
		FamilyMatches:        len(FamilyDescriptors()),
		ViabilityMatches:     len(reports),
		DecisionInputMatches: len(decisions.Inputs),
		Conclusion:           "passed",
	}
	if out.ComparedCandidates == 0 || out.DecisionInputMatches == 0 {
		out.UnexpectedDifferences = append(out.UnexpectedDifferences, "empty_parity_set")
	}
	if ScanMisuse(candidates, observations, reports).PayloadLogged {
		out.PayloadLogged = true
	}
	if out.PayloadLogged || out.SecretLogged || len(out.UnexpectedDifferences) > 0 {
		out.Conclusion = "failed"
	}
	return out
}
