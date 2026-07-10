// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

type FallbackPlan struct {
	PlanID                   string   `json:"plan_id"`
	OrderedCandidateIDs      []string `json:"ordered_candidate_ids"`
	GatedCandidateIDs        []string `json:"gated_candidate_ids"`
	HighRiskCandidateIDs     []string `json:"high_risk_candidate_ids"`
	ExperimentalCandidateIDs []string `json:"experimental_candidate_ids"`
	FallbackRuleHash         string   `json:"fallback_rule_hash"`
	FinalWinnerSelected      bool     `json:"final_winner_selected"`
	PayloadLogged            bool     `json:"payload_logged"`
	SecretLogged             bool     `json:"secret_logged"`
}

type BundleFallbackHint struct {
	CandidateID         string `json:"candidate_id"`
	FallbackClass       string `json:"fallback_class"`
	AppliesAfterFailure string `json:"applies_after_failure"`
	RequiresFreshProbe  bool   `json:"requires_fresh_probe"`
	HighRisk            bool   `json:"high_risk"`
	Experimental        bool   `json:"experimental"`
	HintHash            string `json:"hint_hash"`
	PayloadLogged       bool   `json:"payload_logged"`
	SecretLogged        bool   `json:"secret_logged"`
}

func BuildFallbackPlan(candidates []TransportBundleCandidate) FallbackPlan {
	plan := FallbackPlan{PlanID: "fallback_plan_v1"}
	for _, c := range candidates {
		plan.OrderedCandidateIDs = append(plan.OrderedCandidateIDs, c.CandidateID)
		if c.Gated || c.Role == CandidateRoleHighRiskGated || c.Role == CandidateRoleExperimental {
			plan.GatedCandidateIDs = append(plan.GatedCandidateIDs, c.CandidateID)
		}
		if c.HighRisk {
			plan.HighRiskCandidateIDs = append(plan.HighRiskCandidateIDs, c.CandidateID)
		}
		if c.Experimental {
			plan.ExperimentalCandidateIDs = append(plan.ExperimentalCandidateIDs, c.CandidateID)
		}
	}
	plan.FallbackRuleHash = HashValue(fallbackPlanHashInput(plan))
	return plan
}

func BuildFallbackHints(candidates []TransportBundleCandidate) []BundleFallbackHint {
	out := make([]BundleFallbackHint, 0, len(candidates))
	for _, c := range candidates {
		hint := BundleFallbackHint{
			CandidateID:         c.CandidateID,
			FallbackClass:       c.FallbackClass,
			AppliesAfterFailure: c.FallbackClass,
			RequiresFreshProbe:  true,
			HighRisk:            c.HighRisk,
			Experimental:        c.Experimental,
		}
		if c.HighRisk {
			hint.FallbackClass = "manual_review_only"
			hint.AppliesAfterFailure = "manual_review_only"
		}
		hint.HintHash = HashValue(fallbackHintHashInput(hint))
		out = append(out, hint)
	}
	return out
}

func fallbackPlanHashInput(plan FallbackPlan) FallbackPlan {
	plan.FallbackRuleHash = ""
	return plan
}

func fallbackHintHashInput(hint BundleFallbackHint) BundleFallbackHint {
	hint.HintHash = ""
	return hint
}
