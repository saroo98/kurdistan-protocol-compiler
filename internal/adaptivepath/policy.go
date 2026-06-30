// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

type AdaptivePathPolicy struct {
	PolicyID              string `json:"policy_id"`
	DefaultBehavior       string `json:"default_behavior"`
	HighRiskTreatment     string `json:"high_risk_treatment"`
	StaleSuccessTreatment string `json:"stale_success_treatment"`
	UnknownTreatment      string `json:"unknown_treatment"`
}

func DefaultPolicy() AdaptivePathPolicy {
	return AdaptivePathPolicy{
		PolicyID:              "adaptivepath_policy_v1",
		DefaultBehavior:       "build_decision_inputs_without_winner",
		HighRiskTreatment:     "gated_and_never_default",
		StaleSuccessTreatment: "never_strong",
		UnknownTreatment:      "conservative",
	}
}
