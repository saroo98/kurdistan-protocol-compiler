// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

type FailoverPolicy struct {
	PolicyID                 string `json:"policy_id"`
	MinDegradationEvents     int    `json:"min_degradation_events"`
	SevereFailureImmediate   bool   `json:"severe_failure_immediate"`
	MaxReconnectAttempts     int    `json:"max_reconnect_attempts"`
	FailoverCooldownTicks    int    `json:"failover_cooldown_ticks"`
	QuarantineAfterFailures  int    `json:"quarantine_after_failures"`
	AllowHighRiskDefault     bool   `json:"allow_high_risk_default"`
	AllowExperimentalDefault bool   `json:"allow_experimental_default"`
	PolicyHash               string `json:"policy_hash"`
}

func DefaultPolicy() FailoverPolicy {
	p := FailoverPolicy{
		PolicyID:                 "pathhealth_failover_policy_v1",
		MinDegradationEvents:     2,
		SevereFailureImmediate:   true,
		MaxReconnectAttempts:     2,
		FailoverCooldownTicks:    2,
		QuarantineAfterFailures:  2,
		AllowHighRiskDefault:     false,
		AllowExperimentalDefault: false,
	}
	p.PolicyHash = HashValue(policyHashInput(p))
	return p
}

func policyHashInput(p FailoverPolicy) FailoverPolicy {
	p.PolicyHash = ""
	return p
}
