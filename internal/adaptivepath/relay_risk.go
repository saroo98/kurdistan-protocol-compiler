// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

const (
	RelayRiskLow      = "relay_risk_low"
	RelayRiskMedium   = "relay_risk_medium"
	RelayRiskHigh     = "relay_risk_high"
	RelayRiskCritical = "relay_risk_critical"
)

func relayRiskForFamily(f CandidateFamily) string {
	switch f {
	case CandidateDomesticMediaRisk:
		return RelayRiskCritical
	case CandidateRelayRotation, CandidateCollapsedControl:
		return RelayRiskHigh
	case CandidateDNSSurvival, CandidateExperimentalUDP:
		return RelayRiskMedium
	default:
		return RelayRiskLow
	}
}
