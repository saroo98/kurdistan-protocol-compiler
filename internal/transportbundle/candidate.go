// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "kurdistan/internal/adaptivepath"

func roleForFamily(f adaptivepath.CandidateFamily) BundleCandidateRole {
	switch f {
	case adaptivepath.CandidateHTTPSLikeTCP:
		return CandidateRolePrimaryEligible
	case adaptivepath.CandidateDNSSurvival:
		return CandidateRoleSurvival
	case adaptivepath.CandidateExperimentalUDP:
		return CandidateRoleExperimental
	case adaptivepath.CandidateDomesticMediaRisk:
		return CandidateRoleHighRiskGated
	case adaptivepath.CandidateRelayRotation:
		return CandidateRoleFallback
	case adaptivepath.CandidateBaselineControl, adaptivepath.CandidateCollapsedControl:
		return CandidateRoleControl
	default:
		return CandidateRoleFallback
	}
}

func relayRiskBucket(f adaptivepath.CandidateFamily, index int) string {
	switch f {
	case adaptivepath.CandidateDomesticMediaRisk:
		return "high"
	case adaptivepath.CandidateRelayRotation:
		return "medium"
	case adaptivepath.CandidateCollapsedControl:
		return "critical"
	default:
		if index%4 == 0 {
			return "medium"
		}
		return "low"
	}
}

func hostRiskBucket(index int) string {
	switch index % 3 {
	case 0:
		return "low"
	case 1:
		return "medium"
	default:
		return "low"
	}
}

func burnRiskClass(f adaptivepath.CandidateFamily, index int) string {
	switch f {
	case adaptivepath.CandidateDomesticMediaRisk:
		return "manual_review_risk"
	case adaptivepath.CandidateCollapsedControl:
		return "control_risk"
	default:
		if index%5 == 0 {
			return "watch"
		}
		return "normal"
	}
}

func fallbackClassForFamily(f adaptivepath.CandidateFamily) string {
	switch f {
	case adaptivepath.CandidateHTTPSLikeTCP:
		return "primary_try_first"
	case adaptivepath.CandidateDNSSurvival:
		return "fallback_after_poisoning_signal"
	case adaptivepath.CandidateExperimentalUDP:
		return "fallback_after_udp_block_signal"
	case adaptivepath.CandidateDomesticMediaRisk:
		return "manual_review_only"
	case adaptivepath.CandidateRelayRotation:
		return "fallback_after_relay_burn"
	default:
		return "fallback_after_stall"
	}
}
