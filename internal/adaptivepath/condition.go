// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

const (
	ConditionDNSUDPUsable              = "dns_udp_usable"
	ConditionDNSUDPPoisoned            = "dns_udp_poisoned"
	ConditionDNSUDPTruncated           = "dns_udp_truncated"
	ConditionDNSUDPRateLimited         = "dns_udp_rate_limited"
	ConditionTCP443Usable              = "tcp_443_usable"
	ConditionTCP443Blackholed          = "tcp_443_blackholed"
	ConditionHTTPConnectShapedUsable   = "http_connect_shaped_usable"
	ConditionHTTPConnectShapedRejected = "http_connect_shaped_rejected"
	ConditionUDP443Blocked             = "udp_443_blocked"
	ConditionUDP443Throttled           = "udp_443_throttled"
	ConditionUDP443Unstable            = "udp_443_unstable"
	ConditionRelayUnreachable          = "relay_unreachable"
	ConditionRelayBurned               = "relay_burned"
	ConditionHandshakeStalls           = "handshake_stalls"
	ConditionDataStallsAfterSuccess    = "data_stalls_after_success"
	ConditionRouteBrieflyUsable        = "route_briefly_usable"
	ConditionRouteFlaps                = "route_flaps"
	ConditionSIMOrAPNVariance          = "sim_or_apn_variance"
	ConditionDeviceVariance            = "device_variance"
	ConditionRecentFlowHistoryPenalty  = "recent_flow_history_penalty"
	ConditionUnknown                   = "unknown"
)

type SyntheticPathCondition struct {
	ConditionID        string                `json:"condition_id"`
	ConditionClass     string                `json:"condition_class"`
	AffectedFamilies   []CandidateFamily     `json:"affected_families"`
	ObservationKinds   []PathObservationKind `json:"observation_kinds"`
	ExpectedState      CandidateState        `json:"expected_state"`
	VolatilityBucket   string                `json:"volatility_bucket"`
	ConfidenceTTLClass string                `json:"confidence_ttl_class"`
	ConditionHash      string                `json:"condition_hash"`
	PayloadLogged      bool                  `json:"payload_logged"`
	SecretLogged       bool                  `json:"secret_logged"`
}

func DefaultConditions() []SyntheticPathCondition {
	specs := []struct {
		class string
		fams  []CandidateFamily
		kinds []PathObservationKind
		state CandidateState
		vol   string
		ttl   string
	}{
		{ConditionDNSUDPUsable, []CandidateFamily{CandidateDNSSurvival}, []PathObservationKind{ObservationShortSuccess}, CandidateLikelyUsable, "medium_volatility", TTLSeconds},
		{ConditionDNSUDPPoisoned, []CandidateFamily{CandidateDNSSurvival}, []PathObservationKind{ObservationPoisoningLikeSignal}, CandidateRejected, "high_volatility", TTLSeconds},
		{ConditionDNSUDPTruncated, []CandidateFamily{CandidateDNSSurvival}, []PathObservationKind{ObservationTruncationLikeSignal}, CandidateDegraded, "high_volatility", TTLSeconds},
		{ConditionDNSUDPRateLimited, []CandidateFamily{CandidateDNSSurvival}, []PathObservationKind{ObservationShortFailure}, CandidateUnstable, "high_volatility", TTLSeconds},
		{ConditionTCP443Usable, []CandidateFamily{CandidateHTTPSLikeTCP}, []PathObservationKind{ObservationHandshakeOK, ObservationFirstUsefulByteOK}, CandidateLikelyUsable, "medium_volatility", TTLShortSession},
		{ConditionTCP443Blackholed, []CandidateFamily{CandidateHTTPSLikeTCP}, []PathObservationKind{ObservationBlackholeLikeFailure}, CandidateBlocked, "high_volatility", TTLSeconds},
		{ConditionHTTPConnectShapedUsable, []CandidateFamily{CandidateHTTPSLikeTCP}, []PathObservationKind{ObservationShortSuccess}, CandidateDegraded, "medium_volatility", TTLOneMinute},
		{ConditionHTTPConnectShapedRejected, []CandidateFamily{CandidateHTTPSLikeTCP}, []PathObservationKind{ObservationHandshakeFailed}, CandidateBlocked, "high_volatility", TTLSeconds},
		{ConditionUDP443Blocked, []CandidateFamily{CandidateExperimentalUDP}, []PathObservationKind{ObservationShortFailure}, CandidateBlocked, "high_volatility", TTLSeconds},
		{ConditionUDP443Throttled, []CandidateFamily{CandidateExperimentalUDP}, []PathObservationKind{ObservationStallAfterData}, CandidateDegraded, "high_volatility", TTLSeconds},
		{ConditionUDP443Unstable, []CandidateFamily{CandidateExperimentalUDP}, []PathObservationKind{ObservationResetLikeFailure}, CandidateUnstable, "high_volatility", TTLSeconds},
		{ConditionRelayUnreachable, []CandidateFamily{CandidateRelayRotation, CandidateHTTPSLikeTCP}, []PathObservationKind{ObservationHandshakeFailed}, CandidateBlocked, "medium_volatility", TTLOneMinute},
		{ConditionRelayBurned, []CandidateFamily{CandidateRelayRotation, CandidateHTTPSLikeTCP, CandidateDomesticMediaRisk}, []PathObservationKind{ObservationRelayBurnRisk}, CandidateBurned, "high_volatility", TTLExpired},
		{ConditionHandshakeStalls, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateExperimentalUDP}, []PathObservationKind{ObservationStallAfterHandshake}, CandidateDegraded, "medium_volatility", TTLOneMinute},
		{ConditionDataStallsAfterSuccess, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateExperimentalUDP}, []PathObservationKind{ObservationStallAfterData}, CandidateDegraded, "medium_volatility", TTLOneMinute},
		{ConditionRouteBrieflyUsable, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateDNSSurvival}, []PathObservationKind{ObservationShortSuccess}, CandidateUnstable, "high_volatility", TTLSeconds},
		{ConditionRouteFlaps, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateExperimentalUDP}, []PathObservationKind{ObservationShortSuccess, ObservationShortFailure}, CandidateUnstable, "high_volatility", TTLSeconds},
		{ConditionSIMOrAPNVariance, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateDNSSurvival, CandidateExperimentalUDP}, []PathObservationKind{ObservationShortFailure}, CandidateUnstable, "medium_volatility", TTLOneMinute},
		{ConditionDeviceVariance, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateDNSSurvival}, []PathObservationKind{ObservationShortFailure}, CandidateUnknown, "medium_volatility", TTLOneMinute},
		{ConditionRecentFlowHistoryPenalty, []CandidateFamily{CandidateHTTPSLikeTCP, CandidateRelayRotation}, []PathObservationKind{ObservationShortFailure}, CandidateDegraded, "low_volatility", TTLFiveMinutes},
		{ConditionUnknown, []CandidateFamily{CandidateBaselineControl}, []PathObservationKind{ObservationShortFailure}, CandidateUnknown, "unknown_volatility", TTLExpired},
	}
	out := make([]SyntheticPathCondition, 0, len(specs))
	for _, spec := range specs {
		condition := SyntheticPathCondition{
			ConditionID:        "condition_" + spec.class,
			ConditionClass:     spec.class,
			AffectedFamilies:   spec.fams,
			ObservationKinds:   spec.kinds,
			ExpectedState:      spec.state,
			VolatilityBucket:   spec.vol,
			ConfidenceTTLClass: spec.ttl,
		}
		condition.ConditionHash = HashValue(conditionHashInput(condition))
		out = append(out, condition)
	}
	return out
}

func conditionHashInput(c SyntheticPathCondition) SyntheticPathCondition {
	c.ConditionHash = ""
	return c
}
