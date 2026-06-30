// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

type CandidateViabilityReport struct {
	CandidateID         string   `json:"candidate_id"`
	Family              string   `json:"family"`
	ObservationCount    int      `json:"observation_count"`
	CurrentState        string   `json:"current_state"`
	ViabilityBucket     string   `json:"viability_bucket"`
	FreshnessClass      string   `json:"freshness_class"`
	UncertaintyBucket   string   `json:"uncertainty_bucket"`
	RecentSuccessBucket string   `json:"recent_success_bucket"`
	RecentFailureBucket string   `json:"recent_failure_bucket"`
	LastFailureBucket   string   `json:"last_failure_bucket"`
	RelayRiskBucket     string   `json:"relay_risk_bucket"`
	MetadataRiskBucket  string   `json:"metadata_risk_bucket"`
	BlockingReasons     []string `json:"blocking_reasons,omitempty"`
	Warnings            []string `json:"warnings,omitempty"`
	ReportHash          string   `json:"report_hash"`
	PayloadLogged       bool     `json:"payload_logged"`
	SecretLogged        bool     `json:"secret_logged"`
	Conclusion          string   `json:"conclusion"`
}

func EvaluateViability(candidate PathCandidate, observations []PathObservation) CandidateViabilityReport {
	filtered := observationsForCandidate(candidate.CandidateID, observations)
	state := CandidateUnknown
	reasons := []string{}
	warnings := []string{}
	successes, failures, expired := 0, 0, 0
	freshness := FreshUnknown
	for _, obs := range filtered {
		if obs.FreshnessClass == FreshSeconds || obs.FreshnessClass == FreshShort {
			freshness = obs.FreshnessClass
		} else if freshness == FreshUnknown {
			freshness = obs.FreshnessClass
		}
		if obs.FreshnessClass == Expired {
			expired++
		}
		if isFailureObservation(obs.Kind) {
			failures++
		} else {
			successes++
		}
		switch obs.Kind {
		case ObservationPoisoningLikeSignal:
			if candidate.Family == CandidateDNSSurvival {
				state = CandidateRejected
				reasons = append(reasons, "dns_poisoning_like_signal")
			}
		case ObservationTruncationLikeSignal:
			if candidate.Family == CandidateDNSSurvival && state != CandidateRejected {
				state = CandidateDegraded
				warnings = append(warnings, "dns_truncation_like_signal")
			}
		case ObservationBlackholeLikeFailure:
			if candidate.Family == CandidateHTTPSLikeTCP {
				state = CandidateBlocked
				reasons = append(reasons, "tcp_blackhole_like_signal")
			}
		case ObservationShortFailure, ObservationResetLikeFailure, ObservationStallAfterData:
			if candidate.Family == CandidateExperimentalUDP && state != CandidateRejected {
				state = CandidateDegraded
				warnings = append(warnings, "udp_unstable_or_blocked_signal")
			}
		case ObservationRelayBurnRisk:
			state = CandidateBurned
			reasons = append(reasons, "relay_burn_risk")
		}
	}
	desc, _ := FamilyDescriptor(candidate.Family)
	if desc.HighRisk || candidate.MetadataRiskBucket == "critical_metadata_risk" {
		warnings = append(warnings, "high_metadata_risk_not_default_eligible")
		if state == CandidateLikelyUsable {
			state = CandidateQuarantined
		}
	}
	if state == CandidateUnknown && successes > 0 && failures == 0 && expired == 0 && freshness != Expired {
		state = CandidateLikelyUsable
	}
	if state == CandidateUnknown && successes > 0 && expired > 0 {
		state = CandidateDegraded
		warnings = append(warnings, "stale_success_never_strong")
	}
	if candidate.Family == CandidateCollapsedControl {
		state = CandidateRejected
		reasons = append(reasons, "collapsed_control")
	}
	report := CandidateViabilityReport{
		CandidateID:         string(candidate.CandidateID),
		Family:              string(candidate.Family),
		ObservationCount:    len(filtered),
		CurrentState:        string(state),
		ViabilityBucket:     viabilityBucket(state),
		FreshnessClass:      freshness,
		UncertaintyBucket:   UncertaintyBucket(successes, failures, expired),
		RecentSuccessBucket: countBucket(successes),
		RecentFailureBucket: countBucket(failures),
		LastFailureBucket:   lastFailureBucket(filtered),
		RelayRiskBucket:     candidate.RelayRiskBucket,
		MetadataRiskBucket:  candidate.MetadataRiskBucket,
		BlockingReasons:     uniqueStrings(reasons),
		Warnings:            uniqueStrings(warnings),
		Conclusion:          "passed",
	}
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(viabilityHashInput(report))
	return report
}

func EvaluateAll(candidates []PathCandidate, observations []PathObservation) []CandidateViabilityReport {
	out := make([]CandidateViabilityReport, 0, len(candidates))
	for _, candidate := range candidates {
		out = append(out, EvaluateViability(candidate, observations))
	}
	return out
}

func observationsForCandidate(id CandidateID, observations []PathObservation) []PathObservation {
	out := []PathObservation{}
	for _, obs := range observations {
		if obs.CandidateID == id {
			out = append(out, obs)
		}
	}
	return out
}

func viabilityBucket(state CandidateState) string {
	switch state {
	case CandidateLikelyUsable:
		return "viability_likely"
	case CandidateDegraded, CandidateUnstable:
		return "viability_degraded"
	case CandidateBlocked, CandidateBurned, CandidateQuarantined, CandidateRejected:
		return "viability_not_usable"
	default:
		return "viability_unknown"
	}
}

func viabilityHashInput(r CandidateViabilityReport) CandidateViabilityReport {
	r.ReportHash = ""
	return r
}
