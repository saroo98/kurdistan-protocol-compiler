// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

type CandidateScore struct {
	CandidateID             string `json:"candidate_id"`
	ScoreBucket             string `json:"score_bucket"`
	FreshnessClass          string `json:"freshness_class"`
	UncertaintyBucket       string `json:"uncertainty_bucket"`
	SuccessStreakBucket     string `json:"success_streak_bucket"`
	FailureStreakBucket     string `json:"failure_streak_bucket"`
	LatencyPreferenceBucket string `json:"latency_preference_bucket"`
	RiskPenaltyBucket       string `json:"risk_penalty_bucket"`
	GatingPenaltyBucket     string `json:"gating_penalty_bucket"`
	ScoreHash               string `json:"score_hash"`
	PayloadLogged           bool   `json:"payload_logged"`
	SecretLogged            bool   `json:"secret_logged"`
}

type ShortLivedScoringPolicy struct {
	PolicyID             string `json:"policy_id"`
	SuccessTTLClass      string `json:"success_ttl_class"`
	FailureTTLClass      string `json:"failure_ttl_class"`
	StaleSuccessPenalty  string `json:"stale_success_penalty"`
	FailureStreakPenalty string `json:"failure_streak_penalty"`
	StallPenalty         string `json:"stall_penalty"`
	RelayBurnPenalty     string `json:"relay_burn_penalty"`
	HighRiskPenalty      string `json:"high_risk_penalty"`
	ExperimentalPenalty  string `json:"experimental_penalty"`
	PolicyHash           string `json:"policy_hash"`
}

func DefaultScoringPolicy() ShortLivedScoringPolicy {
	p := ShortLivedScoringPolicy{
		PolicyID:             "pathrace_short_lived_scoring_v1",
		SuccessTTLClass:      "seconds",
		FailureTTLClass:      "seconds",
		StaleSuccessPenalty:  "sharp",
		FailureStreakPenalty: "sharp",
		StallPenalty:         "medium",
		RelayBurnPenalty:     "critical",
		HighRiskPenalty:      "critical",
		ExperimentalPenalty:  "review_gated",
	}
	p.PolicyHash = HashValue(scoringPolicyHashInput(p))
	return p
}

func scoringPolicyHashInput(p ShortLivedScoringPolicy) ShortLivedScoringPolicy {
	p.PolicyHash = ""
	return p
}

func ScoreCandidate(candidate RaceCandidate, verification VerificationResult, events []RaceEvent, policy ShortLivedScoringPolicy) CandidateScore {
	_ = policy
	freshness := freshnessClass(events)
	value := 25 - freshnessPenalty(freshness)
	if verification.HandshakeOK {
		value += 20
	}
	if verification.FirstUsefulByteOK {
		value += 30
	}
	if verification.VerifiedUsable {
		value += 30
	}
	if verification.StallDetected {
		value -= 35
	}
	if verification.FailureBucket != "none" {
		value -= 35
	}
	if verification.RelayBurnRejected {
		value -= 90
	}
	if candidate.HighRisk {
		value -= 70
	}
	if candidate.Experimental {
		value -= 35
	}
	if verification.GatedRejected {
		value -= 100
	}
	score := CandidateScore{
		CandidateID:             candidate.CandidateID,
		ScoreBucket:             scoreBucket(value),
		FreshnessClass:          freshness,
		UncertaintyBucket:       uncertaintyBucket(verification, freshness),
		SuccessStreakBucket:     successBucket(verification),
		FailureStreakBucket:     failureBucket(verification),
		LatencyPreferenceBucket: latencyPreference(events),
		RiskPenaltyBucket:       riskPenalty(candidate, verification),
		GatingPenaltyBucket:     gatingPenalty(candidate, verification),
	}
	score.ScoreHash = HashValue(scoreHashInput(score))
	return score
}

func scoreHashInput(s CandidateScore) CandidateScore {
	s.ScoreHash = ""
	return s
}

func scoreBucket(value int) string {
	switch {
	case value >= 80:
		return "score_high"
	case value >= 45:
		return "score_medium"
	case value > 0:
		return "score_low"
	default:
		return "score_zero"
	}
}

func scoreValue(bucket string) int {
	switch bucket {
	case "score_high":
		return 4
	case "score_medium":
		return 3
	case "score_low":
		return 2
	default:
		return 1
	}
}

func uncertaintyBucket(v VerificationResult, freshness string) string {
	if !v.VerifiedUsable || freshness != "fresh" {
		return "uncertain"
	}
	return "low_uncertainty"
}

func successBucket(v VerificationResult) string {
	if v.VerifiedUsable {
		return "success_recent"
	}
	if v.HandshakeOK {
		return "handshake_only"
	}
	return "none"
}

func failureBucket(v VerificationResult) string {
	if v.FailureBucket != "none" || v.StallDetected || v.RelayBurnRejected {
		return "failure_recent"
	}
	return "none"
}

func latencyPreference(events []RaceEvent) string {
	bucket := lastBucket(events, func(e RaceEvent) string { return e.LatencyBucket }, "unknown_latency")
	switch bucket {
	case "fast", "fast_bucket":
		return "prefer_fast"
	case "slow", "slow_bucket":
		return "prefer_later"
	default:
		return "neutral"
	}
}

func riskPenalty(c RaceCandidate, v VerificationResult) string {
	if v.RelayBurnRejected {
		return "critical_risk_penalty"
	}
	if c.HighRisk {
		return "high_risk_penalty"
	}
	if c.Experimental {
		return "experimental_penalty"
	}
	return "none"
}

func gatingPenalty(c RaceCandidate, v VerificationResult) string {
	if v.GatedRejected || c.Gated {
		return "gated"
	}
	return "none"
}
