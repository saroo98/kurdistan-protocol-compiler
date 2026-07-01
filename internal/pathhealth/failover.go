// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import "kurdistan/internal/pathrace"

const (
	TriggerNone                         = "none"
	TriggerActiveFailed                 = "active_failed"
	TriggerActiveStalledBeyondThreshold = "active_stalled_beyond_threshold"
	TriggerConfidenceExpiredNoProgress  = "confidence_expired_with_no_progress"
	TriggerRelayBurnDetected            = "relay_burn_detected"
	TriggerReconnectLoopDetected        = "reconnect_loop_detected"
	TriggerScoreBelowThreshold          = "score_below_threshold"
	TriggerBlackholeLikeFailure         = "blackhole_like_failure"
	TriggerManualReviewRequired         = "manual_review_required"
)

const (
	OutcomeNoFailoverNeeded          = "no_failover_needed"
	OutcomeFailoverNotPossible       = "failover_not_possible"
	OutcomeFailoverPending           = "failover_pending"
	OutcomeFailoverVerified          = "failover_to_verified_candidate"
	OutcomeFailoverFallback          = "failover_to_fallback_candidate"
	OutcomeFailoverBlockedHighRisk   = "failover_blocked_high_risk"
	OutcomeFailoverBlockedExperiment = "failover_blocked_experimental"
	OutcomeFailoverQuarantined       = "failover_quarantined"
)

type FailoverDecision struct {
	ActivePathID        string `json:"active_path_id"`
	OldCandidateID      string `json:"old_candidate_id"`
	NewCandidateID      string `json:"new_candidate_id"`
	Trigger             string `json:"trigger"`
	Outcome             string `json:"outcome"`
	CandidateRankBefore int    `json:"candidate_rank_before"`
	CandidateRankAfter  int    `json:"candidate_rank_after"`
	HighRiskBlocked     bool   `json:"high_risk_blocked"`
	ExperimentalBlocked bool   `json:"experimental_blocked"`
	RelayBurnBlocked    bool   `json:"relay_burn_blocked"`
	DecisionHash        string `json:"decision_hash"`
	PayloadLogged       bool   `json:"payload_logged"`
	SecretLogged        bool   `json:"secret_logged"`
}

func DecideFailover(active ActivePath, candidates []pathrace.RaceCandidate, degradation DegradationReport, score ActivePathScoreReport, policy FailoverPolicy) FailoverDecision {
	decision := FailoverDecision{
		ActivePathID:        active.ActivePathID,
		OldCandidateID:      active.CandidateID,
		Trigger:             TriggerNone,
		Outcome:             OutcomeNoFailoverNeeded,
		CandidateRankBefore: 1,
	}
	if !requiresFailover(degradation, score, policy) {
		decision.DecisionHash = HashValue(decisionHashInput(decision))
		return decision
	}
	decision.Trigger = failoverTrigger(degradation, score)
	if degradation.RelayBurnDetected {
		decision.Outcome = OutcomeFailoverQuarantined
		decision.DecisionHash = HashValue(decisionHashInput(decision))
		return decision
	}
	for i, candidate := range candidates {
		if candidate.CandidateID == active.CandidateID {
			continue
		}
		if candidate.RelayRiskBucket == "burned" || candidate.RelayRiskBucket == "critical" || candidate.RelayRiskBucket == "quarantined" {
			decision.RelayBurnBlocked = true
			continue
		}
		if candidate.HighRisk && !policy.AllowHighRiskDefault {
			decision.HighRiskBlocked = true
			continue
		}
		if candidate.Experimental && !policy.AllowExperimentalDefault {
			decision.ExperimentalBlocked = true
			continue
		}
		decision.NewCandidateID = candidate.CandidateID
		decision.CandidateRankAfter = i + 1
		if candidate.Role == "fallback" || candidate.Role == "survival" {
			decision.Outcome = OutcomeFailoverFallback
		} else {
			decision.Outcome = OutcomeFailoverVerified
		}
		decision.DecisionHash = HashValue(decisionHashInput(decision))
		return decision
	}
	if decision.Outcome == OutcomeNoFailoverNeeded {
		switch {
		case decision.HighRiskBlocked:
			decision.Outcome = OutcomeFailoverBlockedHighRisk
		case decision.ExperimentalBlocked:
			decision.Outcome = OutcomeFailoverBlockedExperiment
		default:
			decision.Outcome = OutcomeFailoverNotPossible
		}
	}
	decision.DecisionHash = HashValue(decisionHashInput(decision))
	return decision
}

func requiresFailover(d DegradationReport, score ActivePathScoreReport, p FailoverPolicy) bool {
	if d.RelayBurnDetected || d.BlackholeLikeFailures > 0 || d.ReconnectLoopDetected {
		return true
	}
	if d.StallEvents >= p.MinDegradationEvents || d.ResetLikeFailures >= p.MinDegradationEvents {
		return true
	}
	if d.ConfidenceExpired && d.NoProgressEvents > 0 {
		return true
	}
	return score.FinalScoreBucket == "score_zero"
}

func failoverTrigger(d DegradationReport, score ActivePathScoreReport) string {
	switch {
	case d.RelayBurnDetected:
		return TriggerRelayBurnDetected
	case d.BlackholeLikeFailures > 0:
		return TriggerBlackholeLikeFailure
	case d.ReconnectLoopDetected:
		return TriggerReconnectLoopDetected
	case d.StallEvents > 0:
		return TriggerActiveStalledBeyondThreshold
	case d.ConfidenceExpired && d.NoProgressEvents > 0:
		return TriggerConfidenceExpiredNoProgress
	case score.FinalScoreBucket == "score_zero":
		return TriggerScoreBelowThreshold
	default:
		return TriggerActiveFailed
	}
}

func decisionHashInput(d FailoverDecision) FailoverDecision {
	d.DecisionHash = ""
	return d
}
