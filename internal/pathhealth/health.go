// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"fmt"

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/pathrace"
)

type PathHealthVersion string
type ActivePathID string
type HealthState string
type HealthEventKind string

const Version PathHealthVersion = "pathhealth-v1"

const (
	HealthUnknown         HealthState = "unknown"
	HealthHealthy         HealthState = "healthy"
	HealthDegraded        HealthState = "degraded"
	HealthStalled         HealthState = "stalled"
	HealthFailing         HealthState = "failing"
	HealthFailed          HealthState = "failed"
	HealthRecovering      HealthState = "recovering"
	HealthFailoverPending HealthState = "failover_pending"
	HealthFailedOver      HealthState = "failed_over"
	HealthQuarantined     HealthState = "quarantined"
)

const (
	HealthEventActivated            HealthEventKind = "activated"
	HealthEventUsefulByteObserved   HealthEventKind = "useful_byte_observed"
	HealthEventNoProgress           HealthEventKind = "no_progress"
	HealthEventStallDetected        HealthEventKind = "stall_detected"
	HealthEventResetLikeFailure     HealthEventKind = "reset_like_failure"
	HealthEventBlackholeLikeFailure HealthEventKind = "blackhole_like_failure"
	HealthEventRelayBurnSignal      HealthEventKind = "relay_burn_signal"
	HealthEventScoreDecayed         HealthEventKind = "score_decayed"
	HealthEventConfidenceExpired    HealthEventKind = "confidence_expired"
	HealthEventReconnectAttempt     HealthEventKind = "reconnect_attempt"
	HealthEventReconnectSucceeded   HealthEventKind = "reconnect_succeeded"
	HealthEventReconnectFailed      HealthEventKind = "reconnect_failed"
	HealthEventFailoverTriggered    HealthEventKind = "failover_triggered"
	HealthEventFailoverCompleted    HealthEventKind = "failover_completed"
	HealthEventQuarantined          HealthEventKind = "quarantined"
)

type ActivePath struct {
	ActivePathID       string                       `json:"active_path_id"`
	RaceID             string                       `json:"race_id"`
	BundleID           string                       `json:"bundle_id"`
	CandidateID        string                       `json:"candidate_id"`
	Family             adaptivepath.CandidateFamily `json:"family"`
	ProfileSeed        int                          `json:"profile_seed"`
	WirePolicyHash     string                       `json:"wire_policy_hash"`
	RelayID            string                       `json:"relay_id"`
	SyntheticHostID    string                       `json:"synthetic_host_id"`
	RelayRiskBucket    string                       `json:"relay_risk_bucket"`
	MetadataRiskBucket string                       `json:"metadata_risk_bucket"`
	InitialScoreBucket string                       `json:"initial_score_bucket"`
	CurrentScoreBucket string                       `json:"current_score_bucket"`
	CurrentHealthState HealthState                  `json:"current_health_state"`
	ActivatedAtTick    int                          `json:"activated_at_tick"`
	LastUsefulTick     int                          `json:"last_useful_tick"`
	LastFailureTick    int                          `json:"last_failure_tick"`
	PayloadLogged      bool                         `json:"payload_logged"`
	SecretLogged       bool                         `json:"secret_logged"`
}

type HealthEvent struct {
	EventID            string          `json:"event_id"`
	ActivePathID       string          `json:"active_path_id"`
	CandidateID        string          `json:"candidate_id"`
	Kind               HealthEventKind `json:"kind"`
	LogicalTick        int             `json:"logical_tick"`
	ProgressBucket     string          `json:"progress_bucket"`
	StallBucket        string          `json:"stall_bucket"`
	FailureBucket      string          `json:"failure_bucket"`
	ReconnectBucket    string          `json:"reconnect_bucket"`
	ScoreBucket        string          `json:"score_bucket"`
	ConfidenceTTLClass string          `json:"confidence_ttl_class"`
	PayloadLogged      bool            `json:"payload_logged"`
	SecretLogged       bool            `json:"secret_logged"`
}

type HealthTransitionEvent struct {
	EventID       string `json:"event_id"`
	ActivePathID  string `json:"active_path_id"`
	OldState      string `json:"old_state"`
	NewState      string `json:"new_state"`
	ReasonBucket  string `json:"reason_bucket"`
	LogicalTick   int    `json:"logical_tick"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

type PathHealthReport struct {
	Version               string `json:"version"`
	ActivePathID          string `json:"active_path_id"`
	CandidateID           string `json:"candidate_id"`
	InitialState          string `json:"initial_state"`
	FinalState            string `json:"final_state"`
	EventCount            int    `json:"event_count"`
	UsefulEvents          int    `json:"useful_events"`
	StallEvents           int    `json:"stall_events"`
	ResetLikeFailures     int    `json:"reset_like_failures"`
	BlackholeLikeFailures int    `json:"blackhole_like_failures"`
	RelayBurnSignals      int    `json:"relay_burn_signals"`
	ReconnectAttempts     int    `json:"reconnect_attempts"`
	FailoverTriggered     bool   `json:"failover_triggered"`
	FailoverCompleted     bool   `json:"failover_completed"`
	NewCandidateID        string `json:"new_candidate_id"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	ReportHash            string `json:"report_hash"`
	Conclusion            string `json:"conclusion"`
}

type PathHealthRun struct {
	Scenario      HealthScenario           `json:"scenario"`
	ActivePath    ActivePath               `json:"active_path"`
	Candidates    []pathrace.RaceCandidate `json:"candidates"`
	Events        []HealthEvent            `json:"events"`
	Transitions   []HealthTransitionEvent  `json:"transitions"`
	Degradation   DegradationReport        `json:"degradation"`
	Score         ActivePathScoreReport    `json:"score"`
	Failover      FailoverDecision         `json:"failover"`
	Policy        FailoverPolicy           `json:"policy"`
	Report        PathHealthReport         `json:"report"`
	PayloadLogged bool                     `json:"payload_logged"`
	SecretLogged  bool                     `json:"secret_logged"`
}

func CreateActivePathFromRace(run pathrace.PathRaceRun) (ActivePath, error) {
	if run.Report.WinnerCandidateID == "" {
		return ActivePath{}, ErrNoRaceWinner
	}
	for _, candidate := range run.Candidates {
		if candidate.CandidateID == run.Report.WinnerCandidateID {
			active := ActivePath{
				ActivePathID:       "active_" + run.Report.RaceID,
				RaceID:             run.Report.RaceID,
				BundleID:           candidate.BundleID,
				CandidateID:        candidate.CandidateID,
				Family:             candidate.Family,
				ProfileSeed:        candidate.ProfileSeed,
				WirePolicyHash:     candidate.WirePolicyHash,
				RelayID:            "synthetic_relay_bucket",
				SyntheticHostID:    "synthetic_host_bucket",
				RelayRiskBucket:    candidate.RelayRiskBucket,
				MetadataRiskBucket: candidate.MetadataRiskBucket,
				InitialScoreBucket: "score_medium",
				CurrentScoreBucket: "score_medium",
				CurrentHealthState: HealthHealthy,
				ActivatedAtTick:    0,
				LastUsefulTick:     0,
				LastFailureTick:    -1,
			}
			for _, score := range run.Scores {
				if score.CandidateID == candidate.CandidateID {
					active.InitialScoreBucket = score.ScoreBucket
					active.CurrentScoreBucket = score.ScoreBucket
					break
				}
			}
			return active, ScanForLeak(active)
		}
	}
	return ActivePath{}, fmt.Errorf("%w: winner candidate missing", ErrInvalidHealth)
}

func TerminalState(state HealthState) bool {
	return state == HealthFailedOver || state == HealthQuarantined
}

func ValidTransition(oldState, newState HealthState, hasAlternate bool) bool {
	if oldState == newState {
		return true
	}
	if TerminalState(oldState) {
		return false
	}
	allowed := map[HealthState][]HealthState{
		HealthUnknown:         {HealthHealthy},
		HealthHealthy:         {HealthDegraded, HealthStalled, HealthFailing, HealthFailed},
		HealthDegraded:        {HealthHealthy, HealthStalled, HealthFailing, HealthFailed},
		HealthStalled:         {HealthDegraded, HealthFailing, HealthFailed},
		HealthFailing:         {HealthRecovering, HealthFailed},
		HealthRecovering:      {HealthHealthy, HealthDegraded, HealthFailed},
		HealthFailed:          {HealthFailoverPending},
		HealthFailoverPending: {HealthFailedOver, HealthQuarantined},
	}
	for _, candidate := range allowed[oldState] {
		if candidate == newState {
			if oldState == HealthFailed && newState == HealthFailoverPending {
				return hasAlternate
			}
			return true
		}
	}
	return false
}

func transitionForEvent(old HealthState, event HealthEvent, counts DegradationReport, hasAlternate bool) HealthState {
	switch event.Kind {
	case HealthEventUsefulByteObserved, HealthEventReconnectSucceeded:
		if old == HealthRecovering || old == HealthDegraded {
			return HealthHealthy
		}
		return old
	case HealthEventNoProgress:
		if counts.NoProgressEvents >= 3 {
			if old == HealthHealthy {
				return HealthDegraded
			}
			if old == HealthDegraded {
				return HealthStalled
			}
		}
	case HealthEventStallDetected:
		if old == HealthHealthy || old == HealthDegraded {
			return HealthStalled
		}
	case HealthEventResetLikeFailure:
		if counts.ResetLikeFailures >= 2 {
			return HealthFailing
		}
		if old == HealthHealthy {
			return HealthDegraded
		}
	case HealthEventBlackholeLikeFailure:
		return HealthFailed
	case HealthEventRelayBurnSignal:
		return HealthFailed
	case HealthEventConfidenceExpired, HealthEventScoreDecayed:
		if old == HealthHealthy {
			return HealthDegraded
		}
	case HealthEventReconnectAttempt:
		if old == HealthFailing {
			return HealthRecovering
		}
	case HealthEventReconnectFailed:
		if counts.ReconnectLoopDetected || old == HealthRecovering {
			return HealthFailed
		}
	case HealthEventFailoverTriggered:
		if hasAlternate {
			return HealthFailoverPending
		}
	case HealthEventFailoverCompleted:
		return HealthFailedOver
	case HealthEventQuarantined:
		return HealthQuarantined
	}
	return old
}
