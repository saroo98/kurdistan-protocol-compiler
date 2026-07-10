// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import "fmt"

func healthEvent(activeID, candidateID string, kind HealthEventKind, tick int, progress, stall, failure, reconnect, score, ttl string) HealthEvent {
	if progress == "" {
		progress = "none"
	}
	if stall == "" {
		stall = "none"
	}
	if failure == "" {
		failure = "none"
	}
	if reconnect == "" {
		reconnect = "none"
	}
	if score == "" {
		score = "score_medium"
	}
	if ttl == "" {
		ttl = "ttl_short_session"
	}
	return HealthEvent{
		EventID:            fmt.Sprintf("health_%s_%03d_%s", activeID, tick, kind),
		ActivePathID:       activeID,
		CandidateID:        candidateID,
		Kind:               kind,
		LogicalTick:        tick,
		ProgressBucket:     progress,
		StallBucket:        stall,
		FailureBucket:      failure,
		ReconnectBucket:    reconnect,
		ScoreBucket:        score,
		ConfidenceTTLClass: ttl,
	}
}

func transitionEvent(activeID string, oldState, newState HealthState, reason string, tick int) HealthTransitionEvent {
	return HealthTransitionEvent{
		EventID:      fmt.Sprintf("transition_%s_%03d_%s", activeID, tick, reason),
		ActivePathID: activeID,
		OldState:     string(oldState),
		NewState:     string(newState),
		ReasonBucket: reason,
		LogicalTick:  tick,
	}
}
