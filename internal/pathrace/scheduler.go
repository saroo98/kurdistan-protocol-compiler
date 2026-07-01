// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import "fmt"

type RaceSchedulerPolicy struct {
	PolicyID                   string `json:"policy_id"`
	MaxParallelCandidates      int    `json:"max_parallel_candidates"`
	StaggerClass               string `json:"stagger_class"`
	StopAfterFirstVerified     bool   `json:"stop_after_first_verified"`
	ContinueAfterFirstVerified bool   `json:"continue_after_first_verified"`
	AllowExperimental          bool   `json:"allow_experimental"`
	AllowHighRisk              bool   `json:"allow_high_risk"`
	DeterministicTieBreak      string `json:"deterministic_tie_break"`
	PolicyHash                 string `json:"policy_hash"`
}

func DefaultSchedulerPolicy(mode RaceMode) RaceSchedulerPolicy {
	p := RaceSchedulerPolicy{
		PolicyID:                   "pathrace_scheduler_" + string(mode),
		MaxParallelCandidates:      3,
		StaggerClass:               "same_tick_then_bucket",
		ContinueAfterFirstVerified: true,
		DeterministicTieBreak:      "candidate_id_ascending",
	}
	switch mode {
	case RaceModeFirstUsable:
		p.StopAfterFirstVerified = true
		p.ContinueAfterFirstVerified = false
	case RaceModeExperimentalGated:
		p.AllowExperimental = true
	case RaceModeControlCollapsed:
		p.AllowExperimental = true
		p.AllowHighRisk = true
	}
	p.PolicyHash = HashValue(policyHashInput(p))
	return p
}

func policyHashInput(p RaceSchedulerPolicy) RaceSchedulerPolicy {
	p.PolicyHash = ""
	return p
}

func ScheduleStarts(raceID string, candidates []RaceCandidate, policy RaceSchedulerPolicy) []RaceEvent {
	events := []RaceEvent{}
	limit := policy.MaxParallelCandidates
	if limit <= 0 || limit > len(candidates) {
		limit = len(candidates)
	}
	for i, c := range candidates {
		tick := 0
		if i >= limit {
			tick = 1 + (i-limit)/max(1, limit)
		}
		if (c.HighRisk && !policy.AllowHighRisk) || (c.Experimental && !policy.AllowExperimental) {
			events = append(events, raceEvent(raceID, c.CandidateID, RaceEventCandidateRejected, tick, "none", "none", "gated_candidate", "gated"))
			continue
		}
		events = append(events, raceEvent(raceID, c.CandidateID, RaceEventCandidateStarted, tick, "start_bucket", "none", "none", "started"))
	}
	return events
}

func raceEvent(raceID, candidateID string, kind RaceEventKind, tick int, latency, useful, failure, verification string) RaceEvent {
	event := RaceEvent{
		RaceID:                 raceID,
		CandidateID:            candidateID,
		Kind:                   kind,
		LogicalTick:            tick,
		LatencyBucket:          latency,
		TimeToUsefulByteBucket: useful,
		FailureBucket:          failure,
		VerificationBucket:     verification,
	}
	event.EventID = HashValue(fmt.Sprintf("%s:%s:%s:%d", raceID, candidateID, kind, tick))[0:24]
	return event
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
