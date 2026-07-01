// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"sort"

	"kurdistan/internal/pathrace"
)

func MonitorActivePath(active ActivePath, candidates []pathrace.RaceCandidate, events []HealthEvent, policy FailoverPolicy) (PathHealthRun, error) {
	ordered := append([]HealthEvent(nil), events...)
	sort.SliceStable(ordered, func(i, j int) bool {
		if ordered[i].LogicalTick == ordered[j].LogicalTick {
			return ordered[i].EventID < ordered[j].EventID
		}
		return ordered[i].LogicalTick < ordered[j].LogicalTick
	})
	seen := map[string]bool{}
	for _, event := range ordered {
		if event.EventID == "" || seen[event.EventID] {
			return PathHealthRun{}, ErrDuplicateEvent
		}
		seen[event.EventID] = true
		if err := ValidateEvent(event); err != nil {
			return PathHealthRun{}, err
		}
	}
	degradation := DetectDegradation(active, ordered)
	score := ScoreActivePath(active, degradation, ordered)
	failover := DecideFailover(active, candidates, degradation, score, policy)
	state := active.CurrentHealthState
	transitions := []HealthTransitionEvent{}
	hasAlternate := failover.NewCandidateID != "" || failover.Outcome == OutcomeFailoverQuarantined
	for _, event := range ordered {
		next := transitionForEvent(state, event, degradation, hasAlternate)
		if next != state {
			if !ValidTransition(state, next, hasAlternate) {
				return PathHealthRun{}, ErrInvalidTransition
			}
			transitions = append(transitions, transitionEvent(active.ActivePathID, state, next, string(event.Kind), event.LogicalTick))
			state = next
		}
		if event.Kind == HealthEventUsefulByteObserved {
			active.LastUsefulTick = event.LogicalTick
		}
		if event.FailureBucket != "none" {
			active.LastFailureTick = event.LogicalTick
		}
	}
	if failover.Outcome != OutcomeNoFailoverNeeded && state != HealthFailed && state != HealthQuarantined && state != HealthFailoverPending && state != HealthFailedOver {
		if state != HealthFailing {
			if !ValidTransition(state, HealthFailing, hasAlternate) {
				return PathHealthRun{}, ErrInvalidTransition
			}
			transitions = append(transitions, transitionEvent(active.ActivePathID, state, HealthFailing, failover.Trigger, 89))
			state = HealthFailing
		}
		if !ValidTransition(state, HealthFailed, hasAlternate) {
			return PathHealthRun{}, ErrInvalidTransition
		}
		transitions = append(transitions, transitionEvent(active.ActivePathID, state, HealthFailed, failover.Trigger, 90))
		state = HealthFailed
	}
	if (failover.NewCandidateID != "" || failover.Outcome == OutcomeFailoverQuarantined) && state == HealthFailed {
		transitions = append(transitions, transitionEvent(active.ActivePathID, state, HealthFailoverPending, failover.Trigger, 91))
		state = HealthFailoverPending
	}
	if failover.NewCandidateID != "" && state == HealthFailoverPending {
		transitions = append(transitions, transitionEvent(active.ActivePathID, state, HealthFailedOver, failover.Outcome, 92))
		state = HealthFailedOver
	}
	if failover.Outcome == OutcomeFailoverQuarantined {
		transitions = append(transitions, transitionEvent(active.ActivePathID, state, HealthQuarantined, failover.Outcome, 93))
		state = HealthQuarantined
	}
	active.CurrentScoreBucket = score.FinalScoreBucket
	active.CurrentHealthState = state
	report := BuildReport(active, ordered, degradation, failover)
	return PathHealthRun{ActivePath: active, Candidates: append([]pathrace.RaceCandidate(nil), candidates...), Events: ordered, Transitions: transitions, Degradation: degradation, Score: score, Failover: failover, Policy: policy, Report: report}, nil
}
