// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

func eventsForCandidate(events []RaceEvent, candidateID string) []RaceEvent {
	out := []RaceEvent{}
	for _, event := range events {
		if event.CandidateID == candidateID {
			out = append(out, event)
		}
	}
	return out
}

func hasEvent(events []RaceEvent, kind RaceEventKind) bool {
	for _, event := range events {
		if event.Kind == kind {
			return true
		}
	}
	return false
}

func lastBucket(events []RaceEvent, selector func(RaceEvent) string, fallback string) string {
	for i := len(events) - 1; i >= 0; i-- {
		if value := selector(events[i]); value != "" && value != "none" {
			return value
		}
	}
	return fallback
}
