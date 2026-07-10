// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

func freshnessClass(events []RaceEvent) string {
	if len(events) == 0 {
		return "unknown"
	}
	for _, event := range events {
		if event.VerificationBucket == "stale_success" {
			return "stale"
		}
		if event.VerificationBucket == "expired_success" {
			return "expired"
		}
	}
	if hasEvent(events, RaceEventCandidateVerified) || hasEvent(events, RaceEventFirstUsefulByte) {
		return "fresh"
	}
	return "unknown"
}

func freshnessPenalty(class string) int {
	switch class {
	case "fresh":
		return 0
	case "stale":
		return 25
	case "expired":
		return 50
	default:
		return 15
	}
}
