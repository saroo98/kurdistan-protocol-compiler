// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

func BuildOutcome(raceID string, candidate RaceCandidate, verification VerificationResult, score CandidateScore, events []RaceEvent) RaceOutcome {
	state := RaceStateStarted
	reason := ""
	switch {
	case verification.GatedRejected:
		state = RaceStateGated
		reason = "gated_candidate"
	case verification.RelayBurnRejected:
		state = RaceStateRejected
		reason = "relay_burn_rejected"
	case verification.VerifiedUsable:
		state = RaceStateVerified
	case verification.StallDetected:
		state = RaceStateStalled
		reason = "stall_detected"
	case verification.FailureBucket != "none":
		state = RaceStateFailed
		reason = verification.FailureBucket
	default:
		state = RaceStatePending
		reason = "not_verified"
	}
	return RaceOutcome{
		RaceID:                 raceID,
		CandidateID:            candidate.CandidateID,
		Family:                 string(candidate.Family),
		FinalState:             state,
		VerifiedUsable:         verification.VerifiedUsable,
		RejectedReason:         reason,
		LatencyBucket:          lastBucket(events, func(e RaceEvent) string { return e.LatencyBucket }, "unknown_latency"),
		TimeToUsefulByteBucket: lastBucket(events, func(e RaceEvent) string { return e.TimeToUsefulByteBucket }, "unknown_useful_byte"),
		FailureBucket:          verification.FailureBucket,
		ScoreBucket:            score.ScoreBucket,
	}
}
