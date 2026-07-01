// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import "kurdistan/internal/adaptivepath"

type VerificationResult struct {
	CandidateID        string `json:"candidate_id"`
	HandshakeOK        bool   `json:"handshake_ok"`
	FirstUsefulByteOK  bool   `json:"first_useful_byte_ok"`
	StallDetected      bool   `json:"stall_detected"`
	FailureBucket      string `json:"failure_bucket"`
	RelayBurnRejected  bool   `json:"relay_burn_rejected"`
	GatedRejected      bool   `json:"gated_rejected"`
	VerifiedUsable     bool   `json:"verified_usable"`
	VerificationBucket string `json:"verification_bucket"`
	PayloadLogged      bool   `json:"payload_logged"`
	SecretLogged       bool   `json:"secret_logged"`
}

func VerifyCandidate(candidate RaceCandidate, events []RaceEvent, policy RaceSchedulerPolicy) VerificationResult {
	result := VerificationResult{CandidateID: candidate.CandidateID, FailureBucket: "none", VerificationBucket: "unverified"}
	result.HandshakeOK = hasEvent(events, RaceEventHandshakeObserved)
	result.FirstUsefulByteOK = hasEvent(events, RaceEventFirstUsefulByte)
	result.StallDetected = hasEvent(events, RaceEventCandidateStalled)
	result.FailureBucket = lastBucket(events, func(e RaceEvent) string { return e.FailureBucket }, "none")
	result.RelayBurnRejected = candidate.RelayRiskBucket == "burned" || candidate.RelayRiskBucket == "critical" || result.FailureBucket == "relay_burn"
	result.GatedRejected = (candidate.HighRisk && !policy.AllowHighRisk) || (candidate.Experimental && !policy.AllowExperimental)
	if result.GatedRejected {
		result.VerificationBucket = "gated"
		return result
	}
	if familyBlocked(candidate.Family, result.FailureBucket) || result.RelayBurnRejected {
		result.VerificationBucket = "rejected"
		return result
	}
	if result.FailureBucket != "none" {
		result.VerificationBucket = "failed_after_observation"
		return result
	}
	if result.HandshakeOK && result.FirstUsefulByteOK && !result.StallDetected {
		result.VerifiedUsable = true
		result.VerificationBucket = "verified_usable"
	} else if result.HandshakeOK && result.StallDetected {
		result.VerificationBucket = "stalled_after_handshake"
	} else if result.HandshakeOK {
		result.VerificationBucket = "handshake_only"
	}
	return result
}

func familyBlocked(family adaptivepath.CandidateFamily, failure string) bool {
	switch family {
	case adaptivepath.CandidateDNSSurvival:
		return failure == "poisoning_like_signal" || failure == "truncation_like_signal"
	case adaptivepath.CandidateHTTPSLikeTCP, adaptivepath.CandidateRelayRotation:
		return failure == "blackhole_like_failure" || failure == "relay_burn"
	case adaptivepath.CandidateExperimentalUDP:
		return failure == "udp_blocked" || failure == "udp_throttled"
	default:
		return failure == "blocked" || failure == "relay_burn"
	}
}
