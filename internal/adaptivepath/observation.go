// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import "fmt"

type PathObservation struct {
	ObservationID          string              `json:"observation_id"`
	CandidateID            CandidateID         `json:"candidate_id"`
	Kind                   PathObservationKind `json:"kind"`
	LogicalTick            int                 `json:"logical_tick"`
	LatencyBucket          string              `json:"latency_bucket"`
	TimeToUsefulByteBucket string              `json:"time_to_useful_byte_bucket"`
	StallBucket            string              `json:"stall_bucket"`
	FailureBucket          string              `json:"failure_bucket"`
	ConfidenceTTLClass     string              `json:"confidence_ttl_class"`
	FreshnessClass         string              `json:"freshness_class"`
	ObservationHash        string              `json:"observation_hash"`
	PayloadLogged          bool                `json:"payload_logged"`
	SecretLogged           bool                `json:"secret_logged"`
}

func DefaultObservations(candidates []PathCandidate) []PathObservation {
	out := []PathObservation{}
	add := func(c PathCandidate, kind PathObservationKind, tick int, ttl, failure string) {
		o := PathObservation{
			ObservationID:          fmt.Sprintf("observation_%s_%03d", c.CandidateID, len(out)+1),
			CandidateID:            c.CandidateID,
			Kind:                   kind,
			LogicalTick:            tick,
			LatencyBucket:          "latency_bucket_small",
			TimeToUsefulByteBucket: "ttub_bucket_short",
			StallBucket:            "stall_none",
			FailureBucket:          failure,
			ConfidenceTTLClass:     ttl,
			FreshnessClass:         FreshnessAtTick(tick, ttl, 20),
		}
		if kind == ObservationStallAfterData || kind == ObservationStallAfterHandshake {
			o.StallBucket = "stall_observed"
		}
		o.ObservationHash = HashValue(observationHashInput(o))
		out = append(out, o)
	}
	for _, c := range candidates {
		switch c.Family {
		case CandidateHTTPSLikeTCP:
			add(c, ObservationHandshakeOK, 4, TTLFiveMinutes, "none")
			add(c, ObservationBlackholeLikeFailure, 17, TTLSeconds, "blackhole_like_failure")
		case CandidateDNSSurvival:
			add(c, ObservationShortSuccess, 2, TTLSeconds, "none")
			add(c, ObservationPoisoningLikeSignal, 16, TTLSeconds, "poisoning_like_signal")
			add(c, ObservationTruncationLikeSignal, 18, TTLSeconds, "truncation_like_signal")
		case CandidateExperimentalUDP:
			add(c, ObservationShortFailure, 15, TTLSeconds, "udp_blocked")
			add(c, ObservationStallAfterData, 19, TTLSeconds, "udp_throttled")
		case CandidateDomesticMediaRisk:
			add(c, ObservationShortSuccess, 1, TTLExpired, "metadata_risk_high")
			add(c, ObservationRelayBurnRisk, 14, TTLExpired, "relay_burned")
		case CandidateRelayRotation:
			add(c, ObservationRelayBurnRisk, 13, TTLExpired, "relay_burned")
		case CandidateBaselineControl:
			add(c, ObservationHandshakeOK, 3, TTLFiveMinutes, "none")
			add(c, ObservationFirstUsefulByteOK, 4, TTLFiveMinutes, "none")
		case CandidateCollapsedControl:
			add(c, ObservationShortFailure, 1, TTLExpired, "collapse_control")
		}
	}
	return out
}

func observationHashInput(o PathObservation) PathObservation {
	o.ObservationHash = ""
	return o
}
