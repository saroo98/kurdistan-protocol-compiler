// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"
)

func ExtractFeatures(run ScenarioRun) RuntimeFeatureVector {
	s := run.Summary
	return RuntimeFeatureVector{
		TraceID:  traceID(run),
		Scenario: run.Scenario,
		Features: map[string]float64{
			"frames_client_to_server": float64(s.FramesClientToServer),
			"frames_server_to_client": float64(s.FramesServerToClient),
			"streams_opened":          float64(s.StreamsOpened),
			"streams_closed":          float64(s.StreamsClosed),
			"replay_rejected":         float64(s.ReplayRejected),
			"backpressure_events":     float64(s.BackpressureEvents),
			"target_errors":           float64(s.TargetErrors),
			"target_resets":           float64(s.TargetResets),
		},
		Buckets: map[string]string{
			"lifecycle_path":         s.ClientState + "/" + s.ServerState,
			"negotiation_result":     boolBucket(s.CapabilityMatched),
			"security_context":       boolBucket(s.TranscriptMatched),
			"transcript_match":       boolBucket(s.TranscriptMatched),
			"capability_match":       boolBucket(s.CapabilityMatched),
			"frame_counts":           countBucket(s.FramesClientToServer) + "/" + countBucket(s.FramesServerToClient),
			"carrier_family":         s.CarrierFamily,
			"target_distribution":    strings.Join(s.ProxyTargetsExercised, ","),
			"replay_rejection":       countBucket(s.ReplayRejected),
			"backpressure_pattern":   countBucket(s.BackpressureEvents),
			"target_error_reset":     countBucket(s.TargetErrors) + "/" + countBucket(s.TargetResets),
			"payload_secret_hygiene": boolBucket(!s.PayloadLogged && !s.SecretLogged),
			"failure_reason":         run.Failure,
		},
	}
}

func traceID(run ScenarioRun) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s|%s|%s|%s|%d|%d|%d", run.ProfileID, run.Scenario, run.Summary.CarrierFamily, run.Summary.ClientState, run.Summary.FramesClientToServer, run.Summary.BackpressureEvents, run.Summary.ReplayRejected)
	return "runtime_trace_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func boolBucket(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}

func countBucket(value int) string {
	switch {
	case value == 0:
		return "none"
	case value == 1:
		return "one"
	case value <= 3:
		return "few"
	default:
		return "many"
	}
}
