// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapteradversary

import "kurdistan/internal/adapter"

type FeatureVector struct {
	ProfileID string             `json:"profile_id"`
	Scenario  string             `json:"scenario"`
	Numeric   map[string]float64 `json:"numeric"`
	Buckets   map[string]string  `json:"buckets"`
}

func ExtractFeatures(run ScenarioRun) FeatureVector {
	s := run.Summary
	return FeatureVector{
		ProfileID: run.ProfileID,
		Scenario:  run.Scenario,
		Numeric: map[string]float64{
			"flows_opened":        float64(s.FlowsOpened),
			"flows_closed":        float64(s.FlowsClosed),
			"flows_reset":         float64(s.FlowsReset),
			"chunks_read":         float64(s.ChunksRead),
			"chunks_written":      float64(s.ChunksWritten),
			"bytes_in":            float64(s.BytesIn),
			"bytes_out":           float64(s.BytesOut),
			"backpressure_events": float64(s.BackpressureEvents),
			"target_errors":       float64(s.TargetErrors),
			"target_resets":       float64(s.TargetResets),
		},
		Buckets: map[string]string{
			"flow_count":       adapter.CountBucket(s.FlowsOpened),
			"byte_count":       adapter.ByteBucket(s.BytesIn + s.BytesOut),
			"reset_count":      adapter.CountBucket(s.FlowsReset),
			"close_count":      adapter.CountBucket(s.FlowsClosed),
			"backpressure":     adapter.CountBucket(s.BackpressureEvents),
			"mapping":          adapter.CountBucket(s.RuntimeStreamsOpened),
			"policy_shape":     run.PolicyShape,
			"failure_reason":   run.Failure,
			"trace_hygiene":    boolBucket(!s.PayloadLogged && !s.SecretLogged),
			"scenario_correct": boolBucket(run.Correct),
		},
	}
}

func boolBucket(value bool) string {
	if value {
		return "true"
	}
	return "false"
}
