// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapteradversary

type FeatureVector struct {
	TraceID   string             `json:"trace_id"`
	ProfileID string             `json:"profile_id"`
	Scenario  string             `json:"scenario"`
	Features  map[string]float64 `json:"features"`
	Buckets   map[string]string  `json:"buckets"`
}

func ExtractFeatures(run ScenarioRun) FeatureVector {
	sum := run.Summary
	return FeatureVector{
		TraceID:   run.ProfileID + ":" + run.Scenario,
		ProfileID: run.ProfileID,
		Scenario:  run.Scenario,
		Features: map[string]float64{
			"flows":           float64(sum.FlowsOpened),
			"source_chunks":   float64(sum.SourceChunks),
			"sink_chunks":     float64(sum.SinkChunks),
			"source_bytes":    float64(sum.SourceBytes),
			"sink_bytes":      float64(sum.SinkBytes),
			"backpressure":    float64(sum.BackpressureEvents),
			"resets":          float64(sum.FlowsReset),
			"target_errors":   float64(sum.TargetErrors),
			"target_resets":   float64(sum.TargetResets),
			"sequence_reject": float64(sum.SequenceRejected),
		},
		Buckets: map[string]string{
			"policy_shape": run.PolicyShape,
			"source_model": sum.SourceModel,
			"sink_model":   sum.SinkModel,
			"failure":      run.Failure,
			"byte_bucket":  byteBucket(sum.SourceBytes),
			"chunk_bucket": countBucket(sum.SourceChunks),
		},
	}
}

func countBucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n <= 2:
		return "small"
	case n <= 8:
		return "medium"
	default:
		return "large"
	}
}

func byteBucket(n int) string {
	switch {
	case n == 0:
		return "zero"
	case n <= 1024:
		return "small"
	case n <= 64*1024:
		return "medium"
	default:
		return "large"
	}
}
