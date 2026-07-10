// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransportadversary

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
			"frames":            float64(sum.FramesEncoded),
			"fragments":         float64(sum.FragmentsCreated),
			"reassembled":       float64(sum.FragmentsReassembled),
			"bytes":             float64(sum.BytesWritten),
			"backpressure":      float64(sum.BackpressureEvents),
			"sequence_reject":   float64(sum.SequenceRejected),
			"corruption_reject": float64(sum.CorruptionRejected),
			"malformed_reject":  float64(sum.MalformedRejected),
			"runtime_mappings":  float64(sum.RuntimeStreamsMapped),
		},
		Buckets: map[string]string{
			"policy_shape":    run.PolicyShape,
			"frame_bucket":    countBucket(sum.FramesEncoded),
			"fragment_bucket": countBucket(sum.FragmentsCreated),
			"byte_bucket":     byteBucket(sum.BytesWritten),
			"failure":         run.Failure,
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
