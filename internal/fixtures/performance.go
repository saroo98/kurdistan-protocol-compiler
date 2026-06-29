// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import "fmt"

type PerformanceBaseline struct {
	Version                          string `json:"version"`
	ByteFrameEncodeDecodeMaxBucket   string `json:"byte_frame_encode_decode_max_bucket"`
	BytePipeWriteReadMaxBucket       string `json:"byte_pipe_write_read_max_bucket"`
	LocalAdapterScenarioMaxBucket    string `json:"local_adapter_scenario_max_bucket"`
	ByteTransportQuickAuditMaxBucket string `json:"byte_transport_quick_audit_max_bucket"`
	FixtureVerifyMaxBucket           string `json:"fixture_verify_max_bucket"`
	WarningOnly                      bool   `json:"warning_only"`
}

func DefaultPerformanceBaseline() PerformanceBaseline {
	return PerformanceBaseline{
		Version:                          SchemaVersion,
		ByteFrameEncodeDecodeMaxBucket:   "sub_ms",
		BytePipeWriteReadMaxBucket:       "sub_ms",
		LocalAdapterScenarioMaxBucket:    "sub_100ms",
		ByteTransportQuickAuditMaxBucket: "sub_10s",
		FixtureVerifyMaxBucket:           "sub_10s",
		WarningOnly:                      true,
	}
}

func ValidatePerformanceBaseline(baseline PerformanceBaseline) error {
	if baseline.Version != SchemaVersion {
		return fmt.Errorf("%w: performance version", ErrFixtureInvalid)
	}
	for _, bucket := range []string{
		baseline.ByteFrameEncodeDecodeMaxBucket,
		baseline.BytePipeWriteReadMaxBucket,
		baseline.LocalAdapterScenarioMaxBucket,
		baseline.ByteTransportQuickAuditMaxBucket,
		baseline.FixtureVerifyMaxBucket,
	} {
		if !knownPerformanceBucket(bucket) {
			return fmt.Errorf("%w: performance bucket %s", ErrFixtureInvalid, bucket)
		}
	}
	return nil
}

func knownPerformanceBucket(bucket string) bool {
	switch bucket {
	case "sub_ms", "sub_10ms", "sub_100ms", "sub_1s", "sub_10s", "sub_60s", "warning_only":
		return true
	default:
		return false
	}
}
