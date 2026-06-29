// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func HashValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func SummaryHash(summary BytePathFixtureSummary) (string, error) {
	return HashValue(summary)
}

func TraceHash(summary BytePathFixtureSummary) (string, error) {
	traceShape := struct {
		ProfileID            string `json:"profile_id"`
		Scenario             string `json:"scenario"`
		Backend              string `json:"backend"`
		FramesEncoded        int    `json:"frames_encoded"`
		FramesDecoded        int    `json:"frames_decoded"`
		FragmentsCreated     int    `json:"fragments_created"`
		FragmentsReassembled int    `json:"fragments_reassembled"`
		RuntimeStreamsMapped int    `json:"runtime_streams_mapped"`
		TargetErrors         int    `json:"target_errors"`
		TargetResets         int    `json:"target_resets"`
		SinkCompleted        bool   `json:"sink_completed"`
	}{
		ProfileID:            summary.ProfileID,
		Scenario:             summary.Scenario,
		Backend:              summary.Backend,
		FramesEncoded:        summary.FramesEncoded,
		FramesDecoded:        summary.FramesDecoded,
		FragmentsCreated:     summary.FragmentsCreated,
		FragmentsReassembled: summary.FragmentsReassembled,
		RuntimeStreamsMapped: summary.RuntimeStreamsMapped,
		TargetErrors:         summary.TargetErrors,
		TargetResets:         summary.TargetResets,
		SinkCompleted:        summary.SinkCompleted,
	}
	return HashValue(traceShape)
}

func ByteShapeHash(summary BytePathFixtureSummary) (string, error) {
	return HashValue(ByteShapeSummary{
		Scenario:             summary.Scenario,
		Backend:              summary.Backend,
		FramesEncoded:        summary.FramesEncoded,
		FramesDecoded:        summary.FramesDecoded,
		FragmentsCreated:     summary.FragmentsCreated,
		FragmentsReassembled: summary.FragmentsReassembled,
		BytesWrittenBucket:   summary.BytesWrittenBucket,
		BytesReadBucket:      summary.BytesReadBucket,
		BackpressureBucket:   bucketCount(summary.BackpressureEvents),
		SequenceRejected:     summary.SequenceRejected,
		MalformedRejected:    summary.MalformedRejected,
		CorruptionRejected:   summary.CorruptionRejected,
		ReplaysRejected:      summary.ReplaysRejected,
		WirePolicyHash:       summary.WirePolicyHash,
		WireFirstNShape:      summary.WireFirstNShape,
		WireFragmentRhythm:   summary.WireFragmentRhythm,
		WireMetadataExposure: summary.WireMetadataExposure,
	})
}

func bucketBytes(value int) string {
	switch {
	case value <= 0:
		return "zero"
	case value <= 1024:
		return "tiny"
	case value <= 16*1024:
		return "small"
	case value <= 128*1024:
		return "medium"
	default:
		return "large"
	}
}

func bucketCount(value int) string {
	switch {
	case value <= 0:
		return "zero"
	case value == 1:
		return "one"
	case value <= 4:
		return "few"
	case value <= 16:
		return "many"
	default:
		return "high"
	}
}
