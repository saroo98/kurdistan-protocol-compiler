// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package byteparity

import "kurdistan/internal/fixtures"

type ByteParityReport struct {
	ProfileCount          int      `json:"profile_count"`
	ScenarioCount         int      `json:"scenario_count"`
	ComparedPairs         int      `json:"compared_pairs"`
	SemanticMatches       int      `json:"semantic_matches"`
	ByteShapeMatches      int      `json:"byte_shape_matches"`
	AllowedDifferences    []string `json:"allowed_differences,omitempty"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

type Comparison struct {
	SemanticMatch      bool     `json:"semantic_match"`
	ByteShapeMatch     bool     `json:"byte_shape_match"`
	AllowedDifferences []string `json:"allowed_differences,omitempty"`
	UnexpectedDrift    []string `json:"unexpected_drift,omitempty"`
	PayloadLogged      bool     `json:"payload_logged"`
	SecretLogged       bool     `json:"secret_logged"`
}

func CompareSummaries(interpreted, generated fixtures.BytePathFixtureSummary) Comparison {
	out := Comparison{
		PayloadLogged: interpreted.PayloadLogged || generated.PayloadLogged,
		SecretLogged:  interpreted.SecretLogged || generated.SecretLogged,
	}
	if interpreted.ProfileID != generated.ProfileID {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "profile_id")
	}
	if interpreted.ProfileSeed != generated.ProfileSeed {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "profile_seed")
	}
	if interpreted.Scenario != generated.Scenario {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "scenario")
	}
	if interpreted.FramesEncoded != generated.FramesEncoded {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "frames_encoded")
	}
	if interpreted.FramesDecoded != generated.FramesDecoded {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "frames_decoded")
	}
	if interpreted.FragmentsCreated != generated.FragmentsCreated {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "fragments_created")
	}
	if interpreted.FragmentsReassembled != generated.FragmentsReassembled {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "fragments_reassembled")
	}
	if interpreted.SequenceRejected != generated.SequenceRejected {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "sequence_rejected")
	}
	if interpreted.MalformedRejected != generated.MalformedRejected {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "malformed_rejected")
	}
	if interpreted.CorruptionRejected != generated.CorruptionRejected {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "corruption_rejected")
	}
	if interpreted.ReplaysRejected != generated.ReplaysRejected {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "replays_rejected")
	}
	if interpreted.RuntimeStreamsMapped != generated.RuntimeStreamsMapped {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "runtime_streams_mapped")
	}
	if interpreted.TargetErrors != generated.TargetErrors {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "target_errors")
	}
	if interpreted.TargetResets != generated.TargetResets {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "target_resets")
	}
	if interpreted.SinkCompleted != generated.SinkCompleted {
		out.UnexpectedDrift = append(out.UnexpectedDrift, "sink_completed")
	}
	if interpreted.BytesWrittenBucket != generated.BytesWrittenBucket {
		out.AllowedDifferences = append(out.AllowedDifferences, "bytes_written_bucket")
	}
	if interpreted.BytesReadBucket != generated.BytesReadBucket {
		out.AllowedDifferences = append(out.AllowedDifferences, "bytes_read_bucket")
	}
	out.SemanticMatch = len(out.UnexpectedDrift) == 0 && !out.PayloadLogged && !out.SecretLogged
	interpShape, _ := fixtures.ByteShapeHash(interpreted)
	genShape, _ := fixtures.ByteShapeHash(generated)
	out.ByteShapeMatch = interpShape == genShape
	return out
}

func CompareSets(interpreted, generated []fixtures.BytePathFixtureSummary) ByteParityReport {
	byKey := map[string]fixtures.BytePathFixtureSummary{}
	scenarios := map[string]bool{}
	profiles := map[int]bool{}
	for _, summary := range generated {
		byKey[key(summary)] = summary
	}
	report := ByteParityReport{}
	for _, left := range interpreted {
		scenarios[left.Scenario] = true
		profiles[left.ProfileSeed] = true
		right, ok := byKey[key(left)]
		if !ok {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, key(left)+": missing generated summary")
			continue
		}
		comparison := CompareSummaries(left, right)
		report.ComparedPairs++
		if comparison.SemanticMatch {
			report.SemanticMatches++
		}
		if comparison.ByteShapeMatch {
			report.ByteShapeMatches++
		} else if len(comparison.UnexpectedDrift) == 0 {
			report.AllowedDifferences = append(report.AllowedDifferences, key(left)+": byte shape differs")
		}
		report.PayloadLogged = report.PayloadLogged || comparison.PayloadLogged
		report.SecretLogged = report.SecretLogged || comparison.SecretLogged
		for _, drift := range comparison.UnexpectedDrift {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, key(left)+": "+drift)
		}
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(scenarios)
	report.Conclusion = "passed"
	if report.ComparedPairs == 0 ||
		report.SemanticMatches != report.ComparedPairs ||
		report.PayloadLogged ||
		report.SecretLogged ||
		len(report.UnexpectedDifferences) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func key(summary fixtures.BytePathFixtureSummary) string {
	return summary.ProfileID + "|" + summary.Scenario
}
