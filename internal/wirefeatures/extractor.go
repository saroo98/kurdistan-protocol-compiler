// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import (
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/fixtures"
)

func ExtractFromFixtureManifest(manifest fixtures.FixtureManifest) ([]WireFeatureVector, FeatureExtractionReport) {
	vectors := make([]WireFeatureVector, 0, len(manifest.Summaries))
	report := FeatureExtractionReport{FixtureCount: len(manifest.Entries), Conclusion: "passed"}
	profiles := map[int]bool{}
	scenarios := map[string]bool{}
	for _, summary := range manifest.Summaries {
		vector, err := ExtractFromSummary(summary)
		if err != nil {
			report.InvalidFeatures = append(report.InvalidFeatures, fmt.Sprintf("%s/%s: %v", summary.ProfileID, summary.Scenario, err))
			continue
		}
		vectors = append(vectors, vector)
		profiles[summary.ProfileSeed] = true
		scenarios[summary.Scenario] = true
		report.PayloadLogged = report.PayloadLogged || vector.PayloadLogged
		report.SecretLogged = report.SecretLogged || vector.SecretLogged
	}
	sort.Slice(vectors, func(i, j int) bool {
		if vectors[i].ProfileSeed != vectors[j].ProfileSeed {
			return vectors[i].ProfileSeed < vectors[j].ProfileSeed
		}
		if vectors[i].Scenario != vectors[j].Scenario {
			return vectors[i].Scenario < vectors[j].Scenario
		}
		return vectors[i].Backend < vectors[j].Backend
	})
	report.FeatureCount = len(vectors)
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(scenarios)
	if len(report.InvalidFeatures) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return vectors, report
}

func ExtractFromSummary(summary fixtures.BytePathFixtureSummary) (WireFeatureVector, error) {
	firstN, err := FirstNFromSummary(summary, 4)
	if err != nil {
		return WireFeatureVector{}, err
	}
	byteShapeHash, err := fixtures.ByteShapeHash(summary)
	if err != nil {
		return WireFeatureVector{}, err
	}
	vector := WireFeatureVector{
		ProfileID:           summary.ProfileID,
		ProfileSeed:         summary.ProfileSeed,
		Scenario:            summary.Scenario,
		Backend:             summary.Backend,
		PhaseShape:          prefer(summary.WirePhaseShape, phaseShape(summary)),
		FieldLayoutClass:    prefer(summary.WireFieldLayoutClass, fieldLayoutClass(summary)),
		FirstFlightBucket:   firstFlightBucket(summary),
		FirstNPacketShape:   prefer(summary.WireFirstNShape, firstN.Hash),
		DirectionPattern:    firstN.DirectionClass,
		FrameSizeBuckets:    preferredFrameBuckets(summary),
		FragmentRhythm:      prefer(summary.WireFragmentRhythm, fragmentRhythm(summary)),
		ControlRichness:     prefer(summary.WireControlRichness, controlRichness(summary)),
		MetadataExposure:    prefer(summary.WireMetadataExposure, metadataExposure(summary)),
		PayloadVisibility:   "encrypted_payload_class",
		SequenceBehavior:    sequenceBehavior(summary),
		BackpressurePattern: CountBucket(summary.BackpressureEvents),
		ResetClosePattern:   resetClosePattern(summary),
		ErrorMappingPattern: errorMappingPattern(summary),
		ByteShapeHash:       byteShapeHash,
		PayloadLogged:       summary.PayloadLogged,
		SecretLogged:        summary.SecretLogged,
		WirePolicyID:        summary.WirePolicyID,
		WirePolicyHash:      summary.WirePolicyHash,
		WireSelectedFamily:  summary.WireSelectedFamily,
		WireCorpusEntry:     summary.WireCorpusEntry,
	}
	hash, err := FeatureHash(vector)
	if err != nil {
		return WireFeatureVector{}, err
	}
	vector.FeatureHash = hash
	if err := ValidateVector(vector); err != nil {
		return WireFeatureVector{}, err
	}
	return vector, nil
}

func prefer(value, fallback string) string {
	if value != "" {
		return value
	}
	return fallback
}

func firstFlightBucket(summary fixtures.BytePathFixtureSummary) string {
	if len(summary.WireFrameSizeBuckets) > 0 {
		return summary.WireFrameSizeBuckets[0]
	}
	return BucketFromFixtureBucket(summary.BytesWrittenBucket)
}

func preferredFrameBuckets(summary fixtures.BytePathFixtureSummary) []string {
	if len(summary.WireFrameSizeBuckets) > 0 {
		return append([]string(nil), summary.WireFrameSizeBuckets...)
	}
	return frameBuckets(summary)
}

func FirstNFromSummary(summary fixtures.BytePathFixtureSummary, n int) (FirstNPacketShape, error) {
	if n <= 0 {
		n = 4
	}
	total := summary.FramesEncoded
	if summary.FramesDecoded > total {
		total = summary.FramesDecoded
	}
	if total <= 0 {
		total = 1
	}
	if total > n {
		total = n
	}
	packets := make([]PacketShape, 0, total)
	for i := 0; i < total; i++ {
		dir := DirectionClientToServer
		if i%2 == 1 && summary.FramesDecoded > 0 {
			dir = DirectionServerToClient
		}
		kind := "data"
		control := false
		if strings.Contains(summary.Scenario, "corruption") || strings.Contains(summary.Scenario, "replay") {
			kind = "control"
			control = true
		}
		if strings.Contains(summary.Scenario, "reset") {
			kind = "reset"
			control = true
		}
		packets = append(packets, PacketShape{
			Index:      i,
			Direction:  dir,
			SizeBucket: BucketFromFixtureBucket(summary.BytesWrittenBucket),
			KindBucket: kind,
			Final:      i == total-1 && summary.SinkCompleted,
			Reset:      summary.TargetResets > 0 || strings.Contains(summary.Scenario, "reset"),
			Control:    control,
		})
	}
	return NewFirstNShape(packets)
}

func phaseShape(summary fixtures.BytePathFixtureSummary) string {
	parts := []string{"handshake", "data"}
	if summary.BackpressureEvents > 0 {
		parts = append(parts, "control")
	}
	if summary.TargetResets > 0 || strings.Contains(summary.Scenario, "reset") {
		parts = append(parts, "reset")
	}
	if summary.CorruptionRejected > 0 || summary.MalformedRejected > 0 || summary.ReplaysRejected > 0 || summary.SequenceRejected > 0 {
		parts = append(parts, "control")
	}
	parts = append(parts, "close")
	return strings.Join(unique(parts), "-")
}

func fieldLayoutClass(summary fixtures.BytePathFixtureSummary) string {
	if summary.FragmentsCreated > 8 {
		return "length_fragmented_encrypted"
	}
	if summary.FramesEncoded == 1 && summary.FramesDecoded <= 1 {
		return "compact_length_encrypted"
	}
	return "message_oriented_encrypted"
}

func frameBuckets(summary fixtures.BytePathFixtureSummary) []string {
	out := []string{BucketFromFixtureBucket(summary.BytesWrittenBucket), BucketFromFixtureBucket(summary.BytesReadBucket)}
	sort.Strings(out)
	return unique(out)
}

func fragmentRhythm(summary fixtures.BytePathFixtureSummary) string {
	if summary.FragmentsCreated > 8 {
		return "chunked_large"
	}
	if summary.FragmentsCreated > 1 {
		return "small_burst"
	}
	return "single_frame"
}

func controlRichness(summary fixtures.BytePathFixtureSummary) string {
	total := summary.SequenceRejected + summary.MalformedRejected + summary.CorruptionRejected + summary.ReplaysRejected
	if total > 1 || summary.BackpressureEvents > 0 {
		return "high"
	}
	if total == 1 {
		return "moderate"
	}
	return "low"
}

func metadataExposure(summary fixtures.BytePathFixtureSummary) string {
	if summary.FramesEncoded > 1 || summary.BackpressureEvents > 0 {
		return "minimal_visible"
	}
	return "encrypted_header_encrypted_payload"
}

func sequenceBehavior(summary fixtures.BytePathFixtureSummary) string {
	if summary.ReplaysRejected > 0 || summary.SequenceRejected > 0 {
		return "sequence_rejecting"
	}
	return "monotonic"
}

func resetClosePattern(summary fixtures.BytePathFixtureSummary) string {
	if summary.TargetResets > 0 || strings.Contains(summary.Scenario, "reset") {
		return "reset_then_close"
	}
	return "clean_close"
}

func errorMappingPattern(summary fixtures.BytePathFixtureSummary) string {
	if summary.TargetErrors > 0 || summary.CorruptionRejected > 0 || summary.MalformedRejected > 0 {
		return "safe_error_bucket"
	}
	return "none"
}

func unique(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if !seen[value] {
			out = append(out, value)
			seen[value] = true
		}
	}
	return out
}
