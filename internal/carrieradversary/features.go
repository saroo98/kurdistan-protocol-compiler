// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrieradversary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	ktrace "kurdistan/internal/trace"
)

func ExtractFeatures(events []ktrace.Event) FeatureVector {
	families := []string{}
	kinds := []string{}
	flushes := []string{}
	retries, reordered, dropped, backpressure, envelopes := 0, 0, 0, 0, 0
	for _, ev := range events {
		if ev.CarrierFamilyBucket == "" {
			continue
		}
		envelopes++
		families = append(families, ev.CarrierFamilyBucket)
		kinds = append(kinds, ev.CarrierEnvelopeKind)
		flushes = append(flushes, ev.CarrierFlushClass)
		if ev.CarrierRetryCount != "" && ev.CarrierRetryCount != "none" {
			retries++
		}
		if ev.CarrierReordered {
			reordered++
		}
		if ev.CarrierDropped {
			dropped++
		}
		if ev.CarrierBackpressure {
			backpressure++
		}
	}
	return FeatureVector{
		TraceID:  traceID(events),
		Scenario: scenarioFromEvents(events),
		Family:   firstNonEmpty(families),
		Features: map[string]float64{
			"envelope_count":             float64(envelopes),
			"retry_count":                float64(retries),
			"reorder_count":              float64(reordered),
			"drop_count":                 float64(dropped),
			"queue_backpressure_count":   float64(backpressure),
			"coalescing_ratio":           ratio(envelopes-len(kinds), max(envelopes, 1)),
			"semantic_reconstruction_ok": reconstructionScore(events),
		},
		Buckets: map[string]string{
			"carrier_family":            firstNonEmpty(families),
			"envelope_encoding_pattern": firstPolicy(events, "carrier_envelope_encoding"),
			"flush_pattern":             firstPolicy(events, "carrier_flush_policy") + "/" + strings.Join(collapse(flushes), ">"),
			"batch_policy":              firstPolicy(events, "carrier_batch_policy"),
			"batch_size_distribution":   firstPolicy(events, "carrier_batch_policy") + "/" + strings.Join(collapse(kinds), ">"),
			"chunking_policy":           firstPolicy(events, "carrier_chunking_policy"),
			"chunking_rhythm":           firstPolicy(events, "carrier_chunking_policy") + "/" + countBucket(envelopes),
			"retry_pattern":             countBucket(retries),
			"reorder_behavior":          countBucket(reordered),
			"backpressure_pattern":      countBucket(backpressure),
			"coalescing_ratio":          countBucket(envelopes),
			"priority_mapping":          firstPolicy(events, "carrier_priority_mapping"),
			"error_reset_preservation":  firstPolicy(events, "carrier_error_reset"),
		},
	}
}

func ScanCollapse(scenario string, runs []ScenarioRun, thresholds CollapseThresholds) CarrierCollapseReport {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	vectors := []FeatureVector{}
	familySet := map[string]bool{}
	for _, run := range runs {
		if scenario != "" && run.Scenario != scenario {
			continue
		}
		vector := ExtractFeatures(run.Events)
		vectors = append(vectors, vector)
		familySet[run.Family] = true
	}
	report := CarrierCollapseReport{Scenario: scenario, ProfileCount: len(vectors), CarrierFamilies: sortedKeys(familySet), Conclusion: "passed"}
	if len(vectors) == 0 {
		report.Conclusion = "failed"
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "no_runs")
		return report
	}
	checks := map[string][]string{
		"carrier_family":            bucketValues(vectors, "carrier_family"),
		"envelope_encoding_pattern": bucketValues(vectors, "envelope_encoding_pattern"),
		"flush_pattern":             bucketValues(vectors, "flush_pattern"),
		"batch_policy":              bucketValues(vectors, "batch_policy"),
		"batch_size_distribution":   bucketValues(vectors, "batch_size_distribution"),
		"chunking_policy":           bucketValues(vectors, "chunking_policy"),
		"chunking_rhythm":           bucketValues(vectors, "chunking_rhythm"),
		"retry_pattern":             bucketValues(vectors, "retry_pattern"),
		"reorder_behavior":          bucketValues(vectors, "reorder_behavior"),
		"backpressure_pattern":      bucketValues(vectors, "backpressure_pattern"),
		"priority_mapping":          bucketValues(vectors, "priority_mapping"),
		"carrier_behavior_fixed":    compositeValues(vectors),
	}
	uniqueTotal := 0
	for name, values := range checks {
		unique := uniqueCount(values)
		uniqueTotal += unique
		if len(values) >= 4 && dominantRatio(values) >= thresholds.MaxDominantRatio {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, name)
		}
	}
	report.DiversityScore = ratio(uniqueTotal, len(checks)*max(len(vectors), 1))
	sort.Strings(report.SuspiciousMetrics)
	if report.DiversityScore < thresholds.MinDiversityScore || len(report.SuspiciousMetrics) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func bucketValues(vectors []FeatureVector, key string) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, vector.Buckets[key])
	}
	return out
}

func compositeValues(vectors []FeatureVector) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, strings.Join([]string{
			vector.Buckets["carrier_family"],
			vector.Buckets["envelope_encoding_pattern"],
			vector.Buckets["flush_pattern"],
			vector.Buckets["batch_size_distribution"],
			vector.Buckets["chunking_rhythm"],
			vector.Buckets["retry_pattern"],
		}, "|"))
	}
	return out
}

func traceID(events []ktrace.Event) string {
	h := sha256.New()
	for _, ev := range events {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%t|%t\n", ev.ProfileID, ev.CarrierFamilyBucket, ev.CarrierEnvelopeKind, ev.CarrierFlushClass, ev.CarrierRetryCount, ev.CarrierReordered, ev.CarrierBackpressure)
	}
	return "carrier_trace_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func scenarioFromEvents(events []ktrace.Event) string {
	for _, ev := range events {
		if ev.CarrierScenario != "" {
			return ev.CarrierScenario
		}
	}
	return ""
}

func firstPolicy(events []ktrace.Event, key string) string {
	prefix := key + "="
	for _, ev := range events {
		for _, part := range strings.Split(ev.Note, ";") {
			if strings.HasPrefix(part, prefix) {
				return strings.TrimPrefix(part, prefix)
			}
		}
	}
	return "none"
}

func reconstructionScore(events []ktrace.Event) float64 {
	for _, ev := range events {
		if ev.CarrierReconstruction == "failed" {
			return 0
		}
		if ev.CarrierReconstruction == "equivalent" {
			return 1
		}
	}
	return 0
}

func firstNonEmpty(values []string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
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

func collapse(values []string) []string {
	out := []string{}
	prev := ""
	for _, value := range values {
		if value == "" || value == prev {
			continue
		}
		out = append(out, value)
		prev = value
	}
	return out
}

func uniqueCount(values []string) int {
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	return len(seen)
}

func dominantRatio(values []string) float64 {
	counts := map[string]int{}
	for _, value := range values {
		if value != "" {
			counts[value]++
		}
	}
	maxCount := 0
	for _, count := range counts {
		if count > maxCount {
			maxCount = count
		}
	}
	return ratio(maxCount, len(values))
}

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
