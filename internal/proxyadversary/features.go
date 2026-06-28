// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	ktrace "kurdistan/internal/trace"
)

func ExtractProxyFeatures(events []ktrace.Event) ProxyFeatureVector {
	targets := []string{}
	openOrder := []string{}
	closeOrder := []string{}
	responseModes := []string{}
	requestClasses := []string{}
	chunkBuckets := []string{}
	errorCount, resetCount, closeCount, metadataCount, backpressureCount := 0, 0, 0, 0, 0
	responseChunks := 0
	bytesByTarget := map[string]int{}
	for _, ev := range events {
		if ev.TargetClassBucket != "" {
			targets = append(targets, ev.TargetClassBucket)
		}
		if ev.RequestClassBucket != "" {
			requestClasses = append(requestClasses, ev.RequestClassBucket)
		}
		if ev.ResponseModeBucket != "" {
			responseModes = append(responseModes, ev.ResponseModeBucket)
		}
		switch ev.TargetEventType {
		case "open_relay", "target_descriptor":
			openOrder = append(openOrder, ev.TargetClassBucket)
		case "target_close":
			closeOrder = append(closeOrder, ev.TargetClassBucket)
			closeCount++
		case "target_response":
			responseChunks++
			chunkBuckets = append(chunkBuckets, ev.ResponseChunkBucket)
			bytesByTarget[ev.TargetClassBucket] += ev.PayloadBytes
		case "target_error":
			errorCount++
		case "target_reset":
			resetCount++
		case "target_backpressure", "response_backpressure", "flow_backpressure":
			backpressureCount++
		}
		if ev.TargetErrorBucket != "" {
			errorCount++
		}
		if ev.TargetReset {
			resetCount++
		}
		if ev.TargetClose {
			closeCount++
		}
		if ev.TargetBackpressure || ev.Backpressure {
			backpressureCount++
		}
		if ev.EventType == "proxy_metadata" || ev.Semantic == "target_metadata" {
			metadataCount++
		}
	}
	targetCount := uniqueCount(targets)
	features := map[string]float64{
		"target_class_count":                float64(targetCount),
		"target_error_count":                float64(errorCount),
		"target_reset_count":                float64(resetCount),
		"target_close_count":                float64(closeCount),
		"response_chunk_count":              float64(responseChunks),
		"target_induced_backpressure_count": float64(backpressureCount),
		"target_metadata_event_count":       float64(metadataCount),
		"large_object_dominance_ratio":      largestDominance(bytesByTarget),
		"target_response_fairness_score":    ratio(uniqueCount(targets), max(len(targets), 1)),
		"chunk_interleaving_score":          interleavingScore(targets),
	}
	return ProxyFeatureVector{
		TraceID:  traceID(events),
		Scenario: scenarioFromEvents(events),
		Features: features,
		Buckets: map[string]string{
			"target_class_distribution":  canonicalCounts(targets),
			"target_open_order":          canonicalOrder(openOrder),
			"target_close_order":         canonicalOrder(closeOrder),
			"descriptor_encoding_bucket": firstPolicy(events, "descriptor_encoding"),
			"relay_intent_encoding":      firstPolicy(events, "relay_intent_encoding"),
			"response_mode_encoding":     firstPolicy(events, "response_mode_encoding"),
			"response_mode_bucket":       firstPolicy(events, "response_mode_encoding") + "/" + strings.Join(collapse(responseModes), ">"),
			"request_class_mapping":      strings.Join(collapse(requestClasses), ">"),
			"target_error_behavior":      firstPolicy(events, "target_error_policy") + "/" + countBucket(errorCount),
			"target_reset_behavior":      firstPolicy(events, "target_reset_policy") + "/" + countBucket(resetCount),
			"target_close_behavior":      firstPolicy(events, "target_close_policy") + "/" + countBucket(closeCount),
			"target_metadata_policy":     firstPolicy(events, "target_metadata_policy") + "/" + countBucket(metadataCount),
			"chunking_rhythm":            strings.Join(collapse(chunkBuckets), ">"),
			"backpressure_pattern":       countBucket(backpressureCount),
			"descriptor_probe_result":    descriptorProbeResult(events),
		},
	}
}

func ScanCollapse(scenario string, runs []ScenarioRun, thresholds CollapseThresholds) ProxyCollapseReport {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	vectors := []ProxyFeatureVector{}
	for _, run := range runs {
		if scenario != "" && run.Scenario != scenario {
			continue
		}
		vectors = append(vectors, ExtractProxyFeatures(run.Events))
	}
	report := ProxyCollapseReport{Scenario: scenario, ProfileCount: len(vectors), Conclusion: "passed"}
	if len(vectors) == 0 {
		report.Conclusion = "failed"
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "no_runs")
		return report
	}
	checks := map[string][]string{
		"target_open_sequence":        bucketValues(vectors, "relay_intent_encoding"),
		"descriptor_encoding_pattern": bucketValues(vectors, "descriptor_encoding_bucket"),
		"response_mode_encoding":      bucketValues(vectors, "response_mode_encoding"),
		"response_mode_pattern":       bucketValues(vectors, "response_mode_bucket"),
		"target_error_behavior":       bucketValues(vectors, "target_error_behavior"),
		"reset_behavior":              bucketValues(vectors, "target_reset_behavior"),
		"close_behavior":              bucketValues(vectors, "target_close_behavior"),
		"target_metadata_policy":      bucketValues(vectors, "target_metadata_policy"),
		"proxy_behavior_fixed":        compositeValues(vectors),
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

func bucketValues(vectors []ProxyFeatureVector, key string) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, vector.Buckets[key])
	}
	return out
}

func compositeValues(vectors []ProxyFeatureVector) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, strings.Join([]string{
			vector.Buckets["descriptor_encoding_bucket"],
			vector.Buckets["relay_intent_encoding"],
			vector.Buckets["response_mode_bucket"],
			vector.Buckets["target_error_behavior"],
			vector.Buckets["target_close_behavior"],
			vector.Buckets["target_reset_behavior"],
		}, "|"))
	}
	return out
}

func eventsHaveProxyMetadata(events []ktrace.Event) bool {
	for _, ev := range events {
		if ev.TargetClassBucket != "" && ev.TargetEventType != "" && ev.ProxyScenario != "" {
			return true
		}
	}
	return false
}

func canonicalOrder(values []string) string {
	indexes := map[string]int{}
	next := 0
	parts := make([]string, 0, len(values))
	for _, value := range values {
		if _, ok := indexes[value]; !ok {
			indexes[value] = next
			next++
		}
		parts = append(parts, fmt.Sprintf("t%d", indexes[value]))
	}
	return strings.Join(parts, ">")
}

func canonicalCounts(values []string) string {
	counts := map[string]int{}
	for _, value := range values {
		if value != "" {
			counts[value]++
		}
	}
	keys := sortedKeys(counts)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return strings.Join(parts, "|")
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

func descriptorProbeResult(events []ktrace.Event) string {
	for _, ev := range events {
		if ev.TargetEventType == "descriptor_probe_rejected" {
			return "rejected"
		}
	}
	return "none"
}

func traceID(events []ktrace.Event) string {
	h := sha256.New()
	for _, ev := range events {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d|%d|%s|%t\n", ev.ProfileID, ev.EventType, ev.TargetClassBucket, ev.TargetEventType, ev.ResponseModeBucket, ev.FrameBytes, ev.PayloadBytes, ev.Note, ev.TargetBackpressure)
	}
	return "proxy_trace_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func scenarioFromEvents(events []ktrace.Event) string {
	for _, ev := range events {
		if ev.ProxyScenario != "" {
			return ev.ProxyScenario
		}
	}
	return ""
}

func interleavingScore(values []string) float64 {
	if len(values) < 2 {
		return 0
	}
	changes := 0
	prev := values[0]
	for _, value := range values[1:] {
		if value != prev {
			changes++
		}
		prev = value
	}
	return float64(changes) / float64(len(values)-1)
}

func largestDominance(values map[string]int) float64 {
	total, maxValue := 0, 0
	for _, value := range values {
		total += value
		if value > maxValue {
			maxValue = value
		}
	}
	return ratio(maxValue, total)
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

func sortedKeys[T any](values map[string]T) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
