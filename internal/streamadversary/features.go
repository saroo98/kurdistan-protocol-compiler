package streamadversary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	ktrace "kurdistan/internal/trace"
)

func ExtractStreamFeatures(events []ktrace.Event) StreamFeatureVector {
	labels := []string{}
	openOrder := []string{}
	closeOrder := []string{}
	resetPositions := []int{}
	scheduler := []string{}
	closeReset := []string{}
	payloadByStream := map[string]int{}
	blocked := map[string]bool{}
	dataProgress := map[string]bool{}
	interactiveProgress, bulkProgress := 0, 0
	windowUpdates, backpressure, sessionBlocked := 0, 0, 0
	for index, ev := range events {
		if ev.StreamLabel != "" {
			labels = append(labels, ev.StreamLabel)
		}
		switch ev.StreamEvent {
		case "open":
			openOrder = append(openOrder, ev.StreamLabel)
		case "close":
			closeOrder = append(closeOrder, ev.StreamLabel)
		case "reset":
			resetPositions = append(resetPositions, index)
		case "window_update":
			windowUpdates++
		case "blocked":
			blocked[ev.StreamLabel] = true
		case "session_blocked":
			blocked[ev.StreamLabel] = true
			sessionBlocked++
		case "data", "echo", "uneven", "bulk", "interactive_first", "interactive_second", "after_reset_continue", "after_close_continue":
			dataProgress[ev.StreamLabel] = true
		}
		if ev.Backpressure {
			backpressure++
		}
		if ev.EventType == "scheduler_decision" {
			scheduler = append(scheduler, ev.PriorityClass)
		}
		if ev.CloseResetEvent != "" {
			closeReset = append(closeReset, ev.CloseResetEvent+":"+policyFromNote(ev.Note, ev.CloseResetEvent+"_policy"))
		}
		if ev.PayloadBytes > 0 && ev.StreamLabel != "" {
			payloadByStream[ev.StreamLabel] += ev.PayloadBytes
			if ev.PriorityClass == "interactive" {
				interactiveProgress += ev.PayloadBytes
			}
			if ev.PriorityClass == "bulk" {
				bulkProgress += ev.PayloadBytes
			}
		}
	}
	streamCount := uniqueCount(labels)
	features := map[string]float64{
		"stream_count":                   float64(streamCount),
		"reset_count":                    float64(len(resetPositions)),
		"window_update_count":            float64(windowUpdates),
		"backpressure_event_count":       float64(backpressure),
		"blocked_stream_ratio":           ratio(len(blocked), max(streamCount, 1)),
		"session_blocked_count":          float64(sessionBlocked),
		"interleaving_score":             interleavingScore(labels),
		"fairness_score":                 ratio(len(dataProgress), max(streamCount, 1)),
		"largest_stream_dominance_ratio": largestDominance(payloadByStream),
		"priority_progress_ratio":        priorityProgressRatio(interactiveProgress, bulkProgress),
	}
	vector := StreamFeatureVector{
		TraceID:  traceID(events),
		Scenario: scenarioFromEvents(events),
		Features: features,
		Buckets: map[string]string{
			"stream_open_order":           canonicalOrder(openOrder),
			"stream_close_order":          canonicalOrder(closeOrder),
			"reset_position_bucket":       resetBucket(resetPositions, len(events)),
			"window_update_rhythm":        firstPolicy(events, "window_policy"),
			"scheduler_decision_pattern":  strings.Join(collapse(scheduler), ">"),
			"stream_id_pattern_bucket":    firstPolicy(events, "id_encoding") + "/" + firstPolicy(events, "id_strategy"),
			"close_reset_outcome_pattern": strings.Join(collapse(closeReset), ">"),
			"fairness_score_bucket":       scoreBucket(features["fairness_score"]),
			"interleaving_bucket":         scoreBucket(features["interleaving_score"]),
			"backpressure_bucket":         countBucket(backpressure),
		},
	}
	return vector
}

func ScanCollapse(scenario string, runs []ScenarioRun, thresholds CollapseThresholds) StreamCollapseReport {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	vectors := make([]StreamFeatureVector, 0, len(runs))
	for _, run := range runs {
		if scenario != "" && run.Scenario != scenario {
			continue
		}
		vectors = append(vectors, ExtractStreamFeatures(run.Events))
	}
	report := StreamCollapseReport{Scenario: scenario, ProfileCount: len(vectors), Conclusion: "passed"}
	if len(vectors) == 0 {
		report.Conclusion = "failed"
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "no_runs")
		return report
	}
	checks := map[string][]string{
		"stream_id_sequence":         bucketValues(vectors, "stream_id_pattern_bucket"),
		"open_close_order":           bucketValues(vectors, "stream_open_order"),
		"reset_timing_bucket":        bucketValues(vectors, "reset_position_bucket"),
		"window_update_rhythm":       bucketValues(vectors, "window_update_rhythm"),
		"backpressure_behavior":      bucketValues(vectors, "backpressure_bucket"),
		"scheduler_decision_pattern": bucketValues(vectors, "scheduler_decision_pattern"),
		"interleaving_pattern":       bucketValues(vectors, "interleaving_bucket"),
		"stream_fairness_score":      bucketValues(vectors, "fairness_score_bucket"),
		"close_reset_outcome":        bucketValues(vectors, "close_reset_outcome_pattern"),
		"stream_behavior_fixed":      compositeValues(vectors),
	}
	uniqueTotal := 0
	for name, values := range checks {
		unique := uniqueCount(values)
		uniqueTotal += unique
		dominant := dominantRatio(values)
		if len(values) >= 4 && dominant >= thresholds.MaxDominantRatio && shouldFlagMetric(name, values) {
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

func bucketValues(vectors []StreamFeatureVector, key string) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, vector.Buckets[key])
	}
	return out
}

func compositeValues(vectors []StreamFeatureVector) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, strings.Join([]string{
			vector.Buckets["stream_id_pattern_bucket"],
			vector.Buckets["window_update_rhythm"],
			vector.Buckets["scheduler_decision_pattern"],
			vector.Buckets["close_reset_outcome_pattern"],
		}, "|"))
	}
	return out
}

func shouldFlagMetric(name string, values []string) bool {
	if uniqueCount(values) == 0 {
		return false
	}
	switch name {
	case "open_close_order", "reset_timing_bucket", "interleaving_pattern", "stream_fairness_score", "backpressure_behavior":
		return false
	default:
		return true
	}
}

func canonicalOrder(labels []string) string {
	indexes := map[string]int{}
	next := 0
	parts := make([]string, 0, len(labels))
	for _, label := range labels {
		if _, ok := indexes[label]; !ok {
			indexes[label] = next
			next++
		}
		parts = append(parts, fmt.Sprintf("s%d", indexes[label]))
	}
	return strings.Join(parts, ">")
}

func resetBucket(positions []int, total int) string {
	if len(positions) == 0 {
		return "none"
	}
	pos := positions[0]
	switch {
	case total <= 0:
		return "unknown"
	case pos*3 < total:
		return "early"
	case pos*3 < total*2:
		return "middle"
	default:
		return "late"
	}
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

func policyFromNote(note, key string) string {
	prefix := key + "="
	for _, part := range strings.Split(note, ";") {
		if strings.HasPrefix(part, prefix) {
			return strings.TrimPrefix(part, prefix)
		}
	}
	return "none"
}

func interleavingScore(labels []string) float64 {
	if len(labels) < 2 {
		return 0
	}
	changes := 0
	prev := labels[0]
	for _, label := range labels[1:] {
		if label != prev {
			changes++
		}
		prev = label
	}
	return float64(changes) / float64(len(labels)-1)
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

func priorityProgressRatio(interactive, bulk int) float64 {
	if interactive == 0 && bulk == 0 {
		return 0
	}
	if bulk == 0 {
		return 10
	}
	value := float64(interactive) / float64(bulk)
	if value > 10 {
		return 10
	}
	return value
}

func scoreBucket(value float64) string {
	switch {
	case value <= 0:
		return "none"
	case value < 0.34:
		return "low"
	case value < 0.67:
		return "medium"
	default:
		return "high"
	}
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

func traceID(events []ktrace.Event) string {
	h := sha256.New()
	for _, ev := range events {
		fmt.Fprintf(h, "%s|%s|%s|%s|%d|%d|%s|%s|%t\n", ev.ProfileID, ev.EventType, ev.StreamLabel, ev.StreamEvent, ev.FrameBytes, ev.PayloadBytes, ev.PriorityClass, ev.Note, ev.Backpressure)
	}
	return "stream_trace_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func scenarioFromEvents(events []ktrace.Event) string {
	for _, ev := range events {
		for _, part := range strings.Split(ev.Note, ";") {
			if strings.HasPrefix(part, "scenario=") {
				return strings.TrimPrefix(part, "scenario=")
			}
		}
	}
	return ""
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

func collapse(values []string) []string {
	out := make([]string, 0, len(values))
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

func ratio(numerator, denominator int) float64 {
	if denominator == 0 {
		return 0
	}
	return float64(numerator) / float64(denominator)
}
