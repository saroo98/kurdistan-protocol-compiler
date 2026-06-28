// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adversary

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	ktrace "kurdistan/internal/trace"
)

const firstNFrameCount = 5

type FeatureVector struct {
	TraceID   string             `json:"trace_id"`
	ProfileID string             `json:"profile_id,omitempty"`
	Label     string             `json:"label,omitempty"`
	Features  map[string]float64 `json:"features"`
	Buckets   map[string]string  `json:"buckets"`
}

func ExtractFeatures(events []ktrace.Event) FeatureVector {
	return ExtractFeaturesWithMetadata("", "", events)
}

func ExtractFeaturesWithMetadata(traceID, label string, events []ktrace.Event) FeatureVector {
	events = canonicalEvents(events)
	vector := FeatureVector{
		TraceID:  traceID,
		Label:    label,
		Features: map[string]float64{},
		Buckets:  map[string]string{},
	}
	if vector.TraceID == "" {
		vector.TraceID = traceIDForEvents(events)
	}
	vector.ProfileID = firstProfileID(events)
	if vector.Label == "" {
		vector.Label = inferLabel(vector.ProfileID)
	}

	var frameSizes []int
	var payloadSizes []int
	var paddingSizes []int
	var directions []string
	var states []string
	var timings []string
	var schedulerModes []string
	var streamLabels []string
	var streamEvents []string
	var streamStates []string
	var streamWindows []string
	var sessionWindows []string
	var priorityClasses []string
	var uploadBytes, downloadBytes int
	var firstTimestamp int64
	var prevTimestamp int64
	var semanticCount int
	var firstContactCount int
	var closeBehavior string
	var invalidInputOutcome string
	var malformedFrameOutcome string
	var backpressureEvents int

	for _, ev := range events {
		if ev.TimeUnixNano > 0 {
			if firstTimestamp == 0 {
				firstTimestamp = ev.TimeUnixNano
			}
			if prevTimestamp > 0 {
				timings = append(timings, timingBucket(ev.TimeUnixNano-prevTimestamp))
			}
			prevTimestamp = ev.TimeUnixNano
		}
		if ev.EventType == "first_contact" {
			firstContactCount++
		}
		if ev.Semantic != "" {
			semanticCount++
		}
		if ev.State != "" {
			states = append(states, ev.State)
		}
		if ev.Direction != "" {
			directions = append(directions, directionBucket(ev.Direction))
		}
		if ev.SchedulerMode != "" {
			schedulerModes = append(schedulerModes, ev.SchedulerMode)
		}
		if ev.StreamLabel != "" {
			streamLabels = append(streamLabels, ev.StreamLabel)
		}
		if ev.StreamEvent != "" {
			streamEvents = append(streamEvents, ev.StreamEvent)
		}
		if ev.StreamState != "" {
			streamStates = append(streamStates, ev.StreamState)
		}
		if ev.StreamWindowBucket != "" {
			streamWindows = append(streamWindows, ev.StreamWindowBucket)
		}
		if ev.SessionWindowBucket != "" {
			sessionWindows = append(sessionWindows, ev.SessionWindowBucket)
		}
		if ev.PriorityClass != "" {
			priorityClasses = append(priorityClasses, ev.PriorityClass)
		}
		if ev.Backpressure {
			backpressureEvents++
		}
		frameBytes := clampNonNegative(ev.FrameBytes)
		payloadBytes := clampNonNegative(ev.PayloadBytes)
		paddingBytes := clampNonNegative(ev.PaddingBytes)
		if frameBytes > 0 {
			frameSizes = append(frameSizes, frameBytes)
			switch directionBucket(ev.Direction) {
			case "c2s":
				uploadBytes += frameBytes
			case "s2c":
				downloadBytes += frameBytes
			}
		}
		payloadSizes = append(payloadSizes, payloadBytes)
		paddingSizes = append(paddingSizes, paddingBytes)
		switch ev.EventType {
		case "close":
			if closeBehavior == "" {
				closeBehavior = outcomeBucket("close", ev.Note, ev.Semantic)
			}
		case "invalid_input":
			if invalidInputOutcome == "" {
				invalidInputOutcome = outcomeBucket("invalid", ev.Note, ev.Semantic)
			}
		case "malformed_frame":
			if malformedFrameOutcome == "" {
				malformedFrameOutcome = outcomeBucket("malformed", ev.Note, ev.Semantic)
			}
		}
	}

	vector.Features["first_frame_size"] = float64(firstValue(frameSizes))
	vector.Features["first_contact_event_count"] = float64(firstContactCount)
	vector.Features["state_path_length"] = float64(len(states))
	vector.Features["semantic_event_count"] = float64(semanticCount)
	vector.Features["total_frames"] = float64(len(frameSizes))
	vector.Features["total_bytes"] = float64(sum(frameSizes))
	vector.Features["payload_bytes_total"] = float64(sum(payloadSizes))
	vector.Features["padding_bytes_total"] = float64(sum(paddingSizes))
	vector.Features["direction_change_count"] = float64(directionChanges(directions))
	vector.Features["burst_count"] = float64(burstCount(directions))
	vector.Features["upload_download_ratio"] = uploadDownloadRatio(uploadBytes, downloadBytes)
	vector.Features["session_duration_bucket"] = float64(durationBucket(firstTimestamp, prevTimestamp))
	vector.Features["stream_count"] = float64(uniqueCount(streamLabels))
	vector.Features["stream_event_count"] = float64(len(streamEvents))
	vector.Features["backpressure_event_count"] = float64(backpressureEvents)
	vector.Features["direction_stream_change_count"] = float64(directionChanges(streamLabels))
	for i := 0; i < firstNFrameCount; i++ {
		vector.Features[fmt.Sprintf("first_frame_%d", i)] = float64(nthValue(frameSizes, i))
	}
	for bucket, count := range bucketCounts(payloadSizes, sizeBucket) {
		vector.Features["payload_bucket_count_"+bucket] = float64(count)
	}
	for bucket, count := range bucketCounts(paddingSizes, paddingBucket) {
		vector.Features["padding_bucket_count_"+bucket] = float64(count)
	}

	vector.Buckets["first_frame_size_bucket"] = sizeBucket(firstValue(frameSizes))
	vector.Buckets["first_n_frame_size_sequence"] = bucketSequence(frameSizes, firstNFrameCount, sizeBucket)
	vector.Buckets["first_contact_event_count"] = fmt.Sprint(firstContactCount)
	vector.Buckets["direction_sequence"] = strings.Join(limitStrings(directions, 16), ">")
	vector.Buckets["state_path_shape"] = statePathShape(states)
	vector.Buckets["frame_size_histogram"] = histogramBucket(frameSizes, sizeBucket)
	vector.Buckets["payload_byte_buckets"] = histogramBucket(payloadSizes, sizeBucket)
	vector.Buckets["padding_byte_buckets"] = histogramBucket(paddingSizes, paddingBucket)
	vector.Buckets["inter_event_timing_buckets"] = strings.Join(limitStrings(timings, 16), ">")
	vector.Buckets["close_behavior"] = defaultBucket(closeBehavior, "none")
	vector.Buckets["invalid_input_outcome"] = defaultBucket(invalidInputOutcome, "none")
	vector.Buckets["malformed_frame_outcome"] = defaultBucket(malformedFrameOutcome, "none")
	vector.Buckets["scheduler_flush_pattern"] = strings.Join(limitStrings(collapseRepeats(schedulerModes), 8), ">")
	vector.Buckets["stream_interleaving_pattern"] = strings.Join(limitStrings(streamInterleaving(streamLabels, streamEvents), 16), ">")
	vector.Buckets["stream_state_pattern"] = strings.Join(limitStrings(collapseRepeats(streamStates), 16), ">")
	vector.Buckets["stream_window_pattern"] = strings.Join(limitStrings(collapseRepeats(streamWindows), 16), ">")
	vector.Buckets["session_window_pattern"] = strings.Join(limitStrings(collapseRepeats(sessionWindows), 16), ">")
	vector.Buckets["priority_class_pattern"] = strings.Join(limitStrings(collapseRepeats(priorityClasses), 16), ">")
	vector.Buckets["label"] = vector.Label
	return vector
}

func ExtractFeatureVectors(traces [][]ktrace.Event) []FeatureVector {
	vectors := make([]FeatureVector, 0, len(traces))
	for i, events := range traces {
		vectors = append(vectors, ExtractFeaturesWithMetadata(fmt.Sprintf("trace_%03d", i), "", events))
	}
	return vectors
}

func canonicalEvents(events []ktrace.Event) []ktrace.Event {
	if len(events) == 0 {
		return nil
	}
	byKey := map[string]ktrace.Event{}
	for _, ev := range events {
		canonical := ev
		canonical.EventType = eventClass(ev.EventType)
		key := canonicalEventKey(canonical)
		existing, ok := byKey[key]
		if !ok || earlier(canonical, existing) {
			byKey[key] = canonical
		}
	}
	out := make([]ktrace.Event, 0, len(byKey))
	for _, ev := range byKey {
		out = append(out, ev)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].TimeUnixNano == out[j].TimeUnixNano {
			return canonicalEventKey(out[i]) < canonicalEventKey(out[j])
		}
		return out[i].TimeUnixNano < out[j].TimeUnixNano
	})
	return out
}

func eventClass(eventType string) string {
	switch eventType {
	case "frame_encode", "frame_decode":
		return "frame"
	default:
		return eventType
	}
}

func canonicalEventKey(ev ktrace.Event) string {
	return fmt.Sprintf("%s|%s|%s|%d|%d|%d|%s|%s|%s|%s|%s|%t",
		ev.EventType, ev.Semantic, directionBucket(ev.Direction), clampNonNegative(ev.FrameBytes),
		clampNonNegative(ev.PayloadBytes), clampNonNegative(ev.PaddingBytes), ev.SchedulerMode,
		outcomeBucket(ev.EventType, ev.Note, ev.Semantic), ev.StreamEvent, ev.StreamState,
		ev.PriorityClass, ev.Backpressure)
}

func earlier(a, b ktrace.Event) bool {
	if a.TimeUnixNano == 0 {
		return false
	}
	if b.TimeUnixNano == 0 {
		return true
	}
	return a.TimeUnixNano < b.TimeUnixNano
}

func firstProfileID(events []ktrace.Event) string {
	for _, ev := range events {
		if ev.ProfileID != "" {
			return ev.ProfileID
		}
	}
	return ""
}

func inferLabel(profileID string) string {
	switch {
	case strings.HasPrefix(profileID, "fixed_protocol"):
		return "fixed_protocol"
	case strings.HasPrefix(profileID, "noisy_fixed_protocol"):
		return "noisy_fixed_protocol"
	case strings.HasPrefix(profileID, "random_byte_protocol"):
		return "random_byte_protocol"
	case strings.HasPrefix(profileID, "raw_echo_baseline"):
		return "raw_echo_baseline"
	case strings.HasPrefix(profileID, "kp_"):
		return "kurdistan"
	default:
		return "unknown"
	}
}

func traceIDForEvents(events []ktrace.Event) string {
	h := sha256.New()
	for _, ev := range events {
		fmt.Fprintf(h, "%s|%s|%s|%s|%s|%d|%d|%d|%s|%s|%s|%t\n",
			ev.ProfileID, ev.EventType, ev.Role, ev.Semantic, directionBucket(ev.Direction),
			clampNonNegative(ev.FrameBytes), clampNonNegative(ev.PayloadBytes),
			clampNonNegative(ev.PaddingBytes), ev.SchedulerMode, ev.StreamEvent, ev.PriorityClass, ev.Backpressure)
	}
	return "trace_" + hex.EncodeToString(h.Sum(nil))[:16]
}

func clampNonNegative(value int) int {
	if value < 0 {
		return 0
	}
	return value
}

func firstValue(values []int) int {
	return nthValue(values, 0)
}

func nthValue(values []int, index int) int {
	if index < 0 || index >= len(values) {
		return 0
	}
	return values[index]
}

func sum(values []int) int {
	total := 0
	for _, value := range values {
		total += value
	}
	return total
}

func directionBucket(direction string) string {
	switch direction {
	case "client_to_server":
		return "c2s"
	case "server_to_client":
		return "s2c"
	case "":
		return ""
	default:
		return "other"
	}
}

func directionChanges(directions []string) int {
	changes := 0
	prev := ""
	for _, direction := range directions {
		if direction == "" {
			continue
		}
		if prev != "" && prev != direction {
			changes++
		}
		prev = direction
	}
	return changes
}

func burstCount(directions []string) int {
	count := 0
	prev := ""
	for _, direction := range directions {
		if direction == "" {
			continue
		}
		if prev == "" || prev != direction {
			count++
		}
		prev = direction
	}
	return count
}

func uploadDownloadRatio(uploadBytes, downloadBytes int) float64 {
	switch {
	case uploadBytes == 0 && downloadBytes == 0:
		return 0
	case downloadBytes == 0:
		return 10
	default:
		ratio := float64(uploadBytes) / float64(downloadBytes)
		if ratio > 10 {
			return 10
		}
		return ratio
	}
}

func durationBucket(first, last int64) int {
	if first <= 0 || last <= first {
		return 0
	}
	ms := (last - first) / 1_000_000
	switch {
	case ms <= 50:
		return 1
	case ms <= 250:
		return 2
	case ms <= 1000:
		return 3
	default:
		return 4
	}
}

func timingBucket(delta int64) string {
	if delta <= 0 {
		return "0ms"
	}
	ms := delta / 1_000_000
	switch {
	case ms <= 50:
		return "lab_short"
	case ms <= 250:
		return "medium"
	default:
		return "long"
	}
}

func sizeBucket(size int) string {
	switch {
	case size <= 0:
		return "none"
	case size <= 32:
		return "tiny"
	case size <= 96:
		return "small"
	case size <= 512:
		return "medium"
	case size <= 4096:
		return "large"
	default:
		return "huge"
	}
}

func paddingBucket(size int) string {
	switch {
	case size <= 0:
		return "none"
	case size <= 8:
		return "pad_tiny"
	case size <= 32:
		return "pad_small"
	case size <= 128:
		return "pad_medium"
	default:
		return "pad_large"
	}
}

func bucketCounts(values []int, bucket func(int) string) map[string]int {
	counts := map[string]int{}
	for _, value := range values {
		counts[bucket(value)]++
	}
	return counts
}

func bucketSequence(values []int, limit int, bucket func(int) string) string {
	parts := make([]string, 0, limit)
	for i := 0; i < limit; i++ {
		if i >= len(values) {
			parts = append(parts, "missing")
			continue
		}
		parts = append(parts, bucket(values[i]))
	}
	return strings.Join(parts, ">")
}

func histogramBucket(values []int, bucket func(int) string) string {
	counts := bucketCounts(values, bucket)
	keys := make([]string, 0, len(counts))
	for key := range counts {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, fmt.Sprintf("%s:%d", key, counts[key]))
	}
	return strings.Join(parts, ",")
}

func statePathShape(states []string) string {
	indexes := map[string]int{}
	next := 0
	parts := make([]string, 0, len(states))
	for _, state := range states {
		if _, ok := indexes[state]; !ok {
			indexes[state] = next
			next++
		}
		parts = append(parts, fmt.Sprintf("s%d", indexes[state]))
	}
	return strings.Join(parts, ">")
}

func outcomeBucket(kind, note, semantic string) string {
	value := semantic
	if note != "" {
		value = note
	}
	if value == "" {
		return kind
	}
	sum := sha256.Sum256([]byte(value))
	return kind + "_h_" + hex.EncodeToString(sum[:])[:10]
}

func defaultBucket(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func limitStrings(values []string, limit int) []string {
	out := make([]string, 0, min(len(values), limit))
	for i, value := range values {
		if i >= limit {
			break
		}
		out = append(out, value)
	}
	return out
}

func collapseRepeats(values []string) []string {
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

func uniqueCount(values []string) int {
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	return len(seen)
}

func streamInterleaving(labels, events []string) []string {
	n := min(len(labels), len(events))
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, labels[i]+":"+events[i])
	}
	return out
}
