// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adversary

import (
	"math"
	"sort"
)

func Distance(a, b FeatureVector) float64 {
	var weightedSum float64
	var totalWeight float64
	for _, key := range unionFeatureKeys(a.Features, b.Features) {
		weight := numericWeight(key)
		av := finiteValue(a.Features[key])
		bv := finiteValue(b.Features[key])
		diff := math.Abs(av - bv)
		scale := math.Max(1, math.Max(math.Abs(av), math.Abs(bv)))
		weightedSum += weight * math.Min(1, diff/scale)
		totalWeight += weight
	}
	for _, key := range unionBucketKeys(a.Buckets, b.Buckets) {
		weight := bucketWeight(key)
		delta := 0.0
		if a.Buckets[key] != b.Buckets[key] {
			delta = 1
		}
		weightedSum += weight * delta
		totalWeight += weight
	}
	if totalWeight == 0 {
		return 0
	}
	out := weightedSum / totalWeight
	if math.IsNaN(out) || math.IsInf(out, 0) {
		return 1
	}
	return out
}

func Similarity(a, b FeatureVector) float64 {
	distance := Distance(a, b)
	if distance < 0 {
		return 1
	}
	if distance > 1 {
		return 0
	}
	return 1 - distance
}

func finiteValue(value float64) float64 {
	if math.IsNaN(value) || math.IsInf(value, 0) {
		return 0
	}
	return value
}

func numericWeight(key string) float64 {
	switch key {
	case "first_frame_size", "first_contact_event_count", "total_frames", "direction_change_count", "burst_count":
		return 3
	case "state_path_length", "semantic_event_count", "upload_download_ratio":
		return 2
	case "padding_bytes_total", "session_duration_bucket":
		return 0.5
	default:
		return 1
	}
}

func bucketWeight(key string) float64 {
	switch key {
	case "direction_sequence", "first_contact_event_count", "state_path_shape":
		return 4
	case "first_n_frame_size_sequence", "first_frame_size_bucket", "scheduler_flush_pattern":
		return 2
	case "padding_byte_buckets", "inter_event_timing_buckets":
		return 0.5
	case "label":
		return 0
	default:
		return 1
	}
}

func unionFeatureKeys(a, b map[string]float64) []string {
	seen := map[string]bool{}
	for key := range a {
		seen[key] = true
	}
	for key := range b {
		seen[key] = true
	}
	return sortedKeys(seen)
}

func unionBucketKeys(a, b map[string]string) []string {
	seen := map[string]bool{}
	for key := range a {
		seen[key] = true
	}
	for key := range b {
		seen[key] = true
	}
	return sortedKeys(seen)
}

func sortedKeys(seen map[string]bool) []string {
	keys := make([]string, 0, len(seen))
	for key := range seen {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
