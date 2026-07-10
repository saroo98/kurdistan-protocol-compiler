// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import "sort"

func ScanCollapse(scenario string, runs []ScenarioRun, thresholds CollapseThresholds) RuntimeCollapseReport {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	vectors := []RuntimeFeatureVector{}
	families := map[string]bool{}
	for _, run := range runs {
		if scenario != "" && run.Scenario != scenario {
			continue
		}
		vectors = append(vectors, ExtractFeatures(run))
		if run.Summary.CarrierFamily != "" {
			families[run.Summary.CarrierFamily] = true
		}
	}
	report := RuntimeCollapseReport{Scenario: scenario, ProfileCount: len(vectors), RuntimeFamilies: sortedKeys(families), Conclusion: "passed"}
	if len(vectors) == 0 {
		report.Conclusion = "failed"
		report.SuspiciousMetrics = []string{"no_runs"}
		return report
	}
	checks := map[string][]string{
		"lifecycle_path":       bucketValues(vectors, "lifecycle_path"),
		"frame_counts":         bucketValues(vectors, "frame_counts"),
		"carrier_family":       bucketValues(vectors, "carrier_family"),
		"target_distribution":  bucketValues(vectors, "target_distribution"),
		"replay_rejection":     bucketValues(vectors, "replay_rejection"),
		"backpressure_pattern": bucketValues(vectors, "backpressure_pattern"),
		"target_error_reset":   bucketValues(vectors, "target_error_reset"),
	}
	uniqueTotal := 0
	for name, values := range checks {
		uniqueTotal += uniqueCount(values)
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

func bucketValues(vectors []RuntimeFeatureVector, key string) []string {
	out := make([]string, 0, len(vectors))
	for _, vector := range vectors {
		out = append(out, vector.Buckets[key])
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

func sortedKeys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
