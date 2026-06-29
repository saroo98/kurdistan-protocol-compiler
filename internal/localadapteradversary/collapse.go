// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapteradversary

func AnalyzeRuns(runs []ScenarioRun, thresholds CollapseThresholds) Report {
	if thresholds.MaxDominantRatio == 0 {
		thresholds = DefaultCollapseThresholds()
	}
	scenarioSet := map[string]bool{}
	profileSet := map[string]bool{}
	sources := []string{}
	sinks := []string{}
	report := Report{}
	for _, run := range runs {
		report.Correctness.ScenarioRuns++
		scenarioSet[run.Scenario] = true
		profileSet[run.ProfileID] = true
		sources = append(sources, run.Summary.SourceModel)
		sinks = append(sinks, run.Summary.SinkModel)
		if run.Correct {
			report.Correctness.CorrectRuns++
		}
		if !run.Checks.RuntimeMappingCorrect && !allowsExpectedFailure(run) {
			report.Correctness.RuntimeFailures++
		}
		if !run.Checks.BackpressureCorrect {
			report.Correctness.BackpressureFailures++
		}
		if !run.Checks.ResetCorrect {
			report.Correctness.ResetFailures++
		}
		if !run.Checks.ErrorResetCorrect {
			report.Correctness.ErrorResetFailures++
		}
		if !run.Checks.SequenceCorrect && !allowsExpectedFailure(run) {
			report.Correctness.SequenceFailures++
		}
		if !run.Checks.TraceHygiene {
			report.Correctness.TraceHygieneFailures++
		}
	}
	for scenario := range scenarioSet {
		report.CollapseReports = append(report.CollapseReports, CollapseScenario(scenario, filterScenario(runs, scenario), thresholds))
	}
	report.ProfileCount = len(profileSet)
	report.ScenarioCount = len(scenarioSet)
	report.SourceModels = uniqueSorted(sources)
	report.SinkModels = uniqueSorted(sinks)
	report.Conclusion = "passed"
	if report.Correctness.ScenarioRuns > 0 && float64(report.Correctness.CorrectRuns)/float64(report.Correctness.ScenarioRuns) < thresholds.MinScenarioSuccess {
		report.Conclusion = "failed"
	}
	if report.Correctness.RuntimeFailures+report.Correctness.BackpressureFailures+report.Correctness.ResetFailures+report.Correctness.ErrorResetFailures+report.Correctness.SequenceFailures+report.Correctness.TraceHygieneFailures > 0 {
		report.Conclusion = "failed"
	}
	for _, collapse := range report.CollapseReports {
		if collapse.Conclusion != "passed" {
			report.Conclusion = "failed"
		}
	}
	return report
}

func CollapseScenario(scenario string, runs []ScenarioRun, thresholds CollapseThresholds) LocalAdapterCollapseReport {
	vectors := make([]FeatureVector, 0, len(runs))
	sources := []string{}
	sinks := []string{}
	for _, run := range runs {
		vectors = append(vectors, ExtractFeatures(run))
		sources = append(sources, run.Summary.SourceModel)
		sinks = append(sinks, run.Summary.SinkModel)
	}
	score := diversityScore(vectors)
	suspicious := []string{}
	if len(vectors) > 2 && score < thresholds.MinDiversityScore {
		suspicious = append(suspicious, "local_adapter_behavior_fixed")
	}
	if len(vectors) > 2 && dominantRatio(vectors, "policy_shape") > thresholds.MaxDominantRatio {
		suspicious = append(suspicious, "flow_to_stream_mapping_shape")
	}
	conclusion := "passed"
	if len(suspicious) > 0 {
		conclusion = "failed"
	}
	return LocalAdapterCollapseReport{
		Scenario:          scenario,
		ProfileCount:      len(runs),
		SourceModels:      uniqueSorted(sources),
		SinkModels:        uniqueSorted(sinks),
		SuspiciousMetrics: suspicious,
		DiversityScore:    score,
		Conclusion:        conclusion,
	}
}

func filterScenario(runs []ScenarioRun, scenario string) []ScenarioRun {
	out := []ScenarioRun{}
	for _, run := range runs {
		if run.Scenario == scenario {
			out = append(out, run)
		}
	}
	return out
}

func diversityScore(vectors []FeatureVector) float64 {
	if len(vectors) == 0 {
		return 0
	}
	seen := map[string]bool{}
	for _, vector := range vectors {
		seen[vector.Buckets["policy_shape"]] = true
	}
	return float64(len(seen)) / float64(len(vectors))
}

func dominantRatio(vectors []FeatureVector, bucket string) float64 {
	if len(vectors) == 0 {
		return 0
	}
	counts := map[string]int{}
	maxCount := 0
	for _, vector := range vectors {
		value := vector.Buckets[bucket]
		counts[value]++
		if counts[value] > maxCount {
			maxCount = counts[value]
		}
	}
	return float64(maxCount) / float64(len(vectors))
}

func allowsExpectedFailure(run ScenarioRun) bool {
	return run.Scenario == ScenarioMalformedChunk
}
