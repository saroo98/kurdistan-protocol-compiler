// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapteradversary

func AnalyzeRuns(runs []ScenarioRun, thresholds CollapseThresholds) Report {
	if thresholds.MaxDominantRatio == 0 {
		thresholds = DefaultCollapseThresholds()
	}
	scenarioSet := map[string]bool{}
	profileSet := map[string]bool{}
	kinds := []string{"ingress"}
	report := Report{}
	for _, run := range runs {
		report.Correctness.ScenarioRuns++
		scenarioSet[run.Scenario] = true
		profileSet[run.ProfileID] = true
		if run.Correct {
			report.Correctness.CorrectRuns++
		}
		if !adapterScenarioAllowsPreMappingFailure(run.Scenario) && !run.Checks.FlowMappingCorrect {
			report.Correctness.MappingFailures++
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
		if run.Scenario == ScenarioCapabilityDowngrade && !run.Checks.CapabilityRejected {
			report.Correctness.CapabilityFailures++
		}
		if run.Scenario == ScenarioMalformedFlowDescriptor && !run.Checks.MalformedRejected {
			report.Correctness.MalformedFailures++
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
	report.AdapterKinds = kinds
	report.Conclusion = "passed"
	if report.Correctness.ScenarioRuns > 0 {
		success := float64(report.Correctness.CorrectRuns) / float64(report.Correctness.ScenarioRuns)
		if success < thresholds.MinScenarioSuccess {
			report.Conclusion = "failed"
		}
	}
	if report.Correctness.MappingFailures+
		report.Correctness.BackpressureFailures+
		report.Correctness.ResetFailures+
		report.Correctness.ErrorResetFailures+
		report.Correctness.CapabilityFailures+
		report.Correctness.MalformedFailures+
		report.Correctness.TraceHygieneFailures > 0 {
		report.Conclusion = "failed"
	}
	for _, collapse := range report.CollapseReports {
		if collapse.Conclusion != "passed" {
			report.Conclusion = "failed"
		}
	}
	return report
}

func adapterScenarioAllowsPreMappingFailure(scenario string) bool {
	return scenario == ScenarioCapabilityDowngrade || scenario == ScenarioMalformedFlowDescriptor
}

func CollapseScenario(scenario string, runs []ScenarioRun, thresholds CollapseThresholds) AdapterCollapseReport {
	vectors := make([]FeatureVector, 0, len(runs))
	for _, run := range runs {
		vectors = append(vectors, ExtractFeatures(run))
	}
	suspicious := []string{}
	score := diversityScore(vectors)
	if score < thresholds.MinDiversityScore && len(vectors) > 2 {
		suspicious = append(suspicious, "adapter_behavior_fixed")
	}
	if dominantRatio(vectors, "policy_shape") > thresholds.MaxDominantRatio && len(vectors) > 2 {
		suspicious = append(suspicious, "flow_to_stream_mapping_shape")
	}
	conclusion := "passed"
	if len(suspicious) > 0 {
		conclusion = "failed"
	}
	return AdapterCollapseReport{
		Scenario:          scenario,
		ProfileCount:      len(runs),
		AdapterKinds:      []string{"ingress"},
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
