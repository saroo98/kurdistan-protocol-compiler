// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyadversary

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	ktrace "kurdistan/internal/trace"
)

type CollapseThresholds struct {
	MaxDominantRatio   float64 `json:"max_dominant_ratio"`
	MinDiversityScore  float64 `json:"min_diversity_score"`
	MinScenarioSuccess float64 `json:"min_scenario_success"`
}

type ScenarioChecks struct {
	BackpressureEvents        int  `json:"backpressure_events"`
	WindowUpdateEvents        int  `json:"window_update_events"`
	TargetErrorCount          int  `json:"target_error_count"`
	TargetResetCount          int  `json:"target_reset_count"`
	TargetCloseCount          int  `json:"target_close_count"`
	TargetBackpressureCorrect bool `json:"target_backpressure_correct"`
	ErrorResetIsolation       bool `json:"error_reset_isolation"`
	FairnessCorrect           bool `json:"fairness_correct"`
	DescriptorProbeRejected   bool `json:"descriptor_probe_rejected"`
}

type ScenarioRun struct {
	ProfileID     string         `json:"profile_id"`
	Scenario      string         `json:"scenario"`
	Correct       bool           `json:"correct"`
	Checks        ScenarioChecks `json:"checks"`
	TargetClasses []string       `json:"target_classes"`
	Events        []ktrace.Event `json:"-"`
}

type ProxyFeatureVector struct {
	TraceID  string             `json:"trace_id"`
	Scenario string             `json:"scenario"`
	Features map[string]float64 `json:"features"`
	Buckets  map[string]string  `json:"buckets"`
}

type ProxyCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
}

type CorrectnessSummary struct {
	ScenarioRuns            int `json:"scenario_runs"`
	CorrectRuns             int `json:"correct_runs"`
	BackpressureFailures    int `json:"backpressure_failures"`
	ErrorResetFailures      int `json:"error_reset_failures"`
	FairnessFailures        int `json:"fairness_failures"`
	DescriptorProbeFailures int `json:"descriptor_probe_failures"`
	MetadataFailures        int `json:"metadata_failures"`
}

type Report struct {
	Version         string                `json:"version"`
	Mode            string                `json:"mode"`
	ProfileCount    int                   `json:"profile_count"`
	ScenarioCount   int                   `json:"scenario_count"`
	Runs            int                   `json:"runs"`
	TargetClasses   []string              `json:"target_classes"`
	CollapseReports []ProxyCollapseReport `json:"collapse_reports"`
	Correctness     CorrectnessSummary    `json:"correctness"`
	Conclusion      string                `json:"conclusion"`
}

func DefaultCollapseThresholds() CollapseThresholds {
	return CollapseThresholds{MaxDominantRatio: 0.90, MinDiversityScore: 0.18, MinScenarioSuccess: 0.90}
}

func AnalyzeRuns(runs []ScenarioRun, thresholds CollapseThresholds) Report {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	byScenario := map[string][]ScenarioRun{}
	profiles := map[string]bool{}
	targets := map[string]bool{}
	report := Report{Version: "0.10.0-lab", Mode: "proxysem", Runs: len(runs)}
	for _, run := range runs {
		byScenario[run.Scenario] = append(byScenario[run.Scenario], run)
		profiles[run.ProfileID] = true
		for _, class := range run.TargetClasses {
			targets[class] = true
		}
		report.Correctness.ScenarioRuns++
		if run.Correct {
			report.Correctness.CorrectRuns++
		}
		if !run.Checks.TargetBackpressureCorrect {
			report.Correctness.BackpressureFailures++
		}
		if !run.Checks.ErrorResetIsolation {
			report.Correctness.ErrorResetFailures++
		}
		if !run.Checks.FairnessCorrect {
			report.Correctness.FairnessFailures++
		}
		if run.Scenario == ScenarioDescriptorProbe && !run.Checks.DescriptorProbeRejected {
			report.Correctness.DescriptorProbeFailures++
		}
		if run.Scenario != ScenarioDescriptorProbe && !eventsHaveProxyMetadata(run.Events) {
			report.Correctness.MetadataFailures++
		}
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(byScenario)
	report.TargetClasses = sortedKeys(targets)
	for scenario, scenarioRuns := range byScenario {
		if scenario == ScenarioDescriptorProbe {
			continue
		}
		report.CollapseReports = append(report.CollapseReports, ScanCollapse(scenario, scenarioRuns, thresholds))
	}
	report.Conclusion = "passed"
	success := 1.0
	if report.Correctness.ScenarioRuns > 0 {
		success = float64(report.Correctness.CorrectRuns) / float64(report.Correctness.ScenarioRuns)
	}
	if report.Correctness.ScenarioRuns == 0 || success < thresholds.MinScenarioSuccess ||
		report.Correctness.MetadataFailures > 0 || report.Correctness.DescriptorProbeFailures > 0 {
		report.Conclusion = "failed"
	}
	for _, collapse := range report.CollapseReports {
		if collapse.Conclusion != "passed" {
			report.Conclusion = "failed"
		}
	}
	return report
}

func (r Report) HumanSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "proxysem %s (%s)\n", r.Version, r.Mode)
	fmt.Fprintf(&b, "profiles: %d\n", r.ProfileCount)
	fmt.Fprintf(&b, "scenarios: %d\n", r.ScenarioCount)
	fmt.Fprintf(&b, "runs: %d\n", r.Runs)
	fmt.Fprintf(&b, "target_classes: %s\n", strings.Join(r.TargetClasses, ","))
	for _, collapse := range r.CollapseReports {
		status := "PASS"
		if collapse.Conclusion != "passed" {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "[%s] %s: diversity=%.3f suspicious=%v\n", status, collapse.Scenario, collapse.DiversityScore, collapse.SuspiciousMetrics)
	}
	fmt.Fprintf(&b, "correct_runs: %d/%d\n", r.Correctness.CorrectRuns, r.Correctness.ScenarioRuns)
	fmt.Fprintf(&b, "conclusion: %s\n", r.Conclusion)
	return b.String()
}

func WriteJSON(path string, report Report) error {
	if path == "" {
		return nil
	}
	dir := filepath.Dir(path)
	if dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}
