// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeadversary

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	kruntime "kurdistan/internal/runtime"
	ktrace "kurdistan/internal/trace"
)

type ScenarioRun struct {
	ProfileID string                  `json:"profile_id"`
	Scenario  string                  `json:"scenario"`
	Correct   bool                    `json:"correct"`
	Summary   kruntime.HarnessSummary `json:"summary"`
	Events    []ktrace.Event          `json:"-"`
	Failure   string                  `json:"failure,omitempty"`
}

type RuntimeFeatureVector struct {
	TraceID  string             `json:"trace_id"`
	Scenario string             `json:"scenario"`
	Features map[string]float64 `json:"features"`
	Buckets  map[string]string  `json:"buckets"`
}

type RuntimeCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	RuntimeFamilies   []string `json:"runtime_families"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
}

type CorrectnessSummary struct {
	ScenarioRuns          int `json:"scenario_runs"`
	CorrectRuns           int `json:"correct_runs"`
	NegotiationFailures   int `json:"negotiation_failures"`
	CompatibilityFailures int `json:"compatibility_failures"`
	ReplayFailures        int `json:"replay_failures"`
	BackpressureFailures  int `json:"backpressure_failures"`
	TraceHygieneFailures  int `json:"trace_hygiene_failures"`
}

type Report struct {
	Version         string                  `json:"version"`
	Mode            string                  `json:"mode"`
	ProfileCount    int                     `json:"profile_count"`
	ScenarioCount   int                     `json:"scenario_count"`
	Runs            int                     `json:"runs"`
	CarrierFamilies []string                `json:"carrier_families"`
	TargetClasses   []string                `json:"target_classes"`
	Correctness     CorrectnessSummary      `json:"correctness"`
	CollapseReports []RuntimeCollapseReport `json:"collapse_reports"`
	Conclusion      string                  `json:"conclusion"`
}

type CollapseThresholds struct {
	MaxDominantRatio   float64 `json:"max_dominant_ratio"`
	MinDiversityScore  float64 `json:"min_diversity_score"`
	MinScenarioSuccess float64 `json:"min_scenario_success"`
}

func DefaultCollapseThresholds() CollapseThresholds {
	return CollapseThresholds{MaxDominantRatio: 0.92, MinDiversityScore: 0.12, MinScenarioSuccess: 0.90}
}

func AnalyzeRuns(runs []ScenarioRun, thresholds CollapseThresholds) Report {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	byScenario := map[string][]ScenarioRun{}
	profiles := map[string]bool{}
	families := map[string]bool{}
	targets := map[string]bool{}
	report := Report{Version: "0.13.0-lab", Mode: "runtime", Runs: len(runs)}
	for _, run := range runs {
		byScenario[run.Scenario] = append(byScenario[run.Scenario], run)
		profiles[run.ProfileID] = true
		if run.Summary.CarrierFamily != "" {
			families[run.Summary.CarrierFamily] = true
		}
		for _, target := range run.Summary.ProxyTargetsExercised {
			targets[target] = true
		}
		report.Correctness.ScenarioRuns++
		if run.Correct {
			report.Correctness.CorrectRuns++
		}
		if strings.Contains(run.Failure, "capability") {
			report.Correctness.NegotiationFailures++
		}
		if strings.Contains(run.Failure, "profile") || strings.Contains(run.Failure, "compatibility") {
			report.Correctness.CompatibilityFailures++
		}
		if run.Scenario == ScenarioReplayInjection && run.Summary.ReplayRejected == 0 {
			report.Correctness.ReplayFailures++
		}
		if (run.Scenario == ScenarioCarrierQueuePressure || run.Scenario == ScenarioLargeObjectRuntime) && run.Summary.BackpressureEvents == 0 {
			report.Correctness.BackpressureFailures++
		}
		if run.Summary.PayloadLogged || run.Summary.SecretLogged {
			report.Correctness.TraceHygieneFailures++
		}
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(byScenario)
	report.CarrierFamilies = sortedKeys(families)
	report.TargetClasses = sortedKeys(targets)
	for scenario, scenarioRuns := range byScenario {
		report.CollapseReports = append(report.CollapseReports, ScanCollapse(scenario, scenarioRuns, thresholds))
	}
	report.Conclusion = "passed"
	if report.Correctness.ScenarioRuns == 0 || ratio(report.Correctness.CorrectRuns, report.Correctness.ScenarioRuns) < thresholds.MinScenarioSuccess || report.Correctness.TraceHygieneFailures > 0 {
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
	fmt.Fprintf(&b, "runtime %s (%s)\n", r.Version, r.Mode)
	fmt.Fprintf(&b, "profiles: %d\n", r.ProfileCount)
	fmt.Fprintf(&b, "scenarios: %d\n", r.ScenarioCount)
	fmt.Fprintf(&b, "runs: %d\n", r.Runs)
	fmt.Fprintf(&b, "carrier_families: %s\n", strings.Join(r.CarrierFamilies, ","))
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
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}
