// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrieradversary

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	ktrace "kurdistan/internal/trace"
)

type CollapseThresholds struct {
	MaxDominantRatio   float64 `json:"max_dominant_ratio"`
	MinDiversityScore  float64 `json:"min_diversity_score"`
	MinScenarioSuccess float64 `json:"min_scenario_success"`
}

type ScenarioChecks struct {
	SemanticEquivalent   bool `json:"semantic_equivalent"`
	BackpressureCorrect  bool `json:"backpressure_correct"`
	RecoveryCorrect      bool `json:"recovery_correct"`
	ProxySemParity       bool `json:"proxysem_parity"`
	ErrorResetPreserved  bool `json:"error_reset_preserved"`
	MalformedRejected    bool `json:"malformed_rejected"`
	EnvelopeCount        int  `json:"envelope_count"`
	SemanticMessageCount int  `json:"semantic_message_count"`
	BackpressureEvents   int  `json:"backpressure_events"`
	TargetBackpressure   int  `json:"target_backpressure"`
	ReorderEvents        int  `json:"reorder_events"`
	RetryEvents          int  `json:"retry_events"`
	DropEvents           int  `json:"drop_events"`
}

type ScenarioRun struct {
	ProfileID string         `json:"profile_id"`
	Scenario  string         `json:"scenario"`
	Family    string         `json:"family"`
	Correct   bool           `json:"correct"`
	Checks    ScenarioChecks `json:"checks"`
	Events    []ktrace.Event `json:"-"`
}

type FeatureVector struct {
	TraceID  string             `json:"trace_id"`
	Scenario string             `json:"scenario"`
	Family   string             `json:"family"`
	Features map[string]float64 `json:"features"`
	Buckets  map[string]string  `json:"buckets"`
}

type CarrierCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	CarrierFamilies   []string `json:"carrier_families"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
}

type CorrectnessSummary struct {
	ScenarioRuns          int `json:"scenario_runs"`
	CorrectRuns           int `json:"correct_runs"`
	ReconstructionFailure int `json:"reconstruction_failures"`
	BackpressureFailures  int `json:"backpressure_failures"`
	RecoveryFailures      int `json:"recovery_failures"`
	ProxyParityFailures   int `json:"proxy_parity_failures"`
	MalformedFailures     int `json:"malformed_failures"`
}

type Report struct {
	Version         string                  `json:"version"`
	Mode            string                  `json:"mode"`
	ProfileCount    int                     `json:"profile_count"`
	ScenarioCount   int                     `json:"scenario_count"`
	Runs            int                     `json:"runs"`
	CarrierFamilies []string                `json:"carrier_families"`
	CollapseReports []CarrierCollapseReport `json:"collapse_reports"`
	Correctness     CorrectnessSummary      `json:"correctness"`
	Conclusion      string                  `json:"conclusion"`
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
	families := map[string]bool{}
	report := Report{Version: "0.11.0-lab", Mode: "carrier", Runs: len(runs)}
	for _, run := range runs {
		byScenario[run.Scenario] = append(byScenario[run.Scenario], run)
		profiles[run.ProfileID] = true
		families[run.Family] = true
		report.Correctness.ScenarioRuns++
		if run.Correct {
			report.Correctness.CorrectRuns++
		}
		if !run.Checks.SemanticEquivalent {
			report.Correctness.ReconstructionFailure++
		}
		if !run.Checks.BackpressureCorrect {
			report.Correctness.BackpressureFailures++
		}
		if !run.Checks.RecoveryCorrect {
			report.Correctness.RecoveryFailures++
		}
		if !run.Checks.ProxySemParity {
			report.Correctness.ProxyParityFailures++
		}
		if run.Scenario == ScenarioMalformedCarrierEnvelope && !run.Checks.MalformedRejected {
			report.Correctness.MalformedFailures++
		}
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(byScenario)
	report.CarrierFamilies = sortedKeys(families)
	for scenario, scenarioRuns := range byScenario {
		if scenario == ScenarioMalformedCarrierEnvelope {
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
		report.Correctness.ReconstructionFailure > 0 || report.Correctness.ProxyParityFailures > 0 ||
		report.Correctness.MalformedFailures > 0 {
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
	fmt.Fprintf(&b, "carrier %s (%s)\n", r.Version, r.Mode)
	fmt.Fprintf(&b, "profiles: %d\n", r.ProfileCount)
	fmt.Fprintf(&b, "scenarios: %d\n", r.ScenarioCount)
	fmt.Fprintf(&b, "runs: %d\n", r.Runs)
	fmt.Fprintf(&b, "carrier_families: %s\n", strings.Join(r.CarrierFamilies, ","))
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

func sortedKeys(values map[string]bool) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}
