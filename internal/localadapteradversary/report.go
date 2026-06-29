// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapteradversary

import (
	"fmt"
	"sort"

	"kurdistan/internal/localadapter"
	ktrace "kurdistan/internal/trace"
)

type ScenarioRun struct {
	ProfileID   string                           `json:"profile_id"`
	Scenario    string                           `json:"scenario"`
	PolicyShape string                           `json:"policy_shape"`
	Correct     bool                             `json:"correct"`
	Failure     string                           `json:"failure,omitempty"`
	Summary     localadapter.LocalAdapterSummary `json:"summary"`
	Checks      ScenarioChecks                   `json:"checks"`
	Events      []ktrace.Event                   `json:"events,omitempty"`
}

type ScenarioChecks struct {
	RuntimeMappingCorrect bool `json:"runtime_mapping_correct"`
	BackpressureCorrect   bool `json:"backpressure_correct"`
	ResetCorrect          bool `json:"reset_correct"`
	ErrorResetCorrect     bool `json:"error_reset_correct"`
	SequenceCorrect       bool `json:"sequence_correct"`
	TraceHygiene          bool `json:"trace_hygiene"`
}

type CorrectnessStats struct {
	ScenarioRuns         int `json:"scenario_runs"`
	CorrectRuns          int `json:"correct_runs"`
	RuntimeFailures      int `json:"runtime_failures"`
	BackpressureFailures int `json:"backpressure_failures"`
	ResetFailures        int `json:"reset_failures"`
	ErrorResetFailures   int `json:"error_reset_failures"`
	SequenceFailures     int `json:"sequence_failures"`
	TraceHygieneFailures int `json:"trace_hygiene_failures"`
}

type LocalAdapterCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	SourceModels      []string `json:"source_models"`
	SinkModels        []string `json:"sink_models"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
}

type CollapseThresholds struct {
	MaxDominantRatio   float64 `json:"max_dominant_ratio"`
	MinDiversityScore  float64 `json:"min_diversity_score"`
	MinScenarioSuccess float64 `json:"min_scenario_success"`
}

type Report struct {
	Mode            string                       `json:"mode"`
	ProfileCount    int                          `json:"profile_count"`
	ScenarioCount   int                          `json:"scenario_count"`
	SourceModels    []string                     `json:"source_models"`
	SinkModels      []string                     `json:"sink_models"`
	Correctness     CorrectnessStats             `json:"correctness"`
	CollapseReports []LocalAdapterCollapseReport `json:"collapse_reports"`
	Conclusion      string                       `json:"conclusion"`
}

func DefaultCollapseThresholds() CollapseThresholds {
	return CollapseThresholds{MaxDominantRatio: 0.95, MinDiversityScore: 0.15, MinScenarioSuccess: 0.90}
}

func (r Report) HumanSummary() string {
	return fmt.Sprintf("Local adapter adversary: %s (%d profiles, %d scenarios, %d/%d correct)\n", r.Conclusion, r.ProfileCount, r.ScenarioCount, r.Correctness.CorrectRuns, r.Correctness.ScenarioRuns)
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	for _, v := range values {
		if v != "" {
			seen[v] = true
		}
	}
	out := make([]string, 0, len(seen))
	for v := range seen {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}
