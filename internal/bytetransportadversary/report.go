// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransportadversary

import (
	"fmt"
	"sort"

	"kurdistan/internal/bytetransport"
	ktrace "kurdistan/internal/trace"
)

type ScenarioRun struct {
	ProfileID   string                             `json:"profile_id"`
	Scenario    string                             `json:"scenario"`
	PolicyShape string                             `json:"policy_shape"`
	Correct     bool                               `json:"correct"`
	Failure     string                             `json:"failure,omitempty"`
	Summary     bytetransport.ByteTransportSummary `json:"summary"`
	Checks      ScenarioChecks                     `json:"checks"`
	Events      []ktrace.Event                     `json:"events,omitempty"`
}

type ScenarioChecks struct {
	RuntimeIntegrationCorrect bool `json:"runtime_integration_correct"`
	BackpressureCorrect       bool `json:"backpressure_correct"`
	SequenceCorrect           bool `json:"sequence_correct"`
	CorruptionCorrect         bool `json:"corruption_correct"`
	MalformedCorrect          bool `json:"malformed_correct"`
	ReassemblyCorrect         bool `json:"reassembly_correct"`
	ErrorResetCorrect         bool `json:"error_reset_correct"`
	TraceHygiene              bool `json:"trace_hygiene"`
}

type CorrectnessStats struct {
	ScenarioRuns               int `json:"scenario_runs"`
	CorrectRuns                int `json:"correct_runs"`
	RuntimeIntegrationFailures int `json:"runtime_integration_failures"`
	BackpressureFailures       int `json:"backpressure_failures"`
	SequenceFailures           int `json:"sequence_failures"`
	CorruptionFailures         int `json:"corruption_failures"`
	MalformedFailures          int `json:"malformed_failures"`
	ReassemblyFailures         int `json:"reassembly_failures"`
	ErrorResetFailures         int `json:"error_reset_failures"`
	TraceHygieneFailures       int `json:"trace_hygiene_failures"`
}

type ByteTransportCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	FrameKinds        []string `json:"frame_kinds"`
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
	Mode            string                        `json:"mode"`
	ProfileCount    int                           `json:"profile_count"`
	ScenarioCount   int                           `json:"scenario_count"`
	FrameKinds      []string                      `json:"frame_kinds"`
	Correctness     CorrectnessStats              `json:"correctness"`
	CollapseReports []ByteTransportCollapseReport `json:"collapse_reports"`
	Conclusion      string                        `json:"conclusion"`
}

func DefaultCollapseThresholds() CollapseThresholds {
	return CollapseThresholds{MaxDominantRatio: 0.95, MinDiversityScore: 0.15, MinScenarioSuccess: 0.90}
}

func (r Report) HumanSummary() string {
	return fmt.Sprintf("Byte transport adversary: %s (%d profiles, %d scenarios, %d/%d correct)\n", r.Conclusion, r.ProfileCount, r.ScenarioCount, r.Correctness.CorrectRuns, r.Correctness.ScenarioRuns)
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
