// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapteradversary

import (
	"fmt"
	"sort"
	"strings"

	"kurdistan/internal/adapter"
	ktrace "kurdistan/internal/trace"
)

type ScenarioRun struct {
	ProfileID   string                        `json:"profile_id"`
	Scenario    string                        `json:"scenario"`
	PolicyShape string                        `json:"policy_shape"`
	Correct     bool                          `json:"correct"`
	Failure     string                        `json:"failure,omitempty"`
	Summary     adapter.AdapterHarnessSummary `json:"summary"`
	Checks      ScenarioChecks                `json:"checks"`
	Events      []ktrace.Event                `json:"events,omitempty"`
}

type ScenarioChecks struct {
	FlowMappingCorrect  bool `json:"flow_mapping_correct"`
	BackpressureCorrect bool `json:"backpressure_correct"`
	ResetCorrect        bool `json:"reset_correct"`
	ErrorResetCorrect   bool `json:"error_reset_correct"`
	CapabilityRejected  bool `json:"capability_rejected"`
	MalformedRejected   bool `json:"malformed_rejected"`
	TraceHygiene        bool `json:"trace_hygiene"`
}

type CorrectnessStats struct {
	ScenarioRuns         int `json:"scenario_runs"`
	CorrectRuns          int `json:"correct_runs"`
	MappingFailures      int `json:"mapping_failures"`
	BackpressureFailures int `json:"backpressure_failures"`
	ResetFailures        int `json:"reset_failures"`
	ErrorResetFailures   int `json:"error_reset_failures"`
	CapabilityFailures   int `json:"capability_failures"`
	MalformedFailures    int `json:"malformed_failures"`
	TraceHygieneFailures int `json:"trace_hygiene_failures"`
}

type AdapterCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	AdapterKinds      []string `json:"adapter_kinds"`
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
	Mode            string                  `json:"mode"`
	ProfileCount    int                     `json:"profile_count"`
	ScenarioCount   int                     `json:"scenario_count"`
	AdapterKinds    []string                `json:"adapter_kinds"`
	Correctness     CorrectnessStats        `json:"correctness"`
	CollapseReports []AdapterCollapseReport `json:"collapse_reports"`
	Conclusion      string                  `json:"conclusion"`
}

func DefaultCollapseThresholds() CollapseThresholds {
	return CollapseThresholds{MaxDominantRatio: 0.95, MinDiversityScore: 0.2, MinScenarioSuccess: 0.85}
}

func (r Report) HumanSummary() string {
	return fmt.Sprintf("Adapter adversary: %s (%d profiles, %d scenarios, %d/%d correct)\n", r.Conclusion, r.ProfileCount, r.ScenarioCount, r.Correctness.CorrectRuns, r.Correctness.ScenarioRuns)
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	for _, value := range values {
		if value != "" {
			seen[value] = true
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func joinShape(parts ...string) string {
	return strings.Join(parts, "|")
}
