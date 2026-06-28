package streamadversary

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
	BackpressureEvents    int  `json:"backpressure_events"`
	WindowUpdateEvents    int  `json:"window_update_events"`
	SessionBlockedCount   int  `json:"session_blocked_count"`
	ResetCount            int  `json:"reset_count"`
	CloseCount            int  `json:"close_count"`
	OtherStreamsContinued bool `json:"other_streams_continued"`
	WindowUpdateRecovered bool `json:"window_update_recovered"`
	SchedulerCorrect      bool `json:"scheduler_correct"`
	BackpressureCorrect   bool `json:"backpressure_correct"`
	ResetCloseCorrect     bool `json:"reset_close_correct"`
}

type ScenarioRun struct {
	ProfileID string         `json:"profile_id"`
	Scenario  string         `json:"scenario"`
	Correct   bool           `json:"correct"`
	Checks    ScenarioChecks `json:"checks"`
	Events    []ktrace.Event `json:"-"`
}

type StreamFeatureVector struct {
	TraceID  string             `json:"trace_id"`
	Scenario string             `json:"scenario"`
	Features map[string]float64 `json:"features"`
	Buckets  map[string]string  `json:"buckets"`
}

type StreamCollapseReport struct {
	Scenario          string   `json:"scenario"`
	ProfileCount      int      `json:"profile_count"`
	SuspiciousMetrics []string `json:"suspicious_metrics,omitempty"`
	DiversityScore    float64  `json:"diversity_score"`
	Conclusion        string   `json:"conclusion"`
}

type CorrectnessSummary struct {
	ScenarioRuns         int `json:"scenario_runs"`
	CorrectRuns          int `json:"correct_runs"`
	BackpressureFailures int `json:"backpressure_failures"`
	SchedulerFailures    int `json:"scheduler_failures"`
	ResetCloseFailures   int `json:"reset_close_failures"`
	MetadataFailures     int `json:"metadata_failures"`
}

type Report struct {
	Version         string                 `json:"version"`
	Mode            string                 `json:"mode"`
	ProfileCount    int                    `json:"profile_count"`
	ScenarioCount   int                    `json:"scenario_count"`
	Runs            int                    `json:"runs"`
	CollapseReports []StreamCollapseReport `json:"collapse_reports"`
	Correctness     CorrectnessSummary     `json:"correctness"`
	Conclusion      string                 `json:"conclusion"`
}

func DefaultCollapseThresholds() CollapseThresholds {
	return CollapseThresholds{
		MaxDominantRatio:   0.85,
		MinDiversityScore:  0.20,
		MinScenarioSuccess: 0.95,
	}
}

func AnalyzeRuns(runs []ScenarioRun, thresholds CollapseThresholds) Report {
	if thresholds == (CollapseThresholds{}) {
		thresholds = DefaultCollapseThresholds()
	}
	byScenario := map[string][]ScenarioRun{}
	report := Report{Version: "0.9.0-lab", Mode: "streamadversary", Runs: len(runs)}
	profiles := map[string]bool{}
	for _, run := range runs {
		byScenario[run.Scenario] = append(byScenario[run.Scenario], run)
		profiles[run.ProfileID] = true
		report.Correctness.ScenarioRuns++
		if run.Correct {
			report.Correctness.CorrectRuns++
		}
		if !run.Checks.BackpressureCorrect {
			report.Correctness.BackpressureFailures++
		}
		if !run.Checks.SchedulerCorrect {
			report.Correctness.SchedulerFailures++
		}
		if !run.Checks.ResetCloseCorrect {
			report.Correctness.ResetCloseFailures++
		}
		if !eventsHaveStreamMetadata(run.Events) {
			report.Correctness.MetadataFailures++
		}
	}
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(byScenario)
	for scenario, scenarioRuns := range byScenario {
		report.CollapseReports = append(report.CollapseReports, ScanCollapse(scenario, scenarioRuns, thresholds))
	}
	report.Conclusion = "passed"
	if report.Correctness.ScenarioRuns == 0 {
		report.Conclusion = "failed"
	}
	success := 1.0
	if report.Correctness.ScenarioRuns > 0 {
		success = float64(report.Correctness.CorrectRuns) / float64(report.Correctness.ScenarioRuns)
	}
	if success < thresholds.MinScenarioSuccess || report.Correctness.MetadataFailures > 0 {
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
	fmt.Fprintf(&b, "streamadversary %s (%s)\n", r.Version, r.Mode)
	fmt.Fprintf(&b, "profiles: %d\n", r.ProfileCount)
	fmt.Fprintf(&b, "scenarios: %d\n", r.ScenarioCount)
	fmt.Fprintf(&b, "runs: %d\n", r.Runs)
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
