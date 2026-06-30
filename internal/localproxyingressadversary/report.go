// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

type Report struct {
	ScenariosRun      int           `json:"scenarios_run"`
	Runs              []ScenarioRun `json:"runs"`
	SuspiciousMetrics []string      `json:"suspicious_metrics,omitempty"`
	Conclusion        string        `json:"conclusion"`
}

func RunAll(runs []ScenarioRun) Report {
	report := Report{ScenariosRun: len(runs), Runs: runs, Conclusion: "passed"}
	for _, run := range runs {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, run.Collapse.SuspiciousMetrics...)
	}
	if len(report.SuspiciousMetrics) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
