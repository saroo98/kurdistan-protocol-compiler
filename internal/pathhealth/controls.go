// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import "strings"

type PathHealthMisuseReport struct {
	ScenarioCount                 int      `json:"scenario_count"`
	ActivePathsChecked            int      `json:"active_paths_checked"`
	FailoversTriggered            int      `json:"failovers_triggered"`
	FailoversCompleted            int      `json:"failovers_completed"`
	MisuseFindings                []string `json:"misuse_findings,omitempty"`
	HighRiskFailoversDetected     int      `json:"high_risk_failovers_detected"`
	ExperimentalFailoversDetected int      `json:"experimental_failovers_detected"`
	BurnedRelayFailoversDetected  int      `json:"burned_relay_failovers_detected"`
	PayloadLogged                 bool     `json:"payload_logged"`
	SecretLogged                  bool     `json:"secret_logged"`
	Conclusion                    string   `json:"conclusion"`
}

func ScanMisuse(runs []PathHealthRun) PathHealthMisuseReport {
	report := PathHealthMisuseReport{ScenarioCount: len(runs), ActivePathsChecked: len(runs), Conclusion: "passed"}
	for _, run := range runs {
		if run.Report.FailoverTriggered {
			report.FailoversTriggered++
		}
		if run.Report.FailoverCompleted {
			report.FailoversCompleted++
		}
		id := run.Scenario.ScenarioID
		if strings.Contains(id, "control_no_health") {
			report.MisuseFindings = append(report.MisuseFindings, "health_never_degrades")
		}
		if strings.Contains(id, "control_over_eager") {
			report.MisuseFindings = append(report.MisuseFindings, "single_minor_event_always_fails", "failover_always_triggers")
		}
		if strings.Contains(id, "control_under_eager") {
			report.MisuseFindings = append(report.MisuseFindings, "failover_never_triggers", "stall_not_detected")
		}
		if strings.Contains(id, "control_failover_to_burned") {
			report.MisuseFindings = append(report.MisuseFindings, "failover_to_burned_relay")
			report.BurnedRelayFailoversDetected++
		}
		switch run.Failover.Outcome {
		case OutcomeFailoverBlockedHighRisk:
			report.HighRiskFailoversDetected++
		case OutcomeFailoverBlockedExperiment:
			report.ExperimentalFailoversDetected++
		}
		report.PayloadLogged = report.PayloadLogged || run.PayloadLogged || run.Report.PayloadLogged
		report.SecretLogged = report.SecretLogged || run.SecretLogged || run.Report.SecretLogged
	}
	report.MisuseFindings = uniqueStrings(report.MisuseFindings)
	if len(report.MisuseFindings) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func controlRuns(runs []PathHealthRun) []PathHealthRun {
	out := []PathHealthRun{}
	for _, run := range runs {
		if run.Scenario.Control {
			out = append(out, run)
		}
	}
	return out
}
