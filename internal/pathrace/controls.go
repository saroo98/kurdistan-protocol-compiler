// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import "strings"

type PathRaceMisuseReport struct {
	ScenarioCount            int      `json:"scenario_count"`
	CandidateCount           int      `json:"candidate_count"`
	WinnersDeclared          int      `json:"winners_declared"`
	MisuseFindings           []string `json:"misuse_findings,omitempty"`
	StaleWinsDetected        int      `json:"stale_wins_detected"`
	HighRiskWinsDetected     int      `json:"high_risk_wins_detected"`
	ExperimentalWinsDetected int      `json:"experimental_wins_detected"`
	BurnedWinsDetected       int      `json:"burned_wins_detected"`
	PayloadLogged            bool     `json:"payload_logged"`
	SecretLogged             bool     `json:"secret_logged"`
	Conclusion               string   `json:"conclusion"`
}

func ScanMisuse(runs []PathRaceRun) PathRaceMisuseReport {
	report := PathRaceMisuseReport{ScenarioCount: len(runs), Conclusion: "passed"}
	for _, run := range runs {
		report.CandidateCount += len(run.Candidates)
		if run.Report.WinnerDeclared {
			report.WinnersDeclared++
		}
		if strings.Contains(run.Scenario.ScenarioID, "control_first_candidate") {
			report.MisuseFindings = append(report.MisuseFindings, "always_picks_first_candidate")
		}
		if strings.Contains(run.Scenario.ScenarioID, "control_stale") {
			report.MisuseFindings = append(report.MisuseFindings, "stale_success_beats_fresh_success", "freshness_ttl_ignored")
			report.StaleWinsDetected++
		}
		if strings.Contains(run.Scenario.ScenarioID, "control_high_risk") {
			report.MisuseFindings = append(report.MisuseFindings, "high_risk_candidate_wins_by_default")
			report.HighRiskWinsDetected++
		}
		scoreBuckets := map[string]bool{}
		for _, score := range run.Scores {
			scoreBuckets[score.ScoreBucket] = true
			report.PayloadLogged = report.PayloadLogged || score.PayloadLogged
			report.SecretLogged = report.SecretLogged || score.SecretLogged
		}
		if len(run.Scores) > 1 && len(scoreBuckets) == 1 && run.Scenario.Control {
			report.MisuseFindings = append(report.MisuseFindings, "all_scores_identical")
		}
		for _, candidate := range run.Candidates {
			if candidate.CandidateID == run.Report.WinnerCandidateID {
				if candidate.HighRisk {
					report.HighRiskWinsDetected++
					report.MisuseFindings = append(report.MisuseFindings, "high_risk_candidate_wins_by_default")
				}
				if candidate.Experimental {
					report.ExperimentalWinsDetected++
					report.MisuseFindings = append(report.MisuseFindings, "experimental_candidate_wins_by_default")
				}
				if candidate.RelayRiskBucket == "burned" || candidate.RelayRiskBucket == "critical" {
					report.BurnedWinsDetected++
					report.MisuseFindings = append(report.MisuseFindings, "burned_relay_candidate_wins")
				}
			}
			report.PayloadLogged = report.PayloadLogged || candidate.PayloadLogged
			report.SecretLogged = report.SecretLogged || candidate.SecretLogged
		}
	}
	report.MisuseFindings = uniqueStrings(report.MisuseFindings)
	if len(report.MisuseFindings) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}
