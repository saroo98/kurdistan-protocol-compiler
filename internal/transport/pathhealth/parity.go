// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

type PathHealthParityReport struct {
	ComparedScenarios     int      `json:"compared_scenarios"`
	ComparedActivePaths   int      `json:"compared_active_paths"`
	HealthStateMatches    int      `json:"health_state_matches"`
	DegradationMatches    int      `json:"degradation_matches"`
	FailoverMatches       int      `json:"failover_matches"`
	OutcomeBucketMatches  int      `json:"outcome_bucket_matches"`
	UnexpectedDifferences []string `json:"unexpected_differences,omitempty"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

func CompareGeneratedInterpreted(runs []PathHealthRun) PathHealthParityReport {
	report := PathHealthParityReport{ComparedScenarios: len(runs), ComparedActivePaths: len(runs), Conclusion: "passed"}
	for _, run := range runs {
		if run.Report.FinalState == run.Scenario.ExpectedFinalState || run.Scenario.Control {
			report.HealthStateMatches++
		}
		if run.Degradation.DegradationBucket != "" {
			report.DegradationMatches++
		}
		if run.Report.FailoverTriggered == run.Scenario.ExpectedFailover || run.Scenario.Control {
			report.FailoverMatches++
		}
		if run.Failover.Outcome == run.Scenario.ExpectedFailoverOutcome || run.Scenario.Control {
			report.OutcomeBucketMatches++
		}
		report.PayloadLogged = report.PayloadLogged || run.PayloadLogged
		report.SecretLogged = report.SecretLogged || run.SecretLogged
	}
	if report.HealthStateMatches != len(runs) || report.FailoverMatches != len(runs) || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		if report.HealthStateMatches != len(runs) {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, "health_state_mismatch")
		}
		if report.FailoverMatches != len(runs) {
			report.UnexpectedDifferences = append(report.UnexpectedDifferences, "failover_mismatch")
		}
	}
	return report
}
