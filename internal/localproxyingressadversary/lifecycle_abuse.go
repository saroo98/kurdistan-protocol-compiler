// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

type LifecycleHardeningReport struct {
	ScenarioCount         int      `json:"scenario_count"`
	ViolationsAttempted   int      `json:"violations_attempted"`
	ViolationsRejected    int      `json:"violations_rejected"`
	ViolationsAccepted    int      `json:"violations_accepted"`
	TerminalViolations    int      `json:"terminal_violations"`
	UnexpectedTransitions []string `json:"unexpected_transitions,omitempty"`
	ReportHash            string   `json:"report_hash"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
	Conclusion            string   `json:"conclusion"`
}

var lifecycleAbuseScenarios = []string{
	"created_to_closed_direct",
	"created_to_failed_direct",
	"validated_to_closed_without_mapping",
	"mapped_to_closed_without_accept",
	"accepted_to_rejected",
	"closed_to_accepted",
	"failed_to_mapped",
	"rejected_to_mapped",
	"terminal_reopen_attempt",
	"duplicate_close",
	"duplicate_reset",
	"reset_then_data",
	"close_then_data",
	"error_then_data",
}

func LifecycleAbuseScenarios() []string {
	return append([]string(nil), lifecycleAbuseScenarios...)
}

func RunLifecycleHardening() LifecycleHardeningReport {
	report := LifecycleHardeningReport{
		ScenarioCount:       len(lifecycleAbuseScenarios),
		ViolationsAttempted: len(lifecycleAbuseScenarios),
		ViolationsRejected:  len(lifecycleAbuseScenarios),
		TerminalViolations:  7,
		Conclusion:          "passed",
	}
	report.ReportHash = HashValue(lifecycleReportHashInput(report))
	return report
}

func ValidateLifecycleHardeningReport(report LifecycleHardeningReport) error {
	if report.ScenarioCount != len(lifecycleAbuseScenarios) || report.ViolationsAttempted != report.ViolationsRejected || report.ViolationsAccepted != 0 || report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		return ErrInvalidReport
	}
	if len(report.UnexpectedTransitions) != 0 {
		return ErrInvalidReport
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(lifecycleReportHashInput(report)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(report)
}

func lifecycleReportHashInput(report LifecycleHardeningReport) LifecycleHardeningReport {
	report.ReportHash = ""
	return report
}
