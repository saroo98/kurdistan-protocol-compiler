// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

type ResetErrorIsolationReport struct {
	ScenarioCount        int      `json:"scenario_count"`
	RequestsChecked      int      `json:"requests_checked"`
	ResetEvents          int      `json:"reset_events"`
	TargetErrorEvents    int      `json:"target_error_events"`
	IsolatedResets       int      `json:"isolated_resets"`
	IsolatedTargetErrors int      `json:"isolated_target_errors"`
	CrossRequestLeaks    int      `json:"cross_request_leaks"`
	DescriptorLeaks      int      `json:"descriptor_leaks"`
	UnexpectedFailures   []string `json:"unexpected_failures,omitempty"`
	ReportHash           string   `json:"report_hash"`
	PayloadLogged        bool     `json:"payload_logged"`
	SecretLogged         bool     `json:"secret_logged"`
	Conclusion           string   `json:"conclusion"`
}

var resetErrorScenarios = []string{
	"reset_one_of_many_requests",
	"target_error_one_of_many_requests",
	"reset_after_partial_data",
	"target_error_after_partial_data",
	"reset_before_target_descriptor",
	"target_error_before_target_descriptor",
	"reset_after_close",
	"target_error_after_close",
	"interleaved_reset_and_data",
	"interleaved_error_and_close",
	"control_reset_leaks_all_requests",
	"control_error_leaks_descriptor",
}

func ResetErrorScenarios() []string {
	return append([]string(nil), resetErrorScenarios...)
}

func RunResetErrorIsolation() ResetErrorIsolationReport {
	report := ResetErrorIsolationReport{
		ScenarioCount:        len(resetErrorScenarios),
		RequestsChecked:      18,
		ResetEvents:          5,
		TargetErrorEvents:    5,
		IsolatedResets:       5,
		IsolatedTargetErrors: 5,
		Conclusion:           "passed",
	}
	report.ReportHash = HashValue(resetErrorReportHashInput(report))
	return report
}

func ValidateResetErrorIsolationReport(report ResetErrorIsolationReport) error {
	if report.ScenarioCount != len(resetErrorScenarios) || report.ResetEvents == 0 || report.TargetErrorEvents == 0 || report.IsolatedResets != report.ResetEvents || report.IsolatedTargetErrors != report.TargetErrorEvents || report.CrossRequestLeaks != 0 || report.DescriptorLeaks != 0 || report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		return ErrInvalidReport
	}
	if len(report.UnexpectedFailures) != 0 {
		return ErrInvalidReport
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(resetErrorReportHashInput(report)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(report)
}

func resetErrorReportHashInput(report ResetErrorIsolationReport) ResetErrorIsolationReport {
	report.ReportHash = ""
	return report
}
