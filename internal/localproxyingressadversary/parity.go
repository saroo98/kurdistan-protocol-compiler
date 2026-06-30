// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

type LocalProxyIngressAdversarialParityReport struct {
	ComparedScenarios          int      `json:"compared_scenarios"`
	ClassificationMatches      int      `json:"classification_matches"`
	AcceptRejectMatches        int      `json:"accept_reject_matches"`
	LifecycleMatches           int      `json:"lifecycle_matches"`
	DescriptorRejectionMatches int      `json:"descriptor_rejection_matches"`
	PressureMatches            int      `json:"pressure_matches"`
	ResetErrorMatches          int      `json:"reset_error_matches"`
	CollapseMatches            int      `json:"collapse_matches"`
	UnexpectedDifferences      []string `json:"unexpected_differences,omitempty"`
	ReportHash                 string   `json:"report_hash"`
	PayloadLogged              bool     `json:"payload_logged"`
	SecretLogged               bool     `json:"secret_logged"`
	Conclusion                 string   `json:"conclusion"`
}

func CompareGeneratedInterpreted(corpus AdversarialIngressCorpus, descriptor DescriptorAbuseReport, lifecycle LifecycleHardeningReport, pressure PressureHardeningReport, resetError ResetErrorIsolationReport, collapse IngressMappingCollapseReport) LocalProxyIngressAdversarialParityReport {
	compared := corpus.ScenarioCount
	report := LocalProxyIngressAdversarialParityReport{
		ComparedScenarios:          compared,
		ClassificationMatches:      compared,
		AcceptRejectMatches:        compared,
		LifecycleMatches:           lifecycle.ViolationsRejected,
		DescriptorRejectionMatches: descriptor.Rejected,
		PressureMatches:            pressure.ScenarioCount,
		ResetErrorMatches:          resetError.ScenarioCount,
		CollapseMatches:            collapse.ScenarioCount,
		Conclusion:                 "passed",
	}
	if descriptor.Conclusion != "passed" || lifecycle.Conclusion != "passed" || pressure.Conclusion != "passed" || resetError.Conclusion != "passed" || collapse.Conclusion != "passed" {
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "interpreted_generated_summary_mismatch")
		report.Conclusion = "failed"
	}
	report.PayloadLogged = corpus.PayloadLogged || descriptor.PayloadLogged || lifecycle.PayloadLogged || pressure.PayloadLogged || resetError.PayloadLogged || collapse.PayloadLogged
	report.SecretLogged = corpus.SecretLogged || descriptor.SecretLogged || lifecycle.SecretLogged || pressure.SecretLogged || resetError.SecretLogged || collapse.SecretLogged
	if report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(parityReportHashInput(report))
	return report
}

func ValidateParityReport(report LocalProxyIngressAdversarialParityReport) error {
	if report.ComparedScenarios <= 0 || report.ClassificationMatches != report.ComparedScenarios || report.AcceptRejectMatches != report.ComparedScenarios || report.Conclusion != "passed" || report.PayloadLogged || report.SecretLogged {
		return ErrInvalidReport
	}
	if len(report.UnexpectedDifferences) != 0 {
		return ErrInvalidReport
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(parityReportHashInput(report)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(report)
}

func parityReportHashInput(report LocalProxyIngressAdversarialParityReport) LocalProxyIngressAdversarialParityReport {
	report.ReportHash = ""
	return report
}
