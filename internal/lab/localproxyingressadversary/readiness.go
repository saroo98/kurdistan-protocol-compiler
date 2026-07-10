// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

const (
	DecisionGoForLocalProxyEgress = "go_for_local_proxy_egress_model"
	DecisionBlockedDescriptor     = "blocked_descriptor_abuse"
	DecisionBlockedLifecycle      = "blocked_lifecycle_integrity"
	DecisionBlockedPressure       = "blocked_pressure_safety"
	DecisionBlockedResetError     = "blocked_reset_error_isolation"
	DecisionBlockedCollapse       = "blocked_mapping_collapse"
	DecisionBlockedParity         = "blocked_generated_parity"
	DecisionBlockedTraceHygiene   = "blocked_trace_hygiene"
)

type ProxyIngressM27ReadinessReport struct {
	Version                  string   `json:"version"`
	ReviewID                 string   `json:"review_id"`
	CategoriesChecked        int      `json:"categories_checked"`
	BlockingIssues           []string `json:"blocking_issues,omitempty"`
	NonBlockingIssues        []string `json:"non_blocking_issues,omitempty"`
	DescriptorAbusePassed    bool     `json:"descriptor_abuse_passed"`
	LifecycleHardeningPassed bool     `json:"lifecycle_hardening_passed"`
	PressureHardeningPassed  bool     `json:"pressure_hardening_passed"`
	ResetErrorPassed         bool     `json:"reset_error_passed"`
	CollapseResistancePassed bool     `json:"collapse_resistance_passed"`
	ParityPassed             bool     `json:"parity_passed"`
	TraceHygienePassed       bool     `json:"trace_hygiene_passed"`
	GoNoGoDecision           string   `json:"go_no_go_decision"`
	RecommendedNextMilestone string   `json:"recommended_next_milestone"`
	ReportHash               string   `json:"report_hash"`
	PayloadLogged            bool     `json:"payload_logged"`
	SecretLogged             bool     `json:"secret_logged"`
}

func BuildM27ReadinessReport(descriptor DescriptorAbuseReport, lifecycle LifecycleHardeningReport, pressure PressureHardeningReport, resetError ResetErrorIsolationReport, collapse IngressMappingCollapseReport, parity LocalProxyIngressAdversarialParityReport) ProxyIngressM27ReadinessReport {
	report := ProxyIngressM27ReadinessReport{
		Version:                  Version,
		ReviewID:                 "localproxyingress_m27_readiness_v1",
		CategoriesChecked:        10,
		DescriptorAbusePassed:    descriptor.Conclusion == "passed",
		LifecycleHardeningPassed: lifecycle.Conclusion == "passed",
		PressureHardeningPassed:  pressure.Conclusion == "passed",
		ResetErrorPassed:         resetError.Conclusion == "passed",
		CollapseResistancePassed: collapse.Conclusion == "passed",
		ParityPassed:             parity.Conclusion == "passed",
		TraceHygienePassed:       !descriptor.PayloadLogged && !lifecycle.PayloadLogged && !pressure.PayloadLogged && !resetError.PayloadLogged && !collapse.PayloadLogged && !parity.PayloadLogged && !descriptor.SecretLogged && !lifecycle.SecretLogged && !pressure.SecretLogged && !resetError.SecretLogged && !collapse.SecretLogged && !parity.SecretLogged,
		RecommendedNextMilestone: "M27: local proxy egress and relay bridge model",
		GoNoGoDecision:           DecisionGoForLocalProxyEgress,
	}
	switch {
	case !report.DescriptorAbusePassed:
		report.GoNoGoDecision = DecisionBlockedDescriptor
	case !report.LifecycleHardeningPassed:
		report.GoNoGoDecision = DecisionBlockedLifecycle
	case !report.PressureHardeningPassed:
		report.GoNoGoDecision = DecisionBlockedPressure
	case !report.ResetErrorPassed:
		report.GoNoGoDecision = DecisionBlockedResetError
	case !report.CollapseResistancePassed:
		report.GoNoGoDecision = DecisionBlockedCollapse
	case !report.ParityPassed:
		report.GoNoGoDecision = DecisionBlockedParity
	case !report.TraceHygienePassed:
		report.GoNoGoDecision = DecisionBlockedTraceHygiene
	}
	if report.GoNoGoDecision != DecisionGoForLocalProxyEgress {
		report.BlockingIssues = append(report.BlockingIssues, report.GoNoGoDecision)
	}
	report.PayloadLogged = descriptor.PayloadLogged || lifecycle.PayloadLogged || pressure.PayloadLogged || resetError.PayloadLogged || collapse.PayloadLogged || parity.PayloadLogged
	report.SecretLogged = descriptor.SecretLogged || lifecycle.SecretLogged || pressure.SecretLogged || resetError.SecretLogged || collapse.SecretLogged || parity.SecretLogged
	report.ReportHash = HashValue(readinessReportHashInput(report))
	return report
}

func ValidateReadinessReport(report ProxyIngressM27ReadinessReport) error {
	if report.Version != Version || report.ReviewID == "" || report.CategoriesChecked < 10 || report.GoNoGoDecision != DecisionGoForLocalProxyEgress || report.RecommendedNextMilestone == "" || report.PayloadLogged || report.SecretLogged {
		return ErrInvalidReport
	}
	if !report.DescriptorAbusePassed || !report.LifecycleHardeningPassed || !report.PressureHardeningPassed || !report.ResetErrorPassed || !report.CollapseResistancePassed || !report.ParityPassed || !report.TraceHygienePassed {
		return ErrInvalidReport
	}
	if len(report.BlockingIssues) != 0 {
		return ErrInvalidReport
	}
	if report.ReportHash != "" && report.ReportHash != HashValue(readinessReportHashInput(report)) {
		return ErrInvalidReport
	}
	return scanSafeFixture(report)
}

func readinessReportHashInput(report ProxyIngressM27ReadinessReport) ProxyIngressM27ReadinessReport {
	report.ReportHash = ""
	return report
}
