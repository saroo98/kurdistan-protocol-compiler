// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

func BuildLocalDiagnosticReport(fields []ObservationField, policy MeasurementPrivacyPolicy) LocalDiagnosticReport {
	counts := map[string]int{}
	for _, field := range fields {
		counts[field.RedactionClass]++
	}
	report := LocalDiagnosticReport{
		Version:          Version,
		ReportID:         "measurement_local_diagnostics_v1",
		ObservationCount: len(fields),
		FieldCount:       len(fields),
		BucketCounts:     counts,
		ConsentMode:      policy.ConsentMode,
		RetentionClass:   policy.RetentionClass,
		LocalOnly:        policy.LocalDiagnosticsOnly,
		Conclusion:       "passed",
		PayloadLogged:    false,
		SecretLogged:     false,
	}
	if !policy.LocalDiagnosticsOnly || policy.BackgroundCollection || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	report.ReportHash = HashValue(reportHashInput(report))
	return report
}

func reportHashInput(report LocalDiagnosticReport) LocalDiagnosticReport {
	report.ReportHash = ""
	return report
}
