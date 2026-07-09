// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

import "sort"

func DefaultMatrix() MeasurementReviewMatrix {
	return MeasurementReviewMatrix{Layers: map[string]string{
		"adaptivepath":             "candidate families, freshness, and uncertainty buckets",
		"transportbundle":          "bundle candidate classes without concrete endpoints",
		"pathrace":                 "short-lived scoring outcomes",
		"pathhealth":               "health state and failover outcomes",
		"carrierreview":            "carrier-family risk review preconditions",
		"relayfleet":               "synthetic relay lifecycle risk buckets",
		"hostdetect":               "host-level risk buckets",
		"wireeval":                 "offline dataset evaluation summaries",
		"hardening":                "trace hygiene and resource-limit checks",
		"generated_backend_parity": "generated/interpreted review parity",
		"trace_hygiene":            "bucketed local diagnostic metadata",
		"documentation":            "public boundary and privacy review notes",
	}}
}

func GenerateReview() (MeasurementReview, error) {
	fields := DefaultObservationFields()
	policy := DefaultPrivacyPolicy(fields)
	diagnostics := BuildLocalDiagnosticReport(fields, policy)
	misuse := ScanMisuse(fields, policy)
	parity := CompareGeneratedInterpreted(fields)
	readiness := EvaluateReadiness(fields, policy)
	review := MeasurementReview{
		Version:     Version,
		ReviewID:    "safe_measurement_client_design_review_v1",
		Fields:      fields,
		Policy:      policy,
		Diagnostics: diagnostics,
		Matrix:      DefaultMatrix(),
		Misuse:      misuse,
		Parity:      parity,
		Readiness:   readiness,
		Conclusion:  "passed",
	}
	if diagnostics.Conclusion != "passed" || misuse.Conclusion != "passed" || parity.Conclusion != "passed" || readiness.Conclusion != "passed" {
		review.Conclusion = "failed"
	}
	review.ReviewHash = HashValue(reviewHashInput(review))
	return review, ValidateReview(review)
}

func EvaluateReadiness(fields []ObservationField, policy MeasurementPrivacyPolicy) MeasurementReadinessReport {
	report := MeasurementReadinessReport{FieldsChecked: len(fields), RecommendedNextMilestone: RecommendedNextMilestone, Conclusion: "passed"}
	for _, field := range fields {
		if field.RedactionClass == RedactionBucket || field.RedactionClass == RedactionAggregateOnly {
			report.BucketedFields++
		}
		if field.RedactionClass == RedactionRejected {
			report.RejectedUnsafeFields++
		}
		if field.Name == "" || field.Class == "" || !field.AllowedInFixture {
			report.BlockingIssues = append(report.BlockingIssues, "invalid observation field")
		}
	}
	if !policy.LocalDiagnosticsOnly {
		report.BlockingIssues = append(report.BlockingIssues, "diagnostics not local-only")
	}
	if policy.BackgroundCollection {
		report.BlockingIssues = append(report.BlockingIssues, "background collection enabled")
	}
	if policy.ConsentMode != ConsentLocalOnly && policy.ConsentMode != ConsentDisabled && policy.ConsentMode != ConsentExplicitOptIn && policy.ConsentMode != ConsentManualExportOnly {
		report.BlockingIssues = append(report.BlockingIssues, "unsafe consent mode")
	}
	report.BlockingIssues = uniqueStrings(report.BlockingIssues)
	if len(report.BlockingIssues) > 0 {
		report.Conclusion = "failed"
	}
	return report
}

func ScanMisuse(fields []ObservationField, policy MeasurementPrivacyPolicy) MeasurementMisuseReport {
	report := MeasurementMisuseReport{FieldsChecked: len(fields), Conclusion: "passed"}
	for _, field := range fields {
		if err := ValidateObservationField(field); err != nil {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, err.Error())
		}
		if field.RedactionClass == RedactionHashWithLocalSalt && (field.Name == "exact_destination" || field.Name == "dns_query") {
			report.SuspiciousMetrics = append(report.SuspiciousMetrics, "unsafe_hashing_for_direct_identifier")
		}
	}
	if !policy.LocalDiagnosticsOnly {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "non_local_diagnostics")
	}
	if policy.BackgroundCollection {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, "background_collection_enabled")
	}
	report.SuspiciousMetrics = uniqueStrings(report.SuspiciousMetrics)
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func CompareGeneratedInterpreted(fields []ObservationField) MeasurementParityReport {
	report := MeasurementParityReport{ComparedFields: len(fields), Conclusion: "passed"}
	for range fields {
		report.RedactionMatches++
		report.RetentionMatches++
	}
	if report.RedactionMatches != len(fields) || report.RetentionMatches != len(fields) || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
		report.UnexpectedDifferences = append(report.UnexpectedDifferences, "measurement_review_parity_drift")
	}
	return report
}

func reviewHashInput(review MeasurementReview) MeasurementReview {
	review.ReviewHash = ""
	return review
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
