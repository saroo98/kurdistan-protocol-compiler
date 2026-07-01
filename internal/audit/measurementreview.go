// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/measurementreview"
	"kurdistan/internal/mutant"
)

type MeasurementReviewAuditSummary struct {
	Version     string                                              `json:"version"`
	FieldCount  int                                                 `json:"field_count"`
	ConsentMode string                                              `json:"consent_mode"`
	Retention   string                                              `json:"retention"`
	Decision    string                                              `json:"decision"`
	Comparison  measurementreview.MeasurementReviewComparisonReport `json:"comparison"`
	Conclusion  string                                              `json:"conclusion"`
}

func RunMeasurementReviewAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	review, err := measurementreview.GenerateReview()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := measurementReviewComparison(filepath.Join(root, "testdata", "measurementreview", "measurementreview-golden.json"), review)
	gates := MeasurementReviewGates(review, comparison)
	summary := MeasurementReviewAuditSummary{
		Version:     measurementreview.Version,
		FieldCount:  len(review.Fields),
		ConsentMode: review.Policy.ConsentMode,
		Retention:   review.Policy.RetentionClass,
		Decision:    review.Readiness.RecommendedNextMilestone,
		Comparison:  comparison,
		Conclusion:  "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "measurementreview-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: summary,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
		summary.Conclusion = "failed"
		report.TraceScanSummary = summary
	}
	return report, nil
}

func MeasurementReviewGates(review measurementreview.MeasurementReview, comparison measurementreview.MeasurementReviewComparisonReport) []GateResult {
	return []GateResult{
		MeasurementReviewObservationSchemaGate(review),
		MeasurementReviewRedactionPolicyGate(review),
		MeasurementReviewConsentRetentionGate(review),
		MeasurementReviewLocalDiagnosticsGate(review),
		MeasurementReviewPrivacyReadinessGate(review),
		MeasurementReviewMisuseDetectionGate(review),
		MeasurementReviewGeneratedBackendParityGate(review),
		MeasurementReviewTraceHygieneGate(review),
		MeasurementReviewMutantDetectionGate(),
		MeasurementReviewFixtureDriftGate(comparison),
	}
}

func MeasurementReviewObservationSchemaGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if err := measurementreview.ValidateReview(review); err != nil {
		failures = append(failures, err.Error())
	}
	if len(review.Fields) < 18 {
		failures = append(failures, "missing observation taxonomy fields")
	}
	return gate("measurementreview_observation_schema", len(failures) == 0, "required", fmt.Sprintf("%d observation fields checked", len(review.Fields)), nil, failures)
}

func MeasurementReviewRedactionPolicyGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	bucketed := 0
	for _, field := range review.Fields {
		if field.RedactionClass == measurementreview.RedactionBucket || field.RedactionClass == measurementreview.RedactionAggregateOnly {
			bucketed++
		}
		if field.RedactionClass == measurementreview.RedactionHashWithLocalSalt && !measurementreview.RequiresManualReview(field) {
			failures = append(failures, "hash redaction without manual review class")
		}
	}
	if bucketed < len(review.Fields) {
		failures = append(failures, "non-bucketed safe observation field")
	}
	return gate("measurementreview_redaction_policy", len(failures) == 0, "required", fmt.Sprintf("%d bucketed fields", bucketed), nil, failures)
}

func MeasurementReviewConsentRetentionGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if !measurementreview.ConsentModeIsSafeDefault(review.Policy.ConsentMode) {
		failures = append(failures, "unsafe default consent mode")
	}
	if !measurementreview.RetentionIsBounded(review.Policy.RetentionClass) {
		failures = append(failures, "unbounded retention")
	}
	if review.Policy.BackgroundCollection {
		failures = append(failures, "background collection enabled")
	}
	return gate("measurementreview_consent_retention", len(failures) == 0, "required", review.Policy.ConsentMode+"/"+review.Policy.RetentionClass, nil, failures)
}

func MeasurementReviewLocalDiagnosticsGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if !measurementreview.LocalReportIsTraceSafe(review.Diagnostics) {
		failures = append(failures, "local diagnostic report not trace safe")
	}
	return gate("measurementreview_local_diagnostics", len(failures) == 0, "required", fmt.Sprintf("%d diagnostic fields", review.Diagnostics.FieldCount), nil, failures)
}

func MeasurementReviewPrivacyReadinessGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if !measurementreview.ReadyForLocalSyntheticDiagnostics(review.Readiness) {
		failures = append(failures, review.Readiness.BlockingIssues...)
	}
	for _, layer := range []string{"adaptivepath", "transportbundle", "pathrace", "pathhealth", "carrierreview", "wireeval", "hardening", "generated_backend_parity"} {
		if review.Matrix.Layers[layer] == "" {
			failures = append(failures, "missing matrix layer "+layer)
		}
	}
	return gate("measurementreview_privacy_readiness", len(failures) == 0, "required", review.Readiness.RecommendedNextMilestone, nil, failures)
}

func MeasurementReviewMisuseDetectionGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if review.Misuse.Conclusion != "passed" {
		failures = append(failures, review.Misuse.SuspiciousMetrics...)
	}
	controlReport := measurementreview.ScanMisuse(measurementreview.UnsafeControlFields(), review.Policy)
	if controlReport.Conclusion != "failed" {
		failures = append(failures, "unsafe observation controls not detected")
	}
	if err := measurementreview.ScanForLeak(map[string]string{"dns_query": "x"}); err == nil {
		failures = append(failures, "direct diagnostic field accepted")
	}
	return gate("measurementreview_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d fields scanned", review.Misuse.FieldsChecked), nil, failures)
}

func MeasurementReviewGeneratedBackendParityGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if review.Parity.Conclusion != "passed" {
		failures = append(failures, review.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"measurementreview_generated.go", "measurementreview_test.go", "measurementreview_parity_test.go", "measurementreview_hygiene_test.go", "MeasurementReviewSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated measurementreview marker "+marker)
				}
			}
		}
	}
	return gate("measurementreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d fields compared", review.Parity.ComparedFields), nil, failures)
}

func MeasurementReviewTraceHygieneGate(review measurementreview.MeasurementReview) GateResult {
	failures := []string{}
	if err := measurementreview.ScanForLeak(review); err != nil {
		failures = append(failures, err.Error())
	}
	for _, unsafe := range []map[string]string{{"raw_payload": "x"}, {"raw_packet": "x"}, {"dns_query": "x"}, {"resolver_ip": "x"}, {"client_ip": "x"}, {"precise_location": "x"}, {"telemetry_upload": "enabled"}, {"claim": "undetectable"}} {
		if err := measurementreview.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe measurement metadata accepted")
		}
	}
	return gate("measurementreview_trace_hygiene", len(failures) == 0, "required", "measurement review fixtures contain safe metadata only", nil, failures)
}

func MeasurementReviewMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeMeasurementReviewAllowsRawPayload,
		mutant.ModeMeasurementReviewAllowsEndpointData,
		mutant.ModeMeasurementReviewAllowsDNSQuery,
		mutant.ModeMeasurementReviewAllowsResolverIP,
		mutant.ModeMeasurementReviewAllowsLocation,
		mutant.ModeMeasurementReviewAllowsPhoneSIMDevice,
		mutant.ModeMeasurementReviewUploadsWithoutOptIn,
		mutant.ModeMeasurementReviewBackgroundMeasurement,
		mutant.ModeMeasurementReviewUnboundedRetention,
		mutant.ModeMeasurementReviewHashesEndpoint,
		mutant.ModeMeasurementReviewExportWithoutRedaction,
		mutant.ModeMeasurementReviewDomesticNotManual,
		mutant.ModeMeasurementReviewPayloadLeak,
		mutant.ModeMeasurementReviewSecretLeak,
		mutant.ModeMeasurementReviewGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("measurementreview_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d measurementreview mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func MeasurementReviewFixtureDriftGate(report measurementreview.MeasurementReviewComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("measurementreview_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func measurementReviewComparison(path string, current measurementreview.MeasurementReview) measurementreview.MeasurementReviewComparisonReport {
	oldReview, err := measurementreview.LoadReview(path)
	if err != nil {
		return measurementreview.MeasurementReviewComparisonReport{Version: measurementreview.Version, NewHash: current.ReviewHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return measurementreview.CompareReviews(oldReview, current)
}
