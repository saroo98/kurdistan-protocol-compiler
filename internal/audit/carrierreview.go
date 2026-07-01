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

	"kurdistan/internal/carrierreview"
	"kurdistan/internal/mutant"
)

type CarrierReviewAuditSummary struct {
	Version        string                                      `json:"version"`
	FamilyCount    int                                         `json:"family_count"`
	ReadyFamilies  int                                         `json:"ready_families"`
	GatedFamilies  int                                         `json:"gated_families"`
	ManualFamilies int                                         `json:"manual_families"`
	Decision       string                                      `json:"decision"`
	Comparison     carrierreview.CarrierReviewComparisonReport `json:"comparison"`
	Conclusion     string                                      `json:"conclusion"`
}

func RunCarrierReviewAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	review, err := carrierreview.GenerateReview()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := carrierReviewComparison(filepath.Join(root, "testdata", "carrierreview", "carrierreview-golden.json"), review)
	gates := CarrierReviewGates(review, comparison)
	summary := CarrierReviewAuditSummary{
		Version:        carrierreview.Version,
		FamilyCount:    len(review.Descriptors),
		ReadyFamilies:  review.Readiness.ReadySyntheticFamilies,
		GatedFamilies:  review.Readiness.GatedFamilies,
		ManualFamilies: review.Readiness.ManualReviewFamilies,
		Decision:       review.Readiness.RecommendedNextMilestone,
		Comparison:     comparison,
		Conclusion:     "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "carrierreview-" + cfg.Mode,
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

func CarrierReviewGates(review carrierreview.CarrierFamilyReview, comparison carrierreview.CarrierReviewComparisonReport) []GateResult {
	return []GateResult{
		CarrierReviewFamilyDescriptorGate(review),
		CarrierReviewReadinessMatrixGate(review),
		CarrierReviewRiskGate(review),
		CarrierReviewMisuseDetectionGate(review),
		CarrierReviewGeneratedBackendParityGate(review),
		CarrierReviewTraceHygieneGate(review),
		CarrierReviewMutantDetectionGate(),
		CarrierReviewFixtureDriftGate(comparison),
	}
}

func CarrierReviewFamilyDescriptorGate(review carrierreview.CarrierFamilyReview) GateResult {
	failures := []string{}
	if err := carrierreview.ValidateReview(review); err != nil {
		failures = append(failures, err.Error())
	}
	if len(review.Descriptors) < 5 {
		failures = append(failures, "missing carrier family descriptors")
	}
	return gate("carrierreview_family_descriptors", len(failures) == 0, "required", fmt.Sprintf("%d carrier families reviewed", len(review.Descriptors)), nil, failures)
}

func CarrierReviewReadinessMatrixGate(review carrierreview.CarrierFamilyReview) GateResult {
	failures := []string{}
	for _, layer := range []string{"adaptivepath", "transportbundle", "pathrace", "pathhealth", "relayfleet", "hostdetect", "security", "hardening", "generated_backend_parity"} {
		if review.Matrix.Layers[layer] == "" {
			failures = append(failures, "missing matrix layer "+layer)
		}
	}
	if review.Readiness.Conclusion != "passed" {
		failures = append(failures, review.Readiness.BlockingIssues...)
	}
	return gate("carrierreview_readiness_matrix", len(failures) == 0, "required", fmt.Sprintf("%d matrix layers checked", len(review.Matrix.Layers)), nil, failures)
}

func CarrierReviewRiskGate(review carrierreview.CarrierFamilyReview) GateResult {
	failures := []string{}
	manual := 0
	gated := 0
	for _, desc := range review.Descriptors {
		if desc.ManualReviewRequired {
			manual++
		}
		if desc.Readiness == carrierreview.ReadinessGatedSurvival || desc.Readiness == carrierreview.ReadinessExperimentalGated {
			gated++
		}
		if desc.Family == carrierreview.FamilyDomesticMediaRisk && desc.DefaultEligible {
			failures = append(failures, "domestic/media family default eligible")
		}
	}
	if manual == 0 || gated == 0 {
		failures = append(failures, "manual and gated review families not represented")
	}
	return gate("carrierreview_risk_gating", len(failures) == 0, "required", fmt.Sprintf("%d manual and %d gated families", manual, gated), nil, failures)
}

func CarrierReviewMisuseDetectionGate(review carrierreview.CarrierFamilyReview) GateResult {
	failures := []string{}
	unsafe := carrierreview.DefaultDescriptors()
	for i := range unsafe {
		if unsafe[i].Family == carrierreview.FamilyDomesticMediaRisk {
			unsafe[i].DefaultEligible = true
		}
	}
	if carrierreview.ScanMisuse(unsafe).Conclusion != "failed" {
		failures = append(failures, "unsafe domestic default not detected")
	}
	if review.Misuse.Conclusion != "passed" {
		failures = append(failures, review.Misuse.SuspiciousMetrics...)
	}
	return gate("carrierreview_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d descriptors scanned", review.Misuse.DescriptorsChecked), nil, failures)
}

func CarrierReviewGeneratedBackendParityGate(review carrierreview.CarrierFamilyReview) GateResult {
	failures := []string{}
	if review.Parity.Conclusion != "passed" {
		failures = append(failures, review.Parity.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"carrierreview_generated.go", "carrierreview_test.go", "carrierreview_parity_test.go", "carrierreview_hygiene_test.go", "CarrierReviewSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated carrierreview marker "+marker)
				}
			}
		}
	}
	return gate("carrierreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d families compared", review.Parity.ComparedFamilies), nil, failures)
}

func CarrierReviewTraceHygieneGate(review carrierreview.CarrierFamilyReview) GateResult {
	failures := []string{}
	if err := carrierreview.ScanForLeak(review); err != nil {
		failures = append(failures, err.Error())
	}
	for _, unsafe := range []map[string]string{{"endpoint": "x"}, {"dns_query": "x"}, {"resolver_ip": "x"}, {"payload": "x"}, {"secret": "x"}, {"claim": "guaranteed bypass"}} {
		if err := carrierreview.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe carrier review metadata accepted")
		}
	}
	return gate("carrierreview_trace_hygiene", len(failures) == 0, "required", "carrier review fixtures contain safe metadata only", nil, failures)
}

func CarrierReviewMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeCarrierReviewClaimsGuaranteedBypass,
		mutant.ModeCarrierReviewClaimsUndetectable,
		mutant.ModeCarrierReviewFieldReadyCarrier,
		mutant.ModeCarrierReviewRealTLSClaim,
		mutant.ModeCarrierReviewResolverQueryClaim,
		mutant.ModeCarrierReviewQUICCompatibilityClaim,
		mutant.ModeCarrierReviewDomesticDefault,
		mutant.ModeCarrierReviewHighRiskUngated,
		mutant.ModeCarrierReviewExperimentalUngated,
		mutant.ModeCarrierReviewRelayEndpointLeak,
		mutant.ModeCarrierReviewMissingTracePrecondition,
		mutant.ModeCarrierReviewGoDespiteBlocker,
		mutant.ModeCarrierReviewPayloadLeak,
		mutant.ModeCarrierReviewSecretLeak,
		mutant.ModeCarrierReviewGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("carrierreview_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d carrierreview mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func CarrierReviewFixtureDriftGate(report carrierreview.CarrierReviewComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("carrierreview_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func carrierReviewComparison(path string, current carrierreview.CarrierFamilyReview) carrierreview.CarrierReviewComparisonReport {
	oldReview, err := carrierreview.LoadReview(path)
	if err != nil {
		return carrierreview.CarrierReviewComparisonReport{Version: carrierreview.Version, NewHash: current.ReviewHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return carrierreview.CompareReviews(oldReview, current)
}
