// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/contracts/carrier/carriercollapse"
	"kurdistan/internal/mutant"
)

func RunCarrierCollapseAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := carriercollapse.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := carrierCollapseComparison(filepath.Join(root, "testdata", "carriercollapse", "carriercollapse-report-golden.json"), set)
	gates := CarrierCollapseGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "carriercollapse-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		Gates:            gates,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func CarrierCollapseGates(set carriercollapse.FixtureSet, comparison carriercollapse.FixtureComparisonReport) []GateResult {
	return []GateResult{
		CarrierCollapseFamilyDiversityGate(set),
		CarrierCollapseShapeDiversityGate(set),
		CarrierCollapseProfileSensitivityGate(set),
		CarrierCollapseBundleSensitivityGate(set),
		CarrierCollapsePathRaceGate(set),
		CarrierCollapsePathHealthGate(set),
		CarrierCollapseMeasurementReviewGate(set),
		CarrierCollapseCarrierReviewGate(set),
		CarrierCollapseLabEgressGate(set),
		CarrierCollapseFallbackSafetyGate(set),
		CarrierCollapseRuntimeSecurityGate(set),
		CarrierCollapseStreamIsolationGate(set),
		CarrierCollapseBackpressureGate(set),
		CarrierCollapseResetGate(set),
		CarrierCollapseGeneratedParityGate(set),
		CarrierCollapseTraceHygieneGate(set),
		CarrierCollapsePublicClaimGate(set),
		CarrierCollapseMutantDetectionGate(),
		CarrierCollapseFixtureDriftGate(comparison),
	}
}

func CarrierCollapseFamilyDiversityGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.Diversity.CarrierFamilies) < 3 || set.Report.Diversity.DiversityScore < 0.75 {
		failures = append(failures, "carrier family diversity insufficient")
	}
	return gate("carriercollapse_family_diversity", len(failures) == 0, "required", fmt.Sprintf("%d carrier families", len(set.Report.Diversity.CarrierFamilies)), nil, failures)
}

func CarrierCollapseShapeDiversityGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.Diversity.ShapeHashCount < 4 || len(set.Report.Diversity.ShapeClasses) < 4 {
		failures = append(failures, "shape diversity insufficient")
	}
	return gate("carriercollapse_shape_diversity", len(failures) == 0, "required", fmt.Sprintf("%d shape classes", len(set.Report.Diversity.ShapeClasses)), nil, failures)
}

func CarrierCollapseProfileSensitivityGate(set carriercollapse.FixtureSet) GateResult {
	s := set.Report.SelectionCollapse
	failures := []string{}
	if !s.ProfileSensitive || s.ProfileHashCount < 5 {
		failures = append(failures, "profile sensitivity insufficient")
	}
	return gate("carriercollapse_profile_sensitivity", len(failures) == 0, "required", fmt.Sprintf("%d profile hashes", s.ProfileHashCount), nil, failures)
}

func CarrierCollapseBundleSensitivityGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if !set.Report.SelectionCollapse.BundleSensitive {
		failures = append(failures, "transport bundle sensitivity missing")
	}
	return gate("carriercollapse_bundle_sensitivity", len(failures) == 0, "required", "transport bundle sensitivity checked", nil, failures)
}

func CarrierCollapsePathRaceGate(set carriercollapse.FixtureSet) GateResult {
	return enforcementGate("carriercollapse_pathrace_enforcement", set.Report.PathRace)
}

func CarrierCollapsePathHealthGate(set carriercollapse.FixtureSet) GateResult {
	return enforcementGate("carriercollapse_pathhealth_enforcement", set.Report.PathHealth)
}

func CarrierCollapseMeasurementReviewGate(set carriercollapse.FixtureSet) GateResult {
	return enforcementGate("carriercollapse_measurementreview_enforcement", set.Report.MeasurementReview)
}

func CarrierCollapseCarrierReviewGate(set carriercollapse.FixtureSet) GateResult {
	return enforcementGate("carriercollapse_carrierreview_enforcement", set.Report.CarrierReview)
}

func CarrierCollapseLabEgressGate(set carriercollapse.FixtureSet) GateResult {
	return enforcementGate("carriercollapse_labegress_enforcement", set.Report.LabEgress)
}

func enforcementGate(name string, report carriercollapse.EnforcementReport) GateResult {
	failures := []string{}
	if !report.Checked || !report.Enforced || report.BypassesRejected == 0 {
		failures = append(failures, report.Name+" enforcement incomplete")
	}
	return gate(name, len(failures) == 0, "required", fmt.Sprintf("%s bypasses rejected=%d", report.Name, report.BypassesRejected), nil, failures)
}

func CarrierCollapseFallbackSafetyGate(set carriercollapse.FixtureSet) GateResult {
	f := set.Report.FallbackSafety
	failures := []string{}
	if !f.UnsafeFallbackRejected || !f.HighRiskDefaultRejected || !f.PublicNetworkRejected || len(f.BlockedClasses) < 3 {
		failures = append(failures, "fallback safety incomplete")
	}
	return gate("carriercollapse_fallback_safety", len(failures) == 0, "required", fmt.Sprintf("%d fallback classes blocked", len(f.BlockedClasses)), nil, failures)
}

func CarrierCollapseRuntimeSecurityGate(set carriercollapse.FixtureSet) GateResult {
	r := set.Report.RuntimeSafety
	failures := []string{}
	if !r.RuntimeSecurityMetadataConsistent {
		failures = append(failures, "runtime/security metadata mismatch")
	}
	return gate("carriercollapse_runtime_security_metadata", len(failures) == 0, "required", "runtime/security metadata consistent", nil, failures)
}

func CarrierCollapseStreamIsolationGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if !set.Report.RuntimeSafety.StreamIsolationPreserved {
		failures = append(failures, "stream isolation not preserved")
	}
	return gate("carriercollapse_stream_isolation", len(failures) == 0, "required", "stream isolation preserved", nil, failures)
}

func CarrierCollapseBackpressureGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if !set.Report.RuntimeSafety.BackpressureVisible {
		failures = append(failures, "backpressure visibility missing")
	}
	return gate("carriercollapse_backpressure_visibility", len(failures) == 0, "required", "backpressure visible", nil, failures)
}

func CarrierCollapseResetGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if !set.Report.RuntimeSafety.ResetPropagated {
		failures = append(failures, "reset propagation missing")
	}
	return gate("carriercollapse_reset_propagation", len(failures) == 0, "required", "reset propagation checked", nil, failures)
}

func CarrierCollapseGeneratedParityGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	p := set.Report.Parity
	if p.Conclusion != "passed" || p.SemanticMatches != p.ComparedFamilies || len(p.UnexpectedDifferences) > 0 || p.PayloadLogged || p.SecretLogged {
		failures = append(failures, "generated/interpreted carrier collapse parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			source := string(raw)
			for _, marker := range p.GeneratedMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated carrier collapse marker "+marker)
				}
			}
		}
	}
	return gate("carriercollapse_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(p.GeneratedMarkers)), nil, failures)
}

func CarrierCollapseTraceHygieneGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.TraceHygiene.Conclusion != "passed" || set.Report.TraceHygiene.PayloadLogged || set.Report.TraceHygiene.SecretLogged || set.PayloadLogged || set.SecretLogged {
		failures = append(failures, "trace hygiene report failed")
	}
	if err := carriercollapse.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("carriercollapse_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d fixtures scanned", set.Report.TraceHygiene.FixturesScanned), nil, failures)
}

func CarrierCollapsePublicClaimGate(set carriercollapse.FixtureSet) GateResult {
	failures := []string{}
	if !set.Report.PublicClaims.ClaimSafetyPassed || len(set.Report.PublicClaims.UnsafeClaimsFound) > 0 {
		failures = append(failures, "public claim safety failed")
	}
	return gate("carriercollapse_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.Report.PublicClaims.DocsChecked), nil, failures)
}

func CarrierCollapseMutantDetectionGate() GateResult {
	required := carriercollapse.RequiredMutationNames()
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	failures := []string{}
	for _, name := range required {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	return gate("carriercollapse_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d carrier collapse mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func CarrierCollapseFixtureDriftGate(comparison carriercollapse.FixtureComparisonReport) GateResult {
	failures := []string{}
	if comparison.Conclusion != "passed" || len(comparison.UnexpectedDrift) > 0 || comparison.PayloadLogged || comparison.SecretLogged {
		failures = append(failures, "carrier collapse fixture drift detected")
		failures = append(failures, comparison.UnexpectedDrift...)
	}
	return gate("carriercollapse_fixture_drift", len(failures) == 0, "required", comparison.Conclusion, nil, failures)
}

func carrierCollapseComparison(path string, current carriercollapse.FixtureSet) carriercollapse.FixtureComparisonReport {
	oldSet, err := carriercollapse.LoadFixtureSet(path)
	if err != nil {
		return carriercollapse.FixtureComparisonReport{Version: carriercollapse.Version, OldHash: "missing", NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return carriercollapse.CompareFixtureSets(oldSet, current)
}
