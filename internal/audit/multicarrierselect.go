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

	"kurdistan/internal/multicarrierselect"
	"kurdistan/internal/mutant"
)

func RunMultiCarrierSelectAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := multicarrierselect.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := multiCarrierSelectComparison(filepath.Join(root, "testdata", "multicarrierselect", "multicarrierselect-report-golden.json"), set)
	gates := MultiCarrierSelectGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "multicarrierselect-" + cfg.Mode,
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

func MultiCarrierSelectGates(set multicarrierselect.FixtureSet, comparison multicarrierselect.FixtureComparisonReport) []GateResult {
	return []GateResult{
		MultiCarrierSelectInventoryGate(set),
		MultiCarrierSelectCandidateBundleGate(set),
		MultiCarrierSelectPolicyGate(set),
		MultiCarrierSelectProfileSensitivityGate(set),
		MultiCarrierSelectPathRaceGate(set),
		MultiCarrierSelectPathHealthGate(set),
		MultiCarrierSelectFailoverFallbackGate(set),
		MultiCarrierSelectMeasurementReviewGate(set),
		MultiCarrierSelectCarrierReviewGate(set),
		MultiCarrierSelectRuntimeCompositionGate(set),
		MultiCarrierSelectMisuseDetectionGate(set),
		MultiCarrierSelectGeneratedBackendParityGate(set),
		MultiCarrierSelectTraceHygieneGate(set),
		MultiCarrierSelectPublicClaimSafetyGate(set),
		MultiCarrierSelectMutantDetectionGate(),
		MultiCarrierSelectFixtureDriftGate(comparison),
	}
}

func MultiCarrierSelectInventoryGate(set multicarrierselect.FixtureSet) GateResult {
	failures := []string{}
	for _, family := range multicarrierselect.RequiredFamilyClasses() {
		if set.Report.Inventory[family] == 0 {
			failures = append(failures, "missing carrier family "+family)
		}
	}
	for _, family := range set.Report.CarrierFamilies {
		if family.Hash == "" || !family.TraceSafe {
			failures = append(failures, "unsafe carrier family metadata "+family.Family)
		}
	}
	return gate("multicarrierselect_inventory", len(failures) == 0, "required", fmt.Sprintf("%d carrier families", len(set.Report.CarrierFamilies)), map[string]any{"inventory": set.Report.Inventory}, failures)
}

func MultiCarrierSelectCandidateBundleGate(set multicarrierselect.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.Candidates) < 5 {
		failures = append(failures, "candidate bundle too small")
	}
	selected := 0
	blocked := 0
	for _, candidate := range set.Report.Candidates {
		if candidate.Hash == "" || !candidate.ProfileSensitive || candidate.PayloadLogged || candidate.SecretLogged {
			failures = append(failures, "unsafe candidate "+candidate.ID)
		}
		if candidate.Selected {
			selected++
		}
		if candidate.Blocked {
			blocked++
		}
	}
	if selected < 1 || blocked < 5 {
		failures = append(failures, "selected/blocked candidate coverage incomplete")
	}
	return gate("multicarrierselect_candidate_bundle", len(failures) == 0, "required", fmt.Sprintf("%d candidates; %d blocked", len(set.Report.Candidates), blocked), nil, failures)
}

func MultiCarrierSelectPolicyGate(set multicarrierselect.FixtureSet) GateResult {
	p := set.Report.SelectionPolicy
	failures := []string{}
	if !p.ProfileSensitive || !p.HighRiskDefaultRejected || !p.UnsafeFallbackRejected || !p.MeasurementReviewEnforced || !p.CarrierReviewEnforced || !p.PathHealthEnforced || !p.PathRaceEnforced || !p.TransportBundleEnforced || !p.LabEgressEnforced {
		failures = append(failures, "selection policy enforcement incomplete")
	}
	for _, decision := range multicarrierselect.RequiredDecisionClasses() {
		if !containsMultiCarrierString(p.DecisionClasses, decision) {
			failures = append(failures, "missing decision class "+decision)
		}
	}
	return gate("multicarrierselect_policy", len(failures) == 0, "required", fmt.Sprintf("%d decision classes", len(p.DecisionClasses)), nil, failures)
}

func MultiCarrierSelectProfileSensitivityGate(set multicarrierselect.FixtureSet) GateResult {
	s := set.Report.ProfileSensitivity
	failures := []string{}
	if s.ProfileCount < 3 || s.UniqueSelectionHashes < 5 || s.DiversityScore < 0.75 || s.FixedCarrierControls == 0 || s.PaddingOnlyControls == 0 || s.ProfileInsensitiveChecks == 0 {
		failures = append(failures, "profile sensitivity evidence incomplete")
	}
	return gate("multicarrierselect_profile_sensitivity", len(failures) == 0, "required", fmt.Sprintf("diversity=%.2f hashes=%d", s.DiversityScore, s.UniqueSelectionHashes), nil, failures)
}

func MultiCarrierSelectPathRaceGate(set multicarrierselect.FixtureSet) GateResult {
	r := set.Report.Race
	failures := []string{}
	if !r.Deterministic || r.RacedCandidates < 2 || r.SelectedCandidates == 0 || r.RejectedCandidates == 0 || r.StaleRejected == 0 {
		failures = append(failures, "pathrace integration incomplete")
	}
	return gate("multicarrierselect_pathrace_integration", len(failures) == 0, "required", fmt.Sprintf("%d raced candidates", r.RacedCandidates), nil, failures)
}

func MultiCarrierSelectPathHealthGate(set multicarrierselect.FixtureSet) GateResult {
	h := set.Report.Health
	failures := []string{}
	if h.ReportsChecked < len(set.Report.Candidates) || h.BlockedByPathHealth == 0 || h.FailoverCandidates < 1 || !h.FailClosedOnNoCarrier {
		failures = append(failures, "pathhealth integration incomplete")
	}
	return gate("multicarrierselect_pathhealth_integration", len(failures) == 0, "required", fmt.Sprintf("%d health reports", h.ReportsChecked), nil, failures)
}

func MultiCarrierSelectFailoverFallbackGate(set multicarrierselect.FixtureSet) GateResult {
	f := set.Report.Failover
	failures := []string{}
	if f.PrimarySelected == "" || f.BackupSelected == "" || f.UnsafeFallbackBlocked == 0 || f.HighRiskBlocked == 0 || len(f.FailoverClasses) < 3 || len(f.FallbackClasses) < 4 {
		failures = append(failures, "failover/fallback evidence incomplete")
	}
	return gate("multicarrierselect_failover_fallback", len(failures) == 0, "required", fmt.Sprintf("primary=%s backup=%s", f.PrimarySelected, f.BackupSelected), nil, failures)
}

func MultiCarrierSelectMeasurementReviewGate(set multicarrierselect.FixtureSet) GateResult {
	failures := missingMultiCarrierComposition(set, []string{"measurementreview"})
	for _, candidate := range set.Report.Candidates {
		if candidate.MeasurementReview != "measurementreview_enforced" {
			failures = append(failures, "measurementreview not enforced for "+candidate.ID)
		}
	}
	return gate("multicarrierselect_measurementreview_composition", len(failures) == 0, "required", "measurementreview constraints enforced", nil, failures)
}

func MultiCarrierSelectCarrierReviewGate(set multicarrierselect.FixtureSet) GateResult {
	failures := missingMultiCarrierComposition(set, []string{"carrierreview"})
	for _, candidate := range set.Report.Candidates {
		if candidate.CarrierReview != "carrierreview_enforced" {
			failures = append(failures, "carrierreview not enforced for "+candidate.ID)
		}
	}
	return gate("multicarrierselect_carrierreview_composition", len(failures) == 0, "required", "carrierreview constraints enforced", nil, failures)
}

func MultiCarrierSelectRuntimeCompositionGate(set multicarrierselect.FixtureSet) GateResult {
	required := []string{"pathrace", "pathhealth", "transportbundle", "relaybridge", "labegress", "localpipeline", "runtime", "security"}
	failures := missingMultiCarrierComposition(set, required)
	return gate("multicarrierselect_runtime_composition", len(failures) == 0, "required", strings.Join(required, " ")+" mappings checked", nil, failures)
}

func MultiCarrierSelectMisuseDetectionGate(set multicarrierselect.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.Misuse.DetectedCount < len(multicarrierselect.RequiredMisuseNames()) || set.Report.Misuse.Conclusion != "passed" {
		failures = append(failures, "misuse coverage incomplete")
	}
	if set.Report.Misuse.PayloadLogged || set.Report.Misuse.SecretLogged {
		failures = append(failures, "misuse report leaked unsafe metadata")
	}
	return gate("multicarrierselect_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d misuse controls detected", set.Report.Misuse.DetectedCount), nil, failures)
}

func MultiCarrierSelectGeneratedBackendParityGate(set multicarrierselect.FixtureSet) GateResult {
	failures := []string{}
	p := set.Report.Parity
	if p.Conclusion != "passed" || p.ComparedCandidates == 0 || p.SemanticMatches != p.ComparedCandidates || p.DecisionMatches != p.ComparedCandidates || len(p.UnexpectedDifferences) > 0 || p.PayloadLogged || p.SecretLogged {
		failures = append(failures, "generated/interpreted multi-carrier selection parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range p.GeneratedMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated multi-carrier marker "+marker)
				}
			}
		}
	}
	return gate("multicarrierselect_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(p.GeneratedMarkers)), nil, failures)
}

func MultiCarrierSelectTraceHygieneGate(set multicarrierselect.FixtureSet) GateResult {
	failures := []string{}
	if err := multicarrierselect.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged {
		failures = append(failures, "multi-carrier selection trace hygiene failed")
	}
	return gate("multicarrierselect_trace_hygiene", len(failures) == 0, "required", "selection fixtures scanned for unsafe material", nil, failures)
}

func MultiCarrierSelectPublicClaimSafetyGate(set multicarrierselect.FixtureSet) GateResult {
	p := set.Report.PublicClaimSafety
	failures := []string{}
	if p.DocsChecked < 3 || p.UnsafeClaimsFound != 0 || p.Conclusion != "passed" {
		failures = append(failures, "public claim safety failed")
	}
	return gate("multicarrierselect_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d public docs scanned", p.DocsChecked), nil, failures)
}

func MultiCarrierSelectMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeMultiCarrierSelectFixedCarrierDefault,
		mutant.ModeMultiCarrierSelectProfileInsensitiveSelection,
		mutant.ModeMultiCarrierSelectPaddingOnlySelectionVariation,
		mutant.ModeMultiCarrierSelectHighRiskDefaultAllowed,
		mutant.ModeMultiCarrierSelectUnsafeFallbackAllowed,
		mutant.ModeMultiCarrierSelectMeasurementReviewBypass,
		mutant.ModeMultiCarrierSelectCarrierReviewBypass,
		mutant.ModeMultiCarrierSelectPathHealthBypass,
		mutant.ModeMultiCarrierSelectPathRaceBypass,
		mutant.ModeMultiCarrierSelectTransportBundleBypass,
		mutant.ModeMultiCarrierSelectLabEgressBypass,
		mutant.ModeMultiCarrierSelectPublicNetworkAllowed,
		mutant.ModeMultiCarrierSelectPayloadLoggingAllowed,
		mutant.ModeMultiCarrierSelectSecretLeak,
		mutant.ModeMultiCarrierSelectGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("multicarrierselect_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d multi-carrier selection mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func MultiCarrierSelectFixtureDriftGate(report multicarrierselect.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("multicarrierselect_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func multiCarrierSelectComparison(path string, current multicarrierselect.FixtureSet) multicarrierselect.FixtureComparisonReport {
	oldSet, err := multicarrierselect.LoadFixtureSet(path)
	if err != nil {
		return multicarrierselect.FixtureComparisonReport{Version: multicarrierselect.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return multicarrierselect.CompareFixtureSets(oldSet, current)
}

func missingMultiCarrierComposition(set multicarrierselect.FixtureSet, required []string) []string {
	found := map[string]bool{}
	for _, item := range set.Report.Compositions {
		if item.Composed && item.Enforced && item.Conclusion == "passed" {
			found[item.Layer] = true
		}
	}
	failures := []string{}
	for _, layer := range required {
		if !found[layer] {
			failures = append(failures, "missing composition "+layer)
		}
	}
	return failures
}

func containsMultiCarrierString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
