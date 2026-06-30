// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/mutant"
	"kurdistan/internal/transportbundle"
)

type TransportBundleAuditSummary struct {
	Version                string                                          `json:"version"`
	BundleMode             string                                          `json:"bundle_mode"`
	CandidateCount         int                                             `json:"candidate_count"`
	FamilyCounts           map[string]int                                  `json:"family_counts"`
	RoleCounts             map[string]int                                  `json:"role_counts"`
	UniqueProfileSeeds     int                                             `json:"unique_profile_seeds"`
	UniqueWirePolicyHashes int                                             `json:"unique_wire_policy_hashes"`
	FallbackHints          int                                             `json:"fallback_hints"`
	HighRiskCandidates     int                                             `json:"high_risk_candidates"`
	ExperimentalCandidates int                                             `json:"experimental_candidates"`
	FixtureComparison      transportbundle.TransportBundleComparisonReport `json:"fixture_comparison"`
	GeneratedParity        string                                          `json:"generated_parity"`
	Conclusion             string                                          `json:"conclusion"`
}

func RunTransportBundleAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := transportbundle.GenerateFixtureSet(ctx)
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := transportBundleFixtureComparison(filepath.Join(root, "testdata", "transportbundle", "bundle-manifest-golden.json"), set)
	gates := TransportBundleGates(set, comparison)
	summary := TransportBundleAuditSummary{
		Version:                string(transportbundle.Version),
		BundleMode:             string(set.Manifest.Mode),
		CandidateCount:         len(set.Manifest.Candidates),
		FamilyCounts:           set.Manifest.FamilyCounts,
		RoleCounts:             set.Manifest.RoleCounts,
		UniqueProfileSeeds:     set.SeedPlan.UniqueProfileSeeds,
		UniqueWirePolicyHashes: set.CollapseReport.UniqueWirePolicyHashes,
		FallbackHints:          len(set.FallbackHints),
		HighRiskCandidates:     set.CollapseReport.HighRiskCandidates,
		ExperimentalCandidates: set.CollapseReport.ExperimentalCandidates,
		FixtureComparison:      comparison,
		GeneratedParity:        set.Parity.Conclusion,
		Conclusion:             "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "transportbundle-" + cfg.Mode,
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

func TransportBundleGates(set transportbundle.TransportBundleFixtureSet, comparison transportbundle.TransportBundleComparisonReport) []GateResult {
	return []GateResult{
		TransportBundlePolicyValidationGate(set),
		TransportBundleSeedPlanningGate(set),
		TransportBundleFamilyCoverageGate(set),
		TransportBundleAdaptivePathMappingGate(set),
		TransportBundleRelayBindingGate(set),
		TransportBundleFallbackHintsGate(set),
		TransportBundleCollapseDetectionGate(set),
		TransportBundleGeneratedBackendParityGate(set),
		TransportBundleTraceHygieneGate(set),
		TransportBundleMutantDetectionGate(set),
		TransportBundleFixtureDriftGate(comparison),
	}
}

func TransportBundlePolicyValidationGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	for _, policy := range set.Policies {
		if err := transportbundle.ValidatePolicy(policy); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if len(set.Policies) < len(transportbundle.RequiredBundleModes()) {
		failures = append(failures, "missing bundle policy modes")
	}
	return gate("transportbundle_policy_validation", len(failures) == 0, "required", fmt.Sprintf("%d bundle policy modes checked", len(set.Policies)), nil, failures)
}

func TransportBundleSeedPlanningGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if set.SeedPlan.UniqueProfileSeeds < 3 {
		failures = append(failures, "insufficient unique profile seeds")
	}
	if len(set.SeedPlan.CandidateSeeds) != len(set.Manifest.Candidates) {
		failures = append(failures, "candidate seed count mismatch")
	}
	return gate("transportbundle_seed_planning", len(failures) == 0, "required", fmt.Sprintf("%d unique profile seeds", set.SeedPlan.UniqueProfileSeeds), nil, failures)
}

func TransportBundleFamilyCoverageGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	for _, policy := range set.Policies {
		if policy.Mode == transportbundle.BundleModeBalancedAdaptive {
			failures = append(failures, transportbundle.FamilyCoverage(set.Manifest, policy.RequiredFamilies)...)
		}
	}
	return gate("transportbundle_family_coverage", len(failures) == 0, "required", fmt.Sprintf("%d families covered", len(set.Manifest.FamilyCounts)), map[string]any{"family_counts": set.Manifest.FamilyCounts}, failures)
}

func TransportBundleAdaptivePathMappingGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if len(set.AdaptivePathCandidates) != len(set.Manifest.Candidates) {
		failures = append(failures, "adaptivepath mapping count mismatch")
	}
	for _, candidate := range set.AdaptivePathCandidates {
		if candidate.CandidateID == "" || candidate.Family == "" {
			failures = append(failures, "invalid adaptivepath candidate mapping")
			break
		}
	}
	return gate("transportbundle_adaptivepath_mapping", len(failures) == 0, "required", fmt.Sprintf("%d candidates mapped to adaptivepath", len(set.AdaptivePathCandidates)), nil, failures)
}

func TransportBundleRelayBindingGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if set.RelayBinding.Conclusion != "passed" {
		failures = append(failures, "relay binding failed")
	}
	if set.RelayBinding.SyntheticRelays == 0 || set.RelayBinding.SyntheticHosts == 0 {
		failures = append(failures, "missing synthetic relay or host metadata")
	}
	return gate("transportbundle_relay_binding", len(failures) == 0, "required", fmt.Sprintf("%d synthetic relays and %d synthetic hosts", set.RelayBinding.SyntheticRelays, set.RelayBinding.SyntheticHosts), nil, failures)
}

func TransportBundleFallbackHintsGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if len(set.FallbackHints) != len(set.Manifest.Candidates) {
		failures = append(failures, "fallback hint count mismatch")
	}
	if set.Manifest.FallbackPlan.FinalWinnerSelected {
		failures = append(failures, "fallback plan selected final winner")
	}
	for _, hint := range set.FallbackHints {
		if err := transportbundle.ValidateFallbackHint(hint); err != nil {
			failures = append(failures, err.Error())
		}
	}
	return gate("transportbundle_fallback_hints", len(failures) == 0, "required", fmt.Sprintf("%d fallback hints checked", len(set.FallbackHints)), nil, failures)
}

func TransportBundleCollapseDetectionGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if set.CollapseReport.Conclusion != "passed" {
		failures = append(failures, set.CollapseReport.CollapseFindings...)
	}
	if set.ControlCollapseReport.Conclusion != "failed" || len(set.ControlCollapseReport.CollapseFindings) == 0 {
		failures = append(failures, "collapsed control not detected")
	}
	return gate("transportbundle_collapse_detection", len(failures) == 0, "required", fmt.Sprintf("diversity score %.2f; control findings=%d", set.CollapseReport.DiversityScore, len(set.ControlCollapseReport.CollapseFindings)), nil, failures)
}

func TransportBundleGeneratedBackendParityGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" {
		failures = append(failures, set.Parity.UnexpectedDifferences...)
	}
	return gate("transportbundle_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d candidates compared", set.Parity.ComparedCandidates), nil, failures)
}

func TransportBundleTraceHygieneGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	failures := []string{}
	if err := transportbundle.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	for _, tc := range []map[string]string{
		{"endpoint": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"dns_query": "synthetic"},
		{"real_host": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := transportbundle.ScanForLeak(tc); err == nil {
			failures = append(failures, "unsafe transportbundle metadata accepted")
		}
	}
	return gate("transportbundle_trace_hygiene", len(failures) == 0, "required", "transport bundle fixtures contain safe metadata only", nil, failures)
}

func TransportBundleMutantDetectionGate(set transportbundle.TransportBundleFixtureSet) GateResult {
	required := []string{
		mutant.ModeTransportBundleMissingRequiredFamily,
		mutant.ModeTransportBundleAllCandidatesSameFamily,
		mutant.ModeTransportBundleAllCandidatesSameProfile,
		mutant.ModeTransportBundleAllCandidatesSameWirePolicy,
		mutant.ModeTransportBundleHighRiskPrimary,
		mutant.ModeTransportBundleExperimentalPrimary,
		mutant.ModeTransportBundleBurnedRelayPrimary,
		mutant.ModeTransportBundleMissingFallbackPlan,
		mutant.ModeTransportBundleFinalWinnerSelected,
		mutant.ModeTransportBundleEndpointLeak,
		mutant.ModeTransportBundleResolverLeak,
		mutant.ModeTransportBundlePayloadLeak,
		mutant.ModeTransportBundleSecretLeak,
		mutant.ModeTransportBundleGeneratedBackendDrift,
		mutant.ModeTransportBundleControlNotDetected,
	}
	failures := missingMutantModes(required)
	if set.ControlCollapseReport.Conclusion != "failed" {
		failures = append(failures, "transportbundle control not detected")
	}
	if err := transportbundle.ScanForLeak(map[string]string{"endpoint": "synthetic"}); err == nil {
		failures = append(failures, "endpoint leak mutant not detected")
	}
	return gate("transportbundle_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d mutants represented", len(required)-len(failures)), nil, failures)
}

func TransportBundleFixtureDriftGate(report transportbundle.TransportBundleComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("transportbundle_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func transportBundleFixtureComparison(path string, current transportbundle.TransportBundleFixtureSet) transportbundle.TransportBundleComparisonReport {
	oldSet, err := transportbundle.LoadFixtureSet(path)
	if err != nil {
		return transportbundle.TransportBundleComparisonReport{Version: string(transportbundle.Version), NewHash: current.FixtureSetHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return transportbundle.CompareFixtureSets(oldSet, current)
}
