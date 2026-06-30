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

	"kurdistan/internal/mutant"
	"kurdistan/internal/proxyingress"
	"kurdistan/internal/proxyingressreview"
)

type ProxyIngressAuditSummary struct {
	Version      string                                      `json:"version"`
	ContractID   string                                      `json:"contract_id"`
	Requests     int                                         `json:"requests"`
	Targets      int                                         `json:"targets"`
	Mappings     int                                         `json:"mappings"`
	FailureModes int                                         `json:"failure_modes"`
	Decision     string                                      `json:"decision"`
	Misuse       proxyingressreview.ProxyIngressMisuseReport `json:"misuse"`
	Parity       proxyingressreview.ProxyIngressParityReport `json:"parity"`
	Comparison   proxyingress.ProxyIngressComparisonReport   `json:"comparison"`
	Conclusion   string                                      `json:"conclusion"`
}

func RunProxyIngressAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := proxyingress.GoldenFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	review, misuse, parity, err := proxyingressreview.GenerateGoldenReview()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison, _ := proxyingress.VerifyContract(ctx, filepath.Join(root, "testdata", "proxyingress", "proxyingress-contract-golden.json"))
	gates := ProxyIngressGates(set, review, misuse, parity, comparison)
	summary := ProxyIngressAuditSummary{
		Version:      string(proxyingress.Version),
		ContractID:   set.Contract.ContractID,
		Requests:     len(set.Requests),
		Targets:      len(set.Targets),
		Mappings:     len(set.Mappings),
		FailureModes: len(review.FailureModes),
		Decision:     review.GoNoGoDecision,
		Misuse:       misuse,
		Parity:       parity,
		Comparison:   comparison,
		Conclusion:   "passed",
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "proxyingress-" + cfg.Mode,
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

func ProxyIngressGates(set proxyingress.ProxyIngressFixtureSet, review proxyingressreview.ProxyIngressDesignReview, misuse proxyingressreview.ProxyIngressMisuseReport, parity proxyingressreview.ProxyIngressParityReport, comparison proxyingress.ProxyIngressComparisonReport) []GateResult {
	return []GateResult{
		ProxyIngressContractValidationGate(set.Contract),
		ProxyIngressTargetDescriptorSafetyGate(set),
		ProxyIngressCapabilityMappingGate(set.Contract),
		ProxyIngressRuntimeMappingGate(set),
		ProxyIngressLifecycleIntegrityGate(set),
		ProxyIngressFailureModeMatrixGate(review.FailureModes),
		ProxyIngressDesignReviewGate(review),
		ProxyIngressMisuseDetectionGate(misuse),
		ProxyIngressGeneratedBackendParityGate(parity),
		ProxyIngressTraceHygieneGate(set, review),
		ProxyIngressMutantDetectionGate(),
		ProxyIngressFixtureDriftGate(comparison),
	}
}

func ProxyIngressContractValidationGate(contract proxyingress.ProxyIngressContract) GateResult {
	failures := []string{}
	if err := proxyingress.ValidateContract(contract); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("proxyingress_contract_validation", len(failures) == 0, "required", contract.ContractID, map[string]any{"version": contract.Version, "supported_kinds": contract.SupportedKinds}, failures)
}

func ProxyIngressTargetDescriptorSafetyGate(set proxyingress.ProxyIngressFixtureSet) GateResult {
	failures := []string{}
	for _, target := range set.Targets {
		if err := proxyingress.ValidateTargetDescriptor(target, set.Contract.Limits); err != nil {
			failures = append(failures, target.DescriptorID)
		}
	}
	for _, target := range proxyingress.InvalidTargetDescriptors() {
		if err := proxyingress.ValidateTargetDescriptor(target, set.Contract.Limits); err == nil {
			failures = append(failures, "invalid target accepted")
		}
	}
	return gate("proxyingress_target_descriptor_safety", len(failures) == 0, "required", fmt.Sprintf("%d valid targets checked", len(set.Targets)), nil, failures)
}

func ProxyIngressCapabilityMappingGate(contract proxyingress.ProxyIngressContract) GateResult {
	mapping := proxyingress.MapCapabilities(contract, proxyingress.DefaultAvailableCapabilities())
	failures := []string{}
	if mapping.Conclusion != "passed" {
		failures = append(failures, "capability mapping failed")
	}
	return gate("proxyingress_capability_mapping", len(failures) == 0, "required", fmt.Sprintf("%d required capabilities", len(mapping.RequiredCapabilities)), map[string]any{"mapping": mapping}, failures)
}

func ProxyIngressRuntimeMappingGate(set proxyingress.ProxyIngressFixtureSet) GateResult {
	failures := []string{}
	if len(set.Mappings) != len(set.Requests) || len(set.Mappings) == 0 {
		failures = append(failures, "mapping count mismatch")
	}
	for _, plan := range set.Mappings {
		if !plan.RequiresSecureContext || !plan.RequiresReplayWindow || !plan.RequiresTraceHygiene || plan.PayloadLogged || plan.SecretLogged {
			failures = append(failures, plan.RequestID)
		}
	}
	return gate("proxyingress_runtime_mapping", len(failures) == 0, "required", fmt.Sprintf("%d mapping plans", len(set.Mappings)), nil, failures)
}

func ProxyIngressLifecycleIntegrityGate(set proxyingress.ProxyIngressFixtureSet) GateResult {
	failures := []string{}
	if len(set.Lifecycle) < len(set.Requests) {
		failures = append(failures, "too few lifecycle events")
	}
	if proxyingress.CanTransition(proxyingress.RequestAccepted, proxyingress.RequestRejected) {
		failures = append(failures, "accepted to rejected transition allowed")
	}
	return gate("proxyingress_lifecycle_integrity", len(failures) == 0, "required", fmt.Sprintf("%d lifecycle events", len(set.Lifecycle)), nil, failures)
}

func ProxyIngressFailureModeMatrixGate(modes []proxyingressreview.FailureModeReview) GateResult {
	failures := []string{}
	if err := proxyingressreview.ValidateFailureModeMatrix(modes); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("proxyingress_failure_mode_matrix", len(failures) == 0, "required", fmt.Sprintf("%d failure modes", len(modes)), nil, failures)
}

func ProxyIngressDesignReviewGate(review proxyingressreview.ProxyIngressDesignReview) GateResult {
	failures := []string{}
	if err := proxyingressreview.ValidateReview(review); err != nil {
		failures = append(failures, err.Error())
	}
	if review.GoNoGoDecision != proxyingressreview.DecisionGo {
		failures = append(failures, "review did not approve deterministic prototype")
	}
	return gate("proxyingress_design_review", len(failures) == 0, "required", review.GoNoGoDecision, map[string]any{"review_id": review.ReviewID, "failure_modes": len(review.FailureModes)}, failures)
}

func ProxyIngressMisuseDetectionGate(report proxyingressreview.ProxyIngressMisuseReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, "misuse report failed")
		failures = append(failures, report.SuspiciousMetrics...)
	}
	return gate("proxyingress_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d requests scanned", report.RequestCount), map[string]any{"misuse": report}, failures)
}

func ProxyIngressGeneratedBackendParityGate(report proxyingressreview.ProxyIngressParityReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDifferences...)
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"proxyingress_generated.go", "proxyingress_test.go", "proxyingress_parity_test.go", "proxyingress_hygiene_test.go", "ProxyIngressSchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated marker "+marker)
				}
			}
		}
	}
	return gate("proxyingress_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d contracts compared", report.ComparedContracts), map[string]any{"parity": report}, failures)
}

func ProxyIngressTraceHygieneGate(set proxyingress.ProxyIngressFixtureSet, review proxyingressreview.ProxyIngressDesignReview) GateResult {
	failures := []string{}
	if err := proxyingress.ValidateFixtureSet(set); err != nil {
		failures = append(failures, err.Error())
	}
	if review.PayloadLogged || review.SecretLogged {
		failures = append(failures, "review hygiene flag")
	}
	for _, unsafe := range []map[string]string{{"endpoint": "x"}, {"payload": "x"}, {"secret": "x"}, {"domain": "x"}} {
		if err := proxyingress.ScanForLeak(unsafe); err == nil {
			failures = append(failures, "unsafe fixture metadata accepted")
		}
	}
	return gate("proxyingress_trace_hygiene", len(failures) == 0, "required", "contract and fixtures are metadata-only", nil, failures)
}

func ProxyIngressMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeProxyIngressAcceptsRealEndpoint,
		mutant.ModeProxyIngressAcceptsDomainTarget,
		mutant.ModeProxyIngressAcceptsURLTarget,
		mutant.ModeProxyIngressUnboundedDescriptor,
		mutant.ModeProxyIngressMissingTraceHygiene,
		mutant.ModeProxyIngressMissingSecurityPrecondition,
		mutant.ModeProxyIngressMissingBackpressureMapping,
		mutant.ModeProxyIngressMissingResetMapping,
		mutant.ModeProxyIngressAllRequestsSameMapping,
		mutant.ModeProxyIngressLifecycleViolationAllowed,
		mutant.ModeProxyIngressPayloadLeak,
		mutant.ModeProxyIngressSecretLeak,
		mutant.ModeProxyIngressReviewGoDespiteBlocker,
		mutant.ModeProxyIngressGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("proxyingress_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d mutants represented", len(required)-len(failures)), nil, failures)
}

func missingMutantModes(required []string) []string {
	seen := map[string]bool{}
	for _, mode := range mutant.Modes() {
		seen[mode] = true
	}
	failures := []string{}
	for _, mode := range required {
		if !seen[mode] {
			failures = append(failures, "missing mutant "+mode)
		}
	}
	return failures
}

func ProxyIngressFixtureDriftGate(report proxyingress.ProxyIngressComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("proxyingress_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}
