// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"time"

	"kurdistan/internal/hardening"
	"kurdistan/internal/ir"
)

func RunHardeningAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	if cfg.Mode == "quick" && cfg.ProfileCount > 3 {
		cfg.ProfileCount = 3
	}
	if cfg.Mode == "full" && cfg.ProfileCount > 20 {
		cfg.ProfileCount = 20
	}
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	hardeningReport := hardening.Run(ctx, profiles, hardening.Options{Mode: cfg.Mode, ProfileCount: len(profiles), StartSeed: cfg.StartSeed, Full: cfg.Mode == "full"})
	gates := HardeningGatesFromReport(hardeningReport)
	report := AuditReport{
		Version:          hardening.Version,
		Mode:             "hardening-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: hardeningReport,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func HardeningGates(ctx context.Context, profiles []*ir.Profile, cfg AuditConfig) []GateResult {
	limit := 3
	if cfg.Mode == "full" {
		limit = 20
	}
	selected := selectProfiles(profiles, limit)
	report := hardening.Run(ctx, selected, hardening.Options{Mode: cfg.Mode, ProfileCount: len(selected), StartSeed: cfg.StartSeed, Full: cfg.Mode == "full"})
	return HardeningGatesFromReport(report)
}

func HardeningGatesFromReport(report hardening.HardeningReport) []GateResult {
	return []GateResult{
		hardeningCategoryGate("hardening_invariant_registry", report, hardening.CategoryInvariants, report.InvariantsChecked),
		hardeningCategoryGate("hardening_api_contracts", report, hardening.CategoryAPIContracts, report.ContractsChecked),
		hardeningCategoryGate("hardening_panic_safety", report, hardening.CategoryPanicSafety, report.PanicSafetyChecks),
		hardeningCategoryGate("hardening_resource_limits", report, hardening.CategoryResourceLimits, report.ResourceChecks),
		hardeningTraceGate(report),
		hardeningCategoryGate("hardening_concurrency_safety", report, hardening.CategoryConcurrency, report.ConcurrencyChecks),
		hardeningCategoryGate("hardening_generated_parity", report, hardening.CategoryGeneratedParity, report.GeneratedParityChecks),
		hardeningCategoryGate("hardening_pre_adapter_readiness", report, hardening.CategoryPreAdapterReadiness, report.PreAdapterChecks),
		HardeningMutantDetectionGate(),
	}
}

func hardeningCategoryGate(name string, report hardening.HardeningReport, category string, checked int) GateResult {
	failures := []string{}
	for _, result := range report.Results {
		if result.Category == category && !result.Passed {
			failures = append(failures, result.Name+": "+result.Details)
		}
	}
	return gate(name, len(failures) == 0 && checked > 0, "required", fmt.Sprintf("%d %s checks run; %d failures", checked, category, len(failures)), map[string]any{
		"profiles_checked": report.ProfileCount,
		"packages_checked": report.PackagesChecked,
		"checks_run":       checked,
		"failed_checks":    len(failures),
	}, failures)
}

func hardeningTraceGate(report hardening.HardeningReport) GateResult {
	failures := []string{}
	for _, result := range report.Results {
		if (result.Category == hardening.CategoryTraceHygiene || result.Category == hardening.CategorySecurityHygiene) && !result.Passed {
			failures = append(failures, result.Name+": "+result.Details)
		}
	}
	return gate("hardening_trace_hygiene", len(failures) == 0 && report.TraceHygieneChecks > 0, "required", fmt.Sprintf("%d trace/security hygiene checks run; %d failures", report.TraceHygieneChecks, len(failures)), map[string]any{
		"profiles_checked": report.ProfileCount,
		"checks_run":       report.TraceHygieneChecks,
		"failed_checks":    len(failures),
	}, failures)
}

func HardeningMutantDetectionGate() GateResult {
	detected := []string{}
	missed := []string{}
	for _, mode := range hardening.HardeningMutantModes() {
		if hardening.DetectHardeningMutant(mode) {
			detected = append(detected, mode)
		} else {
			missed = append(missed, mode)
		}
	}
	return gate("hardening_mutant_detection", len(missed) == 0, "required", fmt.Sprintf("%d/%d hardening mutant modes detected", len(detected), len(detected)+len(missed)), map[string]any{
		"detected_modes": detected,
		"missed_modes":   missed,
	}, missed)
}
