// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/testkit/mutant"
	"kurdistan/internal/contracts/readiness/operationalhardening"
)

func RunOperationalHardeningAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := operationalhardening.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := operationalHardeningComparison(filepath.Join(root, "testdata", "operationalhardening", "operationalhardening-report-golden.json"), set)
	gates := OperationalHardeningGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "operationalhardening-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
		TraceCount:       0,
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

func OperationalHardeningGates(set operationalhardening.FixtureSet, comparison operationalhardening.FixtureComparisonReport) []GateResult {
	return []GateResult{
		OperationalHardeningReportGate(set),
		OperationalHardeningResourceLimitGate(set),
		OperationalHardeningConfigValidationGate(set),
		OperationalHardeningLifecycleGate(set),
		OperationalHardeningLoggingGate(set),
		OperationalHardeningRollbackGate(set),
		OperationalHardeningHealthGate(set),
		OperationalHardeningCompatibilityGate(set),
		OperationalHardeningMisuseGate(set),
		OperationalHardeningGeneratedParityGate(set),
		OperationalHardeningTraceHygieneGate(set),
		OperationalHardeningPublicClaimSafetyGate(set),
		OperationalHardeningFixtureDriftGate(comparison),
	}
}

func OperationalHardeningReportGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.Decision == "" || set.BlockerCount != 0 || set.RiskCount < 4 || set.Checklist.Failed != 0 {
		failures = append(failures, "operational hardening report incomplete")
	}
	return gate("operationalhardening_report", len(failures) == 0, "required", fmt.Sprintf("decision=%s blockers=%d risks=%d checklist_failed=%d", set.Decision, set.BlockerCount, set.RiskCount, set.Checklist.Failed), nil, failures)
}

func OperationalHardeningResourceLimitGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.ResourceLimits.MissingBounds || len(set.ResourceLimits.Bounds) < 8 {
		failures = append(failures, "resource limits incomplete")
	}
	return gate("operationalhardening_resource_limits", len(failures) == 0, "required", fmt.Sprintf("%d bounds", len(set.ResourceLimits.Bounds)), nil, failures)
}

func OperationalHardeningConfigValidationGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.ConfigValidation.AllowAmbiguousConfig || set.ConfigValidation.AllowOverbroadDefaults || len(set.ConfigValidation.RejectedConfigClasses) < 7 {
		failures = append(failures, "config validation unsafe")
	}
	return gate("operationalhardening_config_validation", len(failures) == 0, "required", set.ConfigValidation.Policy, nil, failures)
}

func OperationalHardeningLifecycleGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if !set.Lifecycle.DeterministicShutdown || !set.Lifecycle.IdempotentRestart || set.Lifecycle.UnboundedRestartLoopAllowed || len(set.Lifecycle.ShutdownPhases) < 5 {
		failures = append(failures, "shutdown/restart lifecycle unsafe")
	}
	return gate("operationalhardening_lifecycle", len(failures) == 0, "required", set.Lifecycle.Policy, nil, failures)
}

func OperationalHardeningLoggingGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.Logging.PayloadLogged || set.Logging.SecretLogged || set.Logging.DestinationLogged || set.Logging.KeyMaterialLogged || set.Logging.NetworkMetadataLeak || len(set.Logging.AllowedFields) < 7 {
		failures = append(failures, "logging diagnostics unsafe")
	}
	return gate("operationalhardening_safe_logging", len(failures) == 0, "required", set.Logging.Policy, nil, failures)
}

func OperationalHardeningRollbackGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if !set.Rollback.FailClosedRequired || set.Rollback.UnsafeRollbackAllowed || len(set.Rollback.ProfileRotationRequired) < 3 || len(set.Rollback.FailClosedClasses) < 4 {
		failures = append(failures, "rollback boundaries unsafe")
	}
	return gate("operationalhardening_rollback_boundaries", len(failures) == 0, "required", set.Rollback.Policy, nil, failures)
}

func OperationalHardeningHealthGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.Health.PayloadLogged || set.Health.SecretLogged || set.Health.ExactUserIdentifierLogged || set.Health.PreciseNetworkMetadata || len(set.Health.SafeFields) < 8 {
		failures = append(failures, "health summary unsafe")
	}
	return gate("operationalhardening_health_summary", len(failures) == 0, "required", set.Health.Policy, nil, failures)
}

func OperationalHardeningCompatibilityGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.Compatibility.BypassesCarrierReview || set.Compatibility.BypassesMeasurementReview || set.Compatibility.BypassesPathHealth || set.Compatibility.BypassesRelayAuth || set.Compatibility.BypassesHardening || set.Compatibility.AllowsGeneratedBackendDrift || len(set.Compatibility.RequiredGates) < 7 {
		failures = append(failures, "prior safety gate integration unsafe")
	}
	return gate("operationalhardening_compatibility_integration", len(failures) == 0, "required", set.Compatibility.Policy, nil, failures)
}

func OperationalHardeningMisuseGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range operationalhardening.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(operationalhardening.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("operationalhardening_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(operationalhardening.RequiredMisuseNames())-len(failures), len(operationalhardening.RequiredMisuseNames())), nil, failures)
}

func OperationalHardeningGeneratedParityGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("operationalhardening_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func OperationalHardeningTraceHygieneGate(set operationalhardening.FixtureSet) GateResult {
	failures := []string{}
	if err := operationalhardening.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.DestinationLogged || set.TraceHygiene.KeyMaterialLogged {
		failures = append(failures, "trace hygiene flags unsafe")
	}
	return gate("operationalhardening_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func OperationalHardeningPublicClaimSafetyGate(set operationalhardening.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "public claim safety failed")
	}
	return gate("operationalhardening_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func OperationalHardeningFixtureDriftGate(report operationalhardening.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("operationalhardening_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func operationalHardeningComparison(path string, current operationalhardening.FixtureSet) operationalhardening.FixtureComparisonReport {
	oldSet, err := operationalhardening.LoadFixtureSet(path)
	if err != nil {
		return operationalhardening.FixtureComparisonReport{Version: operationalhardening.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return operationalhardening.CompareFixtureSets(oldSet, current)
}
