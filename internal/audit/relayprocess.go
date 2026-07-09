// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/mutant"
	"kurdistan/internal/operator/relayprocess"
)

func RunRelayProcessAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := relayprocess.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := relayProcessComparison(filepath.Join(root, "testdata", "relayprocess", "relayprocess-report-golden.json"), set)
	gates := RelayProcessGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "relayprocess-" + cfg.Mode,
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

func RelayProcessGates(set relayprocess.FixtureSet, comparison relayprocess.FixtureComparisonReport) []GateResult {
	return []GateResult{
		RelayProcessRoleInventoryGate(set),
		RelayProcessConfigContractGate(set),
		RelayProcessProfileBundleGate(set),
		RelayProcessLifecycleGate(set),
		RelayProcessLoggingObservabilityGate(set),
		RelayProcessShutdownRecoveryGate(set),
		RelayProcessCompatibilityGate(set),
		RelayProcessResourceGate(set),
		RelayProcessAbuseControlGate(set),
		RelayProcessM53PreconditionsGate(set),
		RelayProcessMisuseGate(set),
		RelayProcessGeneratedParityGate(set),
		RelayProcessTraceHygieneGate(set),
		RelayProcessPublicClaimSafetyGate(set),
		RelayProcessFixtureDriftGate(comparison),
	}
}

func RelayProcessRoleInventoryGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Roles) < 3 {
		failures = append(failures, "process roles incomplete")
	}
	return gate("relayprocess_role_inventory", len(failures) == 0, "required", fmt.Sprintf("%d process roles", len(set.Roles)), nil, failures)
}

func RelayProcessConfigContractGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if !set.Config.RequiresExplicitLabMode || set.Config.AllowPublicDeploymentDefaults || set.Config.AllowCloudProviderDependency || set.Config.AllowProductionKeyingChanges {
		failures = append(failures, "unsafe process config contract")
	}
	return gate("relayprocess_config_contract", len(failures) == 0, "required", set.Config.LoadingPolicy, nil, failures)
}

func RelayProcessProfileBundleGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if set.Config.ProfileBundlePolicy == "" || len(set.Config.AllowedConfigClasses) < 4 || len(set.Config.BlockedConfigClasses) < 5 {
		failures = append(failures, "profile bundle contract incomplete")
	}
	return gate("relayprocess_profile_bundle_contract", len(failures) == 0, "required", set.Config.ProfileBundlePolicy, nil, failures)
}

func RelayProcessLifecycleGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Lifecycle) < 5 {
		failures = append(failures, "lifecycle contracts incomplete")
	}
	return gate("relayprocess_lifecycle_contract", len(failures) == 0, "required", fmt.Sprintf("%d lifecycle contracts", len(set.Lifecycle)), nil, failures)
}

func RelayProcessLoggingObservabilityGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if set.Logging.PublicUploadAllowed || set.Logging.PayloadLogged || set.Logging.SecretLogged || len(set.Logging.ForbiddenFields) < 10 {
		failures = append(failures, "logging or observability contract unsafe")
	}
	return gate("relayprocess_logging_observability", len(failures) == 0, "required", set.Logging.Policy, nil, failures)
}

func RelayProcessShutdownRecoveryGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if !set.Shutdown.IdempotentClose || set.Shutdown.UnreviewedAutoUpdate || len(set.Shutdown.GracefulPhases) < 4 {
		failures = append(failures, "shutdown or recovery contract incomplete")
	}
	return gate("relayprocess_shutdown_recovery", len(failures) == 0, "required", set.Shutdown.Policy, nil, failures)
}

func RelayProcessCompatibilityGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if !set.Compatibility.RejectsDowngrade || len(set.Compatibility.CapabilityChecks) < 5 {
		failures = append(failures, "compatibility contract incomplete")
	}
	return gate("relayprocess_compatibility_policy", len(failures) == 0, "required", set.Compatibility.Policy, nil, failures)
}

func RelayProcessResourceGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if set.Resource.MissingResourcePolicy || len(set.Resource.Bounds) < 5 {
		failures = append(failures, "resource contract incomplete")
	}
	return gate("relayprocess_resource_policy", len(failures) == 0, "required", set.Resource.Policy, nil, failures)
}

func RelayProcessAbuseControlGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if set.Resource.AbuseControlPolicy == "" {
		failures = append(failures, "abuse-control placeholder missing")
	}
	return gate("relayprocess_abuse_control_placeholder", len(failures) == 0, "required", set.Resource.AbuseControlPolicy, nil, failures)
}

func RelayProcessM53PreconditionsGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if set.M53Preconditions.Conclusion != "passed" || len(set.M53Preconditions.Preconditions) < 5 {
		failures = append(failures, "M53 preconditions incomplete")
	}
	return gate("relayprocess_m53_preconditions", len(failures) == 0, "required", fmt.Sprintf("%d preconditions", len(set.M53Preconditions.Preconditions)), nil, failures)
}

func RelayProcessMisuseGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range relayprocess.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(relayprocess.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("relayprocess_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(relayprocess.RequiredMisuseNames())-len(failures), len(relayprocess.RequiredMisuseNames())), nil, failures)
}

func RelayProcessGeneratedParityGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("relayprocess_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func RelayProcessTraceHygieneGate(set relayprocess.FixtureSet) GateResult {
	failures := []string{}
	if err := relayprocess.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	return gate("relayprocess_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d fixtures scanned", set.TraceHygiene.FixturesScanned), nil, failures)
}

func RelayProcessPublicClaimSafetyGate(set relayprocess.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "public claim safety failed")
	}
	return gate("relayprocess_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func RelayProcessFixtureDriftGate(report relayprocess.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("relayprocess_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func relayProcessComparison(path string, current relayprocess.FixtureSet) relayprocess.FixtureComparisonReport {
	oldSet, err := relayprocess.LoadFixtureSet(path)
	if err != nil {
		return relayprocess.FixtureComparisonReport{Version: relayprocess.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return relayprocess.CompareFixtureSets(oldSet, current)
}
