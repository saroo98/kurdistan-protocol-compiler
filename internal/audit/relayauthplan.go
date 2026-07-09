// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/mutant"
	"kurdistan/internal/operator/relayauthplan"
)

func RunRelayAuthPlanAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := relayauthplan.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := relayAuthPlanComparison(filepath.Join(root, "testdata", "relayauthplan", "relayauthplan-report-golden.json"), set)
	gates := RelayAuthPlanGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "relayauthplan-" + cfg.Mode,
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

func RelayAuthPlanGates(set relayauthplan.FixtureSet, comparison relayauthplan.FixtureComparisonReport) []GateResult {
	return []GateResult{
		RelayAuthPlanInventoryGate(set),
		RelayAuthPlanIdentityBindingGate(set),
		RelayAuthPlanCompatibilityMatrixGate(set),
		RelayAuthPlanRotationPolicyGate(set),
		RelayAuthPlanExpiryRevocationGate(set),
		RelayAuthPlanSafeFailureGate(set),
		RelayAuthPlanDowngradeRejectionGate(set),
		RelayAuthPlanUnknownStaleProfileGate(set),
		RelayAuthPlanM55PrereqGate(set),
		RelayAuthPlanMisuseGate(set),
		RelayAuthPlanGeneratedParityGate(set),
		RelayAuthPlanTraceHygieneGate(set),
		RelayAuthPlanPublicClaimSafetyGate(set),
		RelayAuthPlanFixtureDriftGate(comparison),
	}
}

func RelayAuthPlanInventoryGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if len(set.AuthInventory) < 15 {
		failures = append(failures, "relay auth inventory incomplete")
	}
	return gate("relayauthplan_inventory", len(failures) == 0, "required", fmt.Sprintf("%d auth items", len(set.AuthInventory)), nil, failures)
}

func RelayAuthPlanIdentityBindingGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if !set.IdentityBinding.RelayIdentityRequired || !set.IdentityBinding.ClientProfileIdentityRequired || set.IdentityBinding.UnauthenticatedRelayAllowed || len(set.IdentityBinding.BoundComponents) < 6 {
		failures = append(failures, "identity binding unsafe")
	}
	return gate("relayauthplan_identity_binding", len(failures) == 0, "required", set.IdentityBinding.Policy, nil, failures)
}

func RelayAuthPlanCompatibilityMatrixGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if set.CompatibilityMatrix.UnknownVersionFailOpen || set.CompatibilityMatrix.GeneratedDriftAllowed || len(set.CompatibilityMatrix.RelayCompatibility) < 3 || len(set.CompatibilityMatrix.TransportCompatibility) < 3 || len(set.CompatibilityMatrix.CarrierCompatibility) < 3 {
		failures = append(failures, "compatibility matrix unsafe")
	}
	return gate("relayauthplan_compatibility_matrix", len(failures) == 0, "required", set.CompatibilityMatrix.Policy, nil, failures)
}

func RelayAuthPlanRotationPolicyGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if set.RotationPolicy.RotationWithoutWindow || len(set.RotationPolicy.RequiredChecks) < 5 {
		failures = append(failures, "rotation policy unsafe")
	}
	return gate("relayauthplan_rotation_policy", len(failures) == 0, "required", set.RotationPolicy.Policy, nil, failures)
}

func RelayAuthPlanExpiryRevocationGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if set.ExpiryRevocation.StaleProfileFailOpen || set.ExpiryRevocation.RevocationMissing || len(set.ExpiryRevocation.RequiredChecks) < 4 {
		failures = append(failures, "expiry/revocation policy unsafe")
	}
	return gate("relayauthplan_expiry_revocation", len(failures) == 0, "required", set.ExpiryRevocation.Policy, nil, failures)
}

func RelayAuthPlanSafeFailureGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if set.SafeFailure.FailOpenAllowed || set.SafeFailure.PublicDiscovery || set.SafeFailure.ProductionProvision || len(set.SafeFailure.FailureBuckets) < 6 {
		failures = append(failures, "safe failure policy unsafe")
	}
	return gate("relayauthplan_safe_failure", len(failures) == 0, "required", set.SafeFailure.Policy, nil, failures)
}

func RelayAuthPlanDowngradeRejectionGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if !set.DowngradeRejection.RejectsSilentDowngrade || len(set.DowngradeRejection.RequiredBindings) < 5 {
		failures = append(failures, "downgrade rejection incomplete")
	}
	return gate("relayauthplan_downgrade_rejection", len(failures) == 0, "required", set.DowngradeRejection.Policy, nil, failures)
}

func RelayAuthPlanUnknownStaleProfileGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if set.UnknownStaleProfile.UnknownVersionAccepted || set.UnknownStaleProfile.StaleProfileAccepted || len(set.UnknownStaleProfile.SafeDiagnostics) < 4 {
		failures = append(failures, "unknown/stale profile policy unsafe")
	}
	return gate("relayauthplan_unknown_stale_profile", len(failures) == 0, "required", set.UnknownStaleProfile.Policy, nil, failures)
}

func RelayAuthPlanM55PrereqGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if !set.OperationalPrereqs.M55Ready || len(set.OperationalPrereqs.RequiredArtifacts) < 7 {
		failures = append(failures, "M55 prerequisites incomplete")
	}
	return gate("relayauthplan_m55_prerequisites", len(failures) == 0, "required", set.OperationalPrereqs.PackageID, nil, failures)
}

func RelayAuthPlanMisuseGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range relayauthplan.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(relayauthplan.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("relayauthplan_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(relayauthplan.RequiredMisuseNames())-len(failures), len(relayauthplan.RequiredMisuseNames())), nil, failures)
}

func RelayAuthPlanGeneratedParityGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("relayauthplan_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func RelayAuthPlanTraceHygieneGate(set relayauthplan.FixtureSet) GateResult {
	failures := []string{}
	if err := relayauthplan.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.KeyMaterialLogged || set.TraceHygiene.AccountTracking {
		failures = append(failures, "trace hygiene flags unsafe")
	}
	return gate("relayauthplan_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func RelayAuthPlanPublicClaimSafetyGate(set relayauthplan.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "public claim safety failed")
	}
	return gate("relayauthplan_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func RelayAuthPlanFixtureDriftGate(report relayauthplan.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("relayauthplan_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func relayAuthPlanComparison(path string, current relayauthplan.FixtureSet) relayauthplan.FixtureComparisonReport {
	oldSet, err := relayauthplan.LoadFixtureSet(path)
	if err != nil {
		return relayauthplan.FixtureComparisonReport{Version: relayauthplan.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return relayauthplan.CompareFixtureSets(oldSet, current)
}
