// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/contracts/readiness/keyexchangeplan"
	"kurdistan/internal/testkit/mutant"
)

func RunKeyExchangePlanAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := keyexchangeplan.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := keyExchangePlanComparison(filepath.Join(root, "testdata", "keyexchangeplan", "keyexchangeplan-report-golden.json"), set)
	gates := KeyExchangePlanGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "keyexchangeplan-" + cfg.Mode,
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

func KeyExchangePlanGates(set keyexchangeplan.FixtureSet, comparison keyexchangeplan.FixtureComparisonReport) []GateResult {
	return []GateResult{
		KeyExchangePlanDesignInventoryGate(set),
		KeyExchangePlanTranscriptBindingGate(set),
		KeyExchangePlanIdentityBindingGate(set),
		KeyExchangePlanNonceReplayGate(set),
		KeyExchangePlanDowngradeGate(set),
		KeyExchangePlanKeySeparationGate(set),
		KeyExchangePlanRotationReadinessGate(set),
		KeyExchangePlanGeneratedTransportCompatibilityGate(set),
		KeyExchangePlanExternalReviewReadinessGate(set),
		KeyExchangePlanMisuseGate(set),
		KeyExchangePlanGeneratedParityGate(set),
		KeyExchangePlanTraceHygieneGate(set),
		KeyExchangePlanPublicClaimSafetyGate(set),
		KeyExchangePlanFixtureDriftGate(comparison),
	}
}

func KeyExchangePlanDesignInventoryGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if len(set.DesignInventory) < 10 {
		failures = append(failures, "design inventory incomplete")
	}
	return gate("keyexchangeplan_design_inventory", len(failures) == 0, "required", fmt.Sprintf("%d design items", len(set.DesignInventory)), nil, failures)
}

func KeyExchangePlanTranscriptBindingGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if !set.TranscriptBinding.RejectsConfusion || len(set.TranscriptBinding.BoundComponents) < 6 {
		failures = append(failures, "transcript binding incomplete")
	}
	return gate("keyexchangeplan_transcript_binding", len(failures) == 0, "required", fmt.Sprintf("%d bound components", len(set.TranscriptBinding.BoundComponents)), nil, failures)
}

func KeyExchangePlanIdentityBindingGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if set.IdentityBinding.UnauthenticatedRelayID || len(set.IdentityBinding.RequiredChecks) < 4 {
		failures = append(failures, "identity binding unsafe")
	}
	return gate("keyexchangeplan_identity_binding", len(failures) == 0, "required", set.IdentityBinding.Policy, nil, failures)
}

func KeyExchangePlanNonceReplayGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if set.NonceReplay.NonceLogged || set.NonceReplay.ReplayAccepted || len(set.NonceReplay.RequiredChecks) < 5 {
		failures = append(failures, "nonce/replay contract unsafe")
	}
	return gate("keyexchangeplan_nonce_replay", len(failures) == 0, "required", set.NonceReplay.ReplayPolicy, nil, failures)
}

func KeyExchangePlanDowngradeGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if !set.DowngradeResistance.RejectsSilentDowngrade || len(set.DowngradeResistance.RequiredChecks) < 4 {
		failures = append(failures, "downgrade resistance incomplete")
	}
	return gate("keyexchangeplan_downgrade_resistance", len(failures) == 0, "required", set.DowngradeResistance.AlgorithmAgilityBoundary, nil, failures)
}

func KeyExchangePlanKeySeparationGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if set.KeySeparation.KeyReuseAllowed || len(set.KeySeparation.SeparatedContexts) < 5 {
		failures = append(failures, "key separation incomplete")
	}
	return gate("keyexchangeplan_key_separation", len(failures) == 0, "required", set.KeySeparation.Policy, nil, failures)
}

func KeyExchangePlanRotationReadinessGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if len(set.RotationReadiness.RequiredInterfaces) < 5 || set.RotationReadiness.ResumptionPolicy == "" {
		failures = append(failures, "rotation readiness incomplete")
	}
	return gate("keyexchangeplan_rotation_readiness", len(failures) == 0, "required", set.RotationReadiness.Policy, nil, failures)
}

func KeyExchangePlanGeneratedTransportCompatibilityGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if set.TransportCompatibility.GeneratedDriftAllowed || len(set.TransportCompatibility.GeneratedConstraints) < 5 {
		failures = append(failures, "generated transport compatibility unsafe")
	}
	return gate("keyexchangeplan_generated_transport_compatibility", len(failures) == 0, "required", set.TransportCompatibility.Policy, nil, failures)
}

func KeyExchangePlanExternalReviewReadinessGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if !set.ExternalReviewReadiness.IndependentReview || set.ExternalReviewReadiness.ReviewBypassAllowed || len(set.ExternalReviewReadiness.RequiredArtifacts) < 6 {
		failures = append(failures, "external crypto review package incomplete")
	}
	return gate("keyexchangeplan_external_crypto_review_readiness", len(failures) == 0, "required", set.ExternalReviewReadiness.PackageID, nil, failures)
}

func KeyExchangePlanMisuseGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range keyexchangeplan.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(keyexchangeplan.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("keyexchangeplan_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(keyexchangeplan.RequiredMisuseNames())-len(failures), len(keyexchangeplan.RequiredMisuseNames())), nil, failures)
}

func KeyExchangePlanGeneratedParityGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "generated/interpreted parity failed")
	}
	return gate("keyexchangeplan_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func KeyExchangePlanTraceHygieneGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := []string{}
	if err := keyexchangeplan.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.NonceLogged || set.TraceHygiene.AuthTagLogged {
		failures = append(failures, "trace hygiene flags unsafe")
	}
	return gate("keyexchangeplan_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func KeyExchangePlanPublicClaimSafetyGate(set keyexchangeplan.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "public claim safety failed")
	}
	return gate("keyexchangeplan_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func KeyExchangePlanFixtureDriftGate(report keyexchangeplan.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "fixture drift detected")
	}
	return gate("keyexchangeplan_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func keyExchangePlanComparison(path string, current keyexchangeplan.FixtureSet) keyexchangeplan.FixtureComparisonReport {
	oldSet, err := keyexchangeplan.LoadFixtureSet(path)
	if err != nil {
		return keyexchangeplan.FixtureComparisonReport{Version: keyexchangeplan.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return keyexchangeplan.CompareFixtureSets(oldSet, current)
}
