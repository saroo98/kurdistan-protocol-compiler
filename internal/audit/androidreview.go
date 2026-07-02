// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/androidreview"
	"kurdistan/internal/mutant"
)

func RunAndroidReviewAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := androidreview.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := androidReviewComparison(filepath.Join(root, "testdata", "androidreview", "androidreview-report-golden.json"), set)
	gates := AndroidReviewGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "androidreview-" + cfg.Mode,
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

func AndroidReviewGates(set androidreview.FixtureSet, comparison androidreview.FixtureComparisonReport) []GateResult {
	return []GateResult{
		AndroidReviewReportGate(set),
		AndroidReviewUserFlowGate(set),
		AndroidReviewPermissionGate(set),
		AndroidReviewUIStateGate(set),
		AndroidReviewDiagnosticsPrivacyGate(set),
		AndroidReviewKillSwitchGate(set),
		AndroidReviewIntegrationGate(set),
		AndroidReviewFutureContractGate(set),
		AndroidReviewMisuseGate(set),
		AndroidReviewGeneratedParityGate(set),
		AndroidReviewTraceHygieneGate(set),
		AndroidReviewPublicClaimSafetyGate(set),
		AndroidReviewFixtureDriftGate(comparison),
	}
}

func AndroidReviewReportGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Decision != androidreview.DecisionReady || set.BlockerCount != 0 || set.RiskCount < 5 || set.Checklist.Failed != 0 {
		failures = append(failures, "Android architecture review report incomplete")
	}
	return gate("androidreview_report", len(failures) == 0, "required", fmt.Sprintf("decision=%s blockers=%d risks=%d checklist_failed=%d", set.Decision, set.BlockerCount, set.RiskCount, set.Checklist.Failed), nil, failures)
}

func AndroidReviewUserFlowGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.UserFlows.Flows) < 10 || len(set.UserFlows.SafeErrorClasses) < 6 {
		failures = append(failures, "Android user flows incomplete")
	}
	return gate("androidreview_user_flows", len(failures) == 0, "required", fmt.Sprintf("%d flows", len(set.UserFlows.Flows)), nil, failures)
}

func AndroidReviewPermissionGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Permissions.BypassesVPNPermission || set.Permissions.UnboundedBackgroundWork || set.Permissions.SilentBootStartAllowed || len(set.Permissions.RequiredPermissions) < 4 {
		failures = append(failures, "Android permission model unsafe")
	}
	return gate("androidreview_permission_model", len(failures) == 0, "required", set.Permissions.Policy, nil, failures)
}

func AndroidReviewUIStateGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if len(set.UIStates.States) < 14 || len(set.UIStates.Recoverable) < 5 {
		failures = append(failures, "Android UI states incomplete")
	}
	return gate("androidreview_ui_states", len(failures) == 0, "required", fmt.Sprintf("%d states", len(set.UIStates.States)), nil, failures)
}

func AndroidReviewDiagnosticsPrivacyGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.NetworkContentLogged || set.Diagnostics.DeviceIdentifierSaved || set.Diagnostics.AutoUploadAllowed {
		failures = append(failures, "Android diagnostics unsafe")
	}
	if set.Privacy.RawPacketStored || set.Privacy.PrivateEndpointStored || set.Privacy.CredentialStoredInLogs || set.Privacy.PhoneIdentifierCollected || set.Privacy.PreciseLocationCollected || set.Privacy.TelemetryUploadByDefault {
		failures = append(failures, "Android privacy boundary unsafe")
	}
	return gate("androidreview_diagnostics_privacy", len(failures) == 0, "required", set.Diagnostics.Policy, nil, failures)
}

func AndroidReviewKillSwitchGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if !set.KillSwitch.FailClosedRequired || set.KillSwitch.BypassAllowed || set.KillSwitch.ProfileInvalidFailsOpen || set.KillSwitch.PermissionLossFailsOpen {
		failures = append(failures, "Android kill-switch unsafe")
	}
	return gate("androidreview_kill_switch", len(failures) == 0, "required", set.KillSwitch.Policy, nil, failures)
}

func AndroidReviewIntegrationGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Integration.BypassesCarrierSelection || set.Integration.BypassesPathHealth || set.Integration.BypassesRelayAuth || set.Integration.BypassesMeasurementReview || set.Integration.BypassesCarrierReview || set.Integration.BypassesHardening || set.Integration.AllowsGeneratedDrift || len(set.Integration.RequiredCompositions) < 8 {
		failures = append(failures, "Android integration bypass unsafe")
	}
	return gate("androidreview_runtime_composition", len(failures) == 0, "required", set.Integration.Policy, nil, failures)
}

func AndroidReviewFutureContractGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Contracts.ReopenArchitecture || set.Contracts.AndroidImplAdded || len(set.Contracts.M57Requirements) < 6 || len(set.Contracts.M58Requirements) < 6 {
		failures = append(failures, "Android M57/M58 contracts incomplete")
	}
	return gate("androidreview_m57_m58_contracts", len(failures) == 0, "required", fmt.Sprintf("M57=%d M58=%d", len(set.Contracts.M57Requirements), len(set.Contracts.M58Requirements)), nil, failures)
}

func AndroidReviewMisuseGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range androidreview.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(androidreview.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("androidreview_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(androidreview.RequiredMisuseNames())-len(failures), len(androidreview.RequiredMisuseNames())), nil, failures)
}

func AndroidReviewGeneratedParityGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "Android generated/interpreted parity failed")
	}
	return gate("androidreview_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func AndroidReviewTraceHygieneGate(set androidreview.FixtureSet) GateResult {
	failures := []string{}
	if err := androidreview.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.NetworkContentLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged {
		failures = append(failures, "Android trace hygiene flags unsafe")
	}
	return gate("androidreview_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func AndroidReviewPublicClaimSafetyGate(set androidreview.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "Android public claim safety failed")
	}
	return gate("androidreview_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func AndroidReviewFixtureDriftGate(report androidreview.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "Android fixture drift detected")
	}
	return gate("androidreview_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func androidReviewComparison(path string, current androidreview.FixtureSet) androidreview.FixtureComparisonReport {
	oldSet, err := androidreview.LoadFixtureSet(path)
	if err != nil {
		return androidreview.FixtureComparisonReport{Version: androidreview.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return androidreview.CompareFixtureSets(oldSet, current)
}
