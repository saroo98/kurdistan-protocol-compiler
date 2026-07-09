// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/contracts/android/androidcarrier"
	"kurdistan/internal/mutant"
)

func RunAndroidCarrierAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := androidcarrier.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := androidCarrierComparison(filepath.Join(root, "testdata", "androidcarrier", "androidcarrier-report-golden.json"), set)
	gates := AndroidCarrierGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "androidcarrier-" + cfg.Mode,
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

func AndroidCarrierGates(set androidcarrier.FixtureSet, comparison androidcarrier.FixtureComparisonReport) []GateResult {
	return []GateResult{
		AndroidCarrierReportGate(set),
		AndroidCarrierRuntimePathGate(set),
		AndroidCarrierUIStateGate(set),
		AndroidCarrierSelectionGate(set),
		AndroidCarrierRelayCompatibilityGate(set),
		AndroidCarrierFlowIntegrationGate(set),
		AndroidCarrierFailureDiagnosticsGate(set),
		AndroidCarrierReconnectFallbackGate(set),
		AndroidCarrierProfileValidationGate(set),
		AndroidCarrierShutdownSafetyGate(set),
		AndroidCarrierMisuseGate(set),
		AndroidCarrierGeneratedParityGate(set),
		AndroidCarrierTraceHygieneGate(set),
		AndroidCarrierPublicClaimSafetyGate(set),
		AndroidCarrierFixtureDriftGate(comparison),
	}
}

func AndroidCarrierReportGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Decision != androidcarrier.DecisionReady || set.BlockerCount != 0 || set.RiskCount < 8 || set.Checklist.Failed != 0 {
		failures = append(failures, "Android carrier integration report incomplete")
	}
	return gate("androidcarrier_report", len(failures) == 0, "required", fmt.Sprintf("decision=%s blockers=%d risks=%d checklist_failed=%d", set.Decision, set.BlockerCount, set.RiskCount, set.Checklist.Failed), nil, failures)
}

func AndroidCarrierRuntimePathGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.RuntimePath.ProfileValidationBeforeConnect || !set.RuntimePath.RuntimeInitialized || !set.RuntimePath.CarrierSelectionCompleted || !set.RuntimePath.RelayCompatibilityChecked || !set.RuntimePath.AuthenticatedSessionEstablished || !set.RuntimePath.StreamMappingCompleted || !set.RuntimePath.PathHealthChecked || !set.RuntimePath.SafeShutdownLinked || set.RuntimePath.BypassesProfileValidation || set.RuntimePath.BypassesCarrierSelection || set.RuntimePath.BypassesRelayCompatibility || set.RuntimePath.UnreviewedPublicNetworkEgress || set.RuntimePath.UnrestrictedTrafficForwarding || len(set.RuntimePath.RequiredStages) < 9 {
		failures = append(failures, "Android carrier runtime path unsafe")
	}
	return gate("androidcarrier_runtime_path", len(failures) == 0, "required", set.RuntimePath.Policy, nil, failures)
}

func AndroidCarrierUIStateGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !containsAllAndroidCarrierStrings(set.UIStates.States, androidcarrier.RequiredUIStates()) || !set.UIStates.CarrierFailureVisible || !set.UIStates.RelayFailureVisible || !set.UIStates.ProfileExpiryVisible || !set.UIStates.FallbackAttemptVisible || !set.UIStates.DiagnosticReadyVisible || set.UIStates.FieldReadyClaimVisible || set.UIStates.GuaranteedBypassDisplayed {
		failures = append(failures, "Android carrier UI states incomplete or unsafe")
	}
	return gate("androidcarrier_ui_states", len(failures) == 0, "required", fmt.Sprintf("%d states", len(set.UIStates.States)), nil, failures)
}

func AndroidCarrierSelectionGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.CarrierSelection.SelectionRespectsProfile || !set.CarrierSelection.CarrierReviewEnforced || !set.CarrierSelection.MeasurementReviewEnforced || !set.CarrierSelection.PathHealthEnforced || !set.CarrierSelection.RuntimeCompatibilityEnforced || !set.CarrierSelection.OperationalSafetyEnforced || !set.CarrierSelection.GeneratedParityEnforced || set.CarrierSelection.HighRiskDefaultAllowed || set.CarrierSelection.ReviewBypassAllowed || set.CarrierSelection.UnboundedFallbackAllowed || set.CarrierSelection.PublicCarrierAutoSelected || len(set.CarrierSelection.RequiredGates) < 7 {
		failures = append(failures, "Android carrier selection bypassed reviewed constraints")
	}
	return gate("androidcarrier_carrier_selection", len(failures) == 0, "required", set.CarrierSelection.Policy, nil, failures)
}

func AndroidCarrierRelayCompatibilityGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.RelayCompatibility.ProfileIdentityBound || !set.RelayCompatibility.RelayIdentityBound || !set.RelayCompatibility.RelayAuthChecked || !set.RelayCompatibility.RotationWindowChecked || !set.RelayCompatibility.ExpiredProfileRejected || !set.RelayCompatibility.UnknownRelayRejected || !set.RelayCompatibility.AuthenticatedSessionEstablished || set.RelayCompatibility.RelayBypassAllowed || set.RelayCompatibility.DowngradeAccepted || len(set.RelayCompatibility.RequiredChecks) < 7 {
		failures = append(failures, "Android carrier relay compatibility unsafe")
	}
	return gate("androidcarrier_relay_compatibility", len(failures) == 0, "required", set.RelayCompatibility.Policy, nil, failures)
}

func AndroidCarrierFlowIntegrationGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.FlowIntegration.AndroidVpnServiceLinked || !set.FlowIntegration.ControlledTrafficRepresented || !set.FlowIntegration.ConnectedThroughCarrier || set.FlowIntegration.RuntimeStreamsMapped < 4 || set.FlowIntegration.CarrierEnvelopesMapped < 4 || set.FlowIntegration.PacketPayloadLogged || set.FlowIntegration.PacketCaptureEnabled || set.FlowIntegration.RawDestinationLogged || set.FlowIntegration.AppIdentityLogged || len(set.FlowIntegration.MappingRules) < 5 {
		failures = append(failures, "Android carrier flow integration unsafe")
	}
	return gate("androidcarrier_flow_integration", len(failures) == 0, "required", fmt.Sprintf("%d runtime streams, %d carrier envelopes", set.FlowIntegration.RuntimeStreamsMapped, set.FlowIntegration.CarrierEnvelopesMapped), nil, failures)
}

func AndroidCarrierFailureDiagnosticsGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.FailureDiagnostics.CarrierFailuresSurfaced || !set.FailureDiagnostics.RuntimeFailuresSurfaced || !set.FailureDiagnostics.RelayFailuresSurfaced || !set.FailureDiagnostics.ProfileFailuresSurfaced || !set.FailureDiagnostics.FallbackFailuresSurfaced || set.FailureDiagnostics.PayloadLogged || set.FailureDiagnostics.SecretLogged || set.FailureDiagnostics.RawPacketLogged || set.FailureDiagnostics.DomainLogged || set.FailureDiagnostics.URLLogged || set.FailureDiagnostics.SNIHostLogged || set.FailureDiagnostics.DeviceIdentifierLogged || set.FailureDiagnostics.TelemetryUploadConfigured || len(set.FailureDiagnostics.FailureClasses) < 10 {
		failures = append(failures, "Android carrier diagnostics unsafe")
	}
	return gate("androidcarrier_failure_diagnostics", len(failures) == 0, "required", fmt.Sprintf("%d failure classes", len(set.FailureDiagnostics.FailureClasses)), nil, failures)
}

func AndroidCarrierReconnectFallbackGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.ReconnectFallback.NetworkChangeRecovery || !set.ReconnectFallback.CarrierFailureRecovery || !set.ReconnectFallback.RuntimeRestartRecovery || !set.ReconnectFallback.FallbackExhaustionFailClosed || !set.ReconnectFallback.KillSwitchInteractionChecked || set.ReconnectFallback.UnboundedRetry || set.ReconnectFallback.UnsafeFallbackAllowed || set.ReconnectFallback.MaxFallbackAttempts <= 0 || set.ReconnectFallback.MaxFallbackAttempts > 3 || set.ReconnectFallback.MaxReconnectAttempts <= 0 || set.ReconnectFallback.MaxReconnectAttempts > 5 || set.ReconnectFallback.MaxQueuedEvents < 32 {
		failures = append(failures, "Android carrier reconnect/fallback unsafe")
	}
	return gate("androidcarrier_reconnect_fallback", len(failures) == 0, "required", set.ReconnectFallback.Policy, nil, failures)
}

func AndroidCarrierProfileValidationGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.ProfileValidation.ImportedProfileValidated || !set.ProfileValidation.ProfileHashChecked || !set.ProfileValidation.ProfileExpiryChecked || !set.ProfileValidation.RelayCompatibilityBeforeStart || !set.ProfileValidation.InvalidProfileFailsClosed || !set.ProfileValidation.ExpiredProfileFailsClosed || !set.ProfileValidation.StaleProfileRejected || set.ProfileValidation.ProfileValidationBypassed || len(set.ProfileValidation.ValidationStages) < 6 {
		failures = append(failures, "Android carrier profile validation unsafe")
	}
	return gate("androidcarrier_profile_validation", len(failures) == 0, "required", set.ProfileValidation.Policy, nil, failures)
}

func AndroidCarrierShutdownSafetyGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if !set.ShutdownSafety.CarrierSessionClosed || !set.ShutdownSafety.RuntimeSessionClosed || !set.ShutdownSafety.AndroidFlowClosed || !set.ShutdownSafety.DiagnosticsFlushed || !set.ShutdownSafety.KillSwitchEngagedOnUnsafe || !set.ShutdownSafety.StopIdempotent || set.ShutdownSafety.PostShutdownTraffic || set.ShutdownSafety.LeakedSessions != 0 {
		failures = append(failures, "Android carrier shutdown unsafe")
	}
	return gate("androidcarrier_shutdown_safety", len(failures) == 0, "required", set.ShutdownSafety.Policy, nil, failures)
}

func AndroidCarrierMisuseGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range androidcarrier.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(androidcarrier.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("androidcarrier_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(androidcarrier.RequiredMisuseNames())-len(failures), len(androidcarrier.RequiredMisuseNames())), nil, failures)
}

func AndroidCarrierGeneratedParityGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "Android carrier generated/interpreted parity failed")
	}
	return gate("androidcarrier_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func AndroidCarrierTraceHygieneGate(set androidcarrier.FixtureSet) GateResult {
	failures := []string{}
	if err := androidcarrier.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.DomainLogged || set.TraceHygiene.URLLogged || set.TraceHygiene.SNIHostLogged || set.TraceHygiene.ResolverLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged {
		failures = append(failures, "Android carrier trace hygiene flags unsafe")
	}
	return gate("androidcarrier_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func AndroidCarrierPublicClaimSafetyGate(set androidcarrier.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "Android carrier public claim safety failed")
	}
	return gate("androidcarrier_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func AndroidCarrierFixtureDriftGate(report androidcarrier.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "Android carrier fixture drift detected")
	}
	return gate("androidcarrier_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func androidCarrierComparison(path string, current androidcarrier.FixtureSet) androidcarrier.FixtureComparisonReport {
	oldSet, err := androidcarrier.LoadFixtureSet(path)
	if err != nil {
		return androidcarrier.FixtureComparisonReport{Version: androidcarrier.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return androidcarrier.CompareFixtureSets(oldSet, current)
}

func containsAllAndroidCarrierStrings(have, want []string) bool {
	seen := map[string]bool{}
	for _, item := range have {
		seen[item] = true
	}
	for _, item := range want {
		if !seen[item] {
			return false
		}
	}
	return true
}
