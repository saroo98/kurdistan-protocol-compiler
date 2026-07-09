// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"kurdistan/internal/contracts/android/androidvpnservice"
	"kurdistan/internal/mutant"
)

func RunAndroidVPNServiceAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	set, err := androidvpnservice.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		root = "."
	}
	comparison := androidVPNServiceComparison(filepath.Join(root, "testdata", "androidvpnservice", "androidvpnservice-report-golden.json"), set)
	gates := AndroidVPNServiceGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "androidvpnservice-" + cfg.Mode,
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

func AndroidVPNServiceGates(set androidvpnservice.FixtureSet, comparison androidvpnservice.FixtureComparisonReport) []GateResult {
	return []GateResult{
		AndroidVPNServiceReportGate(set),
		AndroidVPNServicePermissionGate(set),
		AndroidVPNServiceLifecycleGate(set),
		AndroidVPNServicePacketFlowGate(set),
		AndroidVPNServiceKillSwitchGate(set),
		AndroidVPNServiceDiagnosticsGate(set),
		AndroidVPNServiceReconnectGate(set),
		AndroidVPNServiceIntegrationGate(set),
		AndroidVPNServiceShutdownGate(set),
		AndroidVPNServiceMisuseGate(set),
		AndroidVPNServiceGeneratedParityGate(set),
		AndroidVPNServiceTraceHygieneGate(set),
		AndroidVPNServicePublicClaimSafetyGate(set),
		AndroidVPNServiceFixtureDriftGate(comparison),
	}
}

func AndroidVPNServiceReportGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if set.Decision != androidvpnservice.DecisionReady || set.BlockerCount != 0 || set.RiskCount < 7 || set.Checklist.Failed != 0 {
		failures = append(failures, "Android VpnService report incomplete")
	}
	return gate("androidvpnservice_report", len(failures) == 0, "required", fmt.Sprintf("decision=%s blockers=%d risks=%d checklist_failed=%d", set.Decision, set.BlockerCount, set.RiskCount, set.Checklist.Failed), nil, failures)
}

func AndroidVPNServicePermissionGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if !set.Permission.PermissionRequiredModeled || !set.Permission.PermissionGrantedModeled || !set.Permission.PermissionRevokedFailClose || set.Permission.StartWithoutPermission || set.Permission.BypassAllowed {
		failures = append(failures, "Android VpnService permission model unsafe")
	}
	return gate("androidvpnservice_permission_model", len(failures) == 0, "required", set.Permission.Policy, nil, failures)
}

func AndroidVPNServiceLifecycleGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Lifecycle.States) < len(androidvpnservice.RequiredVPNStates()) || len(set.Lifecycle.InvalidTransitionsRejected) < 6 || !set.Lifecycle.StartIdempotent || !set.Lifecycle.StopIdempotent || set.Lifecycle.InvalidTransitionAllowed || set.Lifecycle.PostStopPacketAccepted {
		failures = append(failures, "Android VpnService lifecycle unsafe")
	}
	return gate("androidvpnservice_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d states", len(set.Lifecycle.States)), nil, failures)
}

func AndroidVPNServicePacketFlowGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if !set.PacketFlow.PacketFlowMapped || set.PacketFlow.RuntimeStreamsMapped < 4 || set.PacketFlow.CarrierConnectedTraffic || set.PacketFlow.RawPacketCaptured || set.PacketFlow.PacketPayloadLogged || len(set.PacketFlow.RuntimeMappings) < 5 {
		failures = append(failures, "Android VpnService packet-flow mapping unsafe")
	}
	return gate("androidvpnservice_packet_flow_mapping", len(failures) == 0, "required", set.PacketFlow.Policy, nil, failures)
}

func AndroidVPNServiceKillSwitchGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if !set.KillSwitch.FailClosedRequired || len(set.KillSwitch.FailClosedTriggers) < 6 || set.KillSwitch.ProfileValidationFailureFailsOpen || set.KillSwitch.CarrierRuntimeFailureFailsOpen || set.KillSwitch.RelayCompatibilityFailsOpen || set.KillSwitch.AndroidVPNRevocationFailsOpen || set.KillSwitch.BypassAllowed {
		failures = append(failures, "Android VpnService kill switch unsafe")
	}
	return gate("androidvpnservice_kill_switch", len(failures) == 0, "required", set.KillSwitch.Policy, nil, failures)
}

func AndroidVPNServiceDiagnosticsGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if set.Diagnostics.PayloadLogged || set.Diagnostics.SecretLogged || set.Diagnostics.RawPacketLogged || set.Diagnostics.DestinationMetadataLogged || set.Diagnostics.DeviceIdentifierLogged || set.Diagnostics.AutoUploadAllowed || len(set.Diagnostics.AllowedFields) < 10 || len(set.Diagnostics.FailureClasses) < 8 {
		failures = append(failures, "Android VpnService diagnostics unsafe")
	}
	return gate("androidvpnservice_diagnostics", len(failures) == 0, "required", set.Diagnostics.Policy, nil, failures)
}

func AndroidVPNServiceReconnectGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if !set.Reconnect.NetworkSwitchHandled || !set.Reconnect.SleepWakeHandled || !set.Reconnect.PermissionChangeHandled || !set.Reconnect.RuntimeRestartHandled || set.Reconnect.UnboundedRetry || set.Reconnect.BackgroundPolicyBypassed || set.Reconnect.MaxReconnectAttempts <= 0 || set.Reconnect.MaxReconnectAttempts > 5 {
		failures = append(failures, "Android VpnService reconnect policy unsafe")
	}
	return gate("androidvpnservice_reconnect_hooks", len(failures) == 0, "required", set.Reconnect.Policy, nil, failures)
}

func AndroidVPNServiceIntegrationGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if !set.Integration.ProfileValidationLinked || !set.Integration.AndroidReviewLinked || !set.Integration.AndroidRuntimeLinked || !set.Integration.OperationalHardeningLinked || !set.Integration.VPNSemanticsLinked || !set.Integration.LocalVPNAdapterLinked || !set.Integration.PathHealthLinked || !set.Integration.MeasurementReviewLinked || !set.Integration.HardeningLinked || !set.Integration.GeneratedBackendCompatible || set.Integration.BypassesProfileValidation || set.Integration.BypassesMeasurementReview || set.Integration.AllowsGeneratedDrift || set.Integration.AllowsCarrierConnectedTraffic {
		failures = append(failures, "Android VpnService integration unsafe")
	}
	return gate("androidvpnservice_integration", len(failures) == 0, "required", set.Integration.Policy, nil, failures)
}

func AndroidVPNServiceShutdownGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if !set.Shutdown.StopIdempotent || !set.Shutdown.RuntimeSessionClosed || !set.Shutdown.QueuesDrained || !set.Shutdown.DiagnosticsFlushed || !set.Shutdown.FailClosedOnUnsafeStop || set.Shutdown.PostShutdownAllowed || set.Shutdown.LeakedWorkers != 0 {
		failures = append(failures, "Android VpnService shutdown unsafe")
	}
	return gate("androidvpnservice_shutdown", len(failures) == 0, "required", set.Shutdown.Policy, nil, failures)
}

func AndroidVPNServiceMisuseGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	have := map[string]bool{}
	for _, mode := range mutant.Modes() {
		have[mode] = true
	}
	for _, name := range androidvpnservice.RequiredMisuseNames() {
		if !have[name] {
			failures = append(failures, "missing mutant mode "+name)
		}
	}
	if set.Misuse.DetectedCount != len(androidvpnservice.RequiredMisuseNames()) {
		failures = append(failures, "misuse control count mismatch")
	}
	return gate("androidvpnservice_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d misuse controls detected", len(androidvpnservice.RequiredMisuseNames())-len(failures), len(androidvpnservice.RequiredMisuseNames())), nil, failures)
}

func AndroidVPNServiceGeneratedParityGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.InterpretedHash != set.Parity.GeneratedHash || len(set.Parity.GeneratedMarkers) < 6 {
		failures = append(failures, "Android VpnService generated/interpreted parity failed")
	}
	return gate("androidvpnservice_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func AndroidVPNServiceTraceHygieneGate(set androidvpnservice.FixtureSet) GateResult {
	failures := []string{}
	if err := androidvpnservice.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.TraceHygiene.PayloadLogged || set.TraceHygiene.SecretLogged || set.TraceHygiene.RawPacketLogged || set.TraceHygiene.DestinationLogged || set.TraceHygiene.DeviceIdentifierLogged || set.TraceHygiene.TelemetryMarkerLogged {
		failures = append(failures, "Android VpnService trace hygiene flags unsafe")
	}
	return gate("androidvpnservice_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d reports scanned", set.TraceHygiene.ReportsScanned), nil, failures)
}

func AndroidVPNServicePublicClaimSafetyGate(set androidvpnservice.FixtureSet) GateResult {
	failures := append([]string{}, set.PublicClaims.UnsafeClaimsFound...)
	if set.PublicClaims.Conclusion != "passed" {
		failures = append(failures, "Android VpnService public claim safety failed")
	}
	return gate("androidvpnservice_public_claim_safety", len(failures) == 0, "required", fmt.Sprintf("%d docs checked", set.PublicClaims.DocsChecked), nil, failures)
}

func AndroidVPNServiceFixtureDriftGate(report androidvpnservice.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "Android VpnService fixture drift detected")
	}
	return gate("androidvpnservice_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func androidVPNServiceComparison(path string, current androidvpnservice.FixtureSet) androidvpnservice.FixtureComparisonReport {
	oldSet, err := androidvpnservice.LoadFixtureSet(path)
	if err != nil {
		return androidvpnservice.FixtureComparisonReport{Version: androidvpnservice.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return androidvpnservice.CompareFixtureSets(oldSet, current)
}
