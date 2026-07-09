// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/contracts/carrier/httpslikecarrier"
	"kurdistan/internal/testkit/mutant"
)

func RunHTTPSLikeCarrierAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := httpslikecarrier.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := httpsLikeCarrierComparison(filepath.Join(root, "testdata", "httpslikecarrier", "httpslikecarrier-report-golden.json"), set)
	gates := HTTPSLikeCarrierGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "httpslikecarrier-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     cfg.ProfileCount,
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

func HTTPSLikeCarrierGates(set httpslikecarrier.FixtureSet, comparison httpslikecarrier.FixtureComparisonReport) []GateResult {
	return []GateResult{
		HTTPSLikeCarrierScopeGate(set),
		HTTPSLikeCarrierShapeSelectionGate(set),
		HTTPSLikeCarrierSessionLifecycleGate(set),
		HTTPSLikeCarrierStreamLifecycleGate(set),
		HTTPSLikeCarrierFixtureExchangeGate(set),
		HTTPSLikeCarrierBackpressureGate(set),
		HTTPSLikeCarrierResetErrorGate(set),
		HTTPSLikeCarrierRelayIntegrationGate(set),
		HTTPSLikeCarrierPipelineIntegrationGate(set),
		HTTPSLikeCarrierRuntimeSecurityGate(set),
		HTTPSLikeCarrierResourceLimitsGate(set),
		HTTPSLikeCarrierMisuseDetectionGate(set),
		HTTPSLikeCarrierGeneratedBackendParityGate(set),
		HTTPSLikeCarrierTraceHygieneGate(set),
		HTTPSLikeCarrierMutantDetectionGate(),
		HTTPSLikeCarrierFixtureDriftGate(comparison),
	}
}

func HTTPSLikeCarrierScopeGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	required := []string{
		"real_tls",
		"real_https_client",
		"sni_routing",
		"host_header_routing",
		"domain_dependency",
		"cdn_provider_integration",
		"public_network_egress",
		"arbitrary_destination_proxying",
		"payload_logging",
		"packet_capture",
		"measurement_upload",
	}
	for _, want := range required {
		if !containsHTTPSLikeCarrierString(set.Report.ScopesBlocked, want) {
			failures = append(failures, "scope blocker missing: "+want)
		}
	}
	if !set.Report.PublicNetworkBlocked || !set.Report.RealTLSBlocked {
		failures = append(failures, "public network or real TLS blocker not asserted")
	}
	return gate("httpslikecarrier_scope", len(failures) == 0, "required", fmt.Sprintf("%d blocked scopes checked", len(set.Report.ScopesBlocked)), nil, failures)
}

func HTTPSLikeCarrierShapeSelectionGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.RequestShapes) < 4 || len(set.Report.ResponseShapes) < 4 {
		failures = append(failures, "request/response shape classes incomplete")
	}
	if len(set.Report.ShapeDiversityFingerprints) < 8 {
		failures = append(failures, "profile-sensitive shape diversity too low")
	}
	for _, shape := range append(set.Report.RequestShapes, set.Report.ResponseShapes...) {
		if !shape.ProfileSensitive || !shape.PayloadFree || shape.Hash == "" {
			failures = append(failures, "unsafe or unstable shape class: "+shape.ID)
		}
	}
	return gate("httpslikecarrier_shape_selection", len(failures) == 0, "required", fmt.Sprintf("%d shape events and %d diversity fingerprints", len(set.Report.ShapeEvents), len(set.Report.ShapeDiversityFingerprints)), nil, failures)
}

func HTTPSLikeCarrierSessionLifecycleGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if len(set.Report.Sessions) < 4 {
		failures = append(failures, "session lifecycle reports incomplete")
	}
	for _, session := range set.Report.Sessions {
		if session.Hash == "" || len(session.States) < 2 {
			failures = append(failures, "unstable session report: "+session.SessionID)
		}
	}
	return gate("httpslikecarrier_session_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d sessions checked", len(set.Report.Sessions)), nil, failures)
}

func HTTPSLikeCarrierStreamLifecycleGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.StreamsOpened < 4 || set.Report.StreamsClosed == 0 || set.Report.StreamResets == 0 {
		failures = append(failures, "stream open/close/reset lifecycle evidence incomplete")
	}
	for _, stream := range set.Report.Streams {
		if !stream.Isolated || stream.Hash == "" || stream.RequestShape == "" || stream.ResponseShape == "" {
			failures = append(failures, "unsafe stream report")
		}
	}
	return gate("httpslikecarrier_stream_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d streams opened; %d reset", set.Report.StreamsOpened, set.Report.StreamResets), nil, failures)
}

func HTTPSLikeCarrierFixtureExchangeGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	exchange := set.Report.FixtureExchange
	if !exchange.Bounded || exchange.OversizedMarkersRejected == 0 || exchange.PayloadLogged || exchange.SecretLogged {
		failures = append(failures, "fixture exchange did not prove bounded safe metadata")
	}
	if len(set.Fixtures) < 10 {
		failures = append(failures, "fixture controls incomplete")
	}
	return gate("httpslikecarrier_fixture_exchange", len(failures) == 0, "required", fmt.Sprintf("%d fixtures; marker bucket %s", len(set.Fixtures), exchange.MarkerSizeBucket), nil, failures)
}

func HTTPSLikeCarrierBackpressureGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.BackpressureEvents == 0 || set.Report.QueuePressureEvents == 0 {
		failures = append(failures, "backpressure or queue pressure evidence missing")
	}
	return gate("httpslikecarrier_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d pressure events", set.Report.BackpressureEvents+set.Report.QueuePressureEvents), nil, failures)
}

func HTTPSLikeCarrierResetErrorGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Report.StreamResets == 0 || set.Report.TargetErrors == 0 {
		failures = append(failures, "reset/error carrier mapping missing")
	}
	return gate("httpslikecarrier_reset_error", len(failures) == 0, "required", fmt.Sprintf("%d resets and %d target errors", set.Report.StreamResets, set.Report.TargetErrors), nil, failures)
}

func HTTPSLikeCarrierRelayIntegrationGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := missingIntegration(set, []string{"loopbackrelay", "labegress", "relaybridge", "proxyegress"})
	return gate("httpslikecarrier_relay_integration", len(failures) == 0, "required", "loopbackrelay labegress relaybridge proxyegress mappings checked", nil, failures)
}

func HTTPSLikeCarrierPipelineIntegrationGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := missingIntegration(set, []string{"localpipeline", "pathrace", "pathhealth", "carrierreview", "measurementreview"})
	if !set.Report.PathHealthEnforced || !set.Report.CarrierReviewEnforced || !set.Report.MeasurementReviewEnforced {
		failures = append(failures, "review/health enforcement flags missing")
	}
	return gate("httpslikecarrier_pipeline_integration", len(failures) == 0, "required", "localpipeline pathhealth carrierreview measurementreview mappings checked", nil, failures)
}

func HTTPSLikeCarrierRuntimeSecurityGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	status := set.Report.RuntimeSecurity
	if !status.RuntimeBound || !status.SecureEnvelopeMetadata || !status.GeneratedTransportCompatible || status.ProductionKeyingChanged || status.CryptographicSecretLogged {
		failures = append(failures, "runtime/security metadata integration unsafe")
	}
	return gate("httpslikecarrier_runtime_security", len(failures) == 0, "required", status.Conclusion, nil, failures)
}

func HTTPSLikeCarrierResourceLimitsGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	limits := set.Report.ResourceLimits
	if limits.MaxSessions <= 0 || limits.MaxStreams <= 0 || limits.MaxMarkerBytes <= 0 || !limits.DeterministicShutdown || !limits.PanicSafetyChecked || !limits.OversizedMarkerRejected {
		failures = append(failures, "resource limits incomplete")
	}
	return gate("httpslikecarrier_resource_limits", len(failures) == 0, "required", fmt.Sprintf("sessions=%d streams=%d marker=%d", limits.MaxSessions, limits.MaxStreams, limits.MaxMarkerBytes), nil, failures)
}

func HTTPSLikeCarrierMisuseDetectionGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Misuse.DetectedCount < 23 || set.Misuse.Conclusion != "passed" {
		failures = append(failures, "misuse scanner did not cover required controls")
	}
	if set.Misuse.PayloadLogged || set.Misuse.SecretLogged {
		failures = append(failures, "misuse report leaked unsafe metadata")
	}
	return gate("httpslikecarrier_misuse_detection", len(failures) == 0, "required", fmt.Sprintf("%d misuse controls detected", set.Misuse.DetectedCount), nil, failures)
}

func HTTPSLikeCarrierGeneratedBackendParityGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || len(set.Parity.UnexpectedDifferences) > 0 || set.Parity.PayloadLogged || set.Parity.SecretLogged {
		failures = append(failures, "generated/interpreted HTTPS-like carrier parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := codegenGeneratorSource(root)
		if readErr == nil {
			source := string(raw)
			for _, marker := range set.Parity.GeneratedMarkers {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated HTTPS-like carrier marker "+marker)
				}
			}
		}
	}
	return gate("httpslikecarrier_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d generated markers checked", len(set.Parity.GeneratedMarkers)), nil, failures)
}

func HTTPSLikeCarrierTraceHygieneGate(set httpslikecarrier.FixtureSet) GateResult {
	failures := []string{}
	if err := httpslikecarrier.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if set.PayloadLogged || set.SecretLogged || set.Report.PayloadLogged || set.Report.SecretLogged {
		failures = append(failures, "HTTPS-like carrier trace hygiene failed")
	}
	return gate("httpslikecarrier_trace_hygiene", len(failures) == 0, "required", "fixtures and summaries scanned for unsafe material", nil, failures)
}

func HTTPSLikeCarrierMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeHTTPSLikeCarrierAllowsRealTLS,
		mutant.ModeHTTPSLikeCarrierAllowsSNIRouting,
		mutant.ModeHTTPSLikeCarrierAllowsHostHeaderRouting,
		mutant.ModeHTTPSLikeCarrierAllowsDomainDependency,
		mutant.ModeHTTPSLikeCarrierAllowsCDNProvider,
		mutant.ModeHTTPSLikeCarrierAllowsPublicNetwork,
		mutant.ModeHTTPSLikeCarrierAllowsArbitraryEgress,
		mutant.ModeHTTPSLikeCarrierAllowsPayloadForwarding,
		mutant.ModeHTTPSLikeCarrierAllowsPayloadLogging,
		mutant.ModeHTTPSLikeCarrierAllowsPacketCapture,
		mutant.ModeHTTPSLikeCarrierAllowsMeasurementUpload,
		mutant.ModeHTTPSLikeCarrierFixedShape,
		mutant.ModeHTTPSLikeCarrierPaddingOnlyVariation,
		mutant.ModeHTTPSLikeCarrierProfileInsensitive,
		mutant.ModeHTTPSLikeCarrierIgnoresBackpressure,
		mutant.ModeHTTPSLikeCarrierSwallowsReset,
		mutant.ModeHTTPSLikeCarrierCrossStreamLeak,
		mutant.ModeHTTPSLikeCarrierPathHealthBypass,
		mutant.ModeHTTPSLikeCarrierMeasurementReviewBypass,
		mutant.ModeHTTPSLikeCarrierCarrierReviewBypass,
		mutant.ModeHTTPSLikeCarrierGeneratedBackendDrift,
		mutant.ModeHTTPSLikeCarrierPayloadLeak,
		mutant.ModeHTTPSLikeCarrierSecretLeak,
	}
	failures := missingMutantModes(required)
	return gate("httpslikecarrier_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d HTTPS-like carrier mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func HTTPSLikeCarrierFixtureDriftGate(report httpslikecarrier.FixtureComparisonReport) GateResult {
	failures := []string{}
	if report.Conclusion != "passed" {
		failures = append(failures, report.UnexpectedDrift...)
	}
	return gate("httpslikecarrier_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func httpsLikeCarrierComparison(path string, current httpslikecarrier.FixtureSet) httpslikecarrier.FixtureComparisonReport {
	oldSet, err := httpslikecarrier.LoadFixtureSet(path)
	if err != nil {
		return httpslikecarrier.FixtureComparisonReport{Version: httpslikecarrier.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return httpslikecarrier.CompareFixtureSets(oldSet, current)
}

func missingIntegration(set httpslikecarrier.FixtureSet, required []string) []string {
	failures := []string{}
	seen := map[string]bool{}
	for _, status := range set.Report.Integrations {
		if status.Composed && status.Conclusion == "passed" {
			seen[status.Layer] = true
		}
	}
	for _, layer := range required {
		if !seen[layer] {
			failures = append(failures, "missing integration evidence: "+layer)
		}
	}
	return failures
}

func containsHTTPSLikeCarrierString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
