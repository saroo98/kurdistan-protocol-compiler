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

	"kurdistan/internal/loopbackrelay"
	"kurdistan/internal/mutant"
)

type LoopbackRelayAuditSummary struct {
	Version    string                                `json:"version"`
	Fixture    loopbackrelay.LoopbackRelayFixtureSet `json:"fixture"`
	Comparison loopbackrelay.FixtureComparisonReport `json:"comparison"`
}

func RunLoopbackRelayAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	_ = ctx
	start := time.Now()
	set, err := loopbackrelay.GenerateFixtureSet()
	if err != nil {
		return AuditReport{}, err
	}
	root, err := repoRoot()
	if err != nil {
		return AuditReport{}, err
	}
	comparison := loopbackRelayComparison(filepath.Join(root, "testdata", "loopbackrelay", "loopbackrelay-report-golden.json"), set)
	gates := LoopbackRelayGates(set, comparison)
	report := AuditReport{
		Version:          Version,
		Mode:             "loopbackrelay-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     100,
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

func LoopbackRelayGates(set loopbackrelay.LoopbackRelayFixtureSet, comparison loopbackrelay.FixtureComparisonReport) []GateResult {
	return []GateResult{
		LoopbackRelayBindPolicyGate(set),
		LoopbackRelaySessionLifecycleGate(set),
		LoopbackRelayHandshakeGate(set),
		LoopbackRelayFrameRoundTripGate(set),
		LoopbackRelayBackpressureGate(set),
		LoopbackRelayResetIsolationGate(set),
		LoopbackRelayMalformedInputGate(set),
		LoopbackRelayResourceLimitGate(set),
		LoopbackRelayTraceHygieneGate(set),
		LoopbackRelayGeneratedBackendParityGate(set),
		LoopbackRelayMutantDetectionGate(),
		LoopbackRelayFixtureDriftGate(comparison),
	}
}

func LoopbackRelayBindPolicyGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if err := loopbackrelay.ValidateConfig(set.Config); err != nil {
		failures = append(failures, err.Error())
	}
	if set.BindPolicy.UnsafeAddressesRejected < 4 {
		failures = append(failures, "unsafe loopback bind/dial controls not rejected")
	}
	return gate("loopbackrelay_bind_policy", len(failures) == 0, "required", fmt.Sprintf("%d unsafe controls rejected", set.BindPolicy.UnsafeAddressesRejected), nil, failures)
}

func LoopbackRelaySessionLifecycleGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Report.SessionsOpened == 0 || set.Report.SessionsClosed != set.Report.SessionsOpened {
		failures = append(failures, "sessions did not close cleanly")
	}
	return gate("loopbackrelay_session_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d sessions closed", set.Report.SessionsClosed), nil, failures)
}

func LoopbackRelayHandshakeGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Report.HandshakesCompleted != set.Report.SessionsOpened {
		failures = append(failures, "handshake count mismatch")
	}
	return gate("loopbackrelay_handshake", len(failures) == 0, "required", fmt.Sprintf("%d handshakes completed", set.Report.HandshakesCompleted), nil, failures)
}

func LoopbackRelayFrameRoundTripGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Report.FramesEncoded == 0 || set.Report.FramesEncoded != set.Report.FramesDecoded {
		failures = append(failures, "frame encode/decode mismatch")
	}
	return gate("loopbackrelay_frame_round_trip", len(failures) == 0, "required", fmt.Sprintf("%d frames round-tripped", set.Report.FramesEncoded), nil, failures)
}

func LoopbackRelayBackpressureGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Report.BackpressureEvents == 0 {
		failures = append(failures, "no loopback backpressure observed")
	}
	return gate("loopbackrelay_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d backpressure events", set.Report.BackpressureEvents), nil, failures)
}

func LoopbackRelayResetIsolationGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Report.ResetsObserved == 0 {
		failures = append(failures, "no reset isolation event observed")
	}
	return gate("loopbackrelay_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d resets observed", set.Report.ResetsObserved), nil, failures)
}

func LoopbackRelayMalformedInputGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Report.MalformedRejected == 0 {
		failures = append(failures, "malformed loopback frame not rejected")
	}
	return gate("loopbackrelay_malformed_input", len(failures) == 0, "required", fmt.Sprintf("%d malformed inputs rejected", set.Report.MalformedRejected), nil, failures)
}

func LoopbackRelayResourceLimitGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Config.MaxSessions <= 0 || set.Config.MaxFrameBytes <= 0 || set.Config.MaxBufferedBytes <= 0 || set.Report.SessionsOpened > set.Config.MaxSessions*2 {
		failures = append(failures, "loopback relay resource limits invalid")
	}
	return gate("loopbackrelay_resource_limits", len(failures) == 0, "required", "bounded sessions, frames, queues, and events", nil, failures)
}

func LoopbackRelayTraceHygieneGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if err := loopbackrelay.ScanForLeak(set); err != nil {
		failures = append(failures, err.Error())
	}
	if err := loopbackrelay.ScanForLeak(map[string]string{"raw_payload": "synthetic"}); err == nil {
		failures = append(failures, "unsafe loopback trace marker accepted")
	}
	return gate("loopbackrelay_trace_hygiene", len(failures) == 0, "required", "loopback relay summaries contain safe metadata only", nil, failures)
}

func LoopbackRelayGeneratedBackendParityGate(set loopbackrelay.LoopbackRelayFixtureSet) GateResult {
	failures := []string{}
	if set.Parity.Conclusion != "passed" || set.Parity.SemanticMatches != set.Parity.ComparedSessions {
		failures = append(failures, "generated/interpreted loopback relay parity failed")
	}
	root, err := repoRoot()
	if err == nil {
		raw, readErr := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator.go"))
		if readErr == nil {
			source := string(raw)
			for _, marker := range []string{"loopbackrelay_generated.go", "loopbackrelay_test.go", "loopbackrelay_parity_test.go", "loopbackrelay_hygiene_test.go", "LoopbackRelaySchemaVersion"} {
				if !strings.Contains(source, marker) {
					failures = append(failures, "missing generated loopback relay marker "+marker)
				}
			}
		}
	}
	return gate("loopbackrelay_generated_backend_parity", len(failures) == 0, "required", fmt.Sprintf("%d sessions compared", set.Parity.ComparedSessions), nil, failures)
}

func LoopbackRelayMutantDetectionGate() GateResult {
	required := []string{
		mutant.ModeLoopbackRelayAllowsExternalBind,
		mutant.ModeLoopbackRelayAllowsExternalDial,
		mutant.ModeLoopbackRelayAllowsDNSResolution,
		mutant.ModeLoopbackRelayLogsPayload,
		mutant.ModeLoopbackRelayIgnoresBackpressure,
		mutant.ModeLoopbackRelayAcceptsMalformedFrame,
		mutant.ModeLoopbackRelayGeneratedBackendDrift,
	}
	failures := missingMutantModes(required)
	return gate("loopbackrelay_mutant_detection", len(failures) == 0, "required", fmt.Sprintf("%d/%d loopback relay mutant modes detected", len(required)-len(failures), len(required)), nil, failures)
}

func LoopbackRelayFixtureDriftGate(report loopbackrelay.FixtureComparisonReport) GateResult {
	failures := append([]string{}, report.UnexpectedDrift...)
	if report.Conclusion != "passed" {
		failures = append(failures, "loopback relay fixture drift detected")
	}
	return gate("loopbackrelay_fixture_drift", len(failures) == 0, "required", report.Conclusion, map[string]any{"comparison": report}, failures)
}

func loopbackRelayComparison(path string, current loopbackrelay.LoopbackRelayFixtureSet) loopbackrelay.FixtureComparisonReport {
	oldSet, err := loopbackrelay.LoadFixtureSet(path)
	if err != nil {
		return loopbackrelay.FixtureComparisonReport{Version: loopbackrelay.Version, NewHash: current.FixtureHash, UnexpectedDrift: []string{err.Error()}, Conclusion: "failed"}
	}
	return loopbackrelay.CompareFixtureSets(oldSet, current)
}
