// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/phase17evidence"
)

func TestTerminalDurationMillisecondsNeverDropsImmediateFailureEvidence(t *testing.T) {
	for _, elapsed := range []time.Duration{0, time.Nanosecond, 999 * time.Microsecond, time.Millisecond} {
		if got := terminalDurationMilliseconds(elapsed); got != 1 {
			t.Fatalf("elapsed=%v durationMs=%d", elapsed, got)
		}
	}
	if got := terminalDurationMilliseconds(2500 * time.Millisecond); got != 2500 {
		t.Fatalf("durationMs=%d", got)
	}
}

func TestBuildPassingEvidenceV3BindsQualifiedCandidateAndExactCampaign(t *testing.T) {
	fixture := newQualifiedRunFixture(t, "Stress")
	qualified, err := loadQualifiedRun("Stress", fixture.inputs, fixture.artifacts)
	if err != nil {
		t.Fatal(err)
	}
	outcome := functionalOutcome{campaign: rawCampaign{
		Mode: "Stress", RestartReconnectCycles: 100, ProfileRotationCycles: 100,
		Impairments: []string{"bandwidth", "latency", "loss", "combined", "carrier-reset"},
	}, reconnects: 205}
	tracker := resourceTracker{peakRSS: 32 << 20, peakFDs: 48, peakSwap: 0, peakOOMKills: 0}
	value, err := buildPassingEvidenceV3(
		qualified, 36, "x86_64", true, 12_000, tracker, outcome,
		validScannerReceiptsForRunnerTest(),
		phase17evidence.FieldBoundaryV3{Result: "PASS", MonitorSHA256: strings.Repeat("4", 64)},
	)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := phase17evidence.MarshalOwnedVPSRawV3(value)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := phase17evidence.DecodeOwnedVPSRawV3(raw)
	if err != nil {
		t.Fatal(err)
	}
	if decoded.Subject.CandidateID != qualified.candidate.Roots.CandidateID || decoded.Attempt.AttemptID != qualified.attempt.AttemptID ||
		decoded.Campaign.SoakDurationMS != 0 || decoded.Campaign.RestartReconnectCycles != 100 || decoded.Metrics.Reconnects != 205 {
		t.Fatalf("evidence=%+v", decoded)
	}
}

func TestBuildTerminalEvidenceV3RecordsCategoricalFailureWithoutInventingPasses(t *testing.T) {
	fixture := newQualifiedRunFixture(t, "Stress")
	qualified, err := loadQualifiedRun("Stress", fixture.inputs, fixture.artifacts)
	if err != nil {
		t.Fatal(err)
	}
	value, err := buildTerminalEvidenceV3(
		qualified, 36, "x86_64", true, 5_000,
		resourceTracker{peakRSS: 1 << 20, peakFDs: 12},
		functionalOutcome{campaign: rawCampaign{Mode: "Stress", RestartReconnectCycles: 7, Impairments: []string{}}},
		&fieldActionFailure{action: "traffic", category: "INSTRUMENTATION_STARTED_WITHOUT_TERMINAL_RESULT"},
	)
	if err != nil {
		t.Fatal(err)
	}
	if value.Outcome != "FAIL_HARNESS" || value.Checks[21].Result != "FAIL" || value.Checks[0].Result != "NOT_RUN" ||
		value.Scanners[0].Result != "NOT_RUN" || value.Boundary.Result != "NOT_RUN" ||
		value.Campaign.RestartReconnectCycles != 7 {
		t.Fatalf("terminal evidence=%+v", value)
	}
	if _, err := phase17evidence.MarshalOwnedVPSRawV3(value); err != nil {
		t.Fatal(err)
	}
}

func TestBuildTerminalEvidenceV3ClassifiesPrivacyAndIdentityFailuresFailClosed(t *testing.T) {
	fixture := newQualifiedRunFixture(t, "Functional")
	qualified, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		err         error
		wantOutcome string
		wantCheck   string
	}{
		"privacy":             {err: errors.New("boundary monitor found route or DNS leakage"), wantOutcome: "FAIL_PRIVACY", wantCheck: "routeDnsLeak"},
		"continuous boundary": {err: &fieldActionFailure{action: "traffic", category: "BOUNDARY_LEAK"}, wantOutcome: "FAIL_PRIVACY", wantCheck: "routeDnsLeak"},
		"detailed boundary": {
			err: &fieldActionFailure{
				action:   "traffic",
				category: "BOUNDARY_LEAK:VPN_PASS:IPV4_PASS:IPV6_PASS:DNS_FAIL:BYPASS_PASS:TUNNEL_PASS:COVERAGE_PASS",
			},
			wantOutcome: "FAIL_PRIVACY",
			wantCheck:   "routeDnsLeak",
		},
		"identity":            {err: errors.New("source identity differs from locked candidate"), wantOutcome: "INVALID_IDENTITY", wantCheck: "preflight"},
		"forward suspend gap": {err: errCampaignClockGap, wantOutcome: "ABORT_ENVIRONMENT", wantCheck: "preflight"},
		"backward clock jump": {err: errCampaignClockReversed, wantOutcome: "ABORT_ENVIRONMENT", wantCheck: "preflight"},
		"authorized emulator lost": {
			err: errAndroidEnvironmentUnavailable, wantOutcome: "ABORT_ENVIRONMENT", wantCheck: "preflight",
		},
		"owner VPS transport lost": {
			err: errVPSEnvironmentUnavailable, wantOutcome: "ABORT_ENVIRONMENT", wantCheck: "preflight",
		},
		"ambiguous cancellation": {err: context.Canceled, wantOutcome: "INCONCLUSIVE", wantCheck: "preflight"},
	} {
		t.Run(name, func(t *testing.T) {
			value, err := buildTerminalEvidenceV3(
				qualified, 36, "x86_64", true, 1_000,
				resourceTracker{}, functionalOutcome{campaign: rawCampaign{Mode: "Functional", Impairments: []string{}}}, test.err,
			)
			if err != nil {
				t.Fatal(err)
			}
			if value.Outcome != test.wantOutcome || checkResultV3(value.Checks, test.wantCheck) == "PASS" {
				t.Fatalf("evidence=%+v", value)
			}
		})
	}
}

func TestCleanupFailureIsHarnessFailureWithoutErasingEarlierProductFailure(t *testing.T) {
	var onlyCleanup error
	joinFieldCleanup(&onlyCleanup, errors.New("synthetic cleanup failure"))
	if outcome, check := classifyFieldFailure(onlyCleanup, functionalOutcome{}); outcome != "FAIL_HARNESS" || check != "preflight" {
		t.Fatalf("cleanup classification=(%s,%s)", outcome, check)
	}

	primary := error(&fieldActionFailure{action: "traffic", category: "DATA_PLANE_PROBE_FAILED"})
	joinFieldCleanup(&primary, errors.New("synthetic cleanup failure"))
	if outcome, check := classifyFieldFailure(primary, functionalOutcome{}); outcome != "FAIL_PRODUCT" || check != "connect" {
		t.Fatalf("joined classification=(%s,%s)", outcome, check)
	}

	primary = errors.New("IPv6 capability unavailable")
	joinFieldCleanup(&primary, errors.New("synthetic cleanup failure"))
	if outcome, check := classifyFieldFailure(primary, functionalOutcome{}); outcome != "FAIL_PRODUCT" || check != "ipv6" {
		t.Fatalf("generic joined classification=(%s,%s)", outcome, check)
	}
}

func checkResultV3(values []phase17evidence.FieldCheckV3, name string) string {
	for _, value := range values {
		if value.Name == name {
			return value.Result
		}
	}
	return ""
}

func TestBuildPassingEvidenceV3RejectsObservedEnvironmentDrift(t *testing.T) {
	fixture := newQualifiedRunFixture(t, "Functional")
	qualified, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts)
	if err != nil {
		t.Fatal(err)
	}
	_, err = buildPassingEvidenceV3(
		qualified, 34, "arm64-v8a", true, 1_000,
		resourceTracker{peakRSS: 1 << 20, peakFDs: 12}, functionalOutcome{campaign: rawCampaign{Mode: "Functional", Impairments: []string{}}},
		validScannerReceiptsForRunnerTest(), phase17evidence.FieldBoundaryV3{Result: "PASS", MonitorSHA256: strings.Repeat("4", 64)},
	)
	if err == nil {
		t.Fatal("environment drift was accepted")
	}
}

func validScannerReceiptsForRunnerTest() []phase17evidence.FieldScannerV3 {
	return []phase17evidence.FieldScannerV3{
		{Name: "GO_A", IdentitySHA256: strings.Repeat("1", 64), InputSHA256: strings.Repeat("2", 64), BytesConsumed: 100, RecordsConsumed: 2, Result: "PASS"},
		{Name: "PYTHON_B", IdentitySHA256: strings.Repeat("3", 64), InputSHA256: strings.Repeat("2", 64), BytesConsumed: 100, RecordsConsumed: 2, Result: "PASS"},
	}
}
