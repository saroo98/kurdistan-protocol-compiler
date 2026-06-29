// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	ktrace "kurdistan/internal/trace"
)

func TestRunHardeningReportPasses(t *testing.T) {
	report := Run(context.Background(), nil, Options{Mode: "quick", ProfileCount: 3})
	if report.Conclusion != "passed" {
		t.Fatalf("hardening report failed: %#v", report.FailedChecks)
	}
	if report.InvariantsChecked == 0 || report.TraceHygieneChecks == 0 || report.GeneratedParityChecks == 0 {
		t.Fatalf("missing hardening coverage: %#v", report)
	}
}

func TestInvariantRegistryReportsFailure(t *testing.T) {
	results := RunInvariantRegistry([]*ir.Profile{{ID: "invalid"}})
	if !hasFailedResult(results) {
		t.Fatalf("expected invariant failure")
	}
}

func TestMustNotPanicReportsPanic(t *testing.T) {
	result := MustNotPanic("boom", func() { panic("boom") })
	if result.Passed {
		t.Fatalf("panic was reported as pass")
	}
}

func TestTraceHygieneScanner(t *testing.T) {
	p, err := compiler.Generate(14001)
	if err != nil {
		t.Fatal(err)
	}
	clean := ScanEvents([]ktrace.Event{{ProfileID: p.ID, EventType: "runtime", PayloadHygiene: true, SecretHygiene: true}})
	if !clean.Passed {
		t.Fatalf("clean trace rejected: %v", clean.Findings)
	}
	for _, raw := range [][]byte{
		[]byte(`{"raw_secret":"x"}`),
		[]byte(`{"client_write_key":"x"}`),
		[]byte(`{"payload":"hello"}`),
		[]byte(`{"payload_logged":true}`),
		[]byte(`{"secret_logged":true}`),
	} {
		if ScanJSON(raw).Passed {
			t.Fatalf("leaky JSON accepted: %s", raw)
		}
	}
}

func TestChecklistRenderingDeterministic(t *testing.T) {
	results := []CheckResult{
		pass("b", CategoryTraceHygiene, "ok", nil),
		pass("a", CategoryInvariants, "ok", nil),
	}
	checklist := BuildChecklist("test", results)
	if !checklist.Passed || len(checklist.Categories) != 2 || checklist.Categories[0] != CategoryInvariants {
		t.Fatalf("unexpected checklist: %#v", checklist)
	}
}

func TestHardeningMutantsDetected(t *testing.T) {
	for _, mode := range HardeningMutantModes() {
		if !DetectHardeningMutant(mode) {
			t.Fatalf("mutant not detected: %s", mode)
		}
	}
}

func hasFailedResult(results []CheckResult) bool {
	for _, result := range results {
		if !result.Passed {
			return true
		}
	}
	return false
}
