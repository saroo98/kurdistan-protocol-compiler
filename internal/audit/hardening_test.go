// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestHardeningQuickAuditPassesAndIncludesGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunHardeningAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("hardening audit failed: %#v", report.Gates)
	}
	for _, name := range []string{
		"hardening_invariant_registry",
		"hardening_api_contracts",
		"hardening_panic_safety",
		"hardening_resource_limits",
		"hardening_trace_hygiene",
		"hardening_concurrency_safety",
		"hardening_generated_parity",
		"hardening_pre_adapter_readiness",
		"hardening_mutant_detection",
	} {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing hardening gate %s", name)
		}
	}
}

func TestHardeningAuditJSONIncludesGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunHardeningAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if !json.Valid(raw) || !strings.Contains(string(raw), "hardening_trace_hygiene") {
		t.Fatalf("hardening JSON missing gates: %s", raw)
	}
}

func TestDefaultQuickAuditIncludesHardeningGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	cfg.TraceCount = 3
	report, err := Run(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := gateByName(report.Gates, "hardening_invariant_registry"); !ok {
		t.Fatalf("default audit missing hardening gate")
	}
}
