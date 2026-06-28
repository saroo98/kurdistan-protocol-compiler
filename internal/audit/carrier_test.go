// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func TestCarrierQuickAuditPassesAndIncludesGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	cfg.TraceCount = 0
	report, err := RunCarrierAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("carrier audit failed: %+v", report.Gates)
	}
	for _, name := range []string{
		"carrier_semantics_correctness",
		"carrier_diversity",
		"carrier_backpressure_preservation",
		"carrier_loss_reorder_recovery",
		"carrier_proxysem_parity",
		"carrier_mutant_detection",
		"carrier_generated_backend_parity",
	} {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing carrier gate %q", name)
		}
	}
}
