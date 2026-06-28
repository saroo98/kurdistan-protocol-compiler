// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func TestProxySemanticsGatesPassQuickGeneratedCorpus(t *testing.T) {
	ctx := context.Background()
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunProxySemanticsAudit(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("proxysem quick audit failed: %s %+v", report.Conclusion, report.Gates)
	}
	for _, name := range []string{
		"proxy_semantics_correctness",
		"proxy_semantics_diversity",
		"proxy_target_backpressure",
		"proxy_error_reset_isolation",
		"proxy_mutant_detection",
		"proxy_generated_backend_parity",
	} {
		if _, ok := gateByName(report.Gates, name); !ok {
			t.Fatalf("missing proxy gate %q", name)
		}
	}
}

func TestProxyMutantDetectionGateFailsExpectedMutants(t *testing.T) {
	gate := ProxyMutantDetectionGate(context.Background(), DefaultThresholds())
	if !gate.Passed {
		t.Fatalf("proxy mutant detection gate missed expected mutants: %+v", gate)
	}
}
