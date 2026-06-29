// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func TestRunAdapterAuditQuick(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunAdapterAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("adapter audit failed: %+v", report.Gates)
	}
	if _, ok := gateByName(report.Gates, "adapter_runtime_boundary"); !ok {
		t.Fatalf("adapter runtime boundary gate missing")
	}
}

func BenchmarkRunAdapterAuditQuick(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		report, err := RunAdapterAudit(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatal("adapter audit failed")
		}
	}
}
