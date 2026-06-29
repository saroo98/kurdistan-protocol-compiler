// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func TestRunLocalAdapterAuditQuick(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunLocalAdapterAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("local adapter audit failed: %+v", report.Gates)
	}
	if _, ok := gateByName(report.Gates, "local_adapter_generated_backend_parity"); !ok {
		t.Fatalf("local adapter generated backend gate missing")
	}
}

func BenchmarkRunLocalAdapterAuditQuick(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		report, err := RunLocalAdapterAudit(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatal(report.Conclusion)
		}
	}
}
