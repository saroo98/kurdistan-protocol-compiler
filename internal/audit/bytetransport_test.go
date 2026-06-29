// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func TestRunByteTransportAuditQuick(t *testing.T) {
	report, err := RunByteTransportAudit(context.Background(), AuditConfig{Mode: "quick", StartSeed: 1, ProfileCount: 3, Thresholds: DefaultThresholds()})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("byte transport audit failed: %+v", report.Gates)
	}
	if _, ok := gateByName(report.Gates, "byte_transport_runtime_integration"); !ok {
		t.Fatalf("missing byte transport runtime gate: %+v", report.Gates)
	}
	if _, ok := gateByName(report.Gates, "byte_transport_generated_backend_parity"); !ok {
		t.Fatalf("missing byte transport gates: %+v", report.Gates)
	}
}

func BenchmarkRunByteTransportAuditQuick(b *testing.B) {
	cfg := AuditConfig{Mode: "quick", StartSeed: 1, ProfileCount: 3, Thresholds: DefaultThresholds()}
	for i := 0; i < b.N; i++ {
		if _, err := RunByteTransportAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}
