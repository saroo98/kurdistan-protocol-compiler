// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"context"
	"testing"
)

func BenchmarkRelayFleetGoldenSummary(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateGoldenSummary(context.Background()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayFleetValidation(b *testing.B) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidateFleet(summary.Fleet); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRelayFleetCollapseScan(b *testing.B) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(summary.Fleet, summary.Assignment, summary.ChurnEvents, summary.MigrationEvents, summary.BurnRisk)
	}
}
