// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func BenchmarkWireGenQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 5
	cfg.TraceCount = 0
	for i := 0; i < b.N; i++ {
		report, err := RunWireGenAudit(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatal(report.Conclusion)
		}
	}
}
