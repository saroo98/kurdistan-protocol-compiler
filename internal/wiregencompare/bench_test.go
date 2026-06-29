// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
)

func BenchmarkGenerateBaseline(b *testing.B) {
	corpus := protocorpus.DefaultCorpus()
	seeds := DefaultSeeds()
	scenarios := DefaultScenarios()
	for i := 0; i < b.N; i++ {
		if _, err := GenerateBaseline(context.Background(), corpus, seeds, scenarios); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCompareBaselines(b *testing.B) {
	corpus := protocorpus.DefaultCorpus()
	baseline, err := GenerateBaseline(context.Background(), corpus, DefaultSeeds(), DefaultScenarios())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		report := CompareBaselines(baseline, baseline)
		if !report.Passed {
			b.Fatal(report)
		}
	}
}
