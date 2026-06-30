// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

func BenchmarkHostAssignment(b *testing.B) {
	dataset, err := wireeval.BuildDataset(context.Background(), protocorpus.DefaultCorpus(), wireeval.BuildOptions{Seeds: wireeval.DefaultSeeds(), Controls: true})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if _, err := BuildObservations(dataset, DefaultBuildOptions()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHostAggregation(b *testing.B) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Aggregate(summary.ObservationSet.Observations)
	}
}

func BenchmarkHostCollapse(b *testing.B) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = Collapse(summary.Aggregates)
	}
}
