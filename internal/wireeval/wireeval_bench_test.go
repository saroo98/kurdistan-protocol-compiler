// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
)

func BenchmarkBuildDataset(b *testing.B) {
	corpus := protocorpus.DefaultCorpus()
	for i := 0; i < b.N; i++ {
		if _, err := BuildDataset(context.Background(), corpus, BuildOptions{Controls: true}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidateDataset(b *testing.B) {
	dataset, err := GenerateGoldenDataset(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		if err := ValidateDataset(dataset); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkObservableDiversity(b *testing.B) {
	dataset, err := GenerateGoldenDataset(context.Background())
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		_ = AnalyzeObservableDiversity(dataset.Records)
	}
}
