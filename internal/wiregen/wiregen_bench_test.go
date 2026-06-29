// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"testing"

	"kurdistan/internal/protocorpus"
)

func BenchmarkSamplePolicy(b *testing.B) {
	corpus := protocorpus.DefaultCorpus()
	for i := 0; i < b.N; i++ {
		if _, err := SamplePolicy(int64(i+1), corpus); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkValidatePolicy(b *testing.B) {
	corpus := protocorpus.DefaultCorpus()
	policy, err := SamplePolicy(12345, corpus)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ValidatePolicy(policy, corpus); err != nil {
			b.Fatal(err)
		}
	}
}
