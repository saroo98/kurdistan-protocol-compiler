// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package byteparity

import (
	"context"
	"testing"

	"kurdistan/internal/bytetransport"
	"kurdistan/internal/fixtures"
)

func TestRunParityPasses(t *testing.T) {
	report, err := Run(context.Background(), []int{12345}, []string{bytetransport.ScenarioSingleFlow, bytetransport.ScenarioReplay})
	if err != nil {
		t.Fatal(err)
	}
	if report.Conclusion != "passed" || report.ComparedPairs != 2 || report.SemanticMatches != 2 {
		t.Fatalf("unexpected parity report: %#v", report)
	}
}

func TestCompareSummariesAllowsByteBucketDifference(t *testing.T) {
	a := fixtures.BytePathFixtureSummary{ProfileID: "p", ProfileSeed: 1, Scenario: "s", Backend: fixtures.BackendLab, FramesEncoded: 1, FramesDecoded: 1, FragmentsCreated: 1, FragmentsReassembled: 1, BytesWrittenBucket: "tiny", BytesReadBucket: "tiny", SinkCompleted: true}
	b := a
	b.Backend = fixtures.BackendGen
	b.BytesWrittenBucket = "small"
	comparison := CompareSummaries(a, b)
	if !comparison.SemanticMatch || comparison.ByteShapeMatch || len(comparison.AllowedDifferences) == 0 {
		t.Fatalf("expected semantic parity with allowed byte-shape difference: %#v", comparison)
	}
}

func TestCompareSummariesRejectsSemanticDriftAndLeaks(t *testing.T) {
	a := fixtures.BytePathFixtureSummary{ProfileID: "p", ProfileSeed: 1, Scenario: "s", Backend: fixtures.BackendLab, FramesEncoded: 1, FramesDecoded: 1, SinkCompleted: true}
	b := a
	b.Backend = fixtures.BackendGen
	b.FramesDecoded = 2
	b.SecretLogged = true
	comparison := CompareSummaries(a, b)
	if comparison.SemanticMatch || len(comparison.UnexpectedDrift) == 0 || !comparison.SecretLogged {
		t.Fatalf("expected semantic drift and secret leak: %#v", comparison)
	}
}

func BenchmarkByteParityComparison(b *testing.B) {
	report, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{
		ProfileSeeds:  []int{12345, 12346, 12347},
		ScenarioNames: fixtures.DefaultScenarios(),
	})
	if err != nil {
		b.Fatal(err)
	}
	generated := append([]fixtures.BytePathFixtureSummary(nil), report.Summaries...)
	for i := range generated {
		generated[i].Backend = fixtures.BackendGen
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		out := CompareSets(report.Summaries, generated)
		if out.Conclusion != "passed" {
			b.Fatal(out)
		}
	}
}
