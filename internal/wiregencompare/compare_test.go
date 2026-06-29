// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregencompare

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wirefeatures"
	"kurdistan/internal/wiregen"
)

func TestGenerateBaselineValidates(t *testing.T) {
	baseline, err := GenerateBaseline(context.Background(), protocorpus.DefaultCorpus(), []int{12345, 12346, 12347}, []string{"byte_single_flow_echo", "byte_replay_rejection"})
	if err != nil {
		t.Fatal(err)
	}
	if baseline.PolicyCount != 3 {
		t.Fatalf("policy count = %d", baseline.PolicyCount)
	}
	if baseline.FeatureCount != 6 {
		t.Fatalf("feature count = %d", baseline.FeatureCount)
	}
	if err := ValidateBaseline(baseline); err != nil {
		t.Fatal(err)
	}
	if baseline.Comparison.Conclusion != "passed" {
		t.Fatalf("comparison failed: %#v", baseline.Comparison)
	}
}

func TestCompareBaselinesDetectsDrift(t *testing.T) {
	corpus := protocorpus.DefaultCorpus()
	oldBaseline, err := GenerateBaseline(context.Background(), corpus, []int{1, 2}, []string{"byte_single_flow_echo"})
	if err != nil {
		t.Fatal(err)
	}
	newBaseline := oldBaseline
	newBaseline.FeatureVectors = append([]wirefeatures.WireFeatureVector(nil), oldBaseline.FeatureVectors...)
	newBaseline.FeatureVectors[0].FeatureHash = "changed"
	report := CompareBaselines(oldBaseline, newBaseline)
	if report.Passed {
		t.Fatal("expected drift report to fail")
	}
}

func TestCollapseScannerDetectsFixedPolicy(t *testing.T) {
	corpus := protocorpus.DefaultCorpus()
	policy, err := wiregen.SamplePolicy(12345, corpus)
	if err != nil {
		t.Fatal(err)
	}
	policies := []wiregen.WireShapePolicy{policy, policy, policy}
	vectors := []wirefeatures.WireFeatureVector{
		ExpectedVector(policy, "byte_single_flow_echo", "interpreted", "a"),
		ExpectedVector(policy, "byte_single_flow_echo", "interpreted", "b"),
		ExpectedVector(policy, "byte_single_flow_echo", "interpreted", "c"),
	}
	report := ScanCollapse(policies, vectors)
	if report.Conclusion != "failed" {
		t.Fatalf("expected collapse failure, got %#v", report)
	}
}
