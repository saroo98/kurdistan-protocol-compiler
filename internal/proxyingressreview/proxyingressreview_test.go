// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

import (
	"testing"

	"kurdistan/internal/proxyingress"
)

func TestDesignReviewGoNoGo(t *testing.T) {
	set, err := proxyingress.GoldenFixtureSet()
	if err != nil {
		t.Fatal(err)
	}
	review, err := RunReview(set.Contract, set.Requests, set.Mappings, set.Lifecycle, DefaultFailureModes())
	if err != nil {
		t.Fatal(err)
	}
	if review.GoNoGoDecision != DecisionGo || !ReadyForPrototype(review) {
		t.Fatalf("unexpected decision: %#v", review)
	}
	if err := ValidateReview(review); err != nil {
		t.Fatal(err)
	}
}

func TestReviewBlocksMissingTraceHygiene(t *testing.T) {
	set, _ := proxyingress.GoldenFixtureSet()
	filtered := []string{}
	for _, capability := range set.Contract.RequiredCapabilities {
		if capability != "trace_hygiene_required" {
			filtered = append(filtered, capability)
		}
	}
	set.Contract.RequiredCapabilities = filtered
	set.Contract.ContractHash = proxyingress.ContractHash(set.Contract)
	review, err := RunReview(set.Contract, set.Requests, set.Mappings, set.Lifecycle, DefaultFailureModes())
	if err != nil {
		t.Fatal(err)
	}
	if review.GoNoGoDecision != DecisionBlockedTraceHygiene {
		t.Fatalf("wrong decision: %s", review.GoNoGoDecision)
	}
}

func TestFailureModeCoverage(t *testing.T) {
	if err := ValidateFailureModeMatrix(DefaultFailureModes()); err != nil {
		t.Fatal(err)
	}
	if err := ValidateFailureModeMatrix(DefaultFailureModes()[:3]); err == nil {
		t.Fatal("expected missing modes to fail")
	}
}

func TestMisuseScannerDetectsUnsafeState(t *testing.T) {
	set, _ := proxyingress.GoldenFixtureSet()
	set.Requests[0].Target.DescriptorID = "127.0.0.1"
	review, _, _, _ := GenerateGoldenReview()
	report := ScanMisuse(set.Contract, set.Requests, set.Mappings, set.Lifecycle, review)
	if report.Conclusion != "failed" || report.UnsafeTargets == 0 {
		t.Fatalf("unsafe target not detected: %#v", report)
	}
}

func BenchmarkDesignReviewGeneration(b *testing.B) {
	set, _ := proxyingress.GoldenFixtureSet()
	modes := DefaultFailureModes()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = RunReview(set.Contract, set.Requests, set.Mappings, set.Lifecycle, modes)
	}
}
