// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreview

import "testing"

func TestGenerateReview(t *testing.T) {
	review, err := GenerateReview()
	if err != nil {
		t.Fatal(err)
	}
	if len(review.Descriptors) != 5 {
		t.Fatalf("descriptor count = %d", len(review.Descriptors))
	}
	if review.Readiness.ReadySyntheticFamilies == 0 || review.Readiness.GatedFamilies == 0 || review.Readiness.ManualReviewFamilies == 0 {
		t.Fatalf("readiness classes not represented: %+v", review.Readiness)
	}
	if review.Misuse.Conclusion != "passed" || review.Parity.Conclusion != "passed" {
		t.Fatalf("review reports failed: %+v %+v", review.Misuse, review.Parity)
	}
}

func TestUnsafeClaimsRejected(t *testing.T) {
	for _, unsafe := range []map[string]string{
		{"claim": "guaranteed bypass"},
		{"endpoint": "synthetic"},
		{"dns_query": "synthetic"},
		{"resolver_ip": "synthetic"},
		{"payload": "synthetic"},
		{"secret": "synthetic"},
	} {
		if err := ScanForLeak(unsafe); err == nil {
			t.Fatalf("unsafe metadata accepted: %+v", unsafe)
		}
	}
}

func TestReadinessRejectsUnsafeDomesticDefault(t *testing.T) {
	descriptors := DefaultDescriptors()
	for i := range descriptors {
		if descriptors[i].Family == FamilyDomesticMediaRisk {
			descriptors[i].DefaultEligible = true
		}
	}
	report := ScanMisuse(descriptors)
	if report.Conclusion != "failed" {
		t.Fatalf("unsafe domestic default not detected: %+v", report)
	}
}

func TestCompareReviews(t *testing.T) {
	review, err := GenerateReview()
	if err != nil {
		t.Fatal(err)
	}
	comparison := CompareReviews(review, review)
	if comparison.Conclusion != "passed" {
		t.Fatalf("unexpected drift: %+v", comparison)
	}
}

func BenchmarkGenerateReview(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateReview(); err != nil {
			b.Fatal(err)
		}
	}
}
