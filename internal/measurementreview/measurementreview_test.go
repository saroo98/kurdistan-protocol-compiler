// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package measurementreview

import "testing"

func TestGenerateReview(t *testing.T) {
	review, err := GenerateReview()
	if err != nil {
		t.Fatalf("GenerateReview() error = %v", err)
	}
	if review.Conclusion != "passed" {
		t.Fatalf("review conclusion = %s", review.Conclusion)
	}
	if len(review.Fields) < 18 {
		t.Fatalf("expected observation taxonomy, got %d fields", len(review.Fields))
	}
	if review.Policy.BackgroundCollection {
		t.Fatal("background collection must not be enabled")
	}
	if !LocalReportIsTraceSafe(review.Diagnostics) {
		t.Fatal("diagnostic report is not trace safe")
	}
}

func TestUnsafeMetadataRejected(t *testing.T) {
	for _, value := range []map[string]string{
		{"raw_payload": "x"},
		{"dns_query": "x"},
		{"resolver_ip": "x"},
		{"precise_location": "x"},
		{"telemetry_upload": "enabled"},
		{"claim": "guaranteed bypass"},
	} {
		if err := ScanForLeak(value); err == nil {
			t.Fatalf("unsafe metadata accepted: %#v", value)
		}
	}
}

func TestUnsafeObservationControlsFail(t *testing.T) {
	policy := DefaultPrivacyPolicy(DefaultObservationFields())
	report := ScanMisuse(UnsafeControlFields(), policy)
	if report.Conclusion != "failed" {
		t.Fatalf("unsafe controls were not detected: %#v", report)
	}
}

func TestCompareReviews(t *testing.T) {
	oldReview, err := GenerateReview()
	if err != nil {
		t.Fatal(err)
	}
	newReview, err := GenerateReview()
	if err != nil {
		t.Fatal(err)
	}
	comparison := CompareReviews(oldReview, newReview)
	if !ComparisonPassed(comparison) {
		t.Fatalf("comparison failed: %#v", comparison)
	}
	newReview.Fields[0].RetentionClass = RetentionManualExportOnly
	newReview.ReviewHash = HashValue(reviewHashInput(newReview))
	comparison = CompareReviews(oldReview, newReview)
	if comparison.Conclusion != "failed" {
		t.Fatalf("expected drift failure")
	}
}
