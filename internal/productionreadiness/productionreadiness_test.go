// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package productionreadiness

import "testing"

func TestGenerateReview(t *testing.T) {
	review, err := GenerateReview()
	if err != nil {
		t.Fatalf("GenerateReview() error = %v", err)
	}
	if review.Conclusion != "passed" {
		t.Fatalf("review conclusion = %s", review.Conclusion)
	}
	if len(review.Items) < 18 || len(review.Contracts) < 4 || len(review.Boundaries) < 5 {
		t.Fatalf("review lacks coverage: items=%d contracts=%d boundaries=%d", len(review.Items), len(review.Contracts), len(review.Boundaries))
	}
	if err := ScanForLeak(review); err != nil {
		t.Fatalf("review leaked unsafe metadata: %v", err)
	}
}

func TestUnsafeMetadataRejected(t *testing.T) {
	for _, value := range []map[string]string{
		{"raw_payload": "x"},
		{"encoded_bytes": "x"},
		{"dns_query": "x"},
		{"deployment_token": "x"},
		{"claim": "guaranteed bypass"},
	} {
		if err := ScanForLeak(value); err == nil {
			t.Fatalf("unsafe metadata accepted: %#v", value)
		}
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
	if report := CompareReviews(oldReview, newReview); report.Conclusion != "passed" {
		t.Fatalf("comparison failed: %#v", report)
	}
	newReview.Items[0].Status = StatusBlocked
	newReview.ReviewHash = HashValue(reviewHashInput(newReview))
	if report := CompareReviews(oldReview, newReview); report.Conclusion != "failed" {
		t.Fatalf("expected drift failure")
	}
}

func TestBoundaryReviewsStayClosed(t *testing.T) {
	review, err := GenerateReview()
	if err != nil {
		t.Fatal(err)
	}
	for _, boundary := range review.Boundaries {
		if boundary.Allowed {
			t.Fatalf("boundary unexpectedly allowed: %s", boundary.Name)
		}
	}
}

func FuzzScanForLeak(f *testing.F) {
	f.Add(`{"note":"safe bucket"}`)
	f.Add(`{"raw_payload":"x"}`)
	f.Fuzz(func(t *testing.T, input string) {
		_ = ScanForLeak(map[string]string{"input": input})
	})
}

func BenchmarkGenerateReview(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if _, err := GenerateReview(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkScanForLeak(b *testing.B) {
	review, err := GenerateReview()
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if err := ScanForLeak(review); err != nil {
			b.Fatal(err)
		}
	}
}
