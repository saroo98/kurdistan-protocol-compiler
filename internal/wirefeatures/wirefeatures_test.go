// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import (
	"context"
	"encoding/json"
	"testing"

	"kurdistan/internal/fixtures"
	"kurdistan/internal/protocorpus"
)

func TestFeatureExtractionFromBytepathFixture(t *testing.T) {
	manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	vectors, report := ExtractFromFixtureManifest(manifest)
	if report.Conclusion != "passed" {
		t.Fatalf("feature extraction failed: %#v", report)
	}
	if len(vectors) != len(manifest.Summaries) {
		t.Fatalf("feature count mismatch")
	}
	for _, vector := range vectors {
		if err := ValidateVector(vector); err != nil {
			t.Fatalf("invalid vector: %v", err)
		}
	}
}

func TestFirstNPacketShapeHashStability(t *testing.T) {
	packets := []PacketShape{{Index: 0, Direction: DirectionClientToServer, SizeBucket: "size_33_64", KindBucket: "data"}}
	a, err := NewFirstNShape(packets)
	if err != nil {
		t.Fatal(err)
	}
	b, err := NewFirstNShape(packets)
	if err != nil {
		t.Fatal(err)
	}
	if a.Hash == "" || a.Hash != b.Hash {
		t.Fatalf("unstable first-n hash")
	}
	packets[0].Direction = DirectionServerToClient
	c, err := NewFirstNShape(packets)
	if err != nil {
		t.Fatal(err)
	}
	if c.Hash == a.Hash {
		t.Fatalf("direction change did not change hash")
	}
}

func TestFirstNRejectsUnsafeShape(t *testing.T) {
	_, err := NewFirstNShape([]PacketShape{{Index: 0, Direction: "bad", SizeBucket: "size_33_64", KindBucket: "data"}})
	if err == nil {
		t.Fatalf("invalid direction accepted")
	}
	_, err = NewFirstNShape([]PacketShape{{Index: 0, Direction: DirectionClientToServer, SizeBucket: "raw_payload", KindBucket: "data"}})
	if err == nil {
		t.Fatalf("invalid size bucket accepted")
	}
	_, err = NewFirstNShape([]PacketShape{{Index: 0, Direction: DirectionClientToServer, SizeBucket: "size_33_64", KindBucket: "raw_payload"}})
	if err == nil {
		t.Fatalf("unsafe kind accepted")
	}
}

func TestCorpusComparisonAndCollapse(t *testing.T) {
	manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	vectors, _ := ExtractFromFixtureManifest(manifest)
	corpus := protocorpus.DefaultCorpus()
	comparison := CompareToCorpus(vectors, corpus)
	if comparison.Conclusion != "passed" {
		t.Fatalf("comparison failed: %#v", comparison)
	}
	collapse := ScanCollapse(vectors)
	if collapse.Conclusion != "passed" {
		t.Fatalf("healthy vectors flagged as collapsed: %#v", collapse)
	}
	collapsed := make([]WireFeatureVector, len(vectors))
	for i := range vectors {
		collapsed[i] = vectors[0]
		collapsed[i].ProfileID = vectors[i].ProfileID
	}
	if ScanCollapse(collapsed).Conclusion != "failed" {
		t.Fatalf("collapsed vectors not flagged")
	}
}

func TestBaselineCompareDetectsChange(t *testing.T) {
	fixtureManifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{})
	if err != nil {
		t.Fatal(err)
	}
	corpus := protocorpus.DefaultCorpus()
	baseline, err := GenerateBaseline(context.Background(), fixtureManifest, corpus)
	if err != nil {
		t.Fatal(err)
	}
	changed := baseline
	changed.FeatureVectors = append([]WireFeatureVector(nil), baseline.FeatureVectors...)
	changed.FeatureVectors[0].FeatureHash = "changed"
	report := CompareBaselines(baseline, changed)
	if report.Passed || len(report.Changed) == 0 {
		t.Fatalf("expected changed baseline report")
	}
}

func TestRedactionRejectsUnsafeFeatureFixture(t *testing.T) {
	if ValidateRedaction(map[string]string{"encoded_bytes": "abcd"}).Passed {
		t.Fatalf("encoded bytes accepted")
	}
	vector := WireFeatureVector{PayloadLogged: true}
	if ValidateRedaction(vector).Passed {
		t.Fatalf("payload leak flag accepted")
	}
}

func FuzzWireFeatureVectorParser(f *testing.F) {
	f.Add(`{"version":"wirefeatures-v1","feature_vectors":[]}`)
	f.Add(`{"raw_payload":"x"}`)
	f.Fuzz(func(t *testing.T, input string) {
		if len(input) > 64*1024 {
			t.Skip()
		}
		var baseline BaselineManifest
		if err := json.Unmarshal([]byte(input), &baseline); err == nil {
			_ = ValidateBaseline(baseline)
			_ = ValidateRedaction(baseline)
		}
	})
}

func BenchmarkFeatureExtractionFromFixtures(b *testing.B) {
	manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{})
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		ExtractFromFixtureManifest(manifest)
	}
}

func BenchmarkFirstNPacketShapeHashing(b *testing.B) {
	packets := []PacketShape{{Index: 0, Direction: DirectionClientToServer, SizeBucket: "size_33_64", KindBucket: "data"}}
	for i := 0; i < b.N; i++ {
		if _, err := NewFirstNShape(packets); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCorpusComparisonOverFixtureSet(b *testing.B) {
	manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{})
	if err != nil {
		b.Fatal(err)
	}
	vectors, _ := ExtractFromFixtureManifest(manifest)
	corpus := protocorpus.DefaultCorpus()
	for i := 0; i < b.N; i++ {
		CompareToCorpus(vectors, corpus)
	}
}

func BenchmarkWireFeatureCollapseScanner(b *testing.B) {
	manifest, err := fixtures.GenerateBytePathManifest(context.Background(), fixtures.ManifestOptions{})
	if err != nil {
		b.Fatal(err)
	}
	vectors, _ := ExtractFromFixtureManifest(manifest)
	for i := 0; i < b.N; i++ {
		ScanCollapse(vectors)
	}
}
