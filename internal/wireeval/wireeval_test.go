// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
)

func TestBuildDatasetValidatesAndHasSplits(t *testing.T) {
	dataset, err := BuildDataset(context.Background(), protocorpus.DefaultCorpus(), BuildOptions{Controls: true})
	if err != nil {
		t.Fatal(err)
	}
	if dataset.Manifest.RecordCount != len(dataset.Records) {
		t.Fatalf("record count mismatch")
	}
	if dataset.Manifest.SplitCounts[string(SplitTrain)] == 0 || dataset.Manifest.SplitCounts[string(SplitTest)] == 0 || dataset.Manifest.SplitCounts[string(SplitOOD)] == 0 {
		t.Fatalf("missing expected split counts: %+v", dataset.Manifest.SplitCounts)
	}
	if err := ValidateDataset(dataset); err != nil {
		t.Fatal(err)
	}
}

func TestObservableDiversityDetectsControls(t *testing.T) {
	dataset, err := BuildDataset(context.Background(), protocorpus.DefaultCorpus(), BuildOptions{Controls: true})
	if err != nil {
		t.Fatal(err)
	}
	report := AnalyzeObservableDiversity(dataset.Records)
	if report.Conclusion != "passed" {
		t.Fatalf("diversity failed: %+v", report)
	}
	if report.ControlFailuresDetected == 0 {
		t.Fatalf("control collapse was not detected")
	}
}

func TestCompareDatasetsDetectsDrift(t *testing.T) {
	dataset, err := BuildDataset(context.Background(), protocorpus.DefaultCorpus(), BuildOptions{Controls: true})
	if err != nil {
		t.Fatal(err)
	}
	modified := dataset
	modified.Records = append([]WireEvalRecord(nil), dataset.Records...)
	modified.Records[0].FeatureHash = "changed"
	modified.Manifest.DatasetHash = DatasetHash(modified.Records)
	report := CompareDatasets(dataset, modified)
	if report.Conclusion != "failed" || len(report.FeatureDrift) == 0 {
		t.Fatalf("expected feature drift, got %+v", report)
	}
}

func TestForbiddenLeakRejected(t *testing.T) {
	record := WireEvalRecord{
		DatasetVersion:  string(Version),
		RecordID:        "rec_safe",
		ProfileID:       "profile",
		Scenario:        "scenario",
		Backend:         "interpreted",
		Split:           SplitTrain,
		Label:           LabelGeneratedKurdistan,
		FeatureHash:     "feature",
		ByteShapeHash:   "byte",
		FirstNShapeHash: "shape",
	}
	if err := ValidateRecord(record); err != nil {
		t.Fatal(err)
	}
	record.SelectedFamily = "raw_payload"
	if err := ValidateRecord(record); err == nil {
		t.Fatalf("forbidden marker accepted")
	}
}

func TestSplitManifestStable(t *testing.T) {
	dataset, err := BuildDataset(context.Background(), protocorpus.DefaultCorpus(), BuildOptions{Controls: true})
	if err != nil {
		t.Fatal(err)
	}
	manifest := BuildSplitManifest(dataset.Records, DefaultSplitMode())
	if !manifest.Passed {
		t.Fatalf("split manifest failed: %+v", manifest)
	}
}
