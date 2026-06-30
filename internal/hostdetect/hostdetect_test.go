// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"context"
	"testing"

	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wireeval"
)

func testDataset(t *testing.T) wireeval.Dataset {
	t.Helper()
	dataset, err := wireeval.BuildDataset(context.Background(), protocorpus.DefaultCorpus(), wireeval.BuildOptions{
		Seeds:    wireeval.DefaultSeeds(),
		Controls: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return dataset
}

func TestBuildObservationsDeterministicAndSafe(t *testing.T) {
	dataset := testDataset(t)
	a, err := BuildObservations(dataset, DefaultBuildOptions())
	if err != nil {
		t.Fatal(err)
	}
	b, err := BuildObservations(dataset, DefaultBuildOptions())
	if err != nil {
		t.Fatal(err)
	}
	if a.DatasetHash != b.DatasetHash || len(a.Observations) == 0 {
		t.Fatalf("host assignment not deterministic")
	}
	if a.PayloadLogged || a.SecretLogged {
		t.Fatalf("host observation set reported leakage")
	}
	for _, observation := range a.Observations {
		if err := ValidateObservation(observation); err != nil {
			t.Fatal(err)
		}
	}
}

func TestAssignmentModes(t *testing.T) {
	dataset := testDataset(t)
	modes := FullAssignmentModes()
	seen := map[string]string{}
	for _, mode := range modes {
		set, err := BuildObservations(dataset, BuildOptions{AssignmentMode: mode, Window: WindowShort, HostCount: 5})
		if err != nil {
			t.Fatalf("%s: %v", mode, err)
		}
		if set.HostCount == 0 {
			t.Fatalf("%s produced no hosts", mode)
		}
		seen[mode] = set.DatasetHash
	}
	if seen[AssignSingleLongLived] == seen[AssignManyHostsUniform] {
		t.Fatalf("assignment modes collapsed to same host shape")
	}
	if err := ValidateAssignmentMode("bad_mode"); err == nil {
		t.Fatalf("bad assignment mode accepted")
	}
}

func TestTimelineOrdering(t *testing.T) {
	if LogicalTime(3, WindowShort) >= LogicalTime(3, WindowLong) {
		t.Fatalf("timeline windows did not differ")
	}
	if err := ValidateWindow("bad_window"); err == nil {
		t.Fatalf("bad window accepted")
	}
}

func TestAggregateConfidenceResistanceAndCollapse(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateSummary(summary); err != nil {
		t.Fatal(err)
	}
	if summary.Detection.ControlHostsFlagged == 0 {
		t.Fatalf("collapsed controls were not flagged")
	}
	if !summary.Resistance.ControlCollapseDetected || !summary.Resistance.PaddingOnlyDetected {
		t.Fatalf("controls were not reflected in resistance report: %+v", summary.Resistance)
	}
	if !summary.Collapse.CollapsedControlDetected {
		t.Fatalf("collapse scanner did not detect collapsed controls")
	}
}

func TestLowObservationConfidenceUnknown(t *testing.T) {
	conf := ScoreHost(HostAggregate{
		SyntheticHostID:  "host_0001",
		HostClass:        HostClassGeneratedRelay,
		ObservationCount: 1,
		ConsistencyScore: 1,
		RiskBucket:       "unknown",
	}, DefaultConfidenceModel())
	if conf.Flagged || conf.RejectReason != "insufficient_observations" {
		t.Fatalf("low-observation host was not rejected as unknown: %+v", conf)
	}
}

func TestRepeatedFeatureCollapseDetected(t *testing.T) {
	report := Collapse(SyntheticCollapsedAggregates())
	if report.Conclusion != "failed" && !report.CollapsedControlDetected {
		t.Fatalf("synthetic collapsed aggregate was not detected")
	}
	if report.HighConsistencyHosts == 0 {
		t.Fatalf("high consistency host missing from report")
	}
}

func TestCompareObservationSets(t *testing.T) {
	summary, err := GenerateGoldenSummary(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	report := CompareObservationSets(summary.ObservationSet, summary.ObservationSet)
	if report.Conclusion != "passed" || report.Changed != 0 {
		t.Fatalf("self compare failed: %+v", report)
	}
	changed := summary.ObservationSet
	changed.Observations = append([]HostObservation(nil), summary.ObservationSet.Observations...)
	changed.Observations[0].FeatureHash = "changed"
	changed.DatasetHash = ObservationSetHash(changed.Observations)
	report = CompareObservationSets(summary.ObservationSet, changed)
	if report.Conclusion != "failed" || report.Changed == 0 {
		t.Fatalf("changed observation did not drift: %+v", report)
	}
}

func TestLeakageRejected(t *testing.T) {
	observation := HostObservation{
		Version:         string(Version),
		ObservationID:   "obs_1",
		SyntheticHostID: "host_0001",
		DatasetRecordID: "rec_1",
		FeatureHash:     "h",
		FirstNShapeHash: "f",
		ByteShapeHash:   "b",
		ProfileID:       "endpoint.example",
	}
	if err := ValidateObservation(observation); err == nil {
		t.Fatalf("endpoint-like value accepted")
	}
	if ScanForLeak(map[string]string{"raw_payload": "x"}) == nil {
		t.Fatalf("raw payload marker accepted")
	}
}
