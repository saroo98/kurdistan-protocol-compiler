package trace

import "testing"

func TestScanTracesFlagsSuspiciousStability(t *testing.T) {
	traces := [][]Event{
		{{ProfileID: "a", EventType: "first_contact", State: "a1", FrameBytes: 12}, {EventType: "frame", FrameBytes: 20}},
		{{ProfileID: "b", EventType: "first_contact", State: "b1", FrameBytes: 12}, {EventType: "frame", FrameBytes: 20}},
		{{ProfileID: "c", EventType: "first_contact", State: "c1", FrameBytes: 12}, {EventType: "frame", FrameBytes: 20}},
	}
	report := ScanTraces(traces, 0.8)
	if len(report.Flagged) == 0 {
		t.Fatal("expected suspicious stability to be flagged")
	}
}

func TestTraceAnalyzerIgnoresTimestampOnlyDifferences(t *testing.T) {
	a := []Event{{TimeUnixNano: 1, ProfileID: "kp_a", EventType: "first_contact", State: "s1", FrameBytes: 10}, {TimeUnixNano: 2, ProfileID: "kp_a", EventType: "frame", Semantic: "data", FrameBytes: 20}}
	b := []Event{{TimeUnixNano: 99, ProfileID: "kp_a", EventType: "first_contact", State: "s1", FrameBytes: 10}, {TimeUnixNano: 100, ProfileID: "kp_a", EventType: "frame", Semantic: "data", FrameBytes: 20}}
	report := CompareEvents(a, b)
	if report.MeaningfullyDifferent {
		t.Fatalf("timestamp-only changes were considered meaningful: %+v", report)
	}
}

func TestProfileIDAloneDoesNotMakeTraceMeaningfullyDifferent(t *testing.T) {
	a := []Event{{ProfileID: "kp_a", EventType: "first_contact", State: "s1", FrameBytes: 10}, {ProfileID: "kp_a", EventType: "frame", Semantic: "data", FrameBytes: 20}}
	b := []Event{{ProfileID: "kp_b", EventType: "first_contact", State: "s1", FrameBytes: 10}, {ProfileID: "kp_b", EventType: "frame", Semantic: "data", FrameBytes: 20}}
	report := CompareEvents(a, b)
	if report.MeaningfullyDifferent {
		t.Fatalf("profile ID alone was considered meaningful: %+v", report)
	}
}

func TestDifferentProfileTraceShapesUsuallyDiffer(t *testing.T) {
	a := []Event{{ProfileID: "kp_a", EventType: "first_contact", State: "s1", FrameBytes: 10}, {ProfileID: "kp_a", EventType: "frame", Semantic: "data", FrameBytes: 20, PaddingBytes: 0, SchedulerMode: "max_speed"}}
	b := []Event{{ProfileID: "kp_b", EventType: "first_contact", State: "z1", FrameBytes: 14}, {ProfileID: "kp_b", EventType: "first_contact", State: "z2", FrameBytes: 18}, {ProfileID: "kp_b", EventType: "frame", Semantic: "data", FrameBytes: 33, PaddingBytes: 8, SchedulerMode: "balanced"}}
	report := CompareEvents(a, b)
	if !report.MeaningfullyDifferent {
		t.Fatalf("different trace shapes were not meaningful: %+v", report)
	}
}
