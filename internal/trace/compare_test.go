package trace

import (
	"bytes"
	"testing"
)

func TestTraceJSONLEncodesDecodes(t *testing.T) {
	var buf bytes.Buffer
	rec := NewRecorder(&buf)
	if err := rec.Record(Event{Role: "client", ProfileID: "kp_a", EventType: "frame", Semantic: "data", FrameBytes: 10}); err != nil {
		t.Fatal(err)
	}
	events, err := DecodeJSONL(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Semantic != "data" {
		t.Fatal("trace decode mismatch")
	}
}

func TestCompareDetectsDifferentProfiles(t *testing.T) {
	a := []Event{{ProfileID: "a", EventType: "first_contact", State: "s1", FrameBytes: 10}, {ProfileID: "a", EventType: "frame", Semantic: "data", FrameBytes: 20, PaddingBytes: 0, SchedulerMode: "max_speed"}}
	b := []Event{{ProfileID: "b", EventType: "first_contact", State: "z1", FrameBytes: 15}, {ProfileID: "b", EventType: "first_contact", State: "z2", FrameBytes: 17}, {ProfileID: "b", EventType: "frame", Semantic: "data", FrameBytes: 30, PaddingBytes: 5, SchedulerMode: "balanced"}}
	report := CompareEvents(a, b)
	if !report.MeaningfullyDifferent {
		t.Fatalf("expected meaningful difference, got %s", report.Conclusion)
	}
}

func TestCompareFlagsIdenticalTracesAsSuspicious(t *testing.T) {
	a := []Event{{ProfileID: "a", EventType: "first_contact", State: "s1", FrameBytes: 10}, {ProfileID: "a", EventType: "frame", Semantic: "data", FrameBytes: 20}}
	report := CompareEvents(a, append([]Event(nil), a...))
	if report.MeaningfullyDifferent || report.Conclusion != "suspiciously similar" {
		t.Fatalf("expected suspiciously similar, got %s", report.Conclusion)
	}
}
