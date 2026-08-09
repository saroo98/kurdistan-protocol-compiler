package labtrace

import (
	"context"
	"testing"

	"kurdistan/internal/protocol/compiler"
)

func TestGenerateCorpusTraceReport(t *testing.T) {
	report, err := GenerateCorpus(context.Background(), CorpusOptions{StartSeed: 300, Count: 5, Message: "hello kurdistan"})
	if err != nil {
		t.Fatal(err)
	}
	if report.Count != 5 || len(report.ProfileIDs) != 5 {
		t.Fatalf("unexpected report count: %+v", report)
	}
	if report.ProfileReport.UniqueFrameGrammarCombinations < 2 {
		t.Fatalf("expected frame grammar diversity: %+v", report.ProfileReport)
	}
	if len(report.TraceReports) == 0 {
		t.Fatal("expected pair trace reports")
	}
}

func TestCaptureTraceWaitsForRelayRecorder(t *testing.T) {
	profile, err := compiler.Generate(901)
	if err != nil {
		t.Fatal(err)
	}
	for attempt := 0; attempt < 32; attempt++ {
		events, err := CaptureTrace(context.Background(), profile, []byte("relay recorder lifecycle"))
		if err != nil {
			t.Fatalf("attempt %d: %v", attempt, err)
		}
		seenServerEncode := false
		for _, event := range events {
			if event.Role == "server" && event.EventType == "frame_encode" {
				seenServerEncode = true
				break
			}
		}
		if !seenServerEncode {
			t.Fatalf("attempt %d: trace returned before the server recorder finished", attempt)
		}
	}
}
