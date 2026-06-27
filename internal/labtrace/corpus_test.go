package labtrace

import (
	"context"
	"testing"
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
