package audit

import (
	"strings"
	"testing"
)

func TestCompareReportsIdenticalBaselinePasses(t *testing.T) {
	oldReport, err := LoadReport("testdata/audit/baseline-small.json")
	if err != nil {
		t.Fatal(err)
	}
	newReport, err := LoadReport("testdata/audit/baseline-small.json")
	if err != nil {
		t.Fatal(err)
	}
	comparison := CompareReports(oldReport, newReport, DefaultComparisonThresholds())
	if !comparison.Passed {
		t.Fatalf("identical baseline should pass: %+v", comparison)
	}
	if comparison.ProfileCountDelta != 0 || comparison.TraceCountDelta != 0 {
		t.Fatalf("unexpected count deltas: %+v", comparison)
	}
}

func TestCompareReportsFailingFixtureRegresses(t *testing.T) {
	oldReport, err := LoadReport("testdata/audit/baseline-small.json")
	if err != nil {
		t.Fatal(err)
	}
	newReport, err := LoadReport("testdata/audit/failing-fixed-small.json")
	if err != nil {
		t.Fatal(err)
	}
	comparison := CompareReports(oldReport, newReport, DefaultComparisonThresholds())
	if comparison.Passed {
		t.Fatalf("failing fixture should regress: %+v", comparison)
	}
	if len(comparison.GateChanges) == 0 {
		t.Fatalf("expected gate changes: %+v", comparison)
	}
	if comparison.MetricDeltas.FrameGrammarCombinations >= 0 {
		t.Fatalf("expected frame grammar regression: %+v", comparison.MetricDeltas)
	}
}

func TestComparisonHumanSummary(t *testing.T) {
	oldReport := AuditReport{Version: Version, Mode: "quick", ProfileCount: 1, TraceCount: 1, Conclusion: "passed"}
	newReport := oldReport
	comparison := CompareReports(oldReport, newReport, DefaultComparisonThresholds())
	text := comparison.HumanSummary()
	for _, want := range []string{"audit comparison", "conclusion", "passed"} {
		if !strings.Contains(text, want) {
			t.Fatalf("summary missing %q:\n%s", want, text)
		}
	}
}

func TestStatusRenderingIncludesBaselineComparison(t *testing.T) {
	report := AuditReport{
		Version:      Version,
		Mode:         "quick",
		GeneratedAt:  "2026-06-27T00:00:00Z",
		ProfileCount: 10,
		TraceCount:   5,
		Gates:        []GateResult{{Name: "profile_corpus_diversity", Passed: true, Severity: "required", Summary: "ok"}},
		Conclusion:   "passed",
	}
	status := RenderStatus(report)
	if !strings.Contains(status, "No baseline comparison was run") {
		t.Fatalf("status should warn when no baseline was run:\n%s", status)
	}
	comparison := CompareReports(report, report, DefaultComparisonThresholds())
	report.BaselineComparison = &comparison
	status = RenderStatus(report)
	for _, want := range []string{"Baseline Comparison", "pass/fail changes", "cluster_count_delta"} {
		if !strings.Contains(status, want) {
			t.Fatalf("status with comparison missing %q:\n%s", want, status)
		}
	}
}
