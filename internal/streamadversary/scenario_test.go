package streamadversary

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
)

func TestRequiredScenariosRunAndStayPayloadFree(t *testing.T) {
	p := mustProfile(t, 901)
	ctx := context.Background()
	for _, kind := range RequiredScenarioTypes() {
		t.Run(kind, func(t *testing.T) {
			run, err := RunScenario(ctx, p, DefaultScenario(kind))
			if err != nil {
				t.Fatal(err)
			}
			if !run.Correct {
				t.Fatalf("scenario was not correct: %+v", run.Checks)
			}
			if len(run.Events) == 0 {
				t.Fatalf("scenario emitted no trace events")
			}
			raw, err := json.Marshal(run.Events)
			if err != nil {
				t.Fatal(err)
			}
			for _, payload := range ScenarioPayloadMarkers(run.Scenario) {
				if bytes.Contains(raw, []byte(payload)) {
					t.Fatalf("trace leaked payload marker %q", payload)
				}
			}
		})
	}
}

func TestBlockedStreamAndSessionWindowSemantics(t *testing.T) {
	p := mustProfile(t, 902)
	blocked, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioBlockedStream))
	if err != nil {
		t.Fatal(err)
	}
	if blocked.Checks.BackpressureEvents == 0 || !blocked.Checks.OtherStreamsContinued {
		t.Fatalf("blocked stream did not prove local backpressure: %+v", blocked.Checks)
	}
	session, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioSessionWindowExhaustion))
	if err != nil {
		t.Fatal(err)
	}
	if session.Checks.SessionBlockedCount == 0 || !session.Checks.WindowUpdateRecovered {
		t.Fatalf("session window exhaustion did not prove global backpressure and recovery: %+v", session.Checks)
	}
}

func TestResetAndCloseRaceKeepOtherStreamsAlive(t *testing.T) {
	p := mustProfile(t, 903)
	reset, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioResetMidstream))
	if err != nil {
		t.Fatal(err)
	}
	if reset.Checks.ResetCount != 1 || !reset.Checks.OtherStreamsContinued {
		t.Fatalf("reset midstream did not remain stream-local: %+v", reset.Checks)
	}
	closeRace, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioCloseRace))
	if err != nil {
		t.Fatal(err)
	}
	if closeRace.Checks.CloseCount == 0 || !closeRace.Checks.OtherStreamsContinued {
		t.Fatalf("close race did not preserve active streams: %+v", closeRace.Checks)
	}
}

func TestStreamFeatureExtractionAndCollapseScan(t *testing.T) {
	profiles := mustProfiles(t, 910, 8)
	runs, err := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioBulkVsInteractive)})
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != len(profiles) {
		t.Fatalf("runs = %d, want %d", len(runs), len(profiles))
	}
	vector := ExtractStreamFeatures(runs[0].Events)
	if vector.Features["stream_count"] < 2 || vector.Features["interleaving_score"] <= 0 {
		t.Fatalf("feature vector missing stream features: %+v", vector)
	}
	report := ScanCollapse(ScenarioBulkVsInteractive, runs, DefaultCollapseThresholds())
	if report.DiversityScore <= 0 || report.Conclusion != "passed" {
		t.Fatalf("expected generated profiles to pass collapse scan: %+v", report)
	}
}

func TestCollapseScannerDetectsStreamMutants(t *testing.T) {
	tests := map[string]string{
		mutant.ModeFixedStreamIDStrategy:      "stream_id_sequence",
		mutant.ModeFixedWindowUpdatePolicy:    "window_update_rhythm",
		mutant.ModeFIFOSchedulerOnly:          "scheduler_decision_pattern",
		mutant.ModeFixedResetClosePolicy:      "close_reset_outcome",
		mutant.ModePaddingOnlyStreamDiversity: "stream_behavior_fixed",
	}
	for mode, metric := range tests {
		t.Run(mode, func(t *testing.T) {
			profiles, err := mutant.GenerateProfiles(mode, 1000, 6)
			if err != nil {
				t.Fatal(err)
			}
			runs, err := RunMutantScenarioCorpus(context.Background(), mode, profiles, []Scenario{DefaultScenario(ScenarioResetMidstream)})
			if err != nil {
				t.Fatal(err)
			}
			report := ScanCollapse(ScenarioResetMidstream, runs, DefaultCollapseThresholds())
			if !containsString(report.SuspiciousMetrics, metric) {
				t.Fatalf("expected suspicious metric %q for %s: %+v", metric, mode, report)
			}
		})
	}
}

func TestNoBackpressureMutantFailsFlowControl(t *testing.T) {
	profiles, err := mutant.GenerateProfiles(mutant.ModeNoBackpressure, 1100, 4)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := RunMutantScenarioCorpus(context.Background(), mutant.ModeNoBackpressure, profiles, []Scenario{DefaultScenario(ScenarioBlockedStream)})
	if err != nil {
		t.Fatal(err)
	}
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Correctness.BackpressureFailures == 0 {
		t.Fatalf("no-backpressure mutant was not detected: %+v", report)
	}
}

func TestFIFOOnlyMutantFailsInteractiveExpectation(t *testing.T) {
	profiles, err := mutant.GenerateProfiles(mutant.ModeFIFOSchedulerOnly, 1200, 4)
	if err != nil {
		t.Fatal(err)
	}
	runs, err := RunMutantScenarioCorpus(context.Background(), mutant.ModeFIFOSchedulerOnly, profiles, []Scenario{DefaultScenario(ScenarioBulkVsInteractive)})
	if err != nil {
		t.Fatal(err)
	}
	report := AnalyzeRuns(runs, DefaultCollapseThresholds())
	if report.Correctness.SchedulerFailures == 0 {
		t.Fatalf("fifo-only scheduler mutant was not detected: %+v", report)
	}
}

func BenchmarkBalancedInterleaveScenario(b *testing.B) {
	p := mustProfile(b, 930)
	scenario := DefaultScenario(ScenarioBalancedInterleave)
	for i := 0; i < b.N; i++ {
		if _, err := RunScenario(context.Background(), p, scenario); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBulkVsInteractiveScenario(b *testing.B) {
	p := mustProfile(b, 931)
	scenario := DefaultScenario(ScenarioBulkVsInteractive)
	for i := 0; i < b.N; i++ {
		if _, err := RunScenario(context.Background(), p, scenario); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkStreamFeatureExtraction(b *testing.B) {
	p := mustProfile(b, 932)
	run, err := RunScenario(context.Background(), p, DefaultScenario(ScenarioUnevenStreamSizes))
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ExtractStreamFeatures(run.Events)
	}
}

func BenchmarkCollapseScanTwentyProfiles(b *testing.B) {
	profiles := mustProfiles(b, 940, 20)
	runs, err := RunScenarioCorpus(context.Background(), profiles, []Scenario{DefaultScenario(ScenarioBalancedInterleave), DefaultScenario(ScenarioBlockedStream)})
	if err != nil {
		b.Fatal(err)
	}
	thresholds := DefaultCollapseThresholds()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ScanCollapse(ScenarioBalancedInterleave, runs, thresholds)
	}
}

func mustProfile(t testing.TB, seed int64) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = ""
	if p.Stream.MaxConcurrentStreams < 4 {
		p.Stream.MaxConcurrentStreams = 4
	}
	if p.Compatibility.MaxStreamCount < p.Stream.MaxConcurrentStreams {
		p.Compatibility.MaxStreamCount = p.Stream.MaxConcurrentStreams
	}
	if p.Stream.InitialSessionWindowBytes < p.Stream.InitialStreamWindowBytes*4 {
		p.Stream.InitialSessionWindowBytes = p.Stream.InitialStreamWindowBytes * 4
	}
	return p
}

func mustProfiles(t testing.TB, start int64, count int) []*ir.Profile {
	t.Helper()
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		profiles = append(profiles, mustProfile(t, start+int64(i)))
	}
	return profiles
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
