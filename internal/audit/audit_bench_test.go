package audit

import (
	"context"
	"testing"

	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/labtrace"
	"kurdistan/internal/mutant"
	ktrace "kurdistan/internal/trace"
)

func BenchmarkQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	for i := 0; i < b.N; i++ {
		if _, err := Run(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkFullAuditCore(b *testing.B) {
	cfg := DefaultConfig("full")
	cfg.TraceCount = 10
	for i := 0; i < b.N; i++ {
		if _, err := Run(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGateEvaluation(b *testing.B) {
	profiles, err := diversity.GenerateProfiles(1, 100)
	if err != nil {
		b.Fatal(err)
	}
	corpus := diversity.SummarizeCorpus(1, profiles)
	rawTraces := makeTraceCorpusForBench(b, profiles[:10])
	scan := ktrace.ScanTraces(rawTraces, ktrace.DefaultStabilityThreshold)
	thresholds := DefaultThresholds()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ProfileCorpusDiversityGate(corpus, thresholds)
		_ = BlackBoxTraceDiversityGate(scan, thresholds)
		_ = FixedSignatureGate(profiles, rawTraces, thresholds)
		_ = AdversarialBlackBoxClusteringGate(context.Background(), profiles, rawTraces, thresholds)
		_ = MalformedProbeBehaviorGate(profiles, thresholds)
	}
}

func BenchmarkAdversarialGateQuick(b *testing.B) {
	profiles, err := diversity.GenerateProfiles(1, 30)
	if err != nil {
		b.Fatal(err)
	}
	rawTraces := makeTraceCorpusForBench(b, profiles[:10])
	thresholds := DefaultThresholds()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = AdversarialBlackBoxClusteringGate(context.Background(), profiles, rawTraces, thresholds)
	}
}

func BenchmarkProxySemQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		if _, err := RunProxySemanticsAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecurityQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		if _, err := RunSecurityAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRuntimeQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		if _, err := RunRuntimeAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHardeningAuditQuickMode(b *testing.B) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		report, err := RunHardeningAudit(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatal(report.Conclusion)
		}
	}
}

func BenchmarkProxyGateEvaluation(b *testing.B) {
	profiles, err := generateAuditProfiles(1, 6)
	if err != nil {
		b.Fatal(err)
	}
	thresholds := DefaultThresholds()
	thresholds.MinProxyPolicyCombinations = 2
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = ProxySemanticsDiversityGate(profiles, thresholds)
		_ = ProxyTargetBackpressureGate(context.Background(), profiles, thresholds)
		_ = ProxyErrorResetIsolationGate(context.Background(), profiles, thresholds)
	}
}

func BenchmarkStatusRendering(b *testing.B) {
	report, err := Run(context.Background(), AuditConfig{
		Mode:         "quick",
		StartSeed:    1,
		ProfileCount: 20,
		TraceCount:   5,
		Thresholds: func() AuditThresholds {
			t := DefaultThresholds()
			t.MinInvalidInputCombinations = 3
			t.MinFrameGrammarCombinations = 3
			t.MinSchedulerCombinations = 3
			t.MinPaddingCombinations = 2
			t.MinDifferentTraceSeparationRatio = 0.4
			return t
		}(),
	})
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RenderStatus(report)
	}
}

func BenchmarkMutationGateEvaluation(b *testing.B) {
	profiles, err := mutant.GenerateProfiles(mutant.ModePaddingNoiseOnly, 1, 20)
	if err != nil {
		b.Fatal(err)
	}
	traces := mutant.TraceFixtures(mutant.ModePaddingNoiseOnly, profiles)
	thresholds := DefaultThresholds()
	thresholds.MinFirstContactPatterns = 2
	thresholds.MinFrameGrammarCombinations = 2
	thresholds.MinSchedulerCombinations = 2
	thresholds.MinPaddingCombinations = 2
	thresholds.MinInvalidInputCombinations = 2
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		summary := diversity.SummarizeCorpus(1, profiles)
		scan := ktrace.ScanTraces(traces, ktrace.DefaultStabilityThreshold)
		_ = ProfileCorpusDiversityGate(summary, thresholds)
		_ = BlackBoxTraceDiversityGate(scan, thresholds)
		_ = AdversarialBlackBoxClusteringGate(context.Background(), profiles, traces, thresholds)
		_ = MalformedProbeBehaviorGate(profiles, thresholds)
	}
}

func BenchmarkAuditComparison(b *testing.B) {
	oldReport, err := LoadReport("testdata/audit/baseline-small.json")
	if err != nil {
		b.Fatal(err)
	}
	newReport, err := LoadReport("testdata/audit/failing-fixed-small.json")
	if err != nil {
		b.Fatal(err)
	}
	thresholds := DefaultComparisonThresholds()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CompareReports(oldReport, newReport, thresholds)
	}
}

func BenchmarkLongitudinalStatusRendering(b *testing.B) {
	report, err := LoadReport("testdata/audit/baseline-small.json")
	if err != nil {
		b.Fatal(err)
	}
	comparison := CompareReports(report, report, DefaultComparisonThresholds())
	report.BaselineComparison = &comparison
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = RenderStatus(report)
	}
}

func makeTraceCorpusForBench(b *testing.B, profiles []*ir.Profile) [][]ktrace.Event {
	b.Helper()
	traces := make([][]ktrace.Event, 0, len(profiles))
	for _, p := range profiles {
		events, err := labtrace.CaptureTrace(context.Background(), p, []byte("hello kurdistan"))
		if err != nil {
			b.Fatal(err)
		}
		traces = append(traces, events)
	}
	return traces
}
