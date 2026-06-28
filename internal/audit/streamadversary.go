package audit

import (
	"context"
	"fmt"
	"time"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/streamadversary"
)

func RunStreamAdversaryAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := streamadversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = streamadversary.FullScenarios()
	}
	runs, err := streamadversary.RunScenarioCorpus(ctx, profiles, scenarios)
	if err != nil {
		return AuditReport{}, err
	}
	analysis := streamadversary.AnalyzeRuns(runs, streamCollapseThresholds(cfg.Thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		MultiStreamAdversarialScenariosGate(ctx, profiles, cfg.Thresholds),
		MultiStreamCollapseResistanceGate(ctx, profiles, cfg.Thresholds),
		MultiStreamMutantDetectionGate(ctx, cfg.Thresholds),
	}
	report := AuditReport{
		Version:          "0.9.0-lab",
		Mode:             "streamadversary-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       len(runs),
		Gates:            gates,
		TraceScanSummary: analysis,
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

func generateAuditProfiles(startSeed int64, count int) ([]*ir.Profile, error) {
	if count <= 0 {
		return nil, fmt.Errorf("profile count must be positive")
	}
	profiles := make([]*ir.Profile, 0, count)
	for i := 0; i < count; i++ {
		p, err := compiler.Generate(startSeed + int64(i))
		if err != nil {
			return nil, err
		}
		profiles = append(profiles, p)
	}
	return profiles, nil
}
