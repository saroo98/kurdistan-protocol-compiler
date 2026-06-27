package adversary

import (
	"context"
	"fmt"

	"kurdistan/internal/diversity"
	"kurdistan/internal/ir"
	"kurdistan/internal/labtrace"
	ktrace "kurdistan/internal/trace"
)

const ReportVersion = "0.4.0-lab"

type AnalysisConfig struct {
	StartSeed        int64   `json:"start_seed"`
	ProfileCount     int     `json:"profile_count"`
	TraceCount       int     `json:"trace_count"`
	ControlCount     int     `json:"control_count"`
	ClusterThreshold float64 `json:"cluster_threshold"`
}

func DefaultAnalysisConfig(mode string) AnalysisConfig {
	cfg := AnalysisConfig{
		StartSeed:        1,
		ProfileCount:     100,
		TraceCount:       20,
		ControlCount:     8,
		ClusterThreshold: DefaultClusterThreshold,
	}
	if mode == "full" {
		cfg.ProfileCount = 1000
		cfg.TraceCount = 100
		cfg.ControlCount = 16
	}
	return cfg
}

func RunLocalAnalysis(ctx context.Context, cfg AnalysisConfig) (AdversaryReport, error) {
	if cfg.ProfileCount <= 0 {
		cfg.ProfileCount = 100
	}
	if cfg.TraceCount <= 0 {
		cfg.TraceCount = 20
	}
	if cfg.TraceCount > cfg.ProfileCount {
		cfg.TraceCount = cfg.ProfileCount
	}
	if cfg.ControlCount <= 0 {
		cfg.ControlCount = 8
	}
	if cfg.ClusterThreshold <= 0 {
		cfg.ClusterThreshold = DefaultClusterThreshold
	}
	profiles, err := diversity.GenerateProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AdversaryReport{}, err
	}
	traces, err := CaptureProfileTraces(ctx, profiles, cfg.TraceCount, []byte("hello kurdistan"))
	if err != nil {
		return AdversaryReport{}, err
	}
	return AnalyzeTraces(traces, cfg), nil
}

func CaptureProfileTraces(ctx context.Context, profiles []*ir.Profile, traceCount int, payload []byte) ([][]ktrace.Event, error) {
	if traceCount > len(profiles) {
		traceCount = len(profiles)
	}
	traces := make([][]ktrace.Event, 0, traceCount)
	for i := 0; i < traceCount; i++ {
		events, err := labtrace.CaptureTrace(ctx, profiles[i], payload)
		if err != nil {
			return nil, fmt.Errorf("capture profile %s: %w", profiles[i].ID, err)
		}
		traces = append(traces, events)
	}
	return traces, nil
}

func AnalyzeTraces(traces [][]ktrace.Event, cfg AnalysisConfig) AdversaryReport {
	if cfg.ClusterThreshold <= 0 {
		cfg.ClusterThreshold = DefaultClusterThreshold
	}
	if cfg.ControlCount <= 0 {
		cfg.ControlCount = 8
	}
	vectors := ExtractFeatureVectors(traces)
	report := AdversaryReport{
		Version:                ReportVersion,
		GeneratedTraceCount:    len(traces),
		FeatureVectorCount:     len(vectors),
		ClusterThreshold:       cfg.ClusterThreshold,
		GeneratedClusterReport: Cluster(vectors, cfg.ClusterThreshold),
		ControlResults:         AnalyzeControlFamilies(DefaultControlFamilies(cfg.ControlCount, cfg.StartSeed), cfg.ClusterThreshold),
	}
	report.Conclusion = "passed"
	if report.GeneratedClusterReport.VectorCount == 0 {
		report.Conclusion = "no traces"
	}
	return report
}

func AnalyzeControlFamilies(families []ControlFamily, threshold float64) []ControlResult {
	results := make([]ControlResult, 0, len(families))
	for _, family := range families {
		vectors := ExtractFeatureVectors(family.Traces)
		clusterReport := Cluster(vectors, threshold)
		result := ControlResult{
			Name:          family.Name,
			Expected:      family.Expected,
			VectorCount:   len(vectors),
			ClusterReport: clusterReport,
		}
		switch family.Name {
		case "fixed_protocol", "noisy_fixed_protocol":
			result.SuspiciouslyTight = clusterReport.ClusterCount == 1 && clusterReport.PairwiseStats.MaxDistance <= 0.25
		default:
			result.SuspiciouslyTight = clusterReport.ClusterCount == 1 && clusterReport.PairwiseStats.MaxDistance <= 0.05
		}
		if result.SuspiciouslyTight {
			result.Conclusion = "suspicious fixed-family control"
		} else {
			result.Conclusion = "not a tight fixed-family control"
		}
		results = append(results, result)
	}
	return results
}
