package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

type ComparisonThresholds struct {
	MaxDiversityMetricDrop         int     `json:"max_diversity_metric_drop"`
	MaxClusterCountDrop            int     `json:"max_cluster_count_drop"`
	MaxLargestClusterRatioIncrease float64 `json:"max_largest_cluster_ratio_increase"`
	MaxSeparationRatioDrop         float64 `json:"max_separation_ratio_drop"`
	FailOnRequiredGateRegression   bool    `json:"fail_on_required_gate_regression"`
}

type GateChange struct {
	Name      string `json:"name"`
	OldPassed bool   `json:"old_passed"`
	NewPassed bool   `json:"new_passed"`
	Severity  string `json:"severity"`
}

type MetricDeltas struct {
	FirstContactPatterns       int     `json:"first_contact_patterns_delta"`
	FrameGrammarCombinations   int     `json:"frame_grammar_combinations_delta"`
	SchedulerCombinations      int     `json:"scheduler_combinations_delta"`
	PaddingCombinations        int     `json:"padding_combinations_delta"`
	InvalidInputCombinations   int     `json:"invalid_input_combinations_delta"`
	ClusterCount               int     `json:"cluster_count_delta"`
	LargestClusterRatio        float64 `json:"largest_cluster_ratio_delta"`
	DifferentProfileSeparation float64 `json:"different_profile_separation_ratio_delta"`
}

type BenchmarkDeltas struct {
	ProfileGenerationMillis int64 `json:"profile_generation_millis_delta"`
	TraceGenerationMillis   int64 `json:"trace_generation_millis_delta"`
	TotalMillis             int64 `json:"total_millis_delta"`
}

type AuditComparisonReport struct {
	OldVersion        string          `json:"old_version"`
	NewVersion        string          `json:"new_version"`
	OldMode           string          `json:"old_mode"`
	NewMode           string          `json:"new_mode"`
	ProfileCountDelta int             `json:"profile_count_delta"`
	TraceCountDelta   int             `json:"trace_count_delta"`
	GateChanges       []GateChange    `json:"gate_changes"`
	MetricDeltas      MetricDeltas    `json:"metric_deltas"`
	BenchmarkDeltas   BenchmarkDeltas `json:"benchmark_deltas"`
	Passed            bool            `json:"passed"`
	Conclusion        string          `json:"conclusion"`
	Failures          []string        `json:"failures,omitempty"`
}

func DefaultComparisonThresholds() ComparisonThresholds {
	return ComparisonThresholds{
		MaxDiversityMetricDrop:         0,
		MaxClusterCountDrop:            0,
		MaxLargestClusterRatioIncrease: 0.05,
		MaxSeparationRatioDrop:         0.05,
		FailOnRequiredGateRegression:   true,
	}
}

func LoadReport(path string) (AuditReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		root, rootErr := repoRoot()
		if rootErr == nil {
			raw, err = os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		}
		if err != nil {
			return AuditReport{}, err
		}
	}
	var report AuditReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return AuditReport{}, err
	}
	return report, nil
}

func CompareReports(oldReport, newReport AuditReport, thresholds ComparisonThresholds) AuditComparisonReport {
	if thresholds == (ComparisonThresholds{}) {
		thresholds = DefaultComparisonThresholds()
	}
	comparison := AuditComparisonReport{
		OldVersion:        oldReport.Version,
		NewVersion:        newReport.Version,
		OldMode:           oldReport.Mode,
		NewMode:           newReport.Mode,
		ProfileCountDelta: newReport.ProfileCount - oldReport.ProfileCount,
		TraceCountDelta:   newReport.TraceCount - oldReport.TraceCount,
		GateChanges:       compareGates(oldReport.Gates, newReport.Gates),
		MetricDeltas:      compareMetrics(oldReport, newReport),
		BenchmarkDeltas:   compareBenchmarks(oldReport.BenchmarkSummary, newReport.BenchmarkSummary),
	}
	failures := []string{}
	if thresholds.FailOnRequiredGateRegression {
		for _, change := range comparison.GateChanges {
			if change.Severity == "required" && change.OldPassed && !change.NewPassed {
				failures = append(failures, "required gate regressed: "+change.Name)
			}
		}
	}
	diversityDrops := map[string]int{
		"first-contact patterns":     comparison.MetricDeltas.FirstContactPatterns,
		"frame grammar combinations": comparison.MetricDeltas.FrameGrammarCombinations,
		"scheduler combinations":     comparison.MetricDeltas.SchedulerCombinations,
		"padding combinations":       comparison.MetricDeltas.PaddingCombinations,
		"invalid-input combinations": comparison.MetricDeltas.InvalidInputCombinations,
	}
	for name, delta := range diversityDrops {
		if delta < -thresholds.MaxDiversityMetricDrop {
			failures = append(failures, fmt.Sprintf("%s dropped by %d", name, -delta))
		}
	}
	if comparison.MetricDeltas.ClusterCount < -thresholds.MaxClusterCountDrop {
		failures = append(failures, fmt.Sprintf("cluster count dropped by %d", -comparison.MetricDeltas.ClusterCount))
	}
	if comparison.MetricDeltas.LargestClusterRatio > thresholds.MaxLargestClusterRatioIncrease {
		failures = append(failures, fmt.Sprintf("largest cluster ratio increased by %.3f", comparison.MetricDeltas.LargestClusterRatio))
	}
	if comparison.MetricDeltas.DifferentProfileSeparation < -thresholds.MaxSeparationRatioDrop {
		failures = append(failures, fmt.Sprintf("different-profile separation ratio dropped by %.3f", -comparison.MetricDeltas.DifferentProfileSeparation))
	}
	comparison.Failures = failures
	comparison.Passed = len(failures) == 0
	if comparison.Passed {
		comparison.Conclusion = "passed"
	} else {
		comparison.Conclusion = "failed"
	}
	return comparison
}

func (r AuditComparisonReport) HumanSummary() string {
	var b strings.Builder
	fmt.Fprintln(&b, "audit comparison")
	fmt.Fprintf(&b, "old: %s (%s)\n", r.OldVersion, r.OldMode)
	fmt.Fprintf(&b, "new: %s (%s)\n", r.NewVersion, r.NewMode)
	fmt.Fprintf(&b, "profile_count_delta: %d\n", r.ProfileCountDelta)
	fmt.Fprintf(&b, "trace_count_delta: %d\n", r.TraceCountDelta)
	fmt.Fprintf(&b, "first_contact_patterns_delta: %d\n", r.MetricDeltas.FirstContactPatterns)
	fmt.Fprintf(&b, "frame_grammar_combinations_delta: %d\n", r.MetricDeltas.FrameGrammarCombinations)
	fmt.Fprintf(&b, "scheduler_combinations_delta: %d\n", r.MetricDeltas.SchedulerCombinations)
	fmt.Fprintf(&b, "padding_combinations_delta: %d\n", r.MetricDeltas.PaddingCombinations)
	fmt.Fprintf(&b, "invalid_input_combinations_delta: %d\n", r.MetricDeltas.InvalidInputCombinations)
	fmt.Fprintf(&b, "cluster_count_delta: %d\n", r.MetricDeltas.ClusterCount)
	fmt.Fprintf(&b, "largest_cluster_ratio_delta: %.3f\n", r.MetricDeltas.LargestClusterRatio)
	fmt.Fprintf(&b, "different_profile_separation_ratio_delta: %.3f\n", r.MetricDeltas.DifferentProfileSeparation)
	for _, change := range r.GateChanges {
		fmt.Fprintf(&b, "gate_change: %s %t -> %t\n", change.Name, change.OldPassed, change.NewPassed)
	}
	for _, failure := range r.Failures {
		fmt.Fprintf(&b, "failure: %s\n", failure)
	}
	fmt.Fprintf(&b, "conclusion: %s\n", r.Conclusion)
	return b.String()
}

func compareGates(oldGates, newGates []GateResult) []GateChange {
	oldByName := gateMap(oldGates)
	newByName := gateMap(newGates)
	names := map[string]bool{}
	for name := range oldByName {
		names[name] = true
	}
	for name := range newByName {
		names[name] = true
	}
	keys := make([]string, 0, len(names))
	for name := range names {
		keys = append(keys, name)
	}
	sort.Strings(keys)
	changes := []GateChange{}
	for _, name := range keys {
		oldGate := oldByName[name]
		newGate := newByName[name]
		severity := newGate.Severity
		if severity == "" {
			severity = oldGate.Severity
		}
		if oldGate.Passed != newGate.Passed {
			changes = append(changes, GateChange{Name: name, OldPassed: oldGate.Passed, NewPassed: newGate.Passed, Severity: severity})
		}
	}
	return changes
}

func gateMap(gates []GateResult) map[string]GateResult {
	out := map[string]GateResult{}
	for _, gate := range gates {
		out[gate.Name] = gate
	}
	return out
}

func compareMetrics(oldReport, newReport AuditReport) MetricDeltas {
	return MetricDeltas{
		FirstContactPatterns:       intMetric(newReport.CorpusSummary, "unique_first_contact_patterns") - intMetric(oldReport.CorpusSummary, "unique_first_contact_patterns"),
		FrameGrammarCombinations:   intMetric(newReport.CorpusSummary, "unique_frame_grammar_combinations") - intMetric(oldReport.CorpusSummary, "unique_frame_grammar_combinations"),
		SchedulerCombinations:      intMetric(newReport.CorpusSummary, "unique_scheduler_combinations") - intMetric(oldReport.CorpusSummary, "unique_scheduler_combinations"),
		PaddingCombinations:        intMetric(newReport.CorpusSummary, "unique_padding_combinations") - intMetric(oldReport.CorpusSummary, "unique_padding_combinations"),
		InvalidInputCombinations:   intMetric(newReport.CorpusSummary, "unique_invalid_input_policy_combinations") - intMetric(oldReport.CorpusSummary, "unique_invalid_input_policy_combinations"),
		ClusterCount:               intGateDetail(newReport, "adversarial_black_box_clustering", "cluster_count") - intGateDetail(oldReport, "adversarial_black_box_clustering", "cluster_count"),
		LargestClusterRatio:        floatGateDetail(newReport, "adversarial_black_box_clustering", "largest_cluster_ratio") - floatGateDetail(oldReport, "adversarial_black_box_clustering", "largest_cluster_ratio"),
		DifferentProfileSeparation: floatGateDetail(newReport, "different_profile_separation", "ratio") - floatGateDetail(oldReport, "different_profile_separation", "ratio"),
	}
}

func compareBenchmarks(oldSummary, newSummary any) BenchmarkDeltas {
	oldBench := benchmarkFromAny(oldSummary)
	newBench := benchmarkFromAny(newSummary)
	return BenchmarkDeltas{
		ProfileGenerationMillis: newBench.ProfileGenerationMillis - oldBench.ProfileGenerationMillis,
		TraceGenerationMillis:   newBench.TraceGenerationMillis - oldBench.TraceGenerationMillis,
		TotalMillis:             newBench.TotalMillis - oldBench.TotalMillis,
	}
}

func intGateDetail(report AuditReport, gateName, key string) int {
	return intFromAny(gateMap(report.Gates)[gateName].Details[key])
}

func floatGateDetail(report AuditReport, gateName, key string) float64 {
	return floatFromAny(gateMap(report.Gates)[gateName].Details[key])
}

func intMetric(summary any, key string) int {
	return intFromAny(mapFromAny(summary)[key])
}

func mapFromAny(value any) map[string]any {
	switch typed := value.(type) {
	case map[string]any:
		return typed
	default:
		out := map[string]any{}
		raw, err := json.Marshal(value)
		if err == nil {
			_ = json.Unmarshal(raw, &out)
		}
		return out
	}
}

func benchmarkFromAny(value any) BenchmarkSummary {
	switch typed := value.(type) {
	case BenchmarkSummary:
		return typed
	default:
		var out BenchmarkSummary
		raw, err := json.Marshal(value)
		if err == nil {
			_ = json.Unmarshal(raw, &out)
		}
		return out
	}
}

func intFromAny(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case json.Number:
		n, _ := typed.Int64()
		return int(n)
	default:
		return 0
	}
}

func floatFromAny(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		n, _ := typed.Float64()
		return n
	default:
		return 0
	}
}
