package adversary

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type ControlResult struct {
	Name              string        `json:"name"`
	Expected          string        `json:"expected"`
	VectorCount       int           `json:"vector_count"`
	ClusterReport     ClusterReport `json:"cluster_report"`
	SuspiciouslyTight bool          `json:"suspiciously_tight"`
	Conclusion        string        `json:"conclusion"`
}

type AdversaryReport struct {
	Version                string          `json:"version"`
	GeneratedTraceCount    int             `json:"generated_trace_count"`
	FeatureVectorCount     int             `json:"feature_vector_count"`
	ClusterThreshold       float64         `json:"cluster_threshold"`
	GeneratedClusterReport ClusterReport   `json:"generated_cluster_report"`
	ControlResults         []ControlResult `json:"control_results"`
	Conclusion             string          `json:"conclusion"`
}

func (r AdversaryReport) HumanSummary() string {
	var b strings.Builder
	fmt.Fprintln(&b, "adversary black-box trace analysis")
	fmt.Fprintf(&b, "traces: %d\n", r.GeneratedTraceCount)
	fmt.Fprintf(&b, "feature_vectors: %d\n", r.FeatureVectorCount)
	fmt.Fprintf(&b, "cluster_threshold: %.3f\n", r.ClusterThreshold)
	fmt.Fprintf(&b, "cluster_count: %d\n", r.GeneratedClusterReport.ClusterCount)
	fmt.Fprintf(&b, "largest_cluster: %d (%.2f)\n", r.GeneratedClusterReport.LargestClusterSize, r.GeneratedClusterReport.LargestClusterRatio)
	stats := r.GeneratedClusterReport.PairwiseStats
	fmt.Fprintf(&b, "pairwise_distance: min=%.3f avg=%.3f max=%.3f\n", stats.MinDistance, stats.AverageDistance, stats.MaxDistance)
	fmt.Fprintf(&b, "same_profile_distance_avg: %.3f pairs=%d\n", stats.SameProfileAverageDistance, stats.SameProfilePairs)
	fmt.Fprintf(&b, "different_profile_distance_avg: %.3f pairs=%d\n", stats.DifferentProfileAverageDistance, stats.DifferentProfilePairs)
	for _, control := range r.ControlResults {
		fmt.Fprintf(&b, "control %s: clusters=%d max_distance=%.3f suspicious=%t\n", control.Name, control.ClusterReport.ClusterCount, control.ClusterReport.PairwiseStats.MaxDistance, control.SuspiciouslyTight)
	}
	fmt.Fprintf(&b, "conclusion: %s\n", r.Conclusion)
	return b.String()
}

func WriteJSON(path string, report AdversaryReport) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	raw = append(raw, '\n')
	return os.WriteFile(path, raw, 0o600)
}
