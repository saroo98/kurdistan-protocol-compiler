package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type AuditReport struct {
	Version          string       `json:"version"`
	Mode             string       `json:"mode"`
	GeneratedAt      string       `json:"generated_at"`
	ProfileCount     int          `json:"profile_count"`
	TraceCount       int          `json:"trace_count"`
	Gates            []GateResult `json:"gates"`
	CorpusSummary    any          `json:"corpus_summary,omitempty"`
	TraceScanSummary any          `json:"trace_scan_summary,omitempty"`
	BenchmarkSummary any          `json:"benchmark_summary,omitempty"`
	Conclusion       string       `json:"conclusion"`
}

type GateResult struct {
	Name     string         `json:"name"`
	Passed   bool           `json:"passed"`
	Severity string         `json:"severity"`
	Summary  string         `json:"summary"`
	Details  map[string]any `json:"details,omitempty"`
}

type BenchmarkSummary struct {
	ProfileGenerationMillis int64 `json:"profile_generation_millis"`
	TraceGenerationMillis   int64 `json:"trace_generation_millis"`
	TotalMillis             int64 `json:"total_millis"`
}

func (r AuditReport) Passed() bool {
	for _, gate := range r.Gates {
		if gate.Severity == "required" && !gate.Passed {
			return false
		}
	}
	return true
}

func (r AuditReport) HumanSummary() string {
	var b strings.Builder
	fmt.Fprintf(&b, "kcheck %s (%s)\n", r.Version, r.Mode)
	fmt.Fprintf(&b, "profiles: %d\n", r.ProfileCount)
	fmt.Fprintf(&b, "traces: %d\n", r.TraceCount)
	for _, gate := range r.Gates {
		status := "PASS"
		if !gate.Passed {
			status = "FAIL"
		}
		fmt.Fprintf(&b, "[%s] %s: %s\n", status, gate.Name, gate.Summary)
	}
	fmt.Fprintf(&b, "conclusion: %s\n", r.Conclusion)
	return b.String()
}

func WriteJSON(path string, report AuditReport) error {
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
