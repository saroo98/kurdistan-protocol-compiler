package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func RenderStatus(report AuditReport) string {
	var b strings.Builder
	fmt.Fprintln(&b, "# Kurdistan Protocol Compiler Status")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> Lab-only research prototype. This status does not claim real-world censorship resistance, undetectability, production safety, or deployment readiness.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Latest audit mode: `%s`\n", report.Mode)
	fmt.Fprintf(&b, "- Generated at: `%s`\n", report.GeneratedAt)
	fmt.Fprintf(&b, "- Profile count: `%d`\n", report.ProfileCount)
	fmt.Fprintf(&b, "- Trace count: `%d`\n", report.TraceCount)
	fmt.Fprintf(&b, "- Conclusion: `%s`\n", report.Conclusion)
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Gate Results")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "| Gate | Result | Severity | Summary |")
	fmt.Fprintln(&b, "| --- | --- | --- | --- |")
	for _, gate := range report.Gates {
		result := "PASS"
		if !gate.Passed {
			result = "FAIL"
		}
		fmt.Fprintf(&b, "| `%s` | %s | `%s` | %s |\n", gate.Name, result, gate.Severity, escapeTable(gate.Summary))
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Benchmark Highlights")
	fmt.Fprintln(&b)
	if summary, ok := report.BenchmarkSummary.(BenchmarkSummary); ok {
		fmt.Fprintf(&b, "- Profile generation: `%d ms`\n", summary.ProfileGenerationMillis)
		fmt.Fprintf(&b, "- Trace generation: `%d ms`\n", summary.TraceGenerationMillis)
		fmt.Fprintf(&b, "- Total audit runtime: `%d ms`\n", summary.TotalMillis)
	} else {
		fmt.Fprintln(&b, "- Benchmark summary unavailable.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Corpus Diversity Summary")
	fmt.Fprintln(&b)
	if summary, ok := report.CorpusSummary.(map[string]any); ok {
		renderSummaryMap(&b, summary, []string{
			"number_of_profiles",
			"unique_first_contact_patterns",
			"unique_frame_grammar_combinations",
			"unique_scheduler_combinations",
			"unique_padding_combinations",
			"unique_invalid_input_policy_combinations",
			"structurally_different_pairs",
		})
	} else {
		fmt.Fprintln(&b, "- See audit JSON for corpus details.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Trace Diversity Summary")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "- The audit checks first frame size, first-contact count, state path shape, frame-size histogram, padding histogram, invalid-input result, and close behavior for suspicious stability.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Adversarial Black-Box Summary")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "adversarial_black_box_clustering"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderGateDetail(&b, gate, "cluster_count")
		renderGateDetail(&b, gate, "largest_cluster_ratio")
		renderGateDetail(&b, gate, "different_profile_average_distance")
		renderGateDetail(&b, gate, "same_profile_distance")
		renderGateDetail(&b, gate, "generated_cluster_conclusion")
	} else {
		fmt.Fprintln(&b, "- Adversarial clustering gate has not been run.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Baseline Comparison")
	fmt.Fprintln(&b)
	if report.BaselineComparison == nil {
		fmt.Fprintln(&b, "- No baseline comparison was run.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck --quick --status STATUS.md --baseline testdata/audit/baseline-small.json` to include longitudinal deltas.")
	} else {
		comparison := report.BaselineComparison
		fmt.Fprintf(&b, "- Conclusion: `%s`\n", comparison.Conclusion)
		fmt.Fprintf(&b, "- pass/fail changes: `%d`\n", len(comparison.GateChanges))
		fmt.Fprintf(&b, "- `first_contact_patterns_delta`: `%d`\n", comparison.MetricDeltas.FirstContactPatterns)
		fmt.Fprintf(&b, "- `frame_grammar_combinations_delta`: `%d`\n", comparison.MetricDeltas.FrameGrammarCombinations)
		fmt.Fprintf(&b, "- `scheduler_combinations_delta`: `%d`\n", comparison.MetricDeltas.SchedulerCombinations)
		fmt.Fprintf(&b, "- `padding_combinations_delta`: `%d`\n", comparison.MetricDeltas.PaddingCombinations)
		fmt.Fprintf(&b, "- `invalid_input_combinations_delta`: `%d`\n", comparison.MetricDeltas.InvalidInputCombinations)
		fmt.Fprintf(&b, "- `cluster_count_delta`: `%d`\n", comparison.MetricDeltas.ClusterCount)
		fmt.Fprintf(&b, "- `largest_cluster_ratio_delta`: `%.3f`\n", comparison.MetricDeltas.LargestClusterRatio)
		fmt.Fprintf(&b, "- `different_profile_separation_ratio_delta`: `%.3f`\n", comparison.MetricDeltas.DifferentProfileSeparation)
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Generated Source Backend")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "generated_backend_codegen"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderGateDetail(&b, gate, "generated_module_count")
		renderGateDetail(&b, gate, "generated_tests_run")
		renderGateDetail(&b, gate, "interpreted_traces_checked")
		renderGateDetail(&b, gate, "generated_traces_checked")
		renderGateDetail(&b, gate, "round_trip_exercised_by")
		renderNamedGateResult(&b, report.Gates, "generated_semantic_equivalence")
		renderNamedGateResult(&b, report.Gates, "generated_profile_diversity")
		renderNamedGateResult(&b, report.Gates, "generated_fixed_signature")
		renderNamedGateResult(&b, report.Gates, "generated_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "generated_source_scanner")
		if summary, ok := report.CodegenSummary.(CodegenAuditSummary); ok {
			fmt.Fprintf(&b, "- `semantic_equivalence`: `%s`\n", summary.SemanticEquivalence)
			fmt.Fprintf(&b, "- `generated_profile_diversity`: `%s`\n", summary.GeneratedProfileDiversity)
			fmt.Fprintf(&b, "- `fixed_signature`: `%s`\n", summary.FixedSignature)
			fmt.Fprintf(&b, "- `mutant_detection`: `%s`\n", summary.MutantDetection)
			fmt.Fprintf(&b, "- `source_scanner`: `%s`\n", summary.SourceScanner)
		}
	} else {
		fmt.Fprintln(&b, "- Generated-backend audit was not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck codegen --quick` for generated source checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Known Limitations")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "- Single-stream loopback-only runtime.")
	fmt.Fprintln(&b, "- Test-only key material and no production key exchange.")
	fmt.Fprintln(&b, "- Generated source still reuses shared lab helpers for IO, framing, scheduling, padding, auth, and traces.")
	fmt.Fprintln(&b, "- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.")
	fmt.Fprintln(&b, "- The audit detects local regressions; it cannot prove undetectability or real-world robustness.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Next Milestone")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Milestone 7 should focus on generated-backend trace comparison depth, richer lab-only malformed-session corpora, and clearer explanations for gate failures.")
	return b.String()
}

func WriteStatus(path string, report AuditReport) error {
	if path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	return os.WriteFile(path, []byte(RenderStatus(report)), 0o600)
}

func escapeTable(value string) string {
	return strings.ReplaceAll(value, "|", "\\|")
}

func renderSummaryMap(b *strings.Builder, summary map[string]any, keys []string) {
	for _, key := range keys {
		if value, ok := summary[key]; ok {
			fmt.Fprintf(b, "- `%s`: `%v`\n", key, value)
		}
	}
}

func gateByName(gates []GateResult, name string) (GateResult, bool) {
	for _, gate := range gates {
		if gate.Name == name {
			return gate, true
		}
	}
	return GateResult{}, false
}

func renderGateDetail(b *strings.Builder, gate GateResult, key string) {
	if gate.Details == nil {
		return
	}
	if value, ok := gate.Details[key]; ok {
		fmt.Fprintf(b, "- `%s`: `%v`\n", key, value)
	}
}

func renderNamedGateResult(b *strings.Builder, gates []GateResult, name string) {
	gate, ok := gateByName(gates, name)
	if !ok {
		return
	}
	result := "failed"
	if gate.Passed {
		result = "passed"
	}
	fmt.Fprintf(b, "- `%s`: `%s`\n", name, result)
}

func toJSONMap(value any) map[string]any {
	out := map[string]any{}
	raw, err := json.Marshal(value)
	if err != nil {
		return out
	}
	_ = json.Unmarshal(raw, &out)
	return out
}
