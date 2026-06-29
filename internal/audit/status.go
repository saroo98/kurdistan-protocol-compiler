// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

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
	fmt.Fprintln(&b, "<!-- SPDX-License-Identifier: CC-BY-SA-4.0 -->")
	fmt.Fprintln(&b, "<!-- Copyright 2026 Saro -->")
	fmt.Fprintln(&b)
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
			"unique_stream_policy_combinations",
			"unique_proxy_policy_combinations",
			"unique_carrier_policy_combinations",
			"unique_security_policy_combinations",
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
		renderNamedGateResult(&b, report.Gates, "multi_stream_generated_parity")
		renderNamedGateResult(&b, report.Gates, "multi_stream_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "proxy_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "carrier_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "security_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "runtime_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "generated_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "generated_source_scanner")
		if summary, ok := report.CodegenSummary.(CodegenAuditSummary); ok {
			fmt.Fprintf(&b, "- `semantic_equivalence`: `%s`\n", summary.SemanticEquivalence)
			fmt.Fprintf(&b, "- `generated_profile_diversity`: `%s`\n", summary.GeneratedProfileDiversity)
			fmt.Fprintf(&b, "- `fixed_signature`: `%s`\n", summary.FixedSignature)
			fmt.Fprintf(&b, "- `multi_stream_generated_parity`: `%s`\n", summary.MultiStreamGeneratedParity)
			fmt.Fprintf(&b, "- `multi_stream_generated_backend_parity`: `%s`\n", summary.StreamAdversaryParity)
			fmt.Fprintf(&b, "- `proxy_generated_backend_parity`: `%s`\n", summary.ProxySemGeneratedParity)
			fmt.Fprintf(&b, "- `carrier_generated_backend_parity`: `%s`\n", summary.CarrierGeneratedParity)
			fmt.Fprintf(&b, "- `security_generated_backend_parity`: `%s`\n", summary.SecurityGeneratedParity)
			fmt.Fprintf(&b, "- `runtime_generated_backend_parity`: `%s`\n", summary.RuntimeGeneratedParity)
			fmt.Fprintf(&b, "- `hardening_generated_backend_parity`: `%s`\n", summary.HardeningGeneratedParity)
			fmt.Fprintf(&b, "- `adapter_generated_backend_parity`: `%s`\n", summary.AdapterGeneratedParity)
			fmt.Fprintf(&b, "- `local_adapter_generated_backend_parity`: `%s`\n", summary.LocalAdapterGeneratedParity)
			fmt.Fprintf(&b, "- `byte_transport_generated_backend_parity`: `%s`\n", summary.ByteTransportGeneratedParity)
			fmt.Fprintf(&b, "- `mutant_detection`: `%s`\n", summary.MutantDetection)
			fmt.Fprintf(&b, "- `source_scanner`: `%s`\n", summary.SourceScanner)
		}
	} else {
		fmt.Fprintln(&b, "- Generated-backend audit was not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck codegen --quick` for generated source checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Multi-Stream Adversary")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "multi_stream_adversarial_scenarios"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderGateDetail(&b, gate, "profile_count")
		renderGateDetail(&b, gate, "scenario_count")
		renderGateDetail(&b, gate, "correct_runs")
		renderGateDetail(&b, gate, "scenario_runs")
		renderNamedGateResult(&b, report.Gates, "multi_stream_collapse_resistance")
		renderNamedGateResult(&b, report.Gates, "multi_stream_mutant_detection")
	} else {
		fmt.Fprintln(&b, "- Multi-stream adversary gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck streamadversary --quick` for stream collapse checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Proxy Semantics")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "proxy_semantics_correctness"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderGateDetail(&b, gate, "profile_count")
		renderGateDetail(&b, gate, "scenario_count")
		renderGateDetail(&b, gate, "correct_runs")
		renderGateDetail(&b, gate, "scenario_runs")
		renderGateDetail(&b, gate, "target_classes")
		renderNamedGateResult(&b, report.Gates, "proxy_semantics_diversity")
		renderNamedGateResult(&b, report.Gates, "proxy_target_backpressure")
		renderNamedGateResult(&b, report.Gates, "proxy_error_reset_isolation")
		renderNamedGateResult(&b, report.Gates, "proxy_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "proxy_generated_backend_parity")
	} else {
		fmt.Fprintln(&b, "- Proxy-semantics gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck proxysem --quick` for proxy-semantics checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Carrier Abstraction")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "carrier_semantics_correctness"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderGateDetail(&b, gate, "profile_count")
		renderGateDetail(&b, gate, "scenario_count")
		renderGateDetail(&b, gate, "carrier_families")
		renderGateDetail(&b, gate, "correct_runs")
		renderGateDetail(&b, gate, "scenario_runs")
		renderNamedGateResult(&b, report.Gates, "carrier_diversity")
		renderNamedGateResult(&b, report.Gates, "carrier_backpressure_preservation")
		renderNamedGateResult(&b, report.Gates, "carrier_loss_reorder_recovery")
		renderNamedGateResult(&b, report.Gates, "carrier_proxysem_parity")
		renderNamedGateResult(&b, report.Gates, "carrier_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "carrier_generated_backend_parity")
	} else {
		fmt.Fprintln(&b, "- Carrier abstraction gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck carrier --quick` for carrier abstraction checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Security Prerequisites")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "security_transcript_binding"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "security_transcript_binding")
		renderNamedGateResult(&b, report.Gates, "security_key_schedule")
		renderNamedGateResult(&b, report.Gates, "security_nonce_uniqueness")
		renderNamedGateResult(&b, report.Gates, "security_replay_rejection")
		renderNamedGateResult(&b, report.Gates, "security_downgrade_resistance")
		renderNamedGateResult(&b, report.Gates, "security_capability_negotiation")
		renderNamedGateResult(&b, report.Gates, "security_profile_compatibility")
		renderNamedGateResult(&b, report.Gates, "security_config_hygiene")
		renderNamedGateResult(&b, report.Gates, "security_secret_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "security_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "security_generated_backend_parity")
		if summary, ok := report.TraceScanSummary.(map[string]any); ok {
			renderSummaryMap(&b, summary, []string{
				"unique_transcript_modes",
				"unique_nonce_modes",
				"unique_replay_policies",
				"unique_capability_policies",
				"security_version",
				"secure_envelope_model",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Security audit was not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck security --quick` for security prerequisite checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Runtime Session Architecture")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "runtime_session_lifecycle"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderGateDetail(&b, gate, "sessions")
		renderNamedGateResult(&b, report.Gates, "runtime_session_lifecycle")
		renderNamedGateResult(&b, report.Gates, "runtime_capability_negotiation")
		renderNamedGateResult(&b, report.Gates, "runtime_profile_compatibility")
		renderNamedGateResult(&b, report.Gates, "runtime_security_context")
		renderNamedGateResult(&b, report.Gates, "runtime_replay_rejection")
		renderNamedGateResult(&b, report.Gates, "runtime_stream_management")
		renderNamedGateResult(&b, report.Gates, "runtime_backpressure")
		renderNamedGateResult(&b, report.Gates, "runtime_error_reset_isolation")
		renderNamedGateResult(&b, report.Gates, "runtime_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "runtime_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "runtime_generated_backend_parity")
		if strings.HasPrefix(report.Mode, "runtime-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"runtime_families",
				"diversity_score",
				"conclusion",
				"runs",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Runtime session gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck runtime --quick` for runtime session checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Implementation Hardening")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "hardening_invariant_registry"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "hardening_invariant_registry")
		renderNamedGateResult(&b, report.Gates, "hardening_api_contracts")
		renderNamedGateResult(&b, report.Gates, "hardening_panic_safety")
		renderNamedGateResult(&b, report.Gates, "hardening_resource_limits")
		renderNamedGateResult(&b, report.Gates, "hardening_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "hardening_concurrency_safety")
		renderNamedGateResult(&b, report.Gates, "hardening_generated_parity")
		renderNamedGateResult(&b, report.Gates, "hardening_pre_adapter_readiness")
		renderNamedGateResult(&b, report.Gates, "hardening_mutant_detection")
		if strings.HasPrefix(report.Mode, "hardening-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"profile_count",
				"invariants_checked",
				"contracts_checked",
				"resource_checks",
				"panic_safety_checks",
				"trace_hygiene_checks",
				"concurrency_checks",
				"generated_parity_checks",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Hardening gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck hardening --quick` for implementation hardening checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Adapter Interface Architecture")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "adapter_interface_contracts"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "adapter_interface_contracts")
		renderNamedGateResult(&b, report.Gates, "adapter_config_validation")
		renderNamedGateResult(&b, report.Gates, "adapter_flow_lifecycle")
		renderNamedGateResult(&b, report.Gates, "adapter_runtime_boundary")
		renderNamedGateResult(&b, report.Gates, "adapter_capability_compatibility")
		renderNamedGateResult(&b, report.Gates, "adapter_backpressure")
		renderNamedGateResult(&b, report.Gates, "adapter_error_reset_mapping")
		renderNamedGateResult(&b, report.Gates, "adapter_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "adapter_collapse_resistance")
		renderNamedGateResult(&b, report.Gates, "adapter_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "adapter_generated_backend_parity")
		if strings.HasPrefix(report.Mode, "adapter-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"profile_count",
				"scenario_count",
				"adapter_kinds",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Adapter interface gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck adapter --quick` for adapter boundary checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Known Limitations")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "- Multi-stream support is a loopback-only lab harness, not SOCKS, VPN, HTTP proxying, or external networking.")
	fmt.Fprintln(&b, "- Proxy-semantics support uses synthetic target descriptors and in-memory target behavior.")
	fmt.Fprintln(&b, "- Carrier abstraction models envelope shapes, retry/reorder metadata, and queue pressure without real carrier integrations.")
	fmt.Fprintln(&b, "- Security prerequisites model transcript binding, key schedules, nonce/replay checks, compatibility, and secure envelope metadata before real adapter integration.")
	fmt.Fprintln(&b, "- Runtime session architecture uses deterministic in-memory links and synthetic scenarios, not OS sockets or live peers.")
	fmt.Fprintln(&b, "- Adapter interface architecture defines contracts and an in-memory harness, not concrete adapter implementations.")
	fmt.Fprintln(&b, "- Hardening gates prove local invariants and misuse resistance only; concrete adapter work still needs separate review.")
	fmt.Fprintln(&b, "- Test-only key material and no production key exchange.")
	fmt.Fprintln(&b, "- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.")
	fmt.Fprintln(&b, "- No VPN, SOCKS, HTTP carrier, TLS mimicry, CDN behavior, deployment scripts, or live-network testing.")
	fmt.Fprintln(&b, "- The audit detects local regressions; it cannot prove undetectability or real-world robustness.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Next Milestone")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "Milestone 16 should focus on a deterministic local adapter prototype with adapter, hardening, runtime, and generated-backend gates kept mandatory.")
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
