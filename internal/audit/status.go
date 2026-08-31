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
	fmt.Fprintln(&b, "> Staged product-development program. Phases 8-11 add bounded profile cryptography, protected Android state, a reserved-range `VpnService`/TUN runtime, and authenticated Kurd-over-TLS/TCP owned-loopback conformance. Owned-network, public-relay, field-resilience, production-safety, deployment, and release evidence remains **[UNVERIFIED]**.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "> Legend: `[live]` executes real behavior locally (current network I/O remains owned-loopback-only) · `[model]` deterministic in-memory contract, not live · `[plan]` design spec only. The audit table includes many historical `[model]`/`[plan]` gates; the separate Phase 9-11 Android and transport boundary is enforced by `go run ./cmd/gate -android` and `docs/PZ-evidence-ref-048`. The security and runtime mutant gates report real lab fault-injection detector sensitivity with paired controls. A pass does not prove defect absence, production security, field resilience, release readiness, or authorization to merge or deploy.")
	fmt.Fprintln(&b)
	fmt.Fprintf(&b, "- Latest audit mode: `%s`\n", report.Mode)
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
	fmt.Fprintln(&b, "- Volatile wall-clock timings are omitted from the committed status snapshot. Use the audit JSON or command output for local performance diagnostics.")
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
		renderGateDetail(&b, gate, "generated_cluster_conclusion")
	} else {
		fmt.Fprintln(&b, "- Adversarial clustering gate has not been run.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Baseline Comparison")
	fmt.Fprintln(&b)
	if report.BaselineComparison == nil {
		fmt.Fprintln(&b, "- No baseline comparison was run.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck --quick --status SZ-evidence-ref-070 --baseline testdata/audit/baseline-small.json` to include longitudinal deltas.")
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
		renderNamedGateResult(&b, report.Gates, "hostdetect_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "transportbundle_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "pathrace_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "androidreview_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "androidruntime_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_generated_backend_parity")
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
			fmt.Fprintf(&b, "- `bytepath_fixture_generated_backend_parity`: `%s`\n", summary.BytePathFixtureParity)
			fmt.Fprintf(&b, "- `wirefeatures_generated_backend_parity`: `%s`\n", summary.WireFeaturesGeneratedParity)
			fmt.Fprintf(&b, "- `wiregen_generated_backend_parity`: `%s`\n", summary.WireGenGeneratedParity)
			fmt.Fprintf(&b, "- `hostdetect_generated_backend_parity`: `%s`\n", summary.HostDetectGeneratedParity)
			fmt.Fprintf(&b, "- `relayfleet_generated_backend_parity`: `%s`\n", summary.RelayFleetGeneratedParity)
			fmt.Fprintf(&b, "- `adaptivepath_generated_backend_parity`: `%s`\n", summary.AdaptivePathGeneratedParity)
			fmt.Fprintf(&b, "- `transportbundle_generated_backend_parity`: `%s`\n", summary.TransportBundleGeneratedParity)
			fmt.Fprintf(&b, "- `pathrace_generated_backend_parity`: `%s`\n", summary.PathRaceGeneratedParity)
			fmt.Fprintf(&b, "- `androidreview_generated_backend_parity`: `%s`\n", summary.AndroidReviewParity)
			fmt.Fprintf(&b, "- `androidruntime_generated_backend_parity`: `%s`\n", summary.AndroidRuntimeParity)
			fmt.Fprintf(&b, "- `androidvpnservice_generated_backend_parity`: `%s`\n", summary.AndroidVPNServiceParity)
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
	fmt.Fprintln(&b, "## Byte-Path Fixture Freeze")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "fixture_bytepath_drift"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "fixture_bytepath_drift")
		renderNamedGateResult(&b, report.Gates, "bytepath_fixture_stability")
		renderNamedGateResult(&b, report.Gates, "bytepath_generated_interpreted_parity")
		renderNamedGateResult(&b, report.Gates, "bytepath_malformed_corpus")
		renderNamedGateResult(&b, report.Gates, "bytepath_regression_baselines")
		renderNamedGateResult(&b, report.Gates, "bytepath_fixture_trace_hygiene")
		if strings.HasPrefix(report.Mode, "bytepath-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"fixture_count",
				"profile_count",
				"scenario_count",
				"malformed_cases",
				"parity_pairs",
				"semantic_matches",
				"byte_shape_matches",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Byte-path fixture gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck bytepath --quick` or `go run ./cmd/kcheck fixtures verify` for fixture stability checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Protocol Feature Corpus")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "protocorpus_schema_valid"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "protocorpus_schema_valid")
		renderNamedGateResult(&b, report.Gates, "protocorpus_feature_taxonomy")
		renderNamedGateResult(&b, report.Gates, "protocorpus_entry_coverage")
		renderNamedGateResult(&b, report.Gates, "protocorpus_trace_hygiene")
		if strings.HasPrefix(report.Mode, "protocorpus-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"corpus_version",
				"entry_count",
				"phase_kinds",
				"field_kinds",
				"visibility_classes",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Protocol corpus gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck protocorpus --quick` for corpus taxonomy checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Wire Feature Baselines")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "wirefeatures_extraction"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "wirefeatures_extraction")
		renderNamedGateResult(&b, report.Gates, "wirefeatures_firstn_model")
		renderNamedGateResult(&b, report.Gates, "wirefeatures_corpus_comparison")
		renderNamedGateResult(&b, report.Gates, "wirefeatures_collapse_resistance")
		renderNamedGateResult(&b, report.Gates, "wirefeatures_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "wirefeatures_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "wirefeatures_baseline")
		if strings.HasPrefix(report.Mode, "wirefeatures-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"feature_schema_version",
				"feature_count",
				"profile_count",
				"scenario_count",
				"unique_first_n_shapes",
				"unique_feature_hashes",
				"matched_families",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Wire-feature gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck wirefeatures --quick` for feature baseline checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Wire-Shape Generator")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "wiregen_policy_generation"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "wiregen_policy_generation")
		renderNamedGateResult(&b, report.Gates, "wiregen_policy_validation")
		renderNamedGateResult(&b, report.Gates, "wiregen_corpus_selection")
		renderNamedGateResult(&b, report.Gates, "wiregen_profile_integration")
		renderNamedGateResult(&b, report.Gates, "wiregen_bytepath_application")
		renderNamedGateResult(&b, report.Gates, "wiregen_feature_expectation_match")
		renderNamedGateResult(&b, report.Gates, "wiregen_firstn_diversity")
		renderNamedGateResult(&b, report.Gates, "wiregen_metadata_exposure_diversity")
		renderNamedGateResult(&b, report.Gates, "wiregen_collapse_resistance")
		renderNamedGateResult(&b, report.Gates, "wiregen_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "wiregen_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "wiregen_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "wiregen_baseline_fixtures")
		if strings.HasPrefix(report.Mode, "wiregen-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"corpus_version",
				"policies",
				"feature_vectors",
				"profile_count",
				"scenario_count",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Wire-shape generator gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck wiregen --quick` for wire-shape generator checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Relay Fleet Lifecycle")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "relayfleet_lifecycle_integrity"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "relayfleet_lifecycle_integrity")
		renderNamedGateResult(&b, report.Gates, "relayfleet_profile_assignment")
		renderNamedGateResult(&b, report.Gates, "relayfleet_churn_schedule")
		renderNamedGateResult(&b, report.Gates, "relayfleet_migration_model")
		renderNamedGateResult(&b, report.Gates, "relayfleet_burn_risk")
		renderNamedGateResult(&b, report.Gates, "relayfleet_collapse_detection")
		renderNamedGateResult(&b, report.Gates, "relayfleet_control_detection")
		renderNamedGateResult(&b, report.Gates, "relayfleet_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "relayfleet_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "relayfleet_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "relayfleet_fixture_drift")
		if strings.HasPrefix(report.Mode, "relayfleet-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"version",
				"fleet_id",
				"relays",
				"active_relays",
				"churn_events",
				"migration_events",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Relay fleet gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck relayfleet --quick` for relay churn and lifecycle checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Adaptive Path Model")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "adaptivepath_candidate_taxonomy"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "adaptivepath_candidate_taxonomy")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_condition_model")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_freshness_uncertainty")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_viability_evaluation")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_decision_inputs")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_misuse_detection")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "adaptivepath_public_docs")
		if strings.HasPrefix(report.Mode, "adaptivepath-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"version",
				"candidate_families",
				"condition_classes",
				"candidate_count",
				"observation_count",
				"rejected_candidates",
				"high_risk_candidates",
				"stale_observations",
				"expired_observations",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Adaptive path gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck adaptivepath --quick` for candidate taxonomy checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Transport Bundle Compiler")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "transportbundle_policy_validation"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "transportbundle_policy_validation")
		renderNamedGateResult(&b, report.Gates, "transportbundle_seed_planning")
		renderNamedGateResult(&b, report.Gates, "transportbundle_family_coverage")
		renderNamedGateResult(&b, report.Gates, "transportbundle_adaptivepath_mapping")
		renderNamedGateResult(&b, report.Gates, "transportbundle_relay_binding")
		renderNamedGateResult(&b, report.Gates, "transportbundle_fallback_hints")
		renderNamedGateResult(&b, report.Gates, "transportbundle_collapse_detection")
		renderNamedGateResult(&b, report.Gates, "transportbundle_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "transportbundle_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "transportbundle_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "transportbundle_fixture_drift")
		if strings.HasPrefix(report.Mode, "transportbundle-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"version",
				"candidate_count",
				"mode_count",
				"family_count",
				"fallback_hint_count",
				"collapse_conclusion",
				"parity_conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Transport bundle compiler gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck transportbundle --quick` for bundle candidate and fallback checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Path Racing and Short-Lived Scoring")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "pathrace_scenario_validation"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "pathrace_scenario_validation")
		renderNamedGateResult(&b, report.Gates, "pathrace_parallel_scheduler")
		renderNamedGateResult(&b, report.Gates, "pathrace_candidate_verification")
		renderNamedGateResult(&b, report.Gates, "pathrace_short_lived_scoring")
		renderNamedGateResult(&b, report.Gates, "pathrace_ranking_tiebreak")
		renderNamedGateResult(&b, report.Gates, "pathrace_misuse_detection")
		renderNamedGateResult(&b, report.Gates, "pathrace_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "pathrace_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "pathrace_mutant_detection")
		renderNamedGateResult(&b, report.Gates, "pathrace_fixture_drift")
		if strings.HasPrefix(report.Mode, "pathrace-") {
			summary := toJSONMap(report.TraceScanSummary)
			renderSummaryMap(&b, summary, []string{
				"version",
				"scenario_count",
				"candidate_count",
				"started_candidates",
				"verified_candidates",
				"failed_candidates",
				"stalled_candidates",
				"rejected_candidates",
				"gated_candidates",
				"winners_declared",
				"generated_parity",
				"conclusion",
			})
		}
	} else {
		fmt.Fprintln(&b, "- Pathrace gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck pathrace --quick` for synthetic racing and scoring checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Android Architecture Review")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "androidreview_report"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "androidreview_report")
		renderNamedGateResult(&b, report.Gates, "androidreview_user_flows")
		renderNamedGateResult(&b, report.Gates, "androidreview_permission_model")
		renderNamedGateResult(&b, report.Gates, "androidreview_ui_states")
		renderNamedGateResult(&b, report.Gates, "androidreview_diagnostics_privacy")
		renderNamedGateResult(&b, report.Gates, "androidreview_kill_switch")
		renderNamedGateResult(&b, report.Gates, "androidreview_runtime_composition")
		renderNamedGateResult(&b, report.Gates, "androidreview_m57_m58_contracts")
		renderNamedGateResult(&b, report.Gates, "androidreview_misuse_detection")
		renderNamedGateResult(&b, report.Gates, "androidreview_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "androidreview_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "androidreview_public_claim_safety")
		renderNamedGateResult(&b, report.Gates, "androidreview_fixture_drift")
	} else {
		fmt.Fprintln(&b, "- Android architecture review gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck androidreview --quick` for Android architecture contract checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Android Local Runtime Port")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "androidruntime_report"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "androidruntime_report")
		renderNamedGateResult(&b, report.Gates, "androidruntime_initialization")
		renderNamedGateResult(&b, report.Gates, "androidruntime_lifecycle")
		renderNamedGateResult(&b, report.Gates, "androidruntime_storage_boundaries")
		renderNamedGateResult(&b, report.Gates, "androidruntime_diagnostics")
		renderNamedGateResult(&b, report.Gates, "androidruntime_concurrency")
		renderNamedGateResult(&b, report.Gates, "androidruntime_compatibility")
		renderNamedGateResult(&b, report.Gates, "androidruntime_shutdown")
		renderNamedGateResult(&b, report.Gates, "androidruntime_misuse_detection")
		renderNamedGateResult(&b, report.Gates, "androidruntime_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "androidruntime_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "androidruntime_public_claim_safety")
		renderNamedGateResult(&b, report.Gates, "androidruntime_fixture_drift")
	} else {
		fmt.Fprintln(&b, "- Android local runtime port gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck androidruntime --quick` for Android local runtime checks.")
	}
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Android VpnService Prototype")
	fmt.Fprintln(&b)
	if gate, ok := gateByName(report.Gates, "androidvpnservice_report"); ok {
		fmt.Fprintf(&b, "- Gate result: `%t`\n", gate.Passed)
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_report")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_permission_model")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_lifecycle")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_packet_flow_mapping")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_kill_switch")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_diagnostics")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_reconnect_hooks")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_integration")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_shutdown")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_misuse_detection")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_generated_backend_parity")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_trace_hygiene")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_public_claim_safety")
		renderNamedGateResult(&b, report.Gates, "androidvpnservice_fixture_drift")
	} else {
		fmt.Fprintln(&b, "- Android VpnService prototype gates were not run in this report.")
		fmt.Fprintln(&b, "- Run `go run ./cmd/kcheck androidvpnservice --quick` for Android VpnService prototype checks.")
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
	fmt.Fprintln(&b, "- Byte-path fixtures freeze safe metadata and hashes, not raw packet captures or production wire behavior.")
	fmt.Fprintln(&b, "- Wire-shape generation is deterministic and fixture-driven; classifier/dataset evaluation is separate future work.")
	fmt.Fprintln(&b, "- Relay fleet modeling uses synthetic relays, schedule ticks, and safe summaries only; it does not provision relays or rotate real infrastructure.")
	fmt.Fprintln(&b, "- Transport bundle compiler output is a local candidate bundle and fallback hint model, not a live selector or path-racing runtime.")
	fmt.Fprintln(&b, "- Path racing uses local synthetic observations and short-lived scoring only; it does not probe, dial, resolve, or select a production active path.")
	fmt.Fprintln(&b, "- Android architecture review defines user flows, permission boundaries, diagnostics, kill-switch behavior, and M57/M58 contracts.")
	fmt.Fprintln(&b, "- Android local runtime port checks local initialization, lifecycle, profile loading, diagnostics, storage boundaries, compatibility, and safe shutdown.")
	fmt.Fprintln(&b, "- The historical Android VpnService audit gates are models; the separately gated Phase 10/11 Android implementation carries only reserved-range test traffic through the authenticated owned-loopback Kurd transport.")
	fmt.Fprintln(&b, "- Hardening gates prove local invariants and misuse resistance only; concrete adapter work still needs separate review.")
	fmt.Fprintln(&b, "- Phase 8 locally implements deterministic profile framing, signed admission, optional recipient sealing, lifecycle activation, and local tooling with non-production fixtures. It has no production key custody, production signer, Android keystore, HSM/KMS, live delivery, deployment, pilot, or release evidence.")
	fmt.Fprintln(&b, "- Generated source still reuses shared lab helpers for IO, framing, stream session logic, scheduling, padding, auth, and traces.")
	fmt.Fprintln(&b, "- There is no unrestricted Internet egress, public relay, SOCKS or HTTP proxy service, TLS mimicry, CDN behavior, deployment automation, or non-loopback field evidence.")
	fmt.Fprintln(&b, "- The audit detects local regressions; it cannot prove undetectability or real-world robustness.")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, "## Milestone Frontier")
	fmt.Fprintln(&b)
	fmt.Fprintln(&b, milestoneFrontierNote(report))
	return b.String()
}

// milestoneFrontierNote derives an honest current-frontier line from the gates
// actually present in this report, instead of a hardcoded (and lagging) future
// milestone claim. It names the latest modelled surface that was evaluated and
// points at the safety boundary.
func milestoneFrontierNote(report AuditReport) string {
	if _, ok := gateByName(report.Gates, "androidcarrier_report"); ok {
		return "The latest modelled surface in this audit table is the Android carrier integration path (`androidcarrier_*`). Separately, Phases 8-11 implement and gate profile cryptography, protected Android state, reserved-range TUN behavior, and authenticated owned-loopback Kurd transport. Owned-LAN, owned-relay, physical-device matrix, capacity, handover, field-resilience, deployment, and release evidence remains **[UNVERIFIED]**."
	}
	if _, ok := gateByName(report.Gates, "androidvpnservice_report"); ok {
		return "The latest modelled surface in this audit table is the Android VpnService prototype (`androidvpnservice_*`). Separately gated Phase 10/11 code implements reserved-range TUN behavior and authenticated owned-loopback Kurd transport. Non-loopback and production evidence remains **[UNVERIFIED]**."
	}
	return "Implementation evidence is summarized by the gate table above. Only the specifically authorized owned-loopback transport is live locally; non-loopback and production operation remains closed."
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
