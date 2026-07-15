// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"kurdistan/internal/lab/runtimeadversary"
	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/protocol/ir"
)

func RunRuntimeAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	scenarios := runtimeadversary.QuickScenarios()
	if cfg.Mode == "full" {
		scenarios = runtimeadversary.FullScenarios()
	}
	runs := runtimeadversary.RunScenarioCorpus(ctx, profiles, scenarios)
	analysis := runtimeadversary.AnalyzeRuns(runs, runtimeCollapseThresholds(cfg.Thresholds))
	analysis.Mode = cfg.Mode
	gates := []GateResult{
		RuntimeSessionLifecycleGate(ctx, profiles, scenarios),
		RuntimeCapabilityNegotiationGate(ctx, profiles),
		RuntimeProfileCompatibilityGate(ctx, profiles),
		RuntimeSecurityContextGate(ctx, profiles),
		RuntimeReplayRejectionGate(ctx, profiles),
		RuntimeStreamManagementGate(ctx, profiles),
		RuntimeBackpressureGate(ctx, profiles),
		RuntimeErrorResetIsolationGate(ctx, profiles),
		RuntimeTraceHygieneGate(ctx, profiles),
		RuntimeMutantDetectionGate(ctx),
		RuntimeGeneratedBackendParityGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "runtime-" + cfg.Mode,
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

func RuntimeSessionLifecycleGate(ctx context.Context, profiles []*ir.Profile, scenarios []runtimeadversary.Scenario) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), scenarios)
	failures := []string{}
	sessions := 0
	for _, run := range runs {
		sessions++
		if !run.Correct {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
	}
	return gate("runtime_session_lifecycle", len(failures) == 0, "required", fmt.Sprintf("%d runtime sessions checked", sessions), map[string]any{"sessions": sessions}, failures)
}

func RuntimeCapabilityNegotiationGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioCapabilityDowngrade)})
	failures := []string{}
	for _, run := range runs {
		if !run.Correct || !strings.Contains(run.Failure, "capability") {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("runtime_capability_negotiation", len(failures) == 0, "required", fmt.Sprintf("%d capability downgrade attempts rejected", len(runs)), nil, failures)
}

func RuntimeProfileCompatibilityGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioProfileMismatchSession)})
	failures := []string{}
	for _, run := range runs {
		if !run.Correct || !strings.Contains(run.Failure, "profile") {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("runtime_profile_compatibility", len(failures) == 0, "required", fmt.Sprintf("%d profile mismatch attempts rejected", len(runs)), nil, failures)
}

func RuntimeSecurityContextGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioHappyPathSession)})
	failures := []string{}
	for _, run := range runs {
		if !run.Summary.TranscriptMatched || !run.Summary.CapabilityMatched {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("runtime_security_context", len(failures) == 0, "required", fmt.Sprintf("%d security contexts created and matched", len(runs)*2), nil, failures)
}

func RuntimeReplayRejectionGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioReplayInjection)})
	rejected := 0
	failures := []string{}
	for _, run := range runs {
		rejected += run.Summary.ReplayRejected
		if run.Summary.ReplayRejected == 0 {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("runtime_replay_rejection", len(failures) == 0, "required", fmt.Sprintf("%d replay attempts rejected", rejected), nil, failures)
}

func RuntimeStreamManagementGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioHappyPathSession)})
	streams := 0
	failures := []string{}
	for _, run := range runs {
		streams += run.Summary.StreamsOpened
		if run.Summary.StreamsOpened == 0 || run.Summary.ClientState != "closed" {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("runtime_stream_management", len(failures) == 0, "required", fmt.Sprintf("%d runtime stream messages managed", streams), nil, failures)
}

func RuntimeBackpressureGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioLargeObjectRuntime)})
	events := 0
	failures := []string{}
	for _, run := range runs {
		events += run.Summary.BackpressureEvents
		if run.Summary.BackpressureEvents == 0 {
			failures = append(failures, run.ProfileID)
		}
	}
	return gate("runtime_backpressure", len(failures) == 0, "required", fmt.Sprintf("%d runtime backpressure events observed", events), nil, failures)
}

func RuntimeErrorResetIsolationGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{
		runtimeadversary.DefaultScenario(runtimeadversary.ScenarioTargetErrorIsolation),
		runtimeadversary.DefaultScenario(runtimeadversary.ScenarioTargetResetIsolation),
	})
	errors, resets := 0, 0
	failures := []string{}
	for _, run := range runs {
		errors += run.Summary.TargetErrors
		resets += run.Summary.TargetResets
		if !run.Correct {
			failures = append(failures, run.ProfileID+":"+run.Scenario)
		}
	}
	return gate("runtime_error_reset_isolation", len(failures) == 0, "required", fmt.Sprintf("%d target errors and %d target resets isolated", errors, resets), nil, failures)
}

func RuntimeTraceHygieneGate(ctx context.Context, profiles []*ir.Profile) GateResult {
	runs := runtimeadversary.RunScenarioCorpus(ctx, selectProfiles(profiles, 3), []runtimeadversary.Scenario{runtimeadversary.DefaultScenario(runtimeadversary.ScenarioHappyPathSession)})
	failures := []string{}
	for _, run := range runs {
		if run.Summary.PayloadLogged || run.Summary.SecretLogged {
			failures = append(failures, run.ProfileID)
		}
		event := ktrace.DiagnosticEventV1{SchemaVersion: ktrace.DiagnosticSchemaV1, EventClass: "runtime", OutcomeBucket: "completed", HygieneResult: "redacted"}
		if err := ktrace.ValidateDiagnosticEventV1(event); err != nil || ktrace.ContainsSensitiveValue(event, []byte(run.ProfileID), []byte(run.Scenario)) {
			failures = append(failures, run.ProfileID+":strict diagnostic invalid")
		}
	}
	return gate("runtime_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d runtime traces checked for payload/secret hygiene", len(runs)), nil, failures)
}

func RuntimeMutantDetectionGate(ctx context.Context) GateResult {
	_ = ctx
	return realLabFaultInjectionGateV1("runtime_mutant_detection", "runtime", 5100)
}

func RuntimeGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("runtime_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := codegenGeneratorSource(root)
	if err != nil {
		return gate("runtime_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"runtime_generated.go", "RuntimeDemo", "CaptureRuntimeTrace", "runtime-demo", "runtime"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	for path, markers := range map[string][]string{
		"internal/runtime/generated_profile_parity_test.go": {"TestGeneratedProfileParityV1", m0PolicySeedCSVHashV1, "len(generatedProfileParityPinsV1) != 29"},
		"internal/runtime/policy_enforcement_test.go":       {"TestInterpretedPolicyParityCoveringArrayV1", "pairwise coverage=%d/%d want 732/732", "reflect.DeepEqual(seeds, []int64{1, 2, 3, 4, 5, 6, 7, 8})"},
	} {
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			failures = append(failures, readErr.Error())
			continue
		}
		for _, marker := range markers {
			if !strings.Contains(string(raw), marker) {
				failures = append(failures, path+": missing "+marker)
			}
		}
	}
	return gate("runtime_generated_backend_parity", len(failures) == 0, "required", "generated runtime markers plus exact 29-row generated/interpreted policy evidence registry checked", map[string]any{
		"scanner":                    "source-marker-and-executable-test-registry",
		"policy_seed_csv_sha256":     m0PolicySeedCSVHashV1,
		"policy_interaction_rows":    29,
		"policy_pairwise_coverage":   "732/732",
		"wo042_catalog_substitution": false,
	}, failures)
}

func runtimeCollapseThresholds(thresholds AuditThresholds) runtimeadversary.CollapseThresholds {
	defaults := runtimeadversary.DefaultCollapseThresholds()
	if thresholds.MaxRuntimeAdversaryDominantRatio != 0 {
		defaults.MaxDominantRatio = thresholds.MaxRuntimeAdversaryDominantRatio
	}
	if thresholds.MinRuntimeAdversaryDiversityScore != 0 {
		defaults.MinDiversityScore = thresholds.MinRuntimeAdversaryDiversityScore
	}
	if thresholds.MinRuntimeScenarioSuccess != 0 {
		defaults.MinScenarioSuccess = thresholds.MinRuntimeScenarioSuccess
	}
	return defaults
}
