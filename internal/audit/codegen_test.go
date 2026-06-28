package audit

import (
	"context"
	"encoding/json"
	"testing"
)

func TestCodegenAuditConfigDefaults(t *testing.T) {
	quick := DefaultCodegenAuditConfig("quick")
	if quick.ProfileCount != 3 || quick.StartSeed != 1 {
		t.Fatalf("quick codegen defaults = %+v", quick)
	}
	full := DefaultCodegenAuditConfig("full")
	if full.ProfileCount <= quick.ProfileCount {
		t.Fatalf("full codegen defaults should be larger than quick: %+v", full)
	}
}

func TestCodegenAuditRunsOneProfile(t *testing.T) {
	cfg := DefaultCodegenAuditConfig("quick")
	cfg.ProfileCount = 1
	report, err := RunCodegenAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed() {
		t.Fatalf("codegen audit failed: %+v", report.Gates)
	}
	if !containsGate(report.Gates, "generated_backend_codegen") {
		t.Fatalf("missing generated backend gate: %+v", report.Gates)
	}
}

func TestGeneratedTraceCorpusSemanticEquivalence(t *testing.T) {
	cfg := DefaultCodegenAuditConfig("quick")
	cfg.ProfileCount = 1
	corpus, err := RunGeneratedBackendTraceCorpus(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(corpus.ProfileRuns) != 1 {
		t.Fatalf("profile runs = %d, want 1", len(corpus.ProfileRuns))
	}
	run := corpus.ProfileRuns[0]
	if !run.SemanticEquivalent {
		t.Fatalf("generated and interpreted traces were not equivalent: %+v", run)
	}
	if run.GeneratedEchoBytes != len(codegenAuditPayload()) {
		t.Fatalf("generated echo bytes = %d, want %d", run.GeneratedEchoBytes, len(codegenAuditPayload()))
	}
	if !run.MultiStreamEquivalent {
		t.Fatalf("generated and interpreted multi-stream traces were not equivalent: %+v", run)
	}
	if run.InterpretedFirstContactCount != run.GeneratedFirstContactCount {
		t.Fatalf("first-contact count mismatch: %+v", run)
	}
	if run.PayloadLogged {
		t.Fatalf("payload was found in generated trace events")
	}
}

func TestCodegenAuditQuickIncludesM7GatesAndJSON(t *testing.T) {
	cfg := DefaultCodegenAuditConfig("quick")
	cfg.ProfileCount = 2
	report, err := RunCodegenAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"generated_backend_codegen",
		"generated_semantic_equivalence",
		"generated_profile_diversity",
		"generated_fixed_signature",
		"generated_vs_interpreted_divergence",
		"multi_stream_generated_parity",
		"multi_stream_generated_backend_parity",
		"generated_mutant_detection",
		"generated_source_scanner",
	}
	for _, name := range required {
		if !containsGate(report.Gates, name) {
			t.Fatalf("missing codegen gate %s: %+v", name, report.Gates)
		}
	}
	if !report.Passed() {
		t.Fatalf("codegen audit failed: %+v", report.Gates)
	}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"\"codegen\"", "semantic_equivalence", "generated_profile_diversity", "fixed_signature", "interpreted_vs_generated", "multi_stream_generated_parity", "multi_stream_generated_backend_parity"} {
		if !containsString(string(raw), want) {
			t.Fatalf("audit JSON missing %q: %s", want, raw)
		}
	}
}

func TestGeneratedMutantDetectionFailsCollapsedProfiles(t *testing.T) {
	gate := GeneratedMutantDetectionGate(context.Background(), []string{
		"cosmetic_symbols_only",
		"fixed_frame_grammar",
		"fixed_first_contact",
		"padding_noise_only",
	}, 4)
	if !gate.Passed {
		t.Fatalf("expected mutant detection gate itself to pass by detecting failures: %+v", gate)
	}
	detected, _ := gate.Details["detected_modes"].([]string)
	if len(detected) < 4 {
		t.Fatalf("expected all mutant modes detected, got %+v", gate.Details)
	}
}

func TestStatusRenderingIncludesCodegenGateDetails(t *testing.T) {
	report := AuditReport{
		Version:      "0.10.0-lab",
		Mode:         "codegen-quick",
		GeneratedAt:  "2026-06-27T00:00:00Z",
		ProfileCount: 2,
		TraceCount:   2,
		Gates: []GateResult{
			{Name: "generated_backend_codegen", Passed: true, Severity: "required", Summary: "ok", Details: map[string]any{"generated_module_count": 2}},
			{Name: "generated_semantic_equivalence", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "generated_profile_diversity", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "generated_fixed_signature", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "multi_stream_generated_parity", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "multi_stream_generated_backend_parity", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "proxy_generated_backend_parity", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "generated_mutant_detection", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "generated_source_scanner", Passed: true, Severity: "required", Summary: "ok"},
		},
		CodegenSummary: CodegenAuditSummary{
			Profiles:                   2,
			GeneratedModules:           2,
			SemanticEquivalence:        "passed",
			GeneratedProfileDiversity:  "passed",
			FixedSignature:             "passed",
			MultiStreamGeneratedParity: "passed",
			StreamAdversaryParity:      "passed",
			ProxySemGeneratedParity:    "passed",
			MutantDetection:            "passed",
			SourceScanner:              "passed",
		},
		Conclusion: "passed",
	}
	status := RenderStatus(report)
	for _, want := range []string{"Generated Source Backend", "generated_semantic_equivalence", "generated_profile_diversity", "generated_fixed_signature", "multi_stream_generated_parity", "multi_stream_generated_backend_parity", "proxy_generated_backend_parity", "generated_mutant_detection", "generated_source_scanner"} {
		if !containsString(status, want) {
			t.Fatalf("status missing %q:\n%s", want, status)
		}
	}
}

func BenchmarkGeneratedBackendTraceCorpusQuick(b *testing.B) {
	cfg := DefaultCodegenAuditConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		if _, err := RunGeneratedBackendTraceCorpus(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGeneratedSemanticEquivalenceComparison(b *testing.B) {
	cfg := DefaultCodegenAuditConfig("quick")
	cfg.ProfileCount = 2
	corpus, err := RunGeneratedBackendTraceCorpus(context.Background(), cfg)
	if err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		gate := GeneratedSemanticEquivalenceGate(corpus)
		if !gate.Passed {
			b.Fatal(gate)
		}
	}
}

func BenchmarkCodegenAuditQuick(b *testing.B) {
	cfg := DefaultCodegenAuditConfig("quick")
	cfg.ProfileCount = 3
	for i := 0; i < b.N; i++ {
		report, err := RunCodegenAudit(context.Background(), cfg)
		if err != nil {
			b.Fatal(err)
		}
		if !report.Passed() {
			b.Fatal(report.Gates)
		}
	}
}

func containsString(value, want string) bool {
	return len(want) == 0 || (len(value) >= len(want) && stringContains(value, want))
}

func stringContains(value, want string) bool {
	for i := 0; i+len(want) <= len(value); i++ {
		if value[i:i+len(want)] == want {
			return true
		}
	}
	return false
}
