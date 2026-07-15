package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/codegen"
)

func TestCodegenAuditConfigDefaults(t *testing.T) {
	quick := DefaultCodegenAuditConfig("quick")
	if quick.profileCount != 3 || quick.startSeed != 1 {
		t.Fatalf("quick codegen defaults = %+v", quick)
	}
	full := DefaultCodegenAuditConfig("full")
	if full.profileCount <= quick.profileCount {
		t.Fatalf("full codegen defaults should be larger than quick: %+v", full)
	}
}

func TestCodegenAuditRunsOneProfile(t *testing.T) {
	cfg := explicitCodegenConfig(t, 1, 1)
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
	cfg := explicitCodegenConfig(t, 1, 1)
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
	cfg := explicitCodegenConfig(t, 1, 2)
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
		"proxy_generated_backend_parity",
		"carrier_generated_backend_parity",
		"security_generated_backend_parity",
		"hostdetect_generated_backend_parity",
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
	for _, want := range []string{"\"codegen\"", "semantic_equivalence", "generated_profile_diversity", "fixed_signature", "interpreted_vs_generated", "multi_stream_generated_parity", "multi_stream_generated_backend_parity", "security_generated_backend_parity", "hostdetect_generated_backend_parity"} {
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
			{Name: "carrier_generated_backend_parity", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "security_generated_backend_parity", Passed: true, Severity: "required", Summary: "ok"},
			{Name: "hostdetect_generated_backend_parity", Passed: true, Severity: "required", Summary: "ok"},
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
			CarrierGeneratedParity:     "passed",
			SecurityGeneratedParity:    "passed",
			HostDetectGeneratedParity:  "passed",
			MutantDetection:            "passed",
			SourceScanner:              "passed",
		},
		Conclusion: "passed",
	}
	status := RenderStatus(report)
	for _, want := range []string{"Generated Source Backend", "generated_semantic_equivalence", "generated_profile_diversity", "generated_fixed_signature", "multi_stream_generated_parity", "multi_stream_generated_backend_parity", "proxy_generated_backend_parity", "carrier_generated_backend_parity", "security_generated_backend_parity", "hostdetect_generated_backend_parity", "generated_mutant_detection", "generated_source_scanner"} {
		if !containsString(status, want) {
			t.Fatalf("status missing %q:\n%s", want, status)
		}
	}
}

func TestCodegenAuthorizationCatalogCompiledFixtureAndDefaultSeedPins(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/codegen/profile-authorization-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, []byte(defaultAuthorizationCatalogJSONV1)) {
		t.Fatal("compiled default authorization catalog differs from reviewed fixture")
	}
	for _, mode := range []string{"", "quick", "full"} {
		cfg := DefaultCodegenAuditConfig(mode)
		normalized, err := NormalizeCodegenAuditConfig(cfg)
		if err != nil {
			t.Fatalf("mode %q: %v", mode, err)
		}
		wantCount := 3
		if mode == "full" {
			wantCount = 8
		}
		if normalized.startSeed != 1 || normalized.profileCount != wantCount || normalized.provenance != codegenAuditConfigProvenanceDefaultV1 {
			t.Fatalf("mode %q normalized config = %+v", mode, normalized)
		}
		if err := normalized.catalog.ValidateExactSeedRangeV1(codegen.AuthorizationCatalogScopeDefaultAuditV1, 1, 8); err != nil {
			t.Fatalf("mode %q full default catalog: %v", mode, err)
		}
	}
}

func TestCodegenAuthorizationCatalogFrozenCanonicalDigestAndInventory(t *testing.T) {
	raw := []byte(defaultAuthorizationCatalogJSONV1)
	var wire struct {
		Version, Scope string
		Entries        []struct {
			Seed          int64
			Client, Relay map[string]any
		}
	}
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	if wire.Version != codegen.AuthorizationCatalogVersionV1 || wire.Scope != codegen.AuthorizationCatalogScopeDefaultAuditV1 || len(wire.Entries) != 8 {
		t.Fatalf("catalog inventory %+v", wire)
	}
	var canonical bytes.Buffer
	lpAuditV1(&canonical, []byte("kurdistan/codegen/authorization-catalog/v1"))
	lpAuditV1(&canonical, []byte(wire.Version))
	lpAuditV1(&canonical, []byte(wire.Scope))
	var u32 [4]byte
	binary.BigEndian.PutUint32(u32[:], uint32(len(wire.Entries)))
	canonical.Write(u32[:])
	for i, entry := range wire.Entries {
		if entry.Seed != int64(i+1) || entry.Client == nil || entry.Relay == nil {
			t.Fatalf("entry %d", i)
		}
		var seed [8]byte
		binary.BigEndian.PutUint64(seed[:], uint64(entry.Seed))
		canonical.Write(seed[:])
		lpAuditV1(&canonical, []byte("client"))
		lpAuditV1(&canonical, auditPinBytesV1(t, entry.Client))
		lpAuditV1(&canonical, []byte("relay"))
		lpAuditV1(&canonical, auditPinBytesV1(t, entry.Relay))
	}
	if canonical.Len() != defaultAuthorizationCatalogCanonicalBytesV1 {
		t.Fatalf("canonical length=%d", canonical.Len())
	}
	sum := sha256.Sum256(canonical.Bytes())
	if got := hex.EncodeToString(sum[:]); got != defaultAuthorizationCatalogPostCutoverSHA256V1 {
		t.Fatalf("post digest=%s; frozen pre=%s", got, defaultAuthorizationCatalogPreCutoverSHA256V1)
	}
	for _, forbidden := range []string{"digest", "secret", "credential", "payload", "destination", "identity_key"} {
		if bytes.Contains(raw, []byte(`"`+forbidden+`"`)) {
			t.Fatalf("fixture contains %q", forbidden)
		}
	}
}

func lpAuditV1(out *bytes.Buffer, value []byte) {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(value)))
	out.Write(n[:])
	out.Write(value)
}
func auditPinBytesV1(t *testing.T, pin map[string]any) []byte {
	t.Helper()
	var out bytes.Buffer
	for _, key := range []string{"profile_hash", "effective_policy_hash", "framing_hash", "state_machine_hash", "scheduler_hash", "padding_hash", "stream_hash", "proxy_hash", "carrier_context_hash"} {
		s, ok := pin[key].(string)
		if !ok {
			t.Fatal(key)
		}
		b, err := hex.DecodeString(s)
		if err != nil || len(b) != 32 {
			t.Fatal(key)
		}
		out.Write(b)
	}
	for _, key := range []string{"effective_replay_window", "effective_max_concurrent_streams", "effective_max_frame_bytes", "effective_max_envelope_bytes"} {
		v, ok := pin[key].(float64)
		if !ok || v <= 0 || v > math.MaxUint32 {
			t.Fatal(key)
		}
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(v))
		out.Write(n[:])
	}
	return out.Bytes()
}

func TestCodegenAuthorizationCatalogSixPathSHA256AndTestdataInventory(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	verifyCommittedEvidenceSetV1(t, root, "WO-042", []committedEvidenceExpectationV1{
		{"internal/audit/codegen.go", "a81e381a01dd4122f83e7c38bb5f1d4fa95e7e27d30949743055e5cebebf50ab"},
		{"internal/audit/codegen_test.go", "d23ba4b99175f3289628a694d788edfcebb06d004b9df8bda759bf26ddea2aaa"},
		{"testdata/codegen/profile-authorization-v1.json", "ABSENT"},
		{"cmd/kcheck/main.go", "21e2b04eab3fb4ba8daac4d977174239523bd458d9a6d53e7896357e70200bcb"},
		{"cmd/kcheck/registry_test.go", "86772d52db8f6a8348c8e766e35063e2522bacb4ecea85a1ddea891c024a81bf"},
		{"internal/runtime/policy_enforcement_test.go", "ABSENT"},
	})
	entries, err := os.ReadDir(filepath.Join(root, "testdata", "codegen"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].IsDir() || entries[0].Name() != "profile-authorization-v1.json" {
		t.Fatalf("testdata/codegen inventory=%v", entries)
	}
}

const committedEvidenceManifestPathV1 = "testdata/evidence/phase1-m0-committed-sha256.json"

type committedEvidenceManifestV1 struct {
	Schema          string                                `json:"schema"`
	HashAlgorithm   string                                `json:"hash_algorithm"`
	SourceCandidate string                                `json:"source_candidate"`
	Sets            map[string][]committedEvidenceEntryV1 `json:"sets"`
}

type committedEvidenceEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

type committedEvidenceExpectationV1 struct {
	Path        string
	PreEvidence string
}

func verifyCommittedEvidenceSetV1(t *testing.T, root, set string, want []committedEvidenceExpectationV1) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "kurdistan.phase1-m0.committed-sha256.v1" || manifest.HashAlgorithm != "sha256" || manifest.SourceCandidate != "cad48bb4be28a09a6293944f78724d7026de4c12" {
		t.Fatalf("invalid committed evidence manifest identity: %+v", manifest)
	}
	requiredSets := map[string]bool{"WO-040": true, "WO-041": true, "WO-042": true, "WO-043": true, "WO-044": true}
	if len(manifest.Sets) != len(requiredSets) {
		t.Fatalf("committed evidence sets=%v", manifest.Sets)
	}
	for name := range manifest.Sets {
		if !requiredSets[name] {
			t.Fatalf("unexpected committed evidence set %q", name)
		}
	}
	entries, ok := manifest.Sets[set]
	if !ok || len(entries) != len(want) {
		t.Fatalf("%s evidence entries=%v want %d", set, entries, len(want))
	}
	for i, expected := range want {
		entry := entries[i]
		if entry.Path != expected.Path || entry.PreEvidence != expected.PreEvidence {
			t.Fatalf("%s evidence[%d]=%+v want path=%s pre=%s", set, i, entry, expected.Path, expected.PreEvidence)
		}
		if entry.Path == committedEvidenceManifestPathV1 || filepath.IsAbs(entry.Path) || filepath.ToSlash(filepath.Clean(entry.Path)) != entry.Path {
			t.Fatalf("%s invalid evidence path %q", set, entry.Path)
		}
		postBytes, err := hex.DecodeString(entry.PostSHA256)
		if err != nil || len(postBytes) != sha256.Size || entry.PostSHA256 != strings.ToLower(entry.PostSHA256) || entry.PostSHA256 == strings.Repeat("0", 64) {
			t.Fatalf("%s invalid post SHA-256 for %s", set, entry.Path)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			preBytes, err := hex.DecodeString(entry.PreEvidence)
			if err != nil || len(preBytes) != sha256.Size || entry.PreEvidence != strings.ToLower(entry.PreEvidence) || entry.PreEvidence == entry.PostSHA256 {
				t.Fatalf("%s invalid pre evidence for %s", set, entry.Path)
			}
		}
		current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(current)
		post := hex.EncodeToString(sum[:])
		if post != entry.PostSHA256 {
			t.Fatalf("%s committed SHA-256 %s=%s want %s", set, entry.Path, post, entry.PostSHA256)
		}
		t.Logf("%s-SHA256 %s pre=%s post=%s", set, entry.Path, entry.PreEvidence, post)
	}
}

func TestArbitrarySeedCatalogRequiresExplicitProvenanceAndExactRange(t *testing.T) {
	cfg := explicitCodegenConfig(t, 1, 2)
	if cfg.provenance != codegenAuditConfigProvenanceExplicitV1 {
		t.Fatalf("explicit provenance = %d", cfg.provenance)
	}
	if _, err := NewExplicitCodegenAuditConfig("quick", 1, 3, cfg.catalog); !errors.Is(err, codegen.ErrAuthorizationCatalogInvalid) {
		t.Fatalf("non-exact explicit range error = %v", err)
	}
	zero := CodegenAuditConfig{Mode: "quick"}
	if _, err := NormalizeCodegenAuditConfig(zero); !errors.Is(err, codegen.ErrStrictSeedRange) && !errors.Is(err, codegen.ErrAuthorizationCatalogInvalid) {
		t.Fatalf("zero provenance error = %v", err)
	}
}

func TestCodegenAuthorizationCatalogStrictSignedBoundsFailClosed(t *testing.T) {
	base := DefaultCodegenAuditConfig("quick")
	for _, seed := range []int64{math.MaxInt64 - 6, math.MaxInt64} {
		cfg := base
		cfg.startSeed = seed
		if _, err := NormalizeCodegenAuditConfig(cfg); !errors.Is(err, codegen.ErrStrictSeedRange) {
			t.Fatalf("seed %d error = %v", seed, err)
		}
	}
	if err := strictCodegenRangeValid(math.MaxInt64-7, 2); !errors.Is(err, codegen.ErrStrictSeedRange) {
		t.Fatalf("range crossing strict render bound error = %v", err)
	}
	for _, seed := range []int64{math.MaxInt64 - 7, -1, math.MinInt64} {
		if err := strictCodegenRangeValid(seed, 1); err != nil {
			t.Fatalf("render-safe seed %d rejected: %v", seed, err)
		}
	}
}

func TestCodegenAuthorizationCatalogLegacyEvidenceClassification(t *testing.T) {
	summary := buildCodegenSummary(GeneratedBackendTraceCorpus{}, nil)
	if summary.LegacyEvidenceClass != "legacy_non_evidentiary_parity" {
		t.Fatalf("legacy evidence class = %q", summary.LegacyEvidenceClass)
	}
	raw, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(raw, []byte(`"legacy_evidence_class":"legacy_non_evidentiary_parity"`)) {
		t.Fatalf("summary JSON lacks legacy classification: %s", raw)
	}
}

func explicitCodegenConfig(tb testing.TB, startSeed int64, profileCount int) CodegenAuditConfig {
	tb.Helper()
	var wire struct {
		Version string            `json:"version"`
		Scope   string            `json:"scope"`
		Entries []json.RawMessage `json:"entries"`
	}
	if err := json.Unmarshal([]byte(defaultAuthorizationCatalogJSONV1), &wire); err != nil {
		tb.Fatal(err)
	}
	if startSeed < 1 || startSeed+int64(profileCount) > 9 {
		tb.Fatalf("test helper range %d/%d is outside reviewed constants", startSeed, profileCount)
	}
	wire.Scope = codegen.AuthorizationCatalogScopeExplicitV1
	wire.Entries = wire.Entries[int(startSeed-1) : int(startSeed-1)+profileCount]
	raw, err := json.Marshal(wire)
	if err != nil {
		tb.Fatal(err)
	}
	catalog, err := codegen.ParseAuthorizationCatalogV1(raw)
	if err != nil {
		tb.Fatal(err)
	}
	cfg, err := NewExplicitCodegenAuditConfig("quick", startSeed, profileCount, catalog)
	if err != nil {
		tb.Fatal(err)
	}
	return cfg
}

func BenchmarkGeneratedBackendTraceCorpusQuick(b *testing.B) {
	cfg := explicitCodegenConfig(b, 1, 3)
	for i := 0; i < b.N; i++ {
		if _, err := RunGeneratedBackendTraceCorpus(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGeneratedSemanticEquivalenceComparison(b *testing.B) {
	cfg := explicitCodegenConfig(b, 1, 2)
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
	cfg := explicitCodegenConfig(b, 1, 3)
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
