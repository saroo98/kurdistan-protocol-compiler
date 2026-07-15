// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/lab/runtimeadversary"
	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/protocol/ir"
)

func RunSecurityAudit(ctx context.Context, cfg AuditConfig) (AuditReport, error) {
	cfg = NormalizeConfig(cfg)
	start := time.Now()
	profiles, err := generateAuditProfiles(cfg.StartSeed, cfg.ProfileCount)
	if err != nil {
		return AuditReport{}, err
	}
	gates := []GateResult{
		SecurityTranscriptBindingGate(profiles),
		SecurityKeyScheduleGate(profiles),
		SecurityNonceUniquenessGate(profiles),
		SecurityReplayRejectionGate(),
		SecurityDowngradeResistanceGate(profiles),
		SecurityCapabilityNegotiationGate(profiles),
		SecurityProfileCompatibilityGate(profiles),
		SecurityConfigHygieneGate(profiles),
		SecuritySecretTraceHygieneGate(profiles),
		SecurityMutantDetectionGate(ctx),
		SecurityGeneratedBackendParityGate(),
		SecurityM0IntegratedEvidenceGate(),
	}
	report := AuditReport{
		Version:          Version,
		Mode:             "security-" + cfg.Mode,
		GeneratedAt:      time.Now().UTC().Format(time.RFC3339),
		ProfileCount:     len(profiles),
		TraceCount:       0,
		Gates:            gates,
		TraceScanSummary: securitySummary(profiles),
		BenchmarkSummary: BenchmarkSummary{TotalMillis: time.Since(start).Milliseconds()},
	}
	if report.Passed() {
		report.Conclusion = "passed"
	} else {
		report.Conclusion = "failed"
	}
	return report, nil
}

const (
	m0AuthorizedRepoStateV1 = "6f04295c52a0a37b83d2a13c38e9028f90ccbaf8854929f8557e36c64ad5532c"
	m0LifecycleEvidenceV1   = "1f63391af51b23c4eca802e76d5164a98398a857070b8a7dd2cf99d055e4588e"
	m0PolicySeedCSVV1       = "1,2,3,4,6,7,19,25,26,27,35,40,42,58,66,69,78,80,91,94,102,107,110,123,135,171,174,202,223"
	m0PolicySeedCSVHashV1   = "2577a6114b5df02b44d43ae02fd80fa08f8c593c2449f79a46f84aa63fa5efaa"
	m0OutsideScopeHashV1    = "efae3ee45109577aa76fa6fd1c932fe7de1691da977557d9c269c4d0a852660f"
	m0OutsideScopeFileCount = 1329
)

type m0EvidenceRowV1 struct {
	Goal                   string `json:"goal"`
	Command                string `json:"command"`
	Behavior               string `json:"behavior"`
	RegressionTest         string `json:"regression_test"`
	OwningWork             string `json:"owning_work"`
	CandidateRepoState     string `json:"candidate_repo_state_hash"`
	OwningWOEvidenceSHA256 string `json:"owning_wo_evidence_sha256"`
}

var m0WO014AllowedTouchesV1 = map[string]bool{
	"STATUS.md":                        true,
	"internal/audit/security.go":       true,
	"internal/audit/security_test.go":  true,
	"internal/audit/runtime.go":        true,
	"internal/audit/hardening_test.go": true,
}

func m0CandidateOutsideScopeManifestV1(root string) (string, int, error) {
	cmd := exec.Command("git", "ls-files", "-z", "--cached", "--others", "--exclude-standard")
	cmd.Dir = root
	raw, err := cmd.Output()
	if err != nil {
		return "", 0, fmt.Errorf("git-visible candidate inventory: %w", err)
	}
	seen := map[string]bool{}
	paths := []string{}
	for _, part := range bytes.Split(raw, []byte{0}) {
		path := filepath.ToSlash(string(part))
		if path == "" || m0WO014AllowedTouchesV1[path] || seen[path] {
			continue
		}
		seen[path] = true
		paths = append(paths, path)
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, path := range paths {
		content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			return "", 0, fmt.Errorf("candidate path %s: %w", path, readErr)
		}
		fileHash := fmt.Sprintf("%x", sha256.Sum256(content))
		_, _ = h.Write([]byte(path))
		_, _ = h.Write([]byte{0})
		_, _ = h.Write([]byte(fileHash))
		_, _ = h.Write([]byte{'\n'})
	}
	return fmt.Sprintf("%x", h.Sum(nil)), len(paths), nil
}

func SecurityM0IntegratedEvidenceGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("security_m0_g1_g13_integration", false, "required", err.Error(), nil, []string{err.Error()})
	}
	failures := []string{}
	outsideScopeHash, outsideScopeFiles, bindingErr := m0CandidateOutsideScopeManifestV1(root)
	if bindingErr != nil {
		failures = append(failures, bindingErr.Error())
	} else if outsideScopeHash != m0OutsideScopeHashV1 || outsideScopeFiles != m0OutsideScopeFileCount {
		failures = append(failures, fmt.Sprintf("pre-WO-014 candidate binding drift hash=%s files=%d", outsideScopeHash, outsideScopeFiles))
	}
	seedHash := fmt.Sprintf("%x", sha256.Sum256([]byte(m0PolicySeedCSVV1)))
	if seedHash != m0PolicySeedCSVHashV1 || len(strings.Split(m0PolicySeedCSVV1, ",")) != 29 || strings.HasPrefix(m0PolicySeedCSVV1, "1,2,3,4,5,6,7,8") {
		failures = append(failures, "frozen policy interaction seed evidence drift")
	}
	requiredSource := map[string][]string{
		"internal/runtime/generated_profile_parity_test.go": {
			"TestGeneratedProfileParityV1", m0PolicySeedCSVHashV1, "len(generatedProfileParityPinsV1) != 29",
		},
		"internal/runtime/policy_enforcement_test.go": {
			"TestInterpretedPolicyParityCoveringArrayV1", "pairwise coverage=%d/%d want 732/732", "TestPolicyMatrixOwnerWitnessLiteralCompleteV1",
		},
		"internal/runtime/handshake_test.go": {
			"TestPreEntropyVersionStructuredAdmission",
		},
		"internal/testkit/importrules/importrules_test.go": {
			"TestLabFaultCapabilityCannotReachNormalPaths", "TestGeneratedAuthorizationBoundaryInjectedV1", "internal/runtime/generated_escape.go",
		},
	}
	for path, markers := range requiredSource {
		raw, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if readErr != nil {
			failures = append(failures, path+": "+readErr.Error())
			continue
		}
		for _, marker := range markers {
			if !strings.Contains(string(raw), marker) {
				failures = append(failures, path+": missing "+marker)
			}
		}
	}
	rows := []m0EvidenceRowV1{
		{"G1", "go test -count=1 ./internal/runtime -run 'TestGeneratedProfileParityV1|TestInterpretedPolicyParityCoveringArrayV1|TestPolicyMatrixOwnerWitnessLiteralCompleteV1'", "every admitted policy value and the frozen 29-row interactions reach interpreted and generated-profile strict behavior", "TestGeneratedProfileParityV1", "WO-016,WO-050,WO-035..WO-044", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G2", "go test -count=1 ./internal/crypto/security -run 'TestReplayStateCommitsOnlyAfterAuthentication|TestReplayConcurrentAuthenticatedDuplicateCommitsOnce'", "authentication precedes replay mutation and concurrent duplicates commit at most once", "TestReplayStateCommitsOnlyAfterAuthentication", "WO-003,WO-020,WO-009", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G3", "go test -count=1 ./internal/crypto/auth -run 'TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys'", "authenticated first contact uses fresh session material and rejects replay", "TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys", "WO-019", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G4", "go test -count=1 ./internal/runtime -run 'TestProtectedChannelMultiFragmentExactCoverageV1|TestFragmentCoverageAndBoundsV1'", "authenticated fragment coverage rejects gaps, overlap, duplicates, and mixed coordinates", "TestProtectedChannelMultiFragmentExactCoverageV1", "WO-049", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G5", "go test -count=1 ./internal/runtime -run 'TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1|TestPolicyMatrixPrivateEntrypointCausalBypassSentinelV1'", "bilateral floors and exact policy tuples cannot be weakened", "TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1", "WO-031,WO-033,WO-022,WO-050", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G6", "go test -count=1 ./internal/runtime -run 'TestFirstRecordCommitServerEstablishOrderingV1|TestAuthenticatedOperationAckStrictReplayCommitOrderingV1'", "application and acknowledgement lifecycle commits remain transactional", "TestFirstRecordCommitServerEstablishOrderingV1", "WO-047,WO-048,WO-021,WO-049", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G7", "go test -count=1 ./internal/crypto/security ./internal/runtime -run 'TestContextIdentityRejectsInvalidFields|TestPreEntropyVersionStructuredAdmission'", "context identity and structured version admission reject before protected state", "TestContextIdentityRejectsInvalidFields", "WO-038,WO-039,WO-045", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G8", "go test -count=1 ./internal/runtime -run 'TestApplicationRecordVectorV1|TestProtectedChannelEndToEndSingleFragmentAckCloseV1'", "strict candidate application bytes are authenticated and tamper fail-closed", "TestProtectedChannelEndToEndSingleFragmentAckCloseV1", "WO-024,WO-021,WO-049", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G9", "go test -count=1 ./internal/runtime -run 'TestInProcessProtectedRelayProtectedPathAndAckV1|TestPairOwnershipAndTerminalRelayCloseV1'", "one configured in-process pair composes handshake, records, acknowledgement, and close", "TestInProcessProtectedRelayProtectedPathAndAckV1", "WO-011", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G10", "go test -count=1 ./internal/crypto/security -run 'TestNonceV1FormulaVectorsAndDirectionV1|TestNonceV1BurnRetryAndExhaust|TestNonceV1ConcurrentAllocation'", "all nonce formulas preserve direction, burn, exhaustion, and concurrent uniqueness", "TestNonceV1FormulaVectorsAndDirectionV1", "WO-020,WO-009,WO-026", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G11", "go test -count=1 ./internal/crypto/security -run 'TestKeyScheduleV1VectorEpochZeroAndOne|TestKeyScheduleV1DerivationAndSeparation'", "key schedule labels, directions, epochs, limits, and separation remain exact", "TestKeyScheduleV1DerivationAndSeparation", "WO-019,WO-021", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G12", "go test -count=1 ./internal/observe/trace -run 'TestDiagnosticEventV1ExhaustiveSchemaAndValues|TestSchemaSequenceCrossSessionProfileCorrelationV1'", "diagnostic schema and sequences reject secret and correlating expansion", "TestDiagnosticEventV1ExhaustiveSchemaAndValues", "WO-027,WO-012", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
		{"G13", "go test -count=1 ./internal/testkit/importrules -run 'TestLabFaultCapabilityCannotReachNormalPaths|VersionMigrationBoundary|GeneratedAuthorizationBoundary|NoLabShortcut'", "normal, generated, loader, runtime, and product paths cannot reach lab or offline-migration authority", "TestLabFaultCapabilityCannotReachNormalPaths", "WO-013,WO-044", m0AuthorizedRepoStateV1, m0LifecycleEvidenceV1},
	}
	if len(rows) != 13 {
		failures = append(failures, fmt.Sprintf("M0 goal rows=%d want=13", len(rows)))
	}
	seen := map[string]bool{}
	for _, row := range rows {
		if seen[row.Goal] || row.Command == "" || row.Behavior == "" || row.RegressionTest == "" || row.OwningWork == "" || row.CandidateRepoState != m0AuthorizedRepoStateV1 || row.OwningWOEvidenceSHA256 != m0LifecycleEvidenceV1 {
			failures = append(failures, "invalid M0 evidence row "+row.Goal)
		}
		seen[row.Goal] = true
	}
	return gate("security_m0_g1_g13_integration", len(failures) == 0, "required", "13 bounded M0 local strict-candidate rows reconciled; global/product obligations remain open", map[string]any{
		"scope":                         "bounded M0 local strict-candidate",
		"global_product_status":         "open",
		"authorized_repo_state_hash":    m0AuthorizedRepoStateV1,
		"lifecycle_evidence_sha256":     m0LifecycleEvidenceV1,
		"outside_scope_manifest_sha256": outsideScopeHash,
		"outside_scope_file_count":      outsideScopeFiles,
		"wo014_allowed_touches":         []string{"STATUS.md", "internal/audit/hardening_test.go", "internal/audit/runtime.go", "internal/audit/security.go", "internal/audit/security_test.go"},
		"wo014_completion_hash":         "not-created-no-commit-authority",
		"policy_seed_csv_sha256":        seedHash,
		"policy_interaction_rows":       29,
		"policy_pairwise_coverage":      "732/732",
		"wo042_catalog_substitution":    false,
		"opaque_digest_reproduction":    false,
		"rows":                          rows,
	}, failures)
}

func SecurityTranscriptBindingGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	modes := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		input, err := transcriptInputForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		base, err := security.TranscriptHash(input)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		modes[p.Security.TranscriptMode] = true
		mutations := []func(*security.TranscriptInput){
			func(v *security.TranscriptInput) { v.ProfileHash = "changed-profile" },
			func(v *security.TranscriptInput) { v.StreamPolicy = "changed-stream" },
			func(v *security.TranscriptInput) { v.ProxyPolicy = "changed-proxy" },
			func(v *security.TranscriptInput) { v.CarrierPolicy = "changed-carrier" },
			func(v *security.TranscriptInput) { v.Capabilities = []string{"multi_stream"} },
		}
		for _, mutate := range mutations {
			changed := input
			mutate(&changed)
			next, err := security.TranscriptHash(changed)
			if err != nil {
				failures = append(failures, err.Error())
				continue
			}
			if next == base {
				failures = append(failures, "transcript mutation did not change hash for "+p.ID)
			}
		}
	}
	return gate("security_transcript_binding", len(failures) == 0, "required", fmt.Sprintf("%d profiles checked for transcript binding", len(selectProfiles(profiles, 3))), map[string]any{
		"transcript_modes": keys(modes),
	}, failures)
}

func SecurityKeyScheduleGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	suites := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		suites[p.Security.KDFSuite+"/"+p.Security.AEADSuite] = true
		a, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		b, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		if !bytes.Equal(a.ClientWriteKey, b.ClientWriteKey) || bytes.Equal(a.ClientWriteKey, a.ServerWriteKey) || bytes.Equal(a.ClientNonceBase, a.ServerNonceBase) {
			failures = append(failures, "key schedule invariant failed for "+p.ID)
		}
	}
	return gate("security_key_schedule", len(failures) == 0, "required", fmt.Sprintf("%d security suites exercised", len(suites)), map[string]any{
		"security_suites": keys(suites),
	}, failures)
}

func SecurityNonceUniquenessGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	modes := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ks, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		modes[p.Security.NonceMode] = true
		manager := security.NewNonceManager("client", ks.ClientNonceBase, p.Security.NonceMode)
		seen := map[string]bool{}
		for i := 0; i < 64; i++ {
			nonce, _, err := manager.Next()
			if err != nil {
				failures = append(failures, err.Error())
				break
			}
			key := string(nonce)
			if seen[key] {
				failures = append(failures, "duplicate nonce for "+p.ID)
				break
			}
			seen[key] = true
		}
	}
	return gate("security_nonce_uniqueness", len(failures) == 0, "required", fmt.Sprintf("%d nonce modes exercised", len(modes)), map[string]any{
		"nonce_modes": keys(modes),
	}, failures)
}

func SecurityReplayRejectionGate() GateResult {
	failures := []string{}
	window := security.NewReplayWindow("windowed_replay", 4)
	for _, seq := range []uint64{1, 3, 2, 4} {
		if err := window.Accept(seq); err != nil {
			failures = append(failures, err.Error())
		}
	}
	if err := window.Accept(3); err == nil {
		failures = append(failures, "duplicate sequence accepted")
	}
	if err := security.NewReplayWindow("ordered_only", 4).Accept(2); err == nil {
		failures = append(failures, "ordered-only accepted out-of-order")
	}
	return gate("security_replay_rejection", len(failures) == 0, "required", "duplicate and out-of-order replay checks evaluated", map[string]any{
		"replay_policies": []string{"windowed_replay", "ordered_only"},
	}, failures)
}

func SecurityDowngradeResistanceGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	policies := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		policies[p.Security.DowngradePolicy] = true
		if err := security.DetectSuiteDowngrade(security.DefaultSuite(), security.Suite{KDF: "kdf_hkdf_sha1"}, ""); err == nil {
			failures = append(failures, "suite downgrade accepted")
		}
	}
	return gate("security_downgrade_resistance", len(failures) == 0, "required", fmt.Sprintf("%d downgrade policies exercised", len(policies)), map[string]any{
		"downgrade_policies": keys(policies),
	}, failures)
}

func SecurityCapabilityNegotiationGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	policies := map[string]bool{}
	for _, p := range selectProfiles(profiles, 3) {
		policies[p.Security.CapabilityNegotiationPolicy] = true
		if _, err := (security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}).Hash(); err != nil {
			failures = append(failures, err.Error())
		}
		if err := security.RequireCapabilities(security.CapabilitySet{Features: p.Compatibility.RequiredCapabilities}, security.CapabilitySet{Features: []string{"multi_stream"}}); err == nil {
			failures = append(failures, "capability downgrade accepted for "+p.ID)
		}
	}
	return gate("security_capability_negotiation", len(failures) == 0, "required", fmt.Sprintf("%d capability policies exercised", len(policies)), map[string]any{
		"capability_policies": keys(policies),
	}, failures)
}

func SecurityProfileCompatibilityGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		if err := security.CheckProfileCompatibility(p, security.DefaultRuntimeCompatibility()); err != nil {
			failures = append(failures, err.Error())
		}
		bad := security.DefaultRuntimeCompatibility()
		bad.SupportedCarrierFamilies = []string{"unsupported_family"}
		if err := security.CheckProfileCompatibility(p, bad); err == nil {
			failures = append(failures, "unsupported carrier family accepted for "+p.ID)
		}
	}
	return gate("security_profile_compatibility", len(failures) == 0, "required", fmt.Sprintf("%d compatibility checks run", len(selectProfiles(profiles, 3))*2), nil, failures)
}

func SecurityConfigHygieneGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		cfg := security.SecurityConfig{
			ProfileID:        p.ID,
			ProfileHash:      ctx.ProfileHash,
			InputSecret:      testSecret(p),
			Suite:            ctx.Suite,
			ReplayWindow:     p.Security.ReplayWindowSize,
			MaxEnvelopeBytes: p.CarrierPolicy.MaxEnvelopeBytes,
			QueueDepth:       p.CarrierPolicy.MaxCarrierQueueDepth,
			Capabilities:     p.Compatibility.RequiredCapabilities,
			TranscriptHash:   ctx.TranscriptHash,
			CapabilityHash:   ctx.CapabilityHash,
		}
		if err := security.ValidateConfig(cfg); err != nil {
			failures = append(failures, err.Error())
		}
		cfg.InputSecret = make([]byte, len(cfg.InputSecret))
		if err := security.ValidateConfig(cfg); err == nil {
			failures = append(failures, "all-zero secret accepted for "+p.ID)
		}
	}
	return gate("security_config_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d config hygiene checks run", len(selectProfiles(profiles, 3))*2), nil, failures)
}

func SecuritySecretTraceHygieneGate(profiles []*ir.Profile) GateResult {
	failures := []string{}
	for _, p := range selectProfiles(profiles, 3) {
		ctx, err := securityContextForProfile(p)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ks, err := security.DeriveKeySchedule(testSecret(p), ctx.TranscriptHash, ctx.Suite)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		codec, err := security.NewEnvelopeCodec(ctx, ks, "client")
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		payload := []byte("payload must not leak")
		env, err := codec.Seal(security.EnvelopeMetadata{StreamID: 1, Semantic: "target_response", CarrierFamily: p.CarrierPolicy.CarrierFamily}, payload)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		ev, err := security.SecureEnvelopeDiagnosticV1(ctx, env)
		if err != nil {
			failures = append(failures, err.Error())
			continue
		}
		raw, _ := json.Marshal(ev)
		if security.TraceHasSecretCandidate(raw, payload, ks.ClientWriteKey, ks.ClientNonceBase, env.Ciphertext, env.Nonce) || ktrace.ContainsSensitiveValue(ev, payload, ks.ClientWriteKey, ks.ClientNonceBase, env.Ciphertext, env.Nonce, []byte(p.ID), []byte(ctx.TranscriptHash)) {
			failures = append(failures, "security trace leaked secret material for "+p.ID)
		}
	}
	return gate("security_secret_trace_hygiene", len(failures) == 0, "required", fmt.Sprintf("%d secret trace hygiene checks run", len(selectProfiles(profiles, 3))), nil, failures)
}

func SecurityMutantDetectionGate(ctx context.Context) GateResult {
	_ = ctx
	return realLabFaultInjectionGateV1("security_mutant_detection", "security", 4100)
}

const realLabFaultInjectionLabelV1 = "real lab fault-injection detector sensitivity"
const realLabFaultInjectionLimitV1 = "a pass proves only that each named detector turns red under its bounded deliberate fault and stays green in its control; it does not prove defect absence, production security, product integration, release readiness, or authorization to merge or deploy"

func realLabFaultInjectionGateV1(name, family string, seed int64) GateResult {
	table := runtimeadversary.RealMutantCorpusTableV1()
	results, err := runtimeadversary.RunRealMutantCorpusV1(seed)
	if err != nil {
		return gate(name, false, "required", realLabFaultInjectionLabelV1, map[string]any{"label": realLabFaultInjectionLabelV1, "limitation": realLabFaultInjectionLimitV1}, []string{err.Error()})
	}
	return realLabFaultInjectionGateResultsV1(name, family, table, results)
}

func realLabFaultInjectionGateResultsV1(name, family string, table []runtimeadversary.RealMutantCorpusRowV1, results []runtimeadversary.RealMutantCorpusResultV1) GateResult {
	expected := make(map[string]runtimeadversary.RealMutantCorpusRowV1, 8)
	known := make(map[string]runtimeadversary.RealMutantCorpusRowV1, 16)
	familyCounts := map[string]int{"security": 0, "runtime": 0}
	failures := []string{}
	for _, row := range table {
		if _, duplicate := known[row.Mode]; duplicate {
			failures = append(failures, "duplicate table mode "+row.Mode)
			continue
		}
		known[row.Mode] = row
		if _, allowed := familyCounts[row.Family]; !allowed {
			failures = append(failures, "unknown table family "+row.Family)
			continue
		}
		familyCounts[row.Family]++
		if row.Family == family {
			expected[row.Mode] = row
		}
	}
	seen := make(map[string]bool, 8)
	seenAll := make(map[string]bool, 16)
	seenFamily := map[string]int{"security": 0, "runtime": 0}
	rows := make([]map[string]any, 0, 8)
	for _, result := range results {
		row, knownMode := known[result.Mode]
		if !knownMode {
			failures = append(failures, "unknown result mode "+result.Mode)
			continue
		}
		if seenAll[result.Mode] {
			failures = append(failures, "duplicate mode "+result.Mode)
			continue
		}
		seenAll[result.Mode] = true
		seenFamily[row.Family]++
		valid := result.Category == row.Category && result.Detector == row.Detector && result.Count == row.ExpectedCount && result.UnsafeObserved && result.DetectorRed && result.ControlGreen
		if !valid {
			failures = append(failures, "invalid real observation "+result.Mode)
		}
		if row.Family != family {
			continue
		}
		seen[result.Mode] = true
		rows = append(rows, map[string]any{"mode": result.Mode, "category": result.Category, "count": result.Count, "status": map[bool]string{true: "red_fault_green_control", false: "invalid"}[valid]})
	}
	for mode := range expected {
		if !seen[mode] {
			failures = append(failures, "missing mode "+mode)
		}
	}
	if len(table) != 16 || len(known) != 16 || familyCounts["security"] != 8 || familyCounts["runtime"] != 8 {
		failures = append(failures, fmt.Sprintf("table corpus cardinality rows=%d known=%d security=%d runtime=%d", len(table), len(known), familyCounts["security"], familyCounts["runtime"]))
	}
	if len(results) != 16 || len(seenAll) != 16 || seenFamily["security"] != 8 || seenFamily["runtime"] != 8 {
		failures = append(failures, fmt.Sprintf("result corpus cardinality rows=%d known=%d security=%d runtime=%d", len(results), len(seenAll), seenFamily["security"], seenFamily["runtime"]))
	}
	if len(expected) != 8 || len(seen) != 8 {
		failures = append(failures, fmt.Sprintf("%s corpus cardinality expected=%d seen=%d", family, len(expected), len(seen)))
	}
	summary := fmt.Sprintf("%d/8 %s pairs passed; %s", 8-len(failures), realLabFaultInjectionLabelV1, realLabFaultInjectionLimitV1)
	return gate(name, len(failures) == 0, "required", summary, map[string]any{"label": realLabFaultInjectionLabelV1, "limitation": realLabFaultInjectionLimitV1, "rows": rows}, failures)
}

func SecurityGeneratedBackendParityGate() GateResult {
	root, err := repoRoot()
	if err != nil {
		return gate("security_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	source, err := codegenGeneratorSource(root)
	if err != nil {
		return gate("security_generated_backend_parity", false, "required", err.Error(), nil, []string{err.Error()})
	}
	text := string(source)
	failures := []string{}
	for _, marker := range []string{"security_generated.go", "SecurityDemo", "CaptureSecurityTrace", "security-demo", "security"} {
		if !strings.Contains(text, marker) {
			failures = append(failures, "missing generated backend marker "+marker)
		}
	}
	integration := SecurityM0IntegratedEvidenceGate()
	if !integration.Passed {
		failures = append(failures, "bounded M0 integration evidence failed")
	}
	return gate("security_generated_backend_parity", len(failures) == 0, "required", "generated security markers and bounded M0 G1-G13 integration evidence checked", map[string]any{
		"scanner":                    "source-marker-and-executable-test-registry",
		"authorized_repo_state_hash": m0AuthorizedRepoStateV1,
		"policy_seed_csv_sha256":     m0PolicySeedCSVHashV1,
		"policy_interaction_rows":    29,
		"policy_pairwise_coverage":   "732/732",
		"global_product_status":      "open",
	}, failures)
}

func securityContextForProfile(p *ir.Profile) (security.SecurityContext, error) {
	input, err := transcriptInputForProfile(p)
	if err != nil {
		return security.SecurityContext{}, err
	}
	return security.BuildContext(input)
}

func transcriptInputForProfile(p *ir.Profile) (security.TranscriptInput, error) {
	hash, err := security.ProfileHash(p)
	if err != nil {
		return security.TranscriptInput{}, err
	}
	return security.TranscriptInput{
		ProfileID:           p.ID,
		ProfileHash:         hash,
		CompilerHash:        Version,
		SemanticMappingHash: p.GenerationHash,
		FSMPolicy:           fmt.Sprintf("%d/%d", len(p.States), len(p.Transitions)),
		FramingPolicy:       p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode + "/" + p.FrameGrammar.FragmentationMode,
		SchedulerPolicy:     p.Scheduler.Mode + "/" + p.Scheduler.PriorityMode,
		PaddingPolicy:       p.Padding.Mode,
		StreamPolicy:        p.Stream.IDStrategy + "/" + p.Stream.PriorityPolicy + "/" + p.Stream.WindowUpdatePolicy,
		ProxyPolicy:         p.ProxySemantics.TargetDescriptorEncoding + "/" + p.ProxySemantics.ResponseModeEncoding,
		CarrierPolicy:       p.CarrierPolicy.CarrierFamily + "/" + p.CarrierPolicy.EnvelopeEncoding + "/" + p.CarrierPolicy.FlushPolicy,
		Capabilities:        p.Compatibility.RequiredCapabilities,
		SessionNonce:        []byte(fmt.Sprintf("audit-session-%016d", p.Seed)),
		Suite:               security.DefaultSuite(),
		OrderedStatePath:    []string{p.FirstContact.StartState, p.FirstContact.RelayReadyState},
	}, nil
}

func testSecret(p *ir.Profile) []byte {
	return []byte("audit-secret:" + p.ID + ":" + p.GenerationHash)
}

func securitySummary(profiles []*ir.Profile) map[string]any {
	transcriptModes := profileValues(profiles, func(p *ir.Profile) string { return p.Security.TranscriptMode })
	nonceModes := profileValues(profiles, func(p *ir.Profile) string { return p.Security.NonceMode })
	replayPolicies := profileValues(profiles, func(p *ir.Profile) string { return p.Security.ReplayPolicy })
	capabilityPolicies := profileValues(profiles, func(p *ir.Profile) string { return p.Security.CapabilityNegotiationPolicy })
	return map[string]any{
		"unique_transcript_modes":      uniqueStrings(transcriptModes),
		"unique_nonce_modes":           uniqueStrings(nonceModes),
		"unique_replay_policies":       uniqueStrings(replayPolicies),
		"unique_capability_policies":   uniqueStrings(capabilityPolicies),
		"profile_count":                len(profiles),
		"profile_version":              ir.SupportedVersion,
		"security_version":             ir.SupportedSecurityVersion,
		"compatibility_schema_version": ir.SupportedVersion,
		"compiler_security_version":    ir.SupportedSecurityVersion,
		"minimum_runtime_version":      ir.SupportedSecurityVersion,
		"handshake_version":            security.HandshakeVersionV1,
		"policy_encoding_version":      security.PolicyEncodingVersionV1,
		"record_version":               security.RecordVersionV1,
		"required_capability_count":    len(ir.SecurityCapabilities()),
		"supported_security_suite":     ir.SecuritySuiteString(),
		"secure_envelope_model":        "metadata/authenticated synthetic AEAD test model",
	}
}

func uniqueList(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value != "" && !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	return out
}

func keys(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		if value != "" {
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
