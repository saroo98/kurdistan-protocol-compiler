// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/assurance"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/lab/runtimeadversary"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/testkit/evidenceoverlay"
)

func expectedSecurityVersionAuditV1() map[string]string {
	return map[string]string{
		"profile_version":              ir.SupportedVersion,
		"security_version":             ir.SupportedSecurityVersion,
		"compatibility_schema_version": ir.SupportedVersion,
		"compiler_security_version":    ir.SupportedSecurityVersion,
		"minimum_runtime_version":      ir.SupportedSecurityVersion,
		"handshake_version":            security.HandshakeVersionV1,
		"policy_encoding_version":      security.PolicyEncodingVersionV1,
		"record_version":               security.RecordVersionV1,
	}
}

func validateSecurityVersionAuditV1(summary map[string]any) error {
	for field, want := range expectedSecurityVersionAuditV1() {
		got, ok := summary[field].(string)
		if !ok || got == "" || got != want {
			return fmt.Errorf("%s=%v want=%q", field, summary[field], want)
		}
	}
	return nil
}

func TestSecurityAuditQuickGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunSecurityAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"security_transcript_binding",
		"security_key_schedule",
		"security_nonce_uniqueness",
		"security_replay_rejection",
		"security_downgrade_resistance",
		"security_capability_negotiation",
		"security_profile_compatibility",
		"security_config_hygiene",
		"security_secret_trace_hygiene",
		"security_mutant_detection",
		"security_generated_backend_parity",
		"security_m0_g1_g13_integration",
	}
	seen := map[string]bool{}
	for _, gate := range report.Gates {
		seen[gate.Name] = true
		if !gate.Passed {
			t.Fatalf("gate %s failed: %s details=%v", gate.Name, gate.Summary, gate.Details)
		}
	}
	for _, name := range required {
		if !seen[name] {
			t.Fatalf("missing security gate %s", name)
		}
	}
	if report.Conclusion != "passed" {
		t.Fatalf("unexpected conclusion %q", report.Conclusion)
	}
	summary, ok := report.TraceScanSummary.(map[string]any)
	if !ok {
		t.Fatalf("security trace summary type=%T", report.TraceScanSummary)
	}
	if err := validateSecurityVersionAuditV1(summary); err != nil {
		t.Fatal(err)
	}
}

func TestSecurityM0IntegratedEvidenceGateV1(t *testing.T) {
	result := SecurityM0IntegratedEvidenceGate()
	if !result.Passed {
		t.Fatalf("integration gate failed: %+v", result)
	}
	if got := result.Details["scope"]; got != "bounded M0 local strict-candidate" {
		t.Fatalf("scope=%v", got)
	}
	if got := result.Details["global_product_status"]; got != "open" {
		t.Fatalf("global/product status=%v", got)
	}
	if got := result.Details["authorized_repo_state_hash"]; got != m0AuthorizedRepoStateV1 {
		t.Fatalf("repo state=%v", got)
	}
	if got := result.Details["lifecycle_evidence_sha256"]; got != m0LifecycleEvidenceV1 {
		t.Fatalf("lifecycle evidence=%v", got)
	}
	if got := result.Details["outside_scope_manifest_sha256"]; got != m0OutsideScopeHashV1 {
		t.Fatalf("outside-scope manifest=%v", got)
	}
	if got := result.Details["outside_scope_file_count"]; got != m0OutsideScopeFileCount {
		t.Fatalf("outside-scope files=%v", got)
	}
	wantMaintenancePaths := []string{
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"docs/GOVERNANCE.md",
		"internal/audit/codegen_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase1-m0-committed-sha256.json",
	}
	if got := result.Details["wo058_maintenance_paths"]; !reflect.DeepEqual(got, wantMaintenancePaths) {
		t.Fatalf("WO-058 maintenance paths=%v", got)
	}
	if got := result.Details["wo058_maintenance_file_count"]; got != m0WO058MaintenanceCount {
		t.Fatalf("WO-058 maintenance files=%v", got)
	}
	if got := result.Details["wo058_maintenance_sha256"]; got != m0WO058MaintenanceHashV1 {
		t.Fatalf("WO-058 maintenance digest=%v", got)
	}
	wantMaintenanceUnion := []string{
		"STATUS.md",
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"docs/GOVERNANCE.md",
		"internal/audit/codegen_test.go",
		"internal/audit/hardening_test.go",
		"internal/audit/runtime.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase1-m0-committed-sha256.json",
	}
	if got := result.Details["maintenance_union_paths"]; !reflect.DeepEqual(got, wantMaintenanceUnion) {
		t.Fatalf("maintenance union paths=%v", got)
	}
	if got := result.Details["maintenance_union_file_count"]; got != 14 {
		t.Fatalf("maintenance union files=%v", got)
	}
	if got := result.Details["m2_maintenance_overlay"]; got != m2MaintenanceOverlayV1 {
		t.Fatalf("M2 maintenance overlay=%v", got)
	}
	if got := result.Details["m2_maintenance_paths"]; !reflect.DeepEqual(got, m2MaintenancePathsV1) {
		t.Fatalf("M2 maintenance paths=%v", got)
	}
	if got := result.Details["m2_phase2_complete_overlay"]; got != m2Phase2CompleteOverlayNameV1 {
		t.Fatalf("M2 phase2-complete overlay=%v", got)
	}
	if got := result.Details["m2_phase2_complete_paths"]; !reflect.DeepEqual(got, m2Phase2CompletePathsV1) {
		t.Fatalf("M2 phase2-complete paths=%v", got)
	}
	wantTouches := []string{"STATUS.md", "internal/audit/hardening_test.go", "internal/audit/runtime.go", "internal/audit/security.go", "internal/audit/security_test.go"}
	if got := result.Details["wo014_allowed_touches"]; !reflect.DeepEqual(got, wantTouches) {
		t.Fatalf("allowed touches=%v", got)
	}
	if got := result.Details["wo014_completion_hash"]; got != "not-created-no-commit-authority" {
		t.Fatalf("completion boundary=%v", got)
	}
	if got := result.Details["policy_seed_csv_sha256"]; got != m0PolicySeedCSVHashV1 {
		t.Fatalf("seed hash=%v", got)
	}
	if got := result.Details["policy_interaction_rows"]; got != 29 {
		t.Fatalf("interaction rows=%v", got)
	}
	if got := result.Details["policy_pairwise_coverage"]; got != "732/732" {
		t.Fatalf("pair coverage=%v", got)
	}
	if got := result.Details["wo042_catalog_substitution"]; got != false {
		t.Fatalf("WO-042 substitution=%v", got)
	}
	rows, ok := result.Details["rows"].([]m0EvidenceRowV1)
	if !ok || len(rows) != 13 {
		t.Fatalf("rows=%T/%d", result.Details["rows"], len(rows))
	}
	commands := []string{
		"go test -count=1 ./internal/runtime -run 'TestGeneratedProfileParityV1|TestInterpretedPolicyParityCoveringArrayV1|TestPolicyMatrixOwnerWitnessLiteralCompleteV1'",
		"go test -count=1 ./internal/crypto/security -run 'TestReplayStateCommitsOnlyAfterAuthentication|TestReplayConcurrentAuthenticatedDuplicateCommitsOnce'",
		"go test -count=1 ./internal/crypto/auth -run 'TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys'",
		"go test -count=1 ./internal/runtime -run 'TestProtectedChannelMultiFragmentExactCoverageV1|TestFragmentCoverageAndBoundsV1'",
		"go test -count=1 ./internal/runtime -run 'TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1|TestPolicyMatrixPrivateEntrypointCausalBypassSentinelV1'",
		"go test -count=1 ./internal/runtime -run 'TestFirstRecordCommitServerEstablishOrderingV1|TestAuthenticatedOperationAckStrictReplayCommitOrderingV1'",
		"go test -count=1 ./internal/crypto/security ./internal/runtime -run 'TestContextIdentityRejectsInvalidFields|TestPreEntropyVersionStructuredAdmission'",
		"go test -count=1 ./internal/runtime -run 'TestApplicationRecordVectorV1|TestProtectedChannelEndToEndSingleFragmentAckCloseV1'",
		"go test -count=1 ./internal/runtime -run 'TestInProcessProtectedRelayProtectedPathAndAckV1|TestPairOwnershipAndTerminalRelayCloseV1'",
		"go test -count=1 ./internal/crypto/security -run 'TestNonceV1FormulaVectorsAndDirectionV1|TestNonceV1BurnRetryAndExhaust|TestNonceV1ConcurrentAllocation'",
		"go test -count=1 ./internal/crypto/security -run 'TestKeyScheduleV1VectorEpochZeroAndOne|TestKeyScheduleV1DerivationAndSeparation'",
		"go test -count=1 ./internal/observe/trace -run 'TestDiagnosticEventV1ExhaustiveSchemaAndValues|TestSchemaSequenceCrossSessionProfileCorrelationV1'",
		"go test -count=1 ./internal/testkit/importrules -run 'TestLabFaultCapabilityCannotReachNormalPaths|VersionMigrationBoundary|GeneratedAuthorizationBoundary|NoLabShortcut'",
	}
	behaviors := []string{
		"every admitted policy value and the frozen 29-row interactions reach interpreted and generated-profile strict behavior",
		"authentication precedes replay mutation and concurrent duplicates commit at most once",
		"authenticated first contact uses fresh session material and rejects replay",
		"authenticated fragment coverage rejects gaps, overlap, duplicates, and mixed coordinates",
		"bilateral floors and exact policy tuples cannot be weakened",
		"application and acknowledgement lifecycle commits remain transactional",
		"context identity and structured version admission reject before protected state",
		"strict candidate application bytes are authenticated and tamper fail-closed",
		"one configured in-process pair composes handshake, records, acknowledgement, and close",
		"all nonce formulas preserve direction, burn, exhaustion, and concurrent uniqueness",
		"key schedule labels, directions, epochs, limits, and separation remain exact",
		"diagnostic schema and sequences reject secret and correlating expansion",
		"normal, generated, loader, runtime, and product paths cannot reach lab or offline-migration authority",
	}
	regressions := []string{
		"TestGeneratedProfileParityV1", "TestReplayStateCommitsOnlyAfterAuthentication", "TestAuthenticatedFirstContactFreshSessionNonceReplayAndKeys",
		"TestProtectedChannelMultiFragmentExactCoverageV1", "TestPolicyMatrixCoveringSeedsProtectedChannelProductionV1", "TestFirstRecordCommitServerEstablishOrderingV1",
		"TestContextIdentityRejectsInvalidFields", "TestProtectedChannelEndToEndSingleFragmentAckCloseV1", "TestInProcessProtectedRelayProtectedPathAndAckV1",
		"TestNonceV1FormulaVectorsAndDirectionV1", "TestKeyScheduleV1DerivationAndSeparation", "TestDiagnosticEventV1ExhaustiveSchemaAndValues",
		"TestLabFaultCapabilityCannotReachNormalPaths",
	}
	owners := []string{
		"WO-016,WO-050,WO-035..WO-044", "WO-003,WO-020,WO-009", "WO-019", "WO-049", "WO-031,WO-033,WO-022,WO-050",
		"WO-047,WO-048,WO-021,WO-049", "WO-038,WO-039,WO-045", "WO-024,WO-021,WO-049", "WO-011", "WO-020,WO-009,WO-026",
		"WO-019,WO-021", "WO-027,WO-012", "WO-013,WO-044",
	}
	for i, row := range rows {
		want := m0EvidenceRowV1{
			Goal: fmt.Sprintf("G%d", i+1), Command: commands[i], Behavior: behaviors[i], RegressionTest: regressions[i], OwningWork: owners[i],
			CandidateRepoState: m0AuthorizedRepoStateV1, OwningWOEvidenceSHA256: m0LifecycleEvidenceV1,
		}
		if row != want {
			t.Fatalf("row %d=%+v want=%+v", i, row, want)
		}
	}
	raw, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	text := strings.ToLower(string(raw))
	for _, forbidden := range []string{"production ready", "production-ready", "undetectable", "unblockable", "completion_hash\":\"6"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("integration evidence overclaim %q: %s", forbidden, raw)
		}
	}
}

func TestM0LineEndingHistoricalOverlayAcceptsEquivalentCheckoutsAndRejectsDrift(t *testing.T) {
	root := t.TempDir()
	path := "legacy.txt"
	canonical := []byte("alpha\nbeta\n")
	historical := []byte("alpha\r\nbeta\r\n")
	overlays := map[string]m0LineEndingOverlayV1{
		path: {
			CanonicalSHA256:  fmt.Sprintf("%x", sha256.Sum256(canonical)),
			HistoricalSHA256: fmt.Sprintf("%x", sha256.Sum256(historical)),
		},
	}
	write := func(content []byte) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(root, path), content, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	for _, content := range [][]byte{canonical, historical} {
		write(content)
		got, err := m0LineEndingHistoricalHashesV1(root, overlays)
		if err != nil {
			t.Fatal(err)
		}
		if got[path] != overlays[path].HistoricalSHA256 {
			t.Fatalf("historical hash=%q want %q", got[path], overlays[path].HistoricalSHA256)
		}
	}

	write([]byte("alpha\nchanged\n"))
	if _, err := m0LineEndingHistoricalHashesV1(root, overlays); err == nil {
		t.Fatal("semantic drift accepted as a line-ending-only overlay")
	}
}

func TestValidationWorkflowProvidesHistoryForEvidenceGuards(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	workflow, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "ci.yml"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(workflow)
	for _, required := range []string{
		"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"persist-credentials: false",
		"fetch-depth: 0",
		"go run ./cmd/gate",
	} {
		if !strings.Contains(text, required) {
			t.Fatalf("validation workflow missing %q", required)
		}
	}
}

func TestSecurityPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	if _, err := loadM2MaintenancePreHashesV1(root); err != nil {
		t.Fatal(err)
	}
	base := ledger.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	mutations := map[string]func(*m2Phase2CompleteOverlayV1){
		"missing-path":   func(v *m2Phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *m2Phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *m2Phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *m2Phase2CompleteOverlayV1) { v.Entries = append(v.Entries, m2Phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *m2Phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *m2Phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *m2Phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *m2Phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *m2Phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]m2Phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validateM8ProfileCryptographyOverlayV1(root, map[string]m2Phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

func TestSecurityPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	mutations := map[string]func(*m2Phase2CompleteOverlayV1){
		"missing-path":   func(v *m2Phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *m2Phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *m2Phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *m2Phase2CompleteOverlayV1) { v.Entries = append(v.Entries, m2Phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *m2Phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *m2Phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *m2Phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *m2Phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]m2Phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validateM8WO801ThreatModelOverlayV1(root, map[string]m2Phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
}

func TestBaselineStabilizationEvidenceOverlayV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	overlay := ledger.BaselineStabilizationOverlays[baselineStabilizationOverlayNameV1]
	wantPaths := []string{
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		m2MaintenanceSelfPathV1,
	}
	if !reflect.DeepEqual(overlay.Paths, wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		t.Fatalf("baseline stabilization ledger mismatch: %+v", overlay)
	}
	phase9Pre := phase10Phase9PreForTestV1(t, root, ledger)
	finalGuardPre, err := validateM8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, ledger.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	guardPre, err := validateM8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, ledger.Phase8GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range guardPre {
		finalGuardPre[path] = hash
	}
	currentAtWO801, err := validateM8WO801AdoptionOverlayAtPostV1(root, finalGuardPre, ledger.Phase8WO801AdoptionOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range finalGuardPre {
		if _, replaced := currentAtWO801[path]; !replaced {
			currentAtWO801[path] = hash
		}
	}
	currentAtWO800, err := validateM8WO801ThreatModelOverlayAtPostV1(root, currentAtWO801, ledger.Phase8WO801ThreatModelOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range currentAtWO801 {
		if _, replaced := currentAtWO800[path]; !replaced {
			currentAtWO800[path] = hash
		}
	}
	currentAtPhase8, err := validateM8ProfileCryptographyOverlayAtPostV1(root, currentAtWO800, ledger.Phase8ProfileCryptographyOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range currentAtWO800 {
		if _, replaced := currentAtPhase8[path]; !replaced {
			currentAtPhase8[path] = hash
		}
	}
	pre, err := validateBaselineStabilizationOverlayV1(root, currentAtPhase8, ledger.BaselineStabilizationOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range overlay.Entries {
		if pre[entry.Path] != entry.PreEvidence {
			t.Fatalf("baseline stabilization pre hash %s=%q want %q", entry.Path, pre[entry.Path], entry.PreEvidence)
		}
	}

	mutateAndReject := func(name string, mutate func(*m2Phase2CompleteOverlayV1)) {
		t.Helper()
		encoded, err := json.Marshal(overlay)
		if err != nil {
			t.Fatal(err)
		}
		var mutated m2Phase2CompleteOverlayV1
		if err := json.Unmarshal(encoded, &mutated); err != nil {
			t.Fatal(err)
		}
		mutate(&mutated)
		bad := map[string]m2Phase2CompleteOverlayV1{baselineStabilizationOverlayNameV1: mutated}
		if _, err := validateBaselineStabilizationOverlayV1(root, currentAtPhase8, bad); err == nil {
			t.Fatalf("accepted baseline stabilization %s drift", name)
		}
	}
	mutateAndReject("predecessor", func(overlay *m2Phase2CompleteOverlayV1) {
		overlay.PredecessorManifestSHA256 = strings.Repeat("1", 64)
	})
	mutateAndReject("path order", func(overlay *m2Phase2CompleteOverlayV1) {
		overlay.Paths[0], overlay.Paths[1] = overlay.Paths[1], overlay.Paths[0]
	})
	mutateAndReject("post hash", func(overlay *m2Phase2CompleteOverlayV1) {
		overlay.Entries[0].PostSHA256 = strings.Repeat("2", 64)
	})
}

func phase10Phase9PreForTestV1(t *testing.T, root string, ledger m2MaintenanceManifestV1) map[string]string {
	t.Helper()
	phase14Pre, err := validateM14AssuranceOverlayV1(root, ledger.Phase14AssuranceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase13Pre, err := validateM13AndroidProductOverlayV1(root, phase14Pre, ledger.Phase13AndroidProductOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase12Pre, err := validateM12OperatorControlPlaneOverlayV1(root, phase13Pre, ledger.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase11Pre, err := validateM11LocalTransportOverlayAtPostV1(root, phase12Pre, ledger.Phase11LocalTransportOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase10Pre, err := validateM10VPNRuntimeOverlayAtPostV1(root, phase11Pre, ledger.Phase10VPNRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase9Pre, err := validateM9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, ledger.Phase9GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	return phase9Pre
}

func baselineStabilizationPreForTestV1(t *testing.T, root string, ledger m2MaintenanceManifestV1) map[string]string {
	t.Helper()
	phase9Pre := phase10Phase9PreForTestV1(t, root, ledger)
	finalGuardPre, err := validateM8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, ledger.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	guardPre, err := validateM8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, ledger.Phase8GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range guardPre {
		finalGuardPre[path] = hash
	}
	currentAtWO801, err := validateM8WO801AdoptionOverlayAtPostV1(root, finalGuardPre, ledger.Phase8WO801AdoptionOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range finalGuardPre {
		if _, replaced := currentAtWO801[path]; !replaced {
			currentAtWO801[path] = hash
		}
	}
	currentAtWO800, err := validateM8WO801ThreatModelOverlayAtPostV1(root, currentAtWO801, ledger.Phase8WO801ThreatModelOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for path, hash := range currentAtWO801 {
		if _, replaced := currentAtWO800[path]; !replaced {
			currentAtWO800[path] = hash
		}
	}
	currentAtPhase8, err := validateM8ProfileCryptographyOverlayAtPostV1(root, currentAtWO800, ledger.Phase8ProfileCryptographyOverlays)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := validateBaselineStabilizationOverlayV1(root, currentAtPhase8, ledger.BaselineStabilizationOverlays)
	if err != nil {
		t.Fatal(err)
	}
	return pre
}

func TestM3ProfileLifecycleEvidenceOverlayV1(t *testing.T) {
	const phase8WO806OutsideScopeHash = "c8f790f82f3cf9e46555c52a248d1cfd9b5aab0a5e1243860d8bfd8de717940a"
	const phase8WO806OutsideScopeFileCount = 1329
	if m0OutsideScopeHashV1 != phase8WO806OutsideScopeHash || m0OutsideScopeFileCount != phase8WO806OutsideScopeFileCount {
		t.Fatalf("phase8 WO-806 guard binding=%s/%d want %s/%d", m0OutsideScopeHashV1, m0OutsideScopeFileCount, phase8WO806OutsideScopeHash, phase8WO806OutsideScopeFileCount)
	}
	root := filepath.Clean(filepath.Join("..", ".."))
	if _, err := loadM2MaintenancePreHashesV1(root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	currentAtM7 := baselineStabilizationPreForTestV1(t, root, ledger)
	currentAtM6, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, ledger.Phase7AppRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	currentAtM5, err := validateM6DiagnosticExportOverlayV1(root, currentAtM6, ledger.Phase6DiagnosticExportOverlays)
	if err != nil {
		t.Fatal(err)
	}
	currentAtM4, err := validateM5RelayDescriptorOverlayV1(root, currentAtM5, ledger.Phase5RelayDescriptorOverlays)
	if err != nil {
		t.Fatal(err)
	}
	currentAtM3, err := validateM4FallbackOverlayV1(root, currentAtM4, ledger.Phase4FallbackOverlays)
	if err != nil {
		t.Fatal(err)
	}
	overlay := ledger.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"]
	overlay.PredecessorManifestSHA256 = strings.Repeat("1", 64)
	ledger.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"] = overlay
	if _, err := validateM3ContractOverlayV1(root, currentAtM3, ledger.Phase3ContractOverlays); err == nil {
		t.Fatal("accepted M3 overlay with mutated predecessor manifest hash")
	}
	manifest, err := m0CandidateOutsideScopeManifestV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.OutsideScopeFileCount != m0OutsideScopeFileCount || manifest.OutsideScopeSHA256 != m0OutsideScopeHashV1 {
		t.Fatalf("historical candidate binding=%s/%d want %s/%d", manifest.OutsideScopeSHA256, manifest.OutsideScopeFileCount, m0OutsideScopeHashV1, m0OutsideScopeFileCount)
	}
}

func TestM5RelayDescriptorEvidenceOverlayV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"ROADMAP.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md",
		"docs/KIP-0072-offline-relay-descriptor-admission-contract.md", "internal/product/relaydescriptor/relaydescriptor.go", "internal/product/relaydescriptor/relaydescriptor_test.go",
		"testdata/consumer/m5-relay-descriptor-sdk/go.mod", "testdata/consumer/m5-relay-descriptor-sdk/relay_descriptor_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1,
	}
	overlay := ledger.Phase5RelayDescriptorOverlays["m5-offline-relay-descriptor-admission-v1"]
	if !reflect.DeepEqual(overlay.Paths, wantPaths) || len(overlay.Entries) != 16 {
		t.Fatalf("M5 ledger mismatch: %+v", overlay)
	}
	currentAtM7 := baselineStabilizationPreForTestV1(t, root, ledger)
	currentAtM6, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, ledger.Phase7AppRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	currentAtM5, err := validateM6DiagnosticExportOverlayV1(root, currentAtM6, ledger.Phase6DiagnosticExportOverlays)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := validateM5RelayDescriptorOverlayV1(root, currentAtM5, ledger.Phase5RelayDescriptorOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range overlay.Entries {
		if entry.PreEvidence == "ABSENT" {
			if _, ok := pre[entry.Path]; ok {
				t.Fatalf("ABSENT M5 path retained at %d: %s", i, entry.Path)
			}
		}
	}
	bad := ledger.Phase5RelayDescriptorOverlays
	mutated := bad["m5-offline-relay-descriptor-admission-v1"]
	mutated.PredecessorManifestSHA256 = strings.Repeat("1", 64)
	bad = map[string]m2Phase2CompleteOverlayV1{"m5-offline-relay-descriptor-admission-v1": mutated}
	if _, err := validateM5RelayDescriptorOverlayV1(root, currentAtM5, bad); err == nil {
		t.Fatal("accepted M5 predecessor drift")
	}
	mutated = overlay
	mutated.Paths = append([]string(nil), overlay.Paths...)
	mutated.Paths[0], mutated.Paths[1] = mutated.Paths[1], mutated.Paths[0]
	bad = map[string]m2Phase2CompleteOverlayV1{"m5-offline-relay-descriptor-admission-v1": mutated}
	if _, err := validateM5RelayDescriptorOverlayV1(root, currentAtM5, bad); err == nil {
		t.Fatal("accepted reordered M5 ledger")
	}
}

func TestM6DiagnosticExportEvidenceOverlayV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"ROADMAP.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md",
		"docs/KIP-0073-offline-diagnostic-export-contract.md", "internal/product/diagnosticexport/diagnosticexport.go", "internal/product/diagnosticexport/diagnosticexport_test.go",
		"testdata/consumer/m6-diagnostic-export-sdk/go.mod", "testdata/consumer/m6-diagnostic-export-sdk/diagnostic_export_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1,
	}
	overlay := ledger.Phase6DiagnosticExportOverlays["m6-offline-diagnostic-export-contract-v1"]
	if !reflect.DeepEqual(overlay.Paths, wantPaths) || len(overlay.Entries) != 16 {
		t.Fatalf("M6 ledger mismatch: %+v", overlay)
	}
	currentAtM7 := baselineStabilizationPreForTestV1(t, root, ledger)
	currentAtM6, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, ledger.Phase7AppRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	pre, err := validateM6DiagnosticExportOverlayV1(root, currentAtM6, ledger.Phase6DiagnosticExportOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range overlay.Entries {
		if entry.PreEvidence == "ABSENT" {
			if _, ok := pre[entry.Path]; ok {
				t.Fatalf("ABSENT M6 path retained at %d: %s", i, entry.Path)
			}
		}
	}
	mutated := overlay
	mutated.PredecessorManifestSHA256 = strings.Repeat("1", 64)
	bad := map[string]m2Phase2CompleteOverlayV1{"m6-offline-diagnostic-export-contract-v1": mutated}
	if _, err := validateM6DiagnosticExportOverlayV1(root, currentAtM6, bad); err == nil {
		t.Fatal("accepted M6 predecessor drift")
	}
	mutated = overlay
	mutated.Paths = append([]string(nil), overlay.Paths...)
	mutated.Paths[0], mutated.Paths[1] = mutated.Paths[1], mutated.Paths[0]
	bad = map[string]m2Phase2CompleteOverlayV1{"m6-offline-diagnostic-export-contract-v1": mutated}
	if _, err := validateM6DiagnosticExportOverlayV1(root, currentAtM6, bad); err == nil {
		t.Fatal("accepted reordered M6 ledger")
	}
}

func TestM7AppRuntimeEvidenceOverlayV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &ledger); err != nil {
		t.Fatal(err)
	}
	wantPaths := []string{
		"ROADMAP.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md",
		"docs/KIP-0074-offline-app-runtime-contract.md", "internal/product/appruntime/appruntime.go", "internal/product/appruntime/appruntime_test.go",
		"testdata/consumer/m7-app-runtime-sdk/go.mod", "testdata/consumer/m7-app-runtime-sdk/app_runtime_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", m2MaintenanceSelfPathV1,
	}
	overlay := ledger.Phase7AppRuntimeOverlays["m7-offline-app-runtime-contract-v1"]
	if !reflect.DeepEqual(overlay.Paths, wantPaths) || len(overlay.Entries) != 16 {
		t.Fatalf("M7 ledger mismatch: %+v", overlay)
	}
	currentAtM7 := baselineStabilizationPreForTestV1(t, root, ledger)
	pre, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, ledger.Phase7AppRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	for i, entry := range overlay.Entries {
		if entry.PreEvidence == "ABSENT" {
			if _, ok := pre[entry.Path]; ok {
				t.Fatalf("ABSENT M7 path retained at %d: %s", i, entry.Path)
			}
		}
	}
	mutated := overlay
	mutated.PredecessorManifestSHA256 = strings.Repeat("1", 64)
	bad := map[string]m2Phase2CompleteOverlayV1{"m7-offline-app-runtime-contract-v1": mutated}
	if _, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, bad); err == nil {
		t.Fatal("accepted M7 predecessor drift")
	}
	mutated = overlay
	mutated.Paths = append([]string(nil), overlay.Paths...)
	mutated.Paths[0], mutated.Paths[1] = mutated.Paths[1], mutated.Paths[0]
	bad = map[string]m2Phase2CompleteOverlayV1{"m7-offline-app-runtime-contract-v1": mutated}
	if _, err := validateM7AppRuntimeOverlayV1(root, currentAtM7, bad); err == nil {
		t.Fatal("accepted reordered M7 ledger")
	}
}

func TestWO058MaintenanceManifestExactContentAndFailureModesV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"docs/GOVERNANCE.md",
		"internal/audit/codegen_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase1-m0-committed-sha256.json",
	}
	fixture := t.TempDir()
	for _, path := range paths {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(fixture, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}

	preHashes, err := loadM2MaintenancePreHashesV1(root)
	if err != nil {
		t.Fatal(err)
	}
	preHashes = m0CandidateMaintenancePreHashesV1(preHashes)
	manifest, err := m0CandidateManifestFromPathsWithPreHashesV1(fixture, paths, preHashes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.MaintenancePaths, paths) || manifest.MaintenanceFileCount != 9 || manifest.MaintenanceSHA256 != "158dc7ebba2a84036fe4f328d3149929d47219dabea6f1caf4374afb82f00c8f" {
		t.Fatalf("maintenance manifest=%+v", manifest)
	}
	if manifest.MaintenanceUnionCount != 14 {
		t.Fatalf("maintenance union=%v/%d", manifest.MaintenanceUnionPaths, manifest.MaintenanceUnionCount)
	}
	unlisted := "unlisted/newly-tracked.txt"
	unlistedTarget := filepath.Join(fixture, filepath.FromSlash(unlisted))
	if err := os.MkdirAll(filepath.Dir(unlistedTarget), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unlistedTarget, []byte("must remain historically visible"), 0o644); err != nil {
		t.Fatal(err)
	}
	withUnlisted := append(append([]string(nil), paths...), unlisted)
	unlistedManifest, err := m0CandidateManifestFromPathsWithPreHashesV1(fixture, withUnlisted, preHashes)
	if err != nil {
		t.Fatal(err)
	}
	if unlistedManifest.OutsideScopeFileCount != manifest.OutsideScopeFileCount+1 || unlistedManifest.OutsideScopeSHA256 == manifest.OutsideScopeSHA256 {
		t.Fatalf("unlisted tracked path was excluded: before=%+v after=%+v", manifest, unlistedManifest)
	}
	if _, err := m0CandidateManifestFromPathsWithPreHashesV1(fixture, paths[:len(paths)-1], preHashes); err == nil || !strings.Contains(err.Error(), "maintenance paths missing") {
		t.Fatalf("missing maintenance path error=%v", err)
	}
	driftPath := filepath.Join(fixture, filepath.FromSlash(paths[0]))
	if err := os.WriteFile(driftPath, []byte("hash drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := m0CandidateManifestFromPathsV1(fixture, paths); err == nil || !strings.Contains(err.Error(), "maintenance hash drift cmd/gate/main.go") {
		t.Fatalf("maintenance hash drift error=%v", err)
	}
}

func TestPhase14AssuranceOverlayRejectsMutationV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]m2MaintenanceOverlayRecordV1 {
		encoded, err := json.Marshal(manifest.Phase14AssuranceOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]m2MaintenanceOverlayRecordV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	if _, err := validateM14AssuranceOverlayV1(root, clone()); err != nil {
		t.Fatal(err)
	}
	absentIndex := -1
	for index, entry := range manifest.Phase14AssuranceOverlays["phase14-assurance-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			absentIndex = index
			break
		}
	}
	if absentIndex < 0 {
		t.Fatal("phase14 mutation fixture has no absent predecessor")
	}
	mutations := map[string]func(map[string]m2MaintenanceOverlayRecordV1){
		"missing-overlay": func(v map[string]m2MaintenanceOverlayRecordV1) { delete(v, "phase14-assurance-v1") },
		"extra-overlay":   func(v map[string]m2MaintenanceOverlayRecordV1) { v["extra"] = v["phase14-assurance-v1"] },
		"reordered-path": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase14-assurance-v1"]
			o.Paths[0], o.Paths[1] = o.Paths[1], o.Paths[0]
			v[o.Version] = o
		},
		"self-pre": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase14-assurance-v1"]
			o.SelfPreSHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"pre-hash": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase14-assurance-v1"]
			o.Entries[0].PreSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
		"absent-predecessor": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase14-assurance-v1"]
			o.Entries[absentIndex].PreEvidence = ""
			o.Entries[absentIndex].PreSHA256 = strings.Repeat("3", 64)
			v[o.Version] = o
		},
		"post-hash": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase14-assurance-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("4", 64)
			v[o.Version] = o
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := clone()
			mutate(candidate)
			if _, err := validateM14AssuranceOverlayV1(root, candidate); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestPhase13AndroidProductOverlayRejectsMutationV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]m2MaintenanceOverlayRecordV1 {
		encoded, err := json.Marshal(manifest.Phase13AndroidProductOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]m2MaintenanceOverlayRecordV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase14Pre, err := validateM14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateM13AndroidProductOverlayV1(root, phase14Pre, clone()); err != nil {
		t.Fatal(err)
	}
	absentIndex := -1
	for index, entry := range manifest.Phase13AndroidProductOverlays["phase13-android-product-v1"].Entries {
		if entry.PreEvidence == "ABSENT" {
			absentIndex = index
			break
		}
	}
	if absentIndex < 0 {
		t.Fatal("phase13 mutation fixture has no absent predecessor")
	}
	mutations := map[string]func(map[string]m2MaintenanceOverlayRecordV1){
		"missing-overlay": func(v map[string]m2MaintenanceOverlayRecordV1) { delete(v, "phase13-android-product-v1") },
		"extra-overlay":   func(v map[string]m2MaintenanceOverlayRecordV1) { v["extra"] = v["phase13-android-product-v1"] },
		"reordered-path": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase13-android-product-v1"]
			o.Paths[0], o.Paths[1] = o.Paths[1], o.Paths[0]
			v[o.Version] = o
		},
		"self-pre": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase13-android-product-v1"]
			o.SelfPreSHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"pre-hash": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase13-android-product-v1"]
			o.Entries[0].PreSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
		"absent-predecessor": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase13-android-product-v1"]
			o.Entries[absentIndex].PreEvidence = ""
			o.Entries[absentIndex].PreSHA256 = strings.Repeat("3", 64)
			v[o.Version] = o
		},
		"post-hash": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase13-android-product-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("4", 64)
			v[o.Version] = o
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := clone()
			mutate(candidate)
			if _, err := validateM13AndroidProductOverlayV1(root, phase14Pre, candidate); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestM2MaintenanceOverlayExactContentAndFailureModesV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	pre, err := loadM2MaintenancePreHashesV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pre) != 18 || pre[m2MaintenanceSelfPathV1] != m0WO058MaintenanceHashesV1[m2MaintenanceSelfPathV1] {
		t.Fatalf("M2 pre-hash overlay=%v", pre)
	}
	for path, want := range map[string]string{
		"README.md":                             "68ebebb5c733c2c8aa31d9d67bed24489635c82e38a0451a9ca6e9e6e0adcb8b",
		"ROADMAP.md":                            "40e8f73ea355dd5de75faca8b50ebb9fc374ad6e041716d08390d648eca95e06",
		"docs/GOVERNANCE.md":                    "867efaac1bb01cdfa62f954ead7deb895f827382c5075f969facb74a30fa3f57",
		"docs/safety.md":                        "b9e571e290c46faf42d77eff7eec254b9d2870a4f26d7ddca8f649896fa55662",
		"internal/product/strategy/strategy.go": "ac03d6928cd00b208060bbe3c8a63e38c4e0e673322e5d918e975b97ce9563ea",
		"internal/product/strategy/strategy_test.go": "8f554de4bf1be16e83ec1ba9269884a79b46803393e1e396e1d47e4660a6805c",
	} {
		if pre[path] != want {
			t.Fatalf("M2 pre-hash %s=%s want %s", path, pre[path], want)
		}
	}

	fixture := t.TempDir()
	manifestRaw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var ledger m2MaintenanceManifestV1
	if err := json.Unmarshal(manifestRaw, &ledger); err != nil {
		t.Fatal(err)
	}
	m3Overlay, ok := ledger.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"]
	if !ok || len(ledger.Phase3ContractOverlays) != 1 || len(m3Overlay.Paths) != 21 || len(m3Overlay.Entries) != 20 || m3Overlay.Paths[20] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid M3 fixture overlay identity/cardinality: %+v", m3Overlay)
	}
	m4Overlay, ok := ledger.Phase4FallbackOverlays["m4-permitted-fallback-contract-v1"]
	if !ok || len(ledger.Phase4FallbackOverlays) != 1 || len(m4Overlay.Paths) != 17 || len(m4Overlay.Entries) != 16 || m4Overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid M4 fixture overlay identity/cardinality: %+v", m4Overlay)
	}
	m5Overlay, ok := ledger.Phase5RelayDescriptorOverlays["m5-offline-relay-descriptor-admission-v1"]
	if !ok || len(ledger.Phase5RelayDescriptorOverlays) != 1 || len(m5Overlay.Paths) != 17 || len(m5Overlay.Entries) != 16 || m5Overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid M5 fixture overlay identity/cardinality: %+v", m5Overlay)
	}
	m6Overlay, ok := ledger.Phase6DiagnosticExportOverlays["m6-offline-diagnostic-export-contract-v1"]
	if !ok || len(ledger.Phase6DiagnosticExportOverlays) != 1 || len(m6Overlay.Paths) != 17 || len(m6Overlay.Entries) != 16 || m6Overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid M6 fixture overlay identity/cardinality: %+v", m6Overlay)
	}
	m7Overlay, ok := ledger.Phase7AppRuntimeOverlays["m7-offline-app-runtime-contract-v1"]
	if !ok || len(ledger.Phase7AppRuntimeOverlays) != 1 || len(m7Overlay.Paths) != 17 || len(m7Overlay.Entries) != 16 || m7Overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid M7 fixture overlay identity/cardinality: %+v", m7Overlay)
	}
	m8Overlay, ok := ledger.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	if !ok || len(ledger.Phase8ProfileCryptographyOverlays) != 1 || len(m8Overlay.Paths) != 17 || len(m8Overlay.Entries) != 16 || m8Overlay.Paths[16] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid Phase 8 fixture overlay identity/cardinality: %+v", m8Overlay)
	}
	wo801Overlay, ok := ledger.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	if !ok || len(ledger.Phase8WO801ThreatModelOverlays) != 1 || len(wo801Overlay.Paths) != 13 || len(wo801Overlay.Entries) != 12 || wo801Overlay.Paths[12] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid WO-801 fixture overlay identity/cardinality: %+v", wo801Overlay)
	}
	adoptionOverlay, ok := ledger.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	if !ok || len(ledger.Phase8WO801AdoptionOverlays) != 1 || len(adoptionOverlay.Paths) != 9 || len(adoptionOverlay.Entries) != 8 || adoptionOverlay.Paths[8] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid WO-801 adoption fixture overlay identity/cardinality: %+v", adoptionOverlay)
	}
	stabilizationOverlay, ok := ledger.BaselineStabilizationOverlays["go126-clean-worktree-stabilization-v1"]
	if !ok || len(ledger.BaselineStabilizationOverlays) != 1 || len(stabilizationOverlay.Paths) != 8 || len(stabilizationOverlay.Entries) != 7 || stabilizationOverlay.Paths[7] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid stabilization fixture overlay identity/cardinality: %+v", stabilizationOverlay)
	}
	guardOverlay, ok := ledger.Phase8GuardMaintenanceOverlays["phase8-wo806-guard-convergence-v1"]
	if !ok || len(ledger.Phase8GuardMaintenanceOverlays) != 1 || len(guardOverlay.Paths) != 8 || len(guardOverlay.Entries) != 7 || guardOverlay.Paths[7] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid Phase 8 guard fixture overlay identity/cardinality: %+v", guardOverlay)
	}
	finalGuardOverlay, ok := ledger.Phase8FinalGuardMaintenanceOverlays["phase8-wo808-final-guard-convergence-v1"]
	if !ok || len(ledger.Phase8FinalGuardMaintenanceOverlays) != 1 || len(finalGuardOverlay.Paths) != 58 || len(finalGuardOverlay.Entries) != 57 || finalGuardOverlay.Paths[57] != m2MaintenanceSelfPathV1 {
		t.Fatalf("invalid Phase 8 final guard fixture overlay identity/cardinality: %+v", finalGuardOverlay)
	}
	phase9Overlay, ok := ledger.Phase9GuardMaintenanceOverlays["phase9-wo909-final-guard-convergence-v1"]
	if !ok || len(ledger.Phase9GuardMaintenanceOverlays) != 1 || len(phase9Overlay.Paths) != 159 || len(phase9Overlay.Entries) != 159 {
		t.Fatalf("invalid Phase 9 guard fixture overlay identity/cardinality: %+v", phase9Overlay)
	}
	phase10Overlay, ok := ledger.Phase10VPNRuntimeOverlays["phase10-local-vpn-runtime-v1"]
	if !ok || len(ledger.Phase10VPNRuntimeOverlays) != 1 || len(phase10Overlay.Paths) != 56 || len(phase10Overlay.Entries) != 56 {
		t.Fatalf("invalid Phase 10 VPN runtime fixture overlay identity/cardinality: %+v", phase10Overlay)
	}
	phase11Overlay, ok := ledger.Phase11LocalTransportOverlays["phase11-local-transport-v1"]
	if !ok || len(ledger.Phase11LocalTransportOverlays) != 1 || len(phase11Overlay.Paths) == 0 || len(phase11Overlay.Entries) != len(phase11Overlay.Paths) {
		t.Fatalf("invalid Phase 11 local transport fixture overlay identity/cardinality: %+v", phase11Overlay)
	}
	phase12Overlay, ok := ledger.Phase12OperatorControlPlaneOverlays["phase12-operator-control-plane-v1"]
	if !ok || len(ledger.Phase12OperatorControlPlaneOverlays) != 1 ||
		len(phase12Overlay.Paths) != 47 || len(phase12Overlay.Entries) != 47 ||
		phase12Overlay.Paths[17] != "internal/operator/controlplane/authority_state.go" {
		t.Fatalf("invalid Phase 12 operator control-plane fixture overlay identity/cardinality: %+v", phase12Overlay)
	}
	phase13Overlay, ok := ledger.Phase13AndroidProductOverlays["phase13-android-product-v1"]
	if !ok || len(ledger.Phase13AndroidProductOverlays) != 1 ||
		len(phase13Overlay.Paths) == 0 || len(phase13Overlay.Entries) != len(phase13Overlay.Paths) {
		t.Fatalf("invalid Phase 13 Android product fixture overlay identity/cardinality: %+v", phase13Overlay)
	}
	phase14Overlay, ok := ledger.Phase14AssuranceOverlays["phase14-assurance-v1"]
	if !ok || len(ledger.Phase14AssuranceOverlays) != 1 || len(phase14Overlay.Paths) == 0 || len(phase14Overlay.Entries) != len(phase14Overlay.Paths) {
		t.Fatalf("invalid Phase 14 assurance fixture overlay identity/cardinality: %+v", phase14Overlay)
	}
	fixturePaths := append([]string(nil), m2Phase2CompletePathsV1...)
	seen := make(map[string]bool, len(fixturePaths)+len(m3Overlay.Entries)+len(m4Overlay.Entries)+len(m5Overlay.Entries)+len(m6Overlay.Entries)+len(m7Overlay.Entries)+len(m8Overlay.Entries)+len(wo801Overlay.Entries)+len(adoptionOverlay.Entries)+len(stabilizationOverlay.Entries)+len(guardOverlay.Entries)+len(finalGuardOverlay.Entries)+len(phase9Overlay.Entries)+len(phase10Overlay.Entries)+len(phase11Overlay.Entries)+len(phase12Overlay.Entries)+len(phase13Overlay.Entries)+len(phase14Overlay.Entries))
	for _, path := range fixturePaths {
		seen[path] = true
	}
	for _, path := range m3Overlay.Paths[:len(m3Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range m4Overlay.Paths[:len(m4Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range m5Overlay.Paths[:len(m5Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range m6Overlay.Paths[:len(m6Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range m7Overlay.Paths[:len(m7Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range m8Overlay.Paths[:len(m8Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range wo801Overlay.Paths[:len(wo801Overlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range adoptionOverlay.Paths[:len(adoptionOverlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, workOrderOverlay := range ledger.Phase8WorkOrderOverlays {
		for _, path := range workOrderOverlay.Paths {
			if !seen[path] {
				fixturePaths = append(fixturePaths, path)
				seen[path] = true
			}
		}
	}
	for _, path := range stabilizationOverlay.Paths[:len(stabilizationOverlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range guardOverlay.Paths[:len(guardOverlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range finalGuardOverlay.Paths[:len(finalGuardOverlay.Paths)-1] {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range phase9Overlay.Paths {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range phase10Overlay.Paths {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range phase11Overlay.Paths {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range phase12Overlay.Paths {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range phase13Overlay.Paths {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	for _, path := range phase14Overlay.Paths {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	phase15Pre, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		t.Fatal(err)
	}
	for path := range phase15Pre {
		if !seen[path] {
			fixturePaths = append(fixturePaths, path)
			seen[path] = true
		}
	}
	fixturePaths = append(fixturePaths,
		evidenceoverlay.PublicDocumentationSuccessorPath,
		evidenceoverlay.SuccessorPath,
		evidenceoverlay.Phase16SuccessorPath,
		evidenceoverlay.Phase16ProductionTrustSuccessorPath,
		evidenceoverlay.Phase16RuntimeSuccessorPath,
		evidenceoverlay.Phase16DecentralizedSuccessorPath,
	)
	for _, path := range fixturePaths {
		content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if errors.Is(readErr, os.ErrNotExist) {
			continue
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		target := filepath.Join(fixture, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := loadM2MaintenancePreHashesV1(fixture); err != nil {
		t.Fatal(err)
	}
	drift := filepath.Join(fixture, "README.md")
	if err := os.WriteFile(drift, []byte("drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil || !strings.Contains(err.Error(), "README.md") {
		t.Fatalf("changed listed content error=%v", err)
	}
	if err := os.Remove(drift); err != nil {
		t.Fatal(err)
	}
	if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil || !strings.Contains(err.Error(), "README.md") {
		t.Fatalf("missing listed path error=%v", err)
	}

	original := m0WO058MaintenanceHashesV1["cmd/gate/main.go"]
	m0WO058MaintenanceHashesV1["cmd/gate/main.go"] = strings.Repeat("1", 64)
	t.Cleanup(func() { m0WO058MaintenanceHashesV1["cmd/gate/main.go"] = original })
	if _, err := m0CandidateManifestFromPathsWithPreHashesV1(root, []string{"cmd/gate/main.go"}, nil); err == nil || !strings.Contains(err.Error(), "maintenance hash drift") {
		t.Fatalf("altered historical value error=%v", err)
	}
}

func TestM2ValidatorOverlayExactContentAndFailureModesV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	for _, path := range m2Phase2CompletePathsV1 {
		content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if errors.Is(readErr, os.ErrNotExist) && path == "ROADMAP.md" {
			continue
		}
		if readErr != nil {
			t.Fatal(readErr)
		}
		target := filepath.Join(fixture, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeHistoricalRoadmapTombstone(t, fixture)
	manifestPath := filepath.Join(fixture, filepath.FromSlash(m2MaintenanceSelfPathV1))
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.ValidatorOverlays[m2ValidatorOverlayV1]
	mutations := []func(*m2LayeredOverlayV1){
		func(v *m2LayeredOverlayV1) { v.Version = "wrong" },
		func(v *m2LayeredOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) },
		func(v *m2LayeredOverlayV1) { v.Entries = v.Entries[:2] },
		func(v *m2LayeredOverlayV1) { v.Entries = append(v.Entries, m2MaintenanceEntryV1{}) },
		func(v *m2LayeredOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] },
		func(v *m2LayeredOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) },
		func(v *m2LayeredOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) },
	}
	for i, mutate := range mutations {
		copyManifest := manifest
		copyOverlay := base
		copyOverlay.Entries = append([]m2MaintenanceEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest.ValidatorOverlays = map[string]m2LayeredOverlayV1{m2ValidatorOverlayV1: copyOverlay}
		encoded, err := json.Marshal(copyManifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHistoricalM2MaintenancePreHashesV1(fixture); err == nil {
			t.Fatalf("validator overlay mutation %d accepted", i)
		}
	}
	copyManifest := manifest
	consumer := manifest.ValidatorConsumerOverlays[m2ValidatorConsumerOverlayV1]
	consumer.Entries = append([]m2MaintenanceEntryV1(nil), consumer.Entries...)
	consumer.Entries[0].PreSHA256 = strings.Repeat("4", 64)
	copyManifest.ValidatorConsumerOverlays = map[string]m2LayeredOverlayV1{m2ValidatorConsumerOverlayV1: consumer}
	encoded, err := json.Marshal(copyManifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHistoricalM2MaintenancePreHashesV1(fixture); err == nil {
		t.Fatal("validator-consumer mutation accepted")
	}
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	driftPath := filepath.Join(fixture, filepath.FromSlash(m2ValidatorPathsV1[0]))
	if err := os.WriteFile(driftPath, []byte("validator drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadHistoricalM2MaintenancePreHashesV1(fixture); err == nil || !strings.Contains(err.Error(), "hash drift") {
		t.Fatalf("validator content drift error=%v", err)
	}
}

func TestM2EvidenceConvergenceMutationsV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	for _, path := range m2Phase2CompletePathsV1 {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if errors.Is(err, os.ErrNotExist) && path == "ROADMAP.md" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(fixture, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeHistoricalRoadmapTombstone(t, fixture)
	manifestPath := filepath.Join(fixture, filepath.FromSlash(m2MaintenanceSelfPathV1))
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.EvidenceConvergenceOverlays[m2EvidenceConvergenceOverlayV1]
	mutations := []func(*m2LayeredOverlayV1){
		func(v *m2LayeredOverlayV1) { v.Version = "wrong" },
		func(v *m2LayeredOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) },
		func(v *m2LayeredOverlayV1) { v.Entries = v.Entries[:6] },
		func(v *m2LayeredOverlayV1) { v.Entries = append(v.Entries, m2MaintenanceEntryV1{}) },
		func(v *m2LayeredOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] },
		func(v *m2LayeredOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) },
		func(v *m2LayeredOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) },
	}
	for i, mutate := range mutations {
		copyManifest := manifest
		copyOverlay := base
		copyOverlay.Entries = append([]m2MaintenanceEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest.EvidenceConvergenceOverlays = map[string]m2LayeredOverlayV1{m2EvidenceConvergenceOverlayV1: copyOverlay}
		encoded, err := json.Marshal(copyManifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHistoricalM2MaintenancePreHashesV1(fixture); err == nil {
			t.Fatalf("convergence mutation %d accepted", i)
		}
	}
}

func TestM2Phase2CompleteOverlayFailureModesV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	for _, path := range m2Phase2CompletePathsV1 {
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if errors.Is(err, os.ErrNotExist) && path == "ROADMAP.md" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(fixture, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeHistoricalRoadmapTombstone(t, fixture)
	manifestPath := filepath.Join(fixture, filepath.FromSlash(m2MaintenanceSelfPathV1))
	raw, err := os.ReadFile(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase2CompleteOverlays[m2Phase2CompleteOverlayNameV1]
	mutations := []func(*m2Phase2CompleteOverlayV1){
		func(v *m2Phase2CompleteOverlayV1) { v.Version = "wrong" },
		func(v *m2Phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		func(v *m2Phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		func(v *m2Phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		func(v *m2Phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		func(v *m2Phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		func(v *m2Phase2CompleteOverlayV1) { v.Entries = append(v.Entries, m2Phase2CompleteOverlayEntryV1{}) },
		func(v *m2Phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
	}
	for i, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]m2Phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest := manifest
		copyManifest.Phase2CompleteOverlays = map[string]m2Phase2CompleteOverlayV1{m2Phase2CompleteOverlayNameV1: copyOverlay}
		encoded, err := json.Marshal(copyManifest)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(manifestPath, encoded, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := loadHistoricalM2MaintenancePreHashesV1(fixture); err == nil {
			t.Fatalf("phase2-complete mutation %d accepted", i)
		}
	}
}

func writeHistoricalRoadmapTombstone(t *testing.T, root string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(evidenceoverlay.PublicDocumentationSuccessorPath))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	const overlay = `{"version":"public-documentation-sanitization-v1","entries":[{"path":"ROADMAP.md","pre_sha256":"b1bc37aa40b84b8e765f5d2413998ab2e51e5b10211e47dd03bd23d9f7900dcc","post_evidence":"ABSENT"}]}`
	if err := os.WriteFile(path, []byte(overlay), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestIntegratedM0NamedFaultMatrixV1(t *testing.T) {
	table := runtimeadversary.RealMutantCorpusTableV1()
	results, err := runtimeadversary.RunRealMutantCorpusV1(6100)
	if err != nil {
		t.Fatal(err)
	}
	if len(table) != 16 || len(results) != 16 {
		t.Fatalf("fault matrix table=%d results=%d want 16/16", len(table), len(results))
	}
	want := map[string]runtimeadversary.RealMutantCorpusRowV1{}
	for _, row := range table {
		if _, duplicate := want[row.Mode]; duplicate {
			t.Fatalf("duplicate named fault %s", row.Mode)
		}
		want[row.Mode] = row
	}
	seen := map[string]bool{}
	for _, result := range results {
		row, ok := want[result.Mode]
		if !ok || seen[result.Mode] || result.Detector != row.Detector || result.Category != row.Category || result.Count != row.ExpectedCount || !result.UnsafeObserved || !result.DetectorRed || !result.ControlGreen {
			t.Fatalf("invalid named fault result: %+v owner=%+v", result, row)
		}
		seen[result.Mode] = true
	}
	if len(seen) != 16 {
		t.Fatalf("named faults seen=%d want=16", len(seen))
	}
}

func TestWO014ExecutableEvidenceMatrixV1(t *testing.T) {
	commands := assurance.ExecutableEvidenceCommands()
	if len(commands) != 4 {
		t.Fatalf("executable evidence command count=%d want=4", len(commands))
	}
	for index, args := range commands {
		if len(args) < 6 || args[0] != "test" || args[1] != "-timeout" || args[2] != "300s" || args[3] != "-count=1" {
			t.Fatalf("executable evidence command %d is not cache-independent and bounded: %v", index, args)
		}
	}
}

func TestSecurityVersionAuditObservabilityV1(t *testing.T) {
	if ir.LegacySchemaVersionV1 != "0.1.0-lab" || ir.NextSchemaVersionV1 != "0.2.0-lab" ||
		ir.LegacySecurityVersionV1 != "0.12.0-lab" || ir.NextSecurityVersionV1 != "0.13.0-lab" ||
		ir.SupportedVersion != ir.NextSchemaVersionV1 || ir.SupportedSecurityVersion != ir.NextSecurityVersionV1 ||
		ir.SupportedVersion == ir.LegacySchemaVersionV1 || ir.SupportedSecurityVersion == ir.LegacySecurityVersionV1 {
		t.Fatal("dormant-versus-active version authority drifted")
	}
	base := map[string]any{}
	for field, value := range expectedSecurityVersionAuditV1() {
		base[field] = value
	}
	if err := validateSecurityVersionAuditV1(base); err != nil {
		t.Fatal(err)
	}
	for field := range expectedSecurityVersionAuditV1() {
		for _, mutation := range []struct {
			name  string
			value any
		}{{"omitted", nil}, {"altered", "altered"}} {
			changed := map[string]any{}
			for key, value := range base {
				changed[key] = value
			}
			if mutation.name == "omitted" {
				delete(changed, field)
			} else {
				changed[field] = mutation.value
			}
			if err := validateSecurityVersionAuditV1(changed); err == nil {
				t.Fatalf("%s accepted %s mutation", field, mutation.name)
			}
		}
	}
}

func TestRealLabFaultInjectionSecurityMutantGateV1(t *testing.T) {
	for _, result := range []GateResult{SecurityMutantDetectionGate(context.Background()), RuntimeMutantDetectionGate(context.Background())} {
		if !result.Passed || !strings.Contains(result.Summary, realLabFaultInjectionLabelV1) || !strings.Contains(result.Summary, "does not prove defect absence") || !strings.Contains(result.Summary, "merge or deploy") {
			t.Fatalf("gate=%+v", result)
		}
		raw, err := json.Marshal(result)
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(raw))
		for _, forbidden := range []string{"channel_secret", "write_key", "ciphertext", "raw_frame", "destination", "profile_id", "transcript_hash", "synthetic-runtime", "canary"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("audit mutant result leaks forbidden field %q: %s", forbidden, raw)
			}
		}
	}
}

func TestRealLabFaultInjectionGateRejectsUnknownAndExtraModesV1(t *testing.T) {
	table := runtimeadversary.RealMutantCorpusTableV1()
	results, err := runtimeadversary.RunRealMutantCorpusV1(4100)
	if err != nil {
		t.Fatal(err)
	}
	results = append(results, runtimeadversary.RealMutantCorpusResultV1{Mode: "unknown-extra-mode"})
	result := realLabFaultInjectionGateResultsV1("security_mutant_detection", "security", table, results)
	if result.Passed {
		t.Fatal("unknown extra mode passed")
	}
	failures, ok := result.Details["failures"].([]string)
	if !ok {
		t.Fatalf("failures=%T", result.Details["failures"])
	}
	joined := strings.Join(failures, "\n")
	if !strings.Contains(joined, "unknown result mode unknown-extra-mode") || !strings.Contains(joined, "result corpus cardinality") {
		t.Fatalf("failures=%q", joined)
	}
}

func TestCompatibilitySimulationRemovedNoSelfTestStampV1(t *testing.T) {
	root := filepath.Join("..", "..")
	paths := []string{"internal/audit/security.go", "internal/audit/runtime.go", "internal/lab/runtimeadversary/runner.go"}
	for _, path := range paths {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		for _, forbidden := range []string{"RunMutantScenarioCorpus", "securityMutantReasons", "runtimeMutantDetected", "runtimeMutantScenarios", "detector self-test", "simulated regression", "self_test"} {
			if strings.Contains(text, forbidden) {
				t.Fatalf("%s retains %q", path, forbidden)
			}
		}
	}
	status := RenderStatus(AuditReport{})
	if !strings.Contains(status, realLabFaultInjectionLabelV1) || !strings.Contains(status, "does not prove defect absence") || !strings.Contains(status, "merge or deploy") {
		t.Fatal("status lacks exact mutant label/limitations")
	}
}
func TestSecurityPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var m m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	base := m.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	muts := map[string]func(map[string]m2Phase2CompleteOverlayV1){"missing-map": func(v map[string]m2Phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") }, "extra-map": func(v map[string]m2Phase2CompleteOverlayV1) { v["extra"] = base }, "wrong-version": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Version = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-predecessor": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-path": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = x.Paths[:8]
		v["phase8-wo801-adoption-v1"] = x
	}, "extra-path": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = append(x.Paths, "x")
		v["phase8-wo801-adoption-v1"] = x
	}, "reordered": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-not-last": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-entry": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = x.Entries[:7]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-entry": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = append(x.Entries, m2Phase2CompleteOverlayEntryV1{})
		v["phase8-wo801-adoption-v1"] = x
	}, "entry-path": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].Path = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "malformed": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PostSHA256 = "bad"
		v["phase8-wo801-adoption-v1"] = x
	}, "evidence-pre": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PreEvidence = strings.Repeat("2", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "consumer-absent": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = "ABSENT"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-pre": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = strings.Repeat("3", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "current-drift": func(v map[string]m2Phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
		v["phase8-wo801-adoption-v1"] = x
	}}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]m2Phase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]m2Phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mut(v)
			if _, err := validateM8WO801AdoptionOverlayV1(root, v); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestSecurityPhase8WorkOrderOverlayChainMutationsV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]m2Phase8WorkOrderOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase8WorkOrderOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]m2Phase8WorkOrderOverlayV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase9Pre := phase10Phase9PreForTestV1(t, root, manifest)
	finalGuardPre, err := validateM8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateM8WorkOrderOverlayChainAtPostV1(root, finalGuardPre, clone()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]m2Phase8WorkOrderOverlayV1){
		"missing": func(v map[string]m2Phase8WorkOrderOverlayV1) { delete(v, "phase8-wo803-canonical-profile-codec-v1") },
		"extra":   func(v map[string]m2Phase8WorkOrderOverlayV1) { v["extra"] = v["phase8-wo802-standards-suite-v1"] },
		"reordered": func(v map[string]m2Phase8WorkOrderOverlayV1) {
			v["phase8-wo803-canonical-profile-codec-v1"], v["phase8-wo804-trust-provider-boundaries-v1"] = v["phase8-wo804-trust-provider-boundaries-v1"], v["phase8-wo803-canonical-profile-codec-v1"]
		},
		"path-substitution": func(v map[string]m2Phase8WorkOrderOverlayV1) {
			o := v["phase8-wo805-verified-profile-activation-v1"]
			o.Paths[0], o.Entries[0].Path = "README.md", "README.md"
			v[o.Version] = o
		},
		"predecessor": func(v map[string]m2Phase8WorkOrderOverlayV1) {
			o := v["phase8-wo807-integrated-assurance-v1"]
			o.PredecessorOverlaySHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"content-drift": func(v map[string]m2Phase8WorkOrderOverlayV1) {
			o := v["phase8-wo802-standards-suite-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := clone()
			mutate(v)
			if _, err := validateM8WorkOrderOverlayChainAtPostV1(root, finalGuardPre, v); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestSecurityPhase8GuardMaintenanceOverlayMutationsV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]m2MaintenanceOverlayRecordV1 {
		encoded, err := json.Marshal(manifest.Phase8GuardMaintenanceOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]m2MaintenanceOverlayRecordV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase9Pre := phase10Phase9PreForTestV1(t, root, manifest)
	finalGuardPre, err := validateM8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateM8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, clone()); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]m2MaintenanceOverlayRecordV1){
		"missing-overlay": func(v map[string]m2MaintenanceOverlayRecordV1) { delete(v, "phase8-wo806-guard-convergence-v1") },
		"extra-overlay":   func(v map[string]m2MaintenanceOverlayRecordV1) { v["extra"] = v["phase8-wo806-guard-convergence-v1"] },
		"missing-path": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = o.Paths[:len(o.Paths)-1]
			v[o.Version] = o
		},
		"extra-path": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = append(o.Paths, "README.md")
			v[o.Version] = o
		},
		"reordered-path": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Paths[1] = o.Paths[1], o.Paths[0]
			v[o.Version] = o
		},
		"self-pre": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.SelfPreSHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"pre-hash": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PreSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
		"post-hash": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("3", 64)
			v[o.Version] = o
		},
		"path-substitution": func(v map[string]m2MaintenanceOverlayRecordV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Entries[0].Path = "README.md", "README.md"
			v[o.Version] = o
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := clone()
			mutate(v)
			if _, err := validateM8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, v); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestPhase8ExistingFileOverlayPreservesHistoricalCandidateBindingV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(m2MaintenanceSelfPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest m2MaintenanceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	entry := manifest.Phase8WorkOrderOverlays["phase8-wo802-standards-suite-v1"].Entries[2]
	if entry.Path != "go.mod" || entry.PreEvidence == "ABSENT" || entry.PreEvidence == m0StabilizationPreHashesV1["go.mod"] {
		t.Fatalf("invalid existing-file overlay regression fixture: %+v", entry)
	}
	candidate, err := m0CandidateOutsideScopeManifestV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if candidate.OutsideScopeSHA256 != "c8f790f82f3cf9e46555c52a248d1cfd9b5aab0a5e1243860d8bfd8de717940a" || candidate.OutsideScopeFileCount != 1329 {
		t.Fatalf("existing-file overlay replaced historical candidate binding: %s/%d", candidate.OutsideScopeSHA256, candidate.OutsideScopeFileCount)
	}
}

func TestM0CandidateManifestIgnoresUntrackedFilesV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	before, err := m0CandidateOutsideScopeManifestV1(root)
	if err != nil {
		t.Fatal(err)
	}
	probe, err := os.CreateTemp(root, "m0-candidate-untracked-")
	if err != nil {
		t.Fatal(err)
	}
	if err := probe.Close(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.Remove(probe.Name()); err != nil {
			t.Error(err)
		}
	})
	after, err := m0CandidateOutsideScopeManifestV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if after.OutsideScopeSHA256 != before.OutsideScopeSHA256 || after.OutsideScopeFileCount != before.OutsideScopeFileCount {
		t.Fatalf("untracked file changed historical candidate: before=%s/%d after=%s/%d", before.OutsideScopeSHA256, before.OutsideScopeFileCount, after.OutsideScopeSHA256, after.OutsideScopeFileCount)
	}
}
