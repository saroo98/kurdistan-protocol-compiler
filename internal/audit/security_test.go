// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/lab/runtimeadversary"
	"kurdistan/internal/protocol/ir"
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
	manifest, err := m0CandidateManifestFromPathsWithPreHashesV1(fixture, paths, preHashes)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(manifest.MaintenancePaths, paths) || manifest.MaintenanceFileCount != 9 || manifest.MaintenanceSHA256 != "41262d1712a957de91e550df01375a2d6f7a7e370635cc96566b9acedfc148a6" {
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

func TestM2MaintenanceOverlayExactContentAndFailureModesV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	pre, err := loadM2MaintenancePreHashesV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(pre) != 12 || pre[m2MaintenanceSelfPathV1] != m0WO058MaintenanceHashesV1[m2MaintenanceSelfPathV1] {
		t.Fatalf("M2 pre-hash overlay=%v", pre)
	}
	for path, want := range map[string]string{
		"README.md":          "68ebebb5c733c2c8aa31d9d67bed24489635c82e38a0451a9ca6e9e6e0adcb8b",
		"ROADMAP.md":         "40e8f73ea355dd5de75faca8b50ebb9fc374ad6e041716d08390d648eca95e06",
		"docs/GOVERNANCE.md": "867efaac1bb01cdfa62f954ead7deb895f827382c5075f969facb74a30fa3f57",
		"docs/safety.md":     "b9e571e290c46faf42d77eff7eec254b9d2870a4f26d7ddca8f649896fa55662",
	} {
		if pre[path] != want {
			t.Fatalf("M2 pre-hash %s=%s want %s", path, pre[path], want)
		}
	}

	fixture := t.TempDir()
	fixturePaths := append(append([]string(nil), m2MaintenancePathsV1...), m2HelperPathsV1...)
	for _, path := range fixturePaths {
		content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
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
	if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil || !strings.Contains(err.Error(), "M2 maintenance hash drift README.md") {
		t.Fatalf("changed listed content error=%v", err)
	}
	if err := os.Remove(drift); err != nil {
		t.Fatal(err)
	}
	if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil || !strings.Contains(err.Error(), "M2 maintenance path README.md") {
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
	for _, path := range append(append([]string(nil), m2MaintenancePathsV1...), m2HelperPathsV1...) {
		content, readErr := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
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
		if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil {
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
	if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil {
		t.Fatal("validator-consumer mutation accepted")
	}
	if err := os.WriteFile(manifestPath, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	driftPath := filepath.Join(fixture, filepath.FromSlash(m2ValidatorPathsV1[0]))
	if err := os.WriteFile(driftPath, []byte("validator drift"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil || !strings.Contains(err.Error(), "hash drift") {
		t.Fatalf("validator content drift error=%v", err)
	}
}

func TestM2EvidenceConvergenceMutationsV1(t *testing.T) {
	root, err := repoRoot()
	if err != nil {
		t.Fatal(err)
	}
	fixture := t.TempDir()
	for _, path := range append(append([]string(nil), m2MaintenancePathsV1...), m2HelperPathsV1...) {
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
		if _, err := loadM2MaintenancePreHashesV1(fixture); err == nil {
			t.Fatalf("convergence mutation %d accepted", i)
		}
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
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	commands := [][]string{
		{"test", "-timeout", "120s", "-count=1", "./internal/runtime", "-run", "TestGeneratedProfileParityV1|TestInterpretedPolicyParityCoveringArrayV1|TestPolicyMatrixOwnerWitnessLiteralCompleteV1|TestPolicyMatrixAdmissionOnlyExecutedLedgerV1|TestPolicyMatrixCausalOwnerRegistryCompleteV1"},
		{"test", "-timeout", "120s", "-count=1", "./internal/codegen", "-run", "TestStrictGeneratedIdentifiersAndRoleSeparatedAuthorization|TestGenerateCreatesBuildableProfileSpecificModule|TestStrictGenerateSignedBoundaryMultiSeedAndPreOutput"},
		{"test", "-timeout", "120s", "-count=1", "./internal/testkit/importrules", "-run", "TestLabFaultCapabilityCannotReachNormalPaths|VersionMigrationBoundary|OfflineMigrationReachability|GeneratedAuthorizationBoundary|NoLabShortcut"},
		{"test", "-timeout", "120s", "-count=1", "./internal/crypto/...", "./internal/runtime/...", "./internal/protocol/framing/..."},
	}
	for _, args := range commands {
		cmd := exec.Command("go", args...)
		cmd.Dir = root
		output, runErr := cmd.CombinedOutput()
		if runErr != nil {
			t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), runErr, output)
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
