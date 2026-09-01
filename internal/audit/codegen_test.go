package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/codegen"
	"kurdistan/internal/testkit/evidenceoverlay"
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
	raw, err := evidenceoverlay.ReadSubjectFile(filepath.Join("..", ".."), "testdata/codegen/profile-authorization-v1.json")
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
	paths, err := evidenceoverlay.HistoricalPaths(root)
	if err != nil {
		t.Fatal(err)
	}
	var entries []string
	for _, path := range paths {
		if strings.HasPrefix(path, "testdata/codegen/") {
			if _, err := evidenceoverlay.ReadHistoricalFile(root, path); err != nil {
				t.Fatal(err)
			}
			entries = append(entries, path)
		}
	}
	if len(entries) != 1 || entries[0] != "testdata/codegen/profile-authorization-v1.json" {
		t.Fatalf("testdata/codegen inventory=%v", entries)
	}
}

const committedEvidenceManifestPathV1 = "testdata/evidence/phase1-m0-committed-sha256.json"

type committedEvidenceManifestV1 struct {
	Schema                              string                                   `json:"schema"`
	HashAlgorithm                       string                                   `json:"hash_algorithm"`
	SourceCandidate                     string                                   `json:"source_candidate"`
	Sets                                map[string][]committedEvidenceEntryV1    `json:"sets"`
	MaintenanceOverlays                 map[string]committedMaintenanceOverlayV1 `json:"maintenance_overlays"`
	HelperOwnerOverlays                 map[string]helperOwnerOverlayV1          `json:"helper_owner_overlays"`
	ValidatorOverlays                   map[string]helperOwnerOverlayV1          `json:"validator_overlays"`
	ValidatorConsumerOverlays           map[string]helperOwnerOverlayV1          `json:"validator_consumer_overlays"`
	EvidenceConvergenceOverlays         map[string]helperOwnerOverlayV1          `json:"evidence_convergence_overlays"`
	Phase2CompleteOverlays              map[string]phase2CompleteOverlayV1       `json:"phase2_complete_overlays"`
	Phase3ContractOverlays              map[string]phase2CompleteOverlayV1       `json:"phase3_contract_overlays"`
	Phase4FallbackOverlays              map[string]phase2CompleteOverlayV1       `json:"phase4_fallback_overlays"`
	Phase5RelayDescriptorOverlays       map[string]phase2CompleteOverlayV1       `json:"phase5_relay_descriptor_overlays"`
	Phase6DiagnosticExportOverlays      map[string]phase2CompleteOverlayV1       `json:"phase6_diagnostic_export_overlays"`
	Phase7AppRuntimeOverlays            map[string]phase2CompleteOverlayV1       `json:"phase7_app_runtime_overlays"`
	BaselineStabilizationOverlays       map[string]phase2CompleteOverlayV1       `json:"baseline_stabilization_overlays"`
	Phase8ProfileCryptographyOverlays   map[string]phase2CompleteOverlayV1       `json:"phase8_profile_cryptography_overlays"`
	Phase8WO801ThreatModelOverlays      map[string]phase2CompleteOverlayV1       `json:"phase8_wo801_threat_model_overlays"`
	Phase8WO801AdoptionOverlays         map[string]phase2CompleteOverlayV1       `json:"phase8_wo801_adoption_overlays"`
	Phase8GuardMaintenanceOverlays      map[string]committedMaintenanceOverlayV1 `json:"phase8_guard_maintenance_overlays"`
	Phase8FinalGuardMaintenanceOverlays map[string]committedMaintenanceOverlayV1 `json:"phase8_final_guard_maintenance_overlays"`
	Phase9GuardMaintenanceOverlays      map[string]committedMaintenanceOverlayV1 `json:"phase9_guard_maintenance_overlays"`
	Phase10VPNRuntimeOverlays           map[string]committedMaintenanceOverlayV1 `json:"phase10_vpn_runtime_overlays"`
	Phase11LocalTransportOverlays       map[string]committedMaintenanceOverlayV1 `json:"phase11_local_transport_overlays"`
	Phase12OperatorControlPlaneOverlays map[string]committedMaintenanceOverlayV1 `json:"phase12_operator_control_plane_overlays"`
	Phase13AndroidProductOverlays       map[string]committedMaintenanceOverlayV1 `json:"phase13_android_product_overlays"`
	Phase14AssuranceOverlays            map[string]committedMaintenanceOverlayV1 `json:"phase14_assurance_overlays"`
}

type committedMaintenanceOverlayV1 struct {
	Version       string                      `json:"version"`
	SelfPath      string                      `json:"self_path"`
	SelfPreSHA256 string                      `json:"self_pre_sha256"`
	Paths         []string                    `json:"paths"`
	Entries       []helperOwnerOverlayEntryV1 `json:"entries"`
}

type helperOwnerOverlayV1 struct {
	Version                string                      `json:"version"`
	PredecessorManifestSHA string                      `json:"predecessor_manifest_sha256"`
	Entries                []helperOwnerOverlayEntryV1 `json:"entries"`
}

type helperOwnerOverlayEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PreSHA256   string `json:"pre_sha256"`
	PostSHA256  string `json:"post_sha256"`
}

type phase2CompleteOverlayV1 struct {
	Version                   string                         `json:"version"`
	PredecessorManifestSHA256 string                         `json:"predecessor_manifest_sha256"`
	Paths                     []string                       `json:"paths"`
	Entries                   []phase2CompleteOverlayEntryV1 `json:"entries"`
}

type phase2CompleteOverlayEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

const helperOwnerOverlayNameV1 = "m2-governance-foundation-helper-owners-v1"
const helperOwnerOverlayNameV2 = "m2-governance-foundation-helper-owners-v2"
const maintenanceOverlayNameV1 = "m2-governance-foundation-v1"
const validatorOverlayNameV1 = "m2-governance-foundation-validators-v1"
const validatorConsumerOverlayNameV1 = "m2-governance-foundation-validator-consumer-v1"
const evidenceConvergenceOverlayNameV1 = "m2-governance-foundation-evidence-convergence-v1"
const phase2CompleteOverlayNameV1 = "m2-governance-foundation-phase2-complete-v1"
const phase2PredecessorManifestSHA256V1 = "c89a6be543ec35e68bef3cd6d5a91b685b1a05e523aca264faabc6d4933c398b"

var helperOwnerPathsV1 = []string{"internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", "cmd/kgen/main_test.go"}
var helperOwnerPreHashesV1 = []string{"0874db08bb14f2d94b94b88171f1d78cd87dd34122e6ca39e3eb4ec9942a00ec", "9f1941a9ef49c70aedddddf11890ea97df0563c2b921c75a3300aee713faf9ac", "a80d10983b1e5684faf64011ee482a3a8216f2ab2393fbe9cd7570cbf4d5524d"}
var helperOwnerPostHashesV1 = []string{"5e7fff88d4e75aadf0b2306c9d9574b76e13a62c585deeebda53ba6a191832d1", "96e6e30ccfe131cfa0384fc4463ac2f75a4e9d0630179233dc40157f7839f30b", "bad5ffb692075048785a98b0c048761f06003462f1a202660b60bddf4c9103e4"}

var maintenancePathsV1 = []string{"README.md", "RZ-evidence-ref-069", "docs/GZ-evidence-ref-001", "docs/sb-evidence-ref-068", "internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}
var maintenancePreHashesV1 = []string{"68ebebb5c733c2c8aa31d9d67bed24489635c82e38a0451a9ca6e9e6e0adcb8b", "40e8f73ea355dd5de75faca8b50ebb9fc374ad6e041716d08390d648eca95e06", "867efaac1bb01cdfa62f954ead7deb895f827382c5075f969facb74a30fa3f57", "b9e571e290c46faf42d77eff7eec254b9d2870a4f26d7ddca8f649896fa55662", "18a050fdb8278db4ab71c61974d08db75e200a4e451067ab66ca669ade9543ea", "3ecb03c06bceae8ba073755a02d56a45fdfbb1899342958b1057214b304bf053", "eb04ddfd64ede4e3d1fab0ed53f008b31afcf18a2a3a157dcb21d296c77045d4", "1128d762990de6bac542df8afbbb08de06cc726c1117ecf55ec8feb69edfe167"}
var maintenancePostHashesV1 = []string{"2014b1d01767cd945f1a8196f90c327ceeadbf50da69eb5185cdd215d85f29d2", "77e6ded9aebca49b2d57138860c4b9131ae2e93683b6d59c858506862a47cc85", "3d12024c334399629bed5f9f4e41b21b3639aeab96448770e49609268010b3b6", "2fd18a43301b48f2f0cc43c542de044989173e0cae756bd417751ce0599454b8", "b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136", "3a170c4752fea63a728d55abff9b0c8a7c91e25e0c98d14bdd4c401e3b56a178"}
var validatorPathsV1 = []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go"}
var validatorPreHashesV1 = []string{"b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136"}
var convergencePathsV1 = []string{"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go"}
var convergencePreHashesV1 = []string{"aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0", "7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "985d46009b1ed6c0faade46de2574b940954de92ad6db8de3ddac0e29ea4a3ae", "f6b623b865407412856cbfc1c3748524b47ccae39ad3d33e40bd8977c9dbeab3", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "53f9635f8761701cd2a9ce2762b3004ff3a0143097cb7334930e7b6f086e33b9", "81ae4a98530acc4a643fd824a939aa658eba6f8f6c4857b7978c1ebeb6853c9f"}
var phase2CompletePathsV1 = []string{"README.md", "RZ-evidence-ref-069", "cmd/kgen/main_test.go", "docs/GZ-evidence-ref-001", "docs/KZ-evidence-ref-003", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023", "docs/sb-evidence-ref-068", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}

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
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "kurdistan.phase1-m0.committed-sha256.v1" || manifest.HashAlgorithm != "sha256" || manifest.SourceCandidate != "68d50f3bca0f1839dd7b04a1551e5fcce47b1b71" {
		t.Fatalf("invalid committed evidence manifest identity: %+v", manifest)
	}
	historicalHashes, err := validateEvidenceOverlaysV1(root, manifest)
	if err != nil {
		t.Fatal(err)
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
		post, err := evidenceoverlay.ResolveCurrentSHA256(root, entry.Path)
		if err != nil {
			t.Fatal(err)
		}
		if historical, ok := historicalHashes[entry.Path]; ok {
			post = historical
		}
		if post != entry.PostSHA256 {
			t.Fatalf("%s committed SHA-256 %s=%s want %s", set, entry.Path, post, entry.PostSHA256)
		}
		t.Logf("%s-SHA256 %s pre=%s post=%s", set, entry.Path, entry.PreEvidence, post)
	}
}

func validateEvidenceOverlaysV1(root string, manifest committedEvidenceManifestV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	phase14Pre, err := validatePhase14AssuranceOverlayAtPostV1(root, state.current, manifest.Phase14AssuranceOverlays)
	if err != nil {
		return nil, err
	}
	phase13Pre, err := validatePhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		return nil, err
	}
	phase12Pre, err := validatePhase12OperatorControlPlaneOverlayV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		return nil, err
	}
	phase11Pre, err := validatePhase11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
	if err != nil {
		return nil, err
	}
	phase10Pre, err := validatePhase10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
	if err != nil {
		return nil, err
	}
	phase9Pre, err := validatePhase9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, manifest.Phase9GuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	finalGuardPre, err := validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	guardPre, err := validatePhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, manifest.Phase8GuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range guardPre {
		if hash == "ABSENT" {
			continue
		}
		finalGuardPre[path] = hash
	}
	currentAtWO801, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, finalGuardPre, manifest.Phase8WO801AdoptionOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range finalGuardPre {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtWO801[path]; !replaced {
			currentAtWO801[path] = hash
		}
	}
	currentAtWO800, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, currentAtWO801, manifest.Phase8WO801ThreatModelOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range currentAtWO801 {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtWO800[path]; !replaced {
			currentAtWO800[path] = hash
		}
	}
	currentAtPhase8, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, currentAtWO800, manifest.Phase8ProfileCryptographyOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range currentAtWO800 {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtPhase8[path]; !replaced {
			currentAtPhase8[path] = hash
		}
	}
	currentAtM7, err := validateBaselineStabilizationEvidenceOverlayV1(root, currentAtPhase8, manifest.BaselineStabilizationOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM6, err := validatePhase7AppRuntimeOverlayV1(root, currentAtM7, manifest.Phase7AppRuntimeOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM5, err := validatePhase6DiagnosticExportOverlayV1(root, currentAtM6, manifest.Phase6DiagnosticExportOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM4, err := validatePhase5RelayDescriptorOverlayV1(root, currentAtM5, manifest.Phase5RelayDescriptorOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM3, err := validatePhase4FallbackOverlayV1(root, currentAtM4, manifest.Phase4FallbackOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM2, err := validatePhase3ContractOverlayV1(root, currentAtM3, manifest.Phase3ContractOverlays)
	if err != nil {
		return nil, err
	}
	currentAtPre, err := validatePhase2CompleteOverlayV1(root, currentAtM2, manifest.Phase2CompleteOverlays)
	if err != nil {
		return nil, err
	}
	currentAtPre, err = validateConvergenceOverlayV1(currentAtPre, manifest.EvidenceConvergenceOverlays)
	if err != nil {
		return nil, err
	}
	validators, ok := manifest.ValidatorOverlays[validatorOverlayNameV1]
	if len(manifest.ValidatorOverlays) != 1 || !ok || validators.Version != validatorOverlayNameV1 || validators.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(validators.Entries) != 3 {
		return nil, fmt.Errorf("invalid validator overlay identity/cardinality")
	}
	for i, entry := range validators.Entries {
		if entry.Path != validatorPathsV1[i] || entry.PreSHA256 != validatorPreHashesV1[i] || currentAtPre[entry.Path] != entry.PostSHA256 {
			return nil, fmt.Errorf("invalid validator chain entry %d", i)
		}
		currentAtPre[entry.Path] = entry.PreSHA256
	}
	consumer, ok := manifest.ValidatorConsumerOverlays[validatorConsumerOverlayNameV1]
	if len(manifest.ValidatorConsumerOverlays) != 1 || !ok || consumer.Version != validatorConsumerOverlayNameV1 || consumer.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(consumer.Entries) != 1 {
		return nil, fmt.Errorf("invalid validator-consumer overlay identity/cardinality")
	}
	consumerEntry := consumer.Entries[0]
	if consumerEntry.Path != "internal/testkit/importrules/importrules_test.go" || consumerEntry.PreSHA256 != "3a170c4752fea63a728d55abff9b0c8a7c91e25e0c98d14bdd4c401e3b56a178" || currentAtPre[consumerEntry.Path] != consumerEntry.PostSHA256 {
		return nil, fmt.Errorf("invalid validator-consumer chain")
	}
	currentAtPre[consumerEntry.Path] = consumerEntry.PreSHA256
	if len(manifest.MaintenanceOverlays) != 1 {
		return nil, fmt.Errorf("maintenance overlays=%d want 1", len(manifest.MaintenanceOverlays))
	}
	maintenance, ok := manifest.MaintenanceOverlays[maintenanceOverlayNameV1]
	if !ok || maintenance.Version != maintenanceOverlayNameV1 || maintenance.SelfPath != committedEvidenceManifestPathV1 || maintenance.SelfPreSHA256 != "4400e503524d1277329f893be0773dee202d5108265f62d22830e09fc8f8fa53" || len(maintenance.Paths) != len(maintenancePathsV1) || len(maintenance.Entries) != len(maintenancePreHashesV1) {
		return nil, fmt.Errorf("invalid maintenance overlay identity/cardinality")
	}
	historical := map[string]string{}
	for i, path := range maintenancePathsV1 {
		if maintenance.Paths[i] != path {
			return nil, fmt.Errorf("maintenance path[%d]=%q want %q", i, maintenance.Paths[i], path)
		}
	}
	for i, entry := range maintenance.Entries {
		if entry.Path != maintenancePathsV1[i] || entry.PreSHA256 != maintenancePreHashesV1[i] || entry.PostSHA256 != maintenancePostHashesV1[i] {
			return nil, fmt.Errorf("invalid maintenance entry %d", i)
		}
		actual := currentAtPre[entry.Path]
		if actual == "" {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		historical[entry.Path] = entry.PreSHA256
	}
	if len(manifest.HelperOwnerOverlays) != 2 {
		return nil, fmt.Errorf("helper-owner overlays=%d want 2", len(manifest.HelperOwnerOverlays))
	}
	v1, ok1 := manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1]
	v2, ok2 := manifest.HelperOwnerOverlays[helperOwnerOverlayNameV2]
	if !ok1 || v1.Version != helperOwnerOverlayNameV1 || v1.PredecessorManifestSHA != "b2a95c93332afbc13c73a4bb08e92067db97e93e843cb55e1f191b9c398e3c7b" || len(v1.Entries) != 3 {
		return nil, fmt.Errorf("invalid helper-owner v1 identity/cardinality")
	}
	if !ok2 || v2.Version != helperOwnerOverlayNameV2 || v2.PredecessorManifestSHA != "7258697b4806469afea99342d981e96b328114036668e874f7c0e5a597a94cc6" || len(v2.Entries) != 3 {
		return nil, fmt.Errorf("invalid helper-owner v2 identity/cardinality")
	}
	for i, path := range helperOwnerPathsV1 {
		oldEntry, newEntry := v1.Entries[i], v2.Entries[i]
		if oldEntry.Path != path || oldEntry.PreSHA256 != helperOwnerPreHashesV1[i] || oldEntry.PostSHA256 != helperOwnerPostHashesV1[i] {
			return nil, fmt.Errorf("invalid helper-owner v1 entry %d", i)
		}
		if newEntry.Path != path || newEntry.PreSHA256 != oldEntry.PostSHA256 || !validHelperOwnerSHA256V1(newEntry.PostSHA256) || newEntry.PostSHA256 == newEntry.PreSHA256 {
			return nil, fmt.Errorf("invalid helper-owner v2 entry %d", i)
		}
		actual := currentAtPre[path]
		if actual != newEntry.PostSHA256 {
			return nil, fmt.Errorf("helper-owner v2 hash drift %s=%s want %s: %v", path, actual, newEntry.PostSHA256, err)
		}
		historical[path] = oldEntry.PreSHA256
	}
	return historical, nil
}

func validatePhase2CompleteOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	overlay, ok := overlays[phase2CompleteOverlayNameV1]
	if len(overlays) != 1 || !ok || overlay.Version != phase2CompleteOverlayNameV1 || overlay.PredecessorManifestSHA256 != phase2PredecessorManifestSHA256V1 || len(overlay.Paths) != len(phase2CompletePathsV1) || len(overlay.Entries) != len(phase2CompletePathsV1)-1 {
		return nil, fmt.Errorf("invalid phase2-complete overlay identity/cardinality")
	}
	for i, path := range phase2CompletePathsV1 {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("phase2-complete path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if entry.Path != phase2CompletePathsV1[i] || entry.Path == committedEvidenceManifestPathV1 || !validHelperOwnerSHA256V1(entry.PostSHA256) || (entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" && !validHelperOwnerSHA256V1(entry.PreEvidence)) {
			return nil, fmt.Errorf("invalid phase2-complete entry %d", i)
		}
		actual, ok := currentAtPost[entry.Path]
		var err error
		if !ok {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase2-complete hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase8ProfileCryptographyOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase8ProfileCryptographyOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase8ProfileCryptographyOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-profile-cryptography-authorization-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069",
		"docs/GZ-evidence-ref-001",
		"docs/sb-evidence-ref-068",
		"docs/KZ-evidence-ref-020",
		"docs/KZ-evidence-ref-022",
		"docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-024",
		"docs/KZ-evidence-ref-029",
		"testdata/evidence/phase8-stabilization-baseline-2026-07-17.json",
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		committedEvidenceManifestPathV1,
	}
	wantStabilized := map[string]string{
		"cmd/kgen/main_test.go":                            "02957beb4e2f7175685d0301277bf87684a60f3a5124bf9665cf1602f44f716f",
		"internal/audit/codegen_test.go":                   "829049208bbe59f4c3589ebbc9224ce4a0c4ba48e208a1fc63cb92e9df04c15a",
		"internal/audit/security.go":                       "b5bd8ac00051ebb5afa2fce66d103eedd91535ac70065edf0da5c21d555396e9",
		"internal/audit/security_test.go":                  "756907f5700a7e6b74668da0e65c3de12f8c684fa763bc310b2e9ceef8909f7e",
		"internal/codegen/authorization_v1_test.go":        "240899c2ee09e28fec883a1de9f84f6e000342933583e63e34796f13f9657f45",
		"internal/runtime/policy_enforcement_test.go":      "8d4103ded5371325e22e4bef362de31f049c8f857487a0f04866524763c32ec8",
		"internal/testkit/importrules/importrules_test.go": "8d54c23846b2b0e679ac55c710a4b3615d03efb2489ea22d438bef63c7e68021",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "dbe03c03259b9446e17836a5f1318d3a472b5a3483ae7880318b108c174cebba" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase8 profile cryptography overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 profile cryptography path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography entry %d", i)
		}
		wantAbsent := i == 7 || i == 8
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor %d", i)
		}
		if !wantAbsent && !validHelperOwnerSHA256V1(entry.PreEvidence) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor hash %d", i)
		}
		if want, guarded := wantStabilized[entry.Path]; guarded && entry.PreEvidence != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 profile cryptography hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if !wantAbsent {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	for path, want := range wantStabilized {
		if pre[path] != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstructed %s=%s want %s", path, pre[path], want)
		}
	}
	return pre, nil
}

func validatePhase8WO801ThreatModelOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase8WO801ThreatModelOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase8WO801ThreatModelOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-threat-model-v1"
	wantPaths := []string{
		"docs/KZ-evidence-ref-030",
		"internal/product/envelope/phase8_trust.go",
		"internal/product/envelope/phase8_trust_test.go",
		"internal/product/profile/phase8_trust.go",
		"internal/product/profile/phase8_trust_test.go",
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		committedEvidenceManifestPathV1,
	}
	wantWO800 := map[string]string{
		"cmd/kgen/main_test.go":                            "9ec962c5601a6090e6289a48b142e200e5e601a4ecf3d366adefa740ea30b0f6",
		"internal/audit/codegen_test.go":                   "e2c3b0e1b7274da45d3861424bb0218f9640ad703f608d03858993531cddec2d",
		"internal/audit/security.go":                       "328e8382c05082b28aa35b92426e6622da030b460a6505b49c1761bd9c45efe9",
		"internal/audit/security_test.go":                  "076830912ef1742d6a7c7cc18279a28af652371eba9bd61db120cfc9ac9f760e",
		"internal/codegen/authorization_v1_test.go":        "421deed4c4aeafc9c8ffdc27432b10aef34a6050d8d87efb1a048da8a6046477",
		"internal/runtime/policy_enforcement_test.go":      "7ec77a79a641ce792a94cbebdc8b8a6c17cafb72c92b9b260203908df5537114",
		"internal/testkit/importrules/importrules_test.go": "29376a1a91fba2100cfc894dae836399f7e84d9756bc65c0bfb41c840a25246d",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "7373da738dde935a1eae25522b1bc9a2ce4efd7ebe50dd221fcf2c8847cb25ae" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase8 WO-801 threat-model overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model entry %d", i)
		}
		wantAbsent := i < 5
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model predecessor %d", i)
		}
		if !wantAbsent && entry.PreEvidence != wantWO800[entry.Path] {
			return nil, fmt.Errorf("phase8 WO-801 reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 threat-model hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if !wantAbsent {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase8GuardMaintenanceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase8GuardMaintenanceOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase8GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase8-wo806-guard-convergence-v1"
	paths := []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", committedEvidenceManifestPathV1}
	preHashes := []string{"10f4a412739c3896e88fb7b649774e0243ccfcfab2c77335b2e7ecaa8948f3ae", "8ed3f3c023baa71d60dbe81c94bb0e4254e8fcaf35b5c4b75d027b2c2290b15b", "1333f376b7ff19580719c40ec831a61ff6c66dd2ea90721a1d257370d698e45e", "4420c4c6582124b04c9330329bfedf213f2976f3c536cb2fa815ab28a28a1fb5", "c3fb2ce202af327107885f8a5866908cbd984aa74b09ee702514d6ed2442901d", "a7e40a30f7a30122bf23e538f8714890f3bba945799466cf378c3566160c4041", "a4664fe1fb3b6a6050af2c8e04eab51263ce32989e5d673c1ae35b97f7b8b79e"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != committedEvidenceManifestPathV1 || o.SelfPreSHA256 != "37ece675df4e2f17bb253a3a5d648c3a7b6e62d9319fd27a138be00cedb3e77a" || len(o.Paths) != 8 || len(o.Entries) != 7 {
		return nil, fmt.Errorf("invalid phase8 guard-maintenance overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		if entry.Path != paths[i] || entry.PreSHA256 != preHashes[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreSHA256
	}
	return pre, nil
}

func validatePhase8FinalGuardMaintenanceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase8-wo808-final-guard-convergence-v1"
	paths := []string{
		"README.md", "RZ-evidence-ref-069", "docs/GZ-evidence-ref-001",
		"docs/sb-evidence-ref-068", "cmd/gate/main.go", ".github/workflows/ci.yml",
		"internal/product/envelope/phase8_suite_test.go", "testdata/evidence/independent/phase8_interop.py", "testdata/evidence/phase8-independent-interop-report.json",
		"internal/product/envelope/phase8_profile_codec.go", "internal/product/envelope/phase8_profile_codec_test.go", "cmd/kprofile/main.go",
		"cmd/kprofile/main_test.go", "internal/product/profile/testdata/phase8-issuance/offline-boundary-report.json", "internal/product/profile/testdata/phase8-issuance/redacted-inspect-report.json",
		"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go",
		"internal/codegen/authorization_v1_test.go", ".gitignore", "internal/audit/status.go",
		"cmd/kprofile/path_other.go", "cmd/kprofile/path_unsupported.go", "cmd/kprofile/path_windows_test.go",
		"cmd/kprofile/path_windows.go", "cmd/kprofile/path.go", "docs/KZ-evidence-ref-036",
		"docs/PZ-evidence-ref-064", "docs/PZ-evidence-ref-065", "internal/product/envelope/phase8_evidence_test.go",
		"internal/product/envelope/phase8_suite.go", "internal/product/profile/phase8_activation_test.go", "internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_providers.go", "internal/product/profile/phase8_tooling_evidence_test.go", "internal/product/profile/phase8_tooling_external_test.go",
		"internal/product/profile/phase8_tooling.go", "internal/product/profile/testdata/phase8-activation/activation-crash-report.json", "internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json", "internal/product/profile/testdata/phase8-activation/policy-bypass-report.json", "internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json", "internal/product/profile/testdata/phase8-issuance/fixture-manifest.json", "internal/product/profile/testdata/phase8-issuance/fixture-reproduction-report.json",
		"internal/product/profile/testdata/phase8-issuance/issuance-negative-report.json", "internal/product/profile/testdata/phase8-issuance/issuance-roundtrip-report.json", "internal/product/profile/testdata/phase8-issuance/production-wiring-negative-report.json",
		"internal/testkit/phase8fixturegen/main_test.go", "internal/testkit/phase8fixturegen/main.go", "internal/testkit/phase8issuancefixture/generate.go",
		"SZ-evidence-ref-070", "testdata/evidence/phase8-release-corpus-manifest.json", "testdata/evidence/phase8-wo807-recovery-report.json",
		"testdata/evidence/phase1-m0-committed-sha256.json",
	}

	preHashes := []string{
		"65b6fe472d0b3bf59704e3793a6337ba8ebd8602bd92e9d70b34e30f445bbed5", "4c4b327d58efabe3569b7a525cf9bc18298b3027d5993ebc9a5f36b9520cb6d2", "483ac28d0d371e10784d83721b7e2efac5e46bffe031dc18fcfb253012781e4d",
		"62fabcee4d7451804f2c7f7df32e9b2e4457c8a8a16687677d20097cca616769", "c7d9d7127fec76e135fe0ea7bebd86285764025c735d8e733c12b9a0e662663f", "ABSENT",
		"f8608b81c1c0b7b2e499a1217e258ba7a9fe842ee61f68cf6728f06506204cb3", "8a312973d42f25c127827db419b0b07355a1b779d2cd243b45a77492bf55288a", "b6424fd088cc2c437175adccafff1c94b3afc6bcf0750491a1c05e72ceaf3cb5",
		"197304bba879d092cf0b37c96f2d260ccc3137ca35378c562ab17f43f7ed92f2", "12dcdff0b67c56c55b3cc29ed5ef10a3d3bfb273b1da02d6012a03940c056a3b", "d3bd61e8094ba10253cde22306b6dde0ca1c4ffe28d34616d5471a34864caa09",
		"82915c199c88ab52bdca5a74c56eab99fc61b095420064f1f3e2d51a3d9818a9", "1cc9b6f1af5157e468870e3cfc849a9e83e2513d7e06ea54f2c8388b1acc437c", "6c4e0ff29540248a2c919eaf4444ab8ee33cdb8a4ac6c8407fcbbd37deb155b4",
		"d7f33f3194065c6b4900a92843da772b74396090ae311532d82118037b2b7b3d", "251c31fcf024a5bebb11a742a0ba03ffca8ae98f146b9c5242e7c82d30cc929a", "9bc732efbf56adcbec93722f206227a43d3f0946cbc8acd0a03b96b66439d1d7",
		"3a46df826b5c108818723af77ff2e7de6530bf2e66e993d2cda364e05eb51fa9", "372f479b0c541f61e2cad4869f62ae8cce895db00ffcc3b19e03bd6925677c14", "e87df0637cdc5c93129a73855e641a98f80b750b2e27a6343e7f37072c816201",
		"9e0feb195c40a435f3d3baf80ef8a2a91d8f38f0b5134fb6bbf50f7760b767bc", "5b183df65d579d6956f2fee4771afc35f32fa0eeb87d1cfa8bb1729e19e92f20", "94dc5eb6ba2ff56fd46820592ecb01e7e5705c2200350ad9d4534221fee0f954",
		"4de767d8872d04668c0077d45be834b3397ca723e6bd9b1d66de85bee32e3d0b", "ABSENT", "ABSENT",
		"a0ada14afde8b72fb1e66513208fc020e9d674f73238896bed3f876dff83674b", "ABSENT", "9514b51d5b3320e11c875b0224e6dc9e6cf4b99b6c88d0f516441086d366daa3",
		"20a6e8732887d76ef49c957369a1132d8bdf3d10df20b3f2abcae5903bbf2cd1", "7ca541e419a2de0f4ef2f1987e21277ec78aba38c8b5acac7b74a31a6d3ca2fd", "e1b66f934f62efdc947c3ac15480e36ae4986f14042bb4a38e92dd6313c41645",
		"71c67b4e27d4f8708115030dd9469f3b133a7b4fdc09a3732e2efb6c2d67944f", "03ef0f0d758f220be50d3b517aebb8e1b2d8cace59836a2c991422c3d5162331", "0747653f3b1efb3783535572bf68843cf0e1a494bd2098a82ccfc7d224dfe1bd",
		"db08f48f7305f9543c2a6e3094218c0b31ed8185298149af05d0a4a671b19bae", "6d894e73ad19bdd05afc504212e93ef18f18e8962db06c9629be4d3bc7cd5d91", "60b60d1932bffb4b6597fb0659b9153c0531a51bab944e4263b620fdfd3af028",
		"154178a1b0bd6da95a1327a32b11c3d5c5a2023a4d323c7dbb999f89e0f807b7", "5eba165b5ea9317b51f609ab4b34ef57d3dc0a42c85ab7d4aae78b1c4b7b15ba", "fd393e178e02ab8f5c96b2502dcb7b2ad411758eb55c7ef4f8144536e47db069",
		"5eba165b5ea9317b51f609ab4b34ef57d3dc0a42c85ab7d4aae78b1c4b7b15ba", "7ce8dc7e7ddb93454c24fad8c9a8c7f375d5bba25d07673e60a757335a13aecc", "e83737cbb6ef895748045a1af296e82a6ee0bfeff72c1615bd003c1cd375b1d1",
		"0c6ca80025d973546aa2d44442f739f94b4e0b1ec9132dafc08ca72bb2f88afc", "993739b3577ab5418bec2c3790e26495c16b9bbb423ef08fce8d96d36d601b36", "19685e69c2e8b9d66b5116d74b7e75cf3e6c61abb8ae4803ab4f782debfb6688",
		"766b6b14fffc20436ad5b0ff5d623582e41dbf7907396a1599bf484639214ac7", "58f43dc6b85ae04dcd682ee7e58a506463fb6118e9eae080d57c1d7618af465b", "8007954c8ec687664fe70841982172c717e11a2933c16a373259b28a001feb55",
		"ABSENT", "00b45845fd49a2d39e1489b61e117dd91c83aa715925f82ae8cb931664230e3a", "05de9cb9f0cd0f40721c7aa6465c619e400f0e19911451629737741bc4f489df",
		"8ed8a14111d09e948879d5cebe3979cf20ce1eb048e996c9bf39e6e409f1bbf1", "7ccec20947e3733149efbf2a38d161a017d698587360353836f52811fda0b6e0", "8db7027e428d1fd09498202f33eacb7285ae56c9b28f061297f60b8642a37583",
	}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != committedEvidenceManifestPathV1 || o.SelfPreSHA256 != "afcef52b1302379c2172815138219421e2dcf2b4e7280724f7c9ae4829d5f76a" || len(o.Paths) != len(paths) || len(o.Entries) != len(preHashes) {
		return nil, fmt.Errorf("invalid phase8 final guard-maintenance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		expectedPre := preHashes[i]
		if entry.Path != paths[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance entry %d", i)
		}
		if expectedPre == "ABSENT" {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase8 final guard-maintenance absent predecessor %d", i)
			}
		} else if entry.PreEvidence != "" || entry.PreSHA256 != expectedPre || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance predecessor %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 final guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = expectedPre
	}
	return pre, nil
}

func validatePhase14AssuranceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase14AssuranceOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase14AssuranceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase14-assurance-v1"
	const predecessorBinding = "9a06e73ef9659dd10dd1c58c53955029b0116d7bd8c0ffa0856b0fa7c3ab230a"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 || !validHelperOwnerSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase14 assurance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, digest := range currentAtPost {
		pre[path] = digest
	}
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	var err error
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath || strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase14 assurance overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase14 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validHelperOwnerSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase14 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, found := currentAtPost[path]
		if !found {
			actual, err = fileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase14 assurance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return nil, fmt.Errorf("invalid phase14 predecessor binding")
	}
	return pre, nil
}

func validatePhase13AndroidProductOverlayV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase13-android-product-v1"
	const predecessorBinding = "93020d6f615b9706dda3bf719ddbffeafa838837f0ec15d3e89ad395d1950c6c"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 || !validHelperOwnerSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase13 Android product overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase13 Android product overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase13 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validHelperOwnerSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase13 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase13 Android product hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return nil, fmt.Errorf("invalid phase13 predecessor binding")
	}
	return pre, nil
}

func validatePhase12OperatorControlPlaneOverlayV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase12-operator-control-plane-v1"
	paths := []string{
		"RZ-evidence-ref-069",
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"cmd/koperator/evidence_test.go",
		"cmd/koperator/main.go",
		"cmd/koperator/main_test.go",
		"cmd/phase9verify/phase11_overlay_test.go",
		"docs/KZ-evidence-ref-041",
		"docs/PZ-evidence-ref-049",
		"docs/sb-evidence-ref-068",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator_templates.go",
		"internal/codegen/generator_test.go",
		"internal/operator/controlplane/authority_state.go",
		"internal/operator/controlplane/controlplane_test.go",
		"internal/operator/controlplane/errors.go",
		"internal/operator/controlplane/journal.go",
		"internal/operator/controlplane/model.go",
		"internal/operator/controlplane/phase_boundaries.go",
		"internal/operator/controlplane/phase_boundaries_test.go",
		"internal/operator/controlplane/reconcile.go",
		"internal/operator/controlplane/reconcile_test.go",
		"internal/operator/controlplane/service.go",
		"internal/operator/controlplane/state.go",
		"internal/product/lifecycle/phase8_verified.go",
		"internal/product/lifecycle/phase8_verified_test.go",
		"internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_admission.go",
		"internal/product/profile/phase8_admission_test.go",
		"internal/product/profile/phase8_emergency_signed.go",
		"internal/product/profile/phase8_emergency_signed_test.go",
		"internal/product/profile/phase8_providers.go",
		"internal/product/profile/phase8_revocation_admission.go",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase12/acceptance-status.json",
		"testdata/evidence/phase8-wo807-recovery-report.json",
	}
	preHashes := map[string]string{
		"RZ-evidence-ref-069":                                                              "586a5e7f377c1809eb67cfe932d996ae81703bb562f52b539935e26ccdc93e8b",
		"cmd/gate/main.go":                                                                 "8f0e4e86384ea012ac54f1c9f795c3a4f760b5ab6c7f4b24f3ab553cad3c96c1",
		"cmd/gate/main_test.go":                                                            "c2b868ec7b155ed5ae95f667181284af9672722ceea8b3c018f4dd32df2d4fdd",
		"cmd/kgen/main_test.go":                                                            "2fabad2630c546749cde3c0c67dd9885ffa855230c298dacb741c65ef497c846",
		"cmd/phase9verify/phase11_overlay_test.go":                                         "95c7e090b93beab82e673513735e6725e1f636f10244a6b37b504adc91cb3a67",
		"docs/sb-evidence-ref-068":                                                         "2846c0453c9a20d8fee0a355d339ba70f658d3f064e2dcd6ddef693d7bbb50b0",
		"internal/audit/codegen_test.go":                                                   "c1896696926104de33e540f207c4cc3e7f477edfddc006cfc9f279dd34e5df94",
		"internal/audit/security.go":                                                       "a180d1b42b37ac390a1bdf718a4c8172cafc8f14b8afd9c46c24831fe461cbe9",
		"internal/audit/security_test.go":                                                  "b4674dd844d0f006fe83ced7fbd6855a309e1bbd76ac1cd2fb6c8a73711a5519",
		"internal/codegen/authorization_v1_test.go":                                        "e2d8caf8757c35bc9e1aea7ba6c5a129d328f507d9aa54889223b83e536e4c51",
		"internal/codegen/generator_templates.go":                                          "53651959c9fbc7a936c23d4ae6cf5e4821e2322befc38596cbf215f3f24ff643",
		"internal/codegen/generator_test.go":                                               "2a519ad4aaf1d0ba4e4f9cf6294dc0772059f677e82a113b81c3712ac2832f31",
		"internal/product/lifecycle/phase8_verified.go":                                    "e9fd50ec54dca326be6580815153a3983555f1b31ea028e4a3c052257e7e17c6",
		"internal/product/lifecycle/phase8_verified_test.go":                               "7e3aad03d9af6dcec588c37225c4791cce3d38c7d0b3dfb7c69218b3ae5e5769",
		"internal/product/profile/phase8_activation.go":                                    "3de078f241b4bd4da039891cf19db34f30eae083363cd23ea21b393d88a3a080",
		"internal/product/profile/phase8_providers.go":                                     "9bf824c879fc0186de623f4c6a589a0ef2dce0cefb33b6168397363cd0a5f33c",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json": "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json": "20b5867ab1fd0ff1aff509702021c2ccc0d529f5cd4434ad48cf74864d8b185b",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json":    "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json":               "d4987c0461d703870dcfc2a53d107537fc529cacfff0cb7ceef55343cb3722fa",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json":       "6f2c3e15819d1fd18954aa242f5283e89fa1cc6a3c3964ea9ed864ee7553f364",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json":     "2fe3a7161549f9366a7d03e3724e9ec2d341659dec8af9e74e31778a908da2f0",
		"internal/runtime/policy_enforcement_test.go":                                                 "24ee3246889bf9393bece92e0016b464c3bd252ab4cf4a10038a69c069a2af20",
		"internal/testkit/importrules/importrules_test.go":                                            "f9f719b207174e13a2a1577c8fb450412fe0c2135b301c49311311fe84863221",
		"testdata/evidence/phase8-wo807-recovery-report.json":                                         "9ab249ec04fc5c012c5ed052e6bc927bcf1ed058760e26b2bbf48c0948a81c66",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		overlay.SelfPreSHA256 != "050dd24b449122dfd58a79df263c61a1e9cb8c83f4b038df82e7629e49d6dfc2" ||
		len(overlay.Paths) != len(paths) || len(overlay.Entries) != len(paths) {
		return nil, fmt.Errorf("invalid phase12 operator control-plane overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range paths {
		entry := overlay.Entries[i]
		if overlay.Paths[i] != path || entry.Path != path || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase12 operator control-plane entry %d", i)
		}
		predecessor, existed := preHashes[path]
		if existed {
			if entry.PreEvidence != "" || entry.PreSHA256 != predecessor || entry.PostSHA256 == entry.PreSHA256 {
				return nil, fmt.Errorf("invalid phase12 operator control-plane predecessor %d", i)
			}
		} else {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase12 operator control-plane absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase12 operator control-plane hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
	}
	return pre, nil
}

func validatePhase11LocalTransportOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase11LocalTransportOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase11LocalTransportOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase11-local-transport-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		!validHelperOwnerSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 128 ||
		len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase11 local transport overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || path == committedEvidenceManifestPathV1 ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase11 local transport entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase11 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validHelperOwnerSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase11 existing predecessor %d", i)
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase11 local transport hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	return pre, nil
}

func validatePhase10VPNRuntimeOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase10VPNRuntimeOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase10VPNRuntimeOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase10-local-vpn-runtime-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		overlay.SelfPreSHA256 != "45559ed3772b777924c8ef5e2a24980b8ddfccab89e67613ff379f5b48824d76" ||
		len(overlay.Paths) != 56 || len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase10 VPN runtime overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	scope := sha256.New()
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase10 VPN runtime entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase10 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validHelperOwnerSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase10 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase10 VPN runtime hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "a05d9436a931ac6286fa9c77f8d16cd24af6eb283c64168700de50dfb1278477" {
		return nil, fmt.Errorf("phase10 VPN runtime scope drift %s", got)
	}
	return pre, nil
}

func validatePhase9GuardMaintenanceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase9GuardMaintenanceOverlayAtPostV1(root, state.current, overlays)
}

func validatePhase9GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase9-wo909-final-guard-convergence-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		overlay.SelfPreSHA256 != "1f8149bb5ff5057e6b25dcad186c07303d57af4073f940708f257a17c9656623" ||
		len(overlay.Paths) != 159 || len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase9 guard-maintenance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	scope := sha256.New()
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase9 guard-maintenance entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase9 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validHelperOwnerSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase9 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase9 guard-maintenance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "d7ea283af5423eef0dc6af53d6b3004b241ba1474b3f50a1899edfddc69c12a1" {
		return nil, fmt.Errorf("phase9 guard-maintenance scope drift %s", got)
	}
	return pre, nil
}

func validatePhase8WO801AdoptionOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	state, err := loadEvidenceStateV1(root, evidenceoverlay.LoadSuccessor)
	if err != nil {
		return nil, err
	}
	return validatePhase8WO801AdoptionOverlayAtPostV1(root, state.current, overlays)
}
func validatePhase8WO801AdoptionOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-adoption-v1"
	wantPaths := []string{"testdata/evidence/phase8-wo801-adoption-2026-07-17.json", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}
	wantPre := map[string]string{"cmd/kgen/main_test.go": "f3756c80bd358535e929a8bffa4ef79129f346318fb6304fdd01abd6c915a846", "internal/audit/codegen_test.go": "00ac00353fda287944ba5fd1965a130830514b2807c5df1ea46eccbcc1299791", "internal/audit/security.go": "d71fc4a337b995790ee397b944e3d7cf47ba675dc9204eeb8b5f2c513250b73d", "internal/audit/security_test.go": "dba0df11ef69fa6364a262d2f3fdf4bb8046f089fa314148ed5a7ae13c4cf7d8", "internal/codegen/authorization_v1_test.go": "c9b8f29d924a37e1b2fbba5b6a69ef04fc6043e4c2e0f77aafd162edf66d5adc", "internal/runtime/policy_enforcement_test.go": "ab7ab4f454448750a82e5a50a8acfba96b08ca5c4c492539c371f4a6f9f49241", "internal/testkit/importrules/importrules_test.go": "1c465b2026c31246a3685f96849604d0879e0025e892fc6a4b3875bf0ef09a17"}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "989df23699da6edfb8e5279752dbe66863a854b530a532119a2689320049c56f" || len(overlay.Paths) != 9 || len(overlay.Entries) != 8 {
		return nil, fmt.Errorf("invalid phase8 WO-801 adoption overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption entry %d", i)
		}
		if i == 0 {
			if entry.PreEvidence != "ABSENT" {
				return nil, fmt.Errorf("invalid phase8 WO-801 adoption evidence predecessor")
			}
		} else if !validHelperOwnerSHA256V1(entry.PreEvidence) || entry.PreEvidence != wantPre[entry.Path] {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 adoption current hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if i > 0 {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	for path, want := range wantPre {
		if pre[path] != want {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstructed %s=%s want %s", path, pre[path], want)
		}
	}
	return pre, nil
}

func validateBaselineStabilizationEvidenceOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "go126-clean-worktree-stabilization-v1"
	wantPaths := []string{
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/" + "testkit/importrules/importrules_test.go",
		committedEvidenceManifestPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "4bc0e7279b17cfbac0dc7138654991f20331b535d0c097c406efee68a1af8f74" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid baseline stabilization overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid baseline stabilization path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validHelperOwnerSHA256V1(entry.PreEvidence) || !validHelperOwnerSHA256V1(entry.PostSHA256) || entry.PreEvidence == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid baseline stabilization entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("baseline stabilization hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreEvidence
	}
	return pre, nil
}

func validatePhase7AppRuntimeOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m7-offline-app-runtime-contract-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-028", "internal/product/appruntime/appruntime.go", "internal/product/appruntime/appruntime_test.go",
		"testdata/consumer/m7-app-runtime-sdk/go.mod", "testdata/consumer/m7-app-runtime-sdk/app_runtime_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/" + "testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "34f5d8d2048faf1de49c2ccd2ebb4a5c507ad3bf0b2d75b5db1e7e6d5c13a0a7" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase7 app runtime overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase7 app runtime path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase7 app runtime entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase7 app runtime hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validHelperOwnerSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase7 app runtime pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase6DiagnosticExportOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m6-offline-diagnostic-export-contract-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-027", "internal/product/diagnosticexport/diagnosticexport.go", "internal/product/diagnosticexport/diagnosticexport_test.go",
		"testdata/consumer/m6-diagnostic-export-sdk/go.mod", "testdata/consumer/m6-diagnostic-export-sdk/diagnostic_export_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "77fcaaa94436a401f071fbfbade94baeb0cd770574c7309ae5c427a76c030977" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase6 diagnostic export overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase6 diagnostic export path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase6 diagnostic export entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase6 diagnostic export hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase6 diagnostic export pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase5RelayDescriptorOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m5-offline-relay-descriptor-admission-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "709e4a5a7412ee115fc71c2d825ebe9ac4f167439b4861a1649dd63fcf0c150f" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase5 relay descriptor overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase5 relay descriptor entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase5 relay descriptor hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase5 relay descriptor pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase4FallbackOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m4-permitted-fallback-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "772ae344c99edb21a4d04fadd77f51978a6e81aa4d555ec30190cb64e7a7c2d9" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase4 fallback overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase4 fallback entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase4 fallback hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			if !validHelperOwnerSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase4 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase3ContractOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase3 contract overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase3 contract entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = fileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validHelperOwnerSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		} else {
			delete(pre, entry.Path)
		}
	}
	return pre, nil
}

func validateConvergenceOverlayV1(currentAtPost map[string]string, overlays map[string]helperOwnerOverlayV1) (map[string]string, error) {
	convergence, ok := overlays[evidenceConvergenceOverlayNameV1]
	if len(overlays) != 1 || !ok || convergence.Version != evidenceConvergenceOverlayNameV1 || convergence.PredecessorManifestSHA != "1502ae4db6d151839f554e6becde9e81994286cbff378945282739015492bf1e" || len(convergence.Entries) != 7 {
		return nil, fmt.Errorf("invalid convergence overlay identity/cardinality")
	}
	result := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		result[path] = hash
	}
	for i, entry := range convergence.Entries {
		if entry.Path != convergencePathsV1[i] || entry.PreSHA256 != convergencePreHashesV1[i] || !validHelperOwnerSHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
			return nil, fmt.Errorf("invalid convergence entry %d", i)
		}
		actual := currentAtPost[entry.Path]
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("convergence hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		result[entry.Path] = entry.PreSHA256
	}
	return result, nil
}

type evidenceSuccessorLoaderV1 func(root, expectedVersion string) (map[string]string, error)

type evidenceStateV1 struct {
	root    string
	current map[string]string
}

func loadEvidenceStateV1(root string, load evidenceSuccessorLoaderV1) (evidenceStateV1, error) {
	current, err := load(root, "phase15-production-contract-v1")
	if err != nil {
		return evidenceStateV1{}, fmt.Errorf("load Phase 15 successor overlay: %w", err)
	}
	return evidenceStateV1{root: root, current: current}, nil
}

func (s evidenceStateV1) resolve(path string) (string, error) {
	if digest, ok := s.current[path]; ok {
		return digest, nil
	}
	return fileSHA256V1(s.root, path)
}

func fileSHA256V1(root, path string) (string, error) {
	content, err := evidenceoverlay.ReadSubjectFile(root, path)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(content)
	return hex.EncodeToString(digest[:]), nil
}

func validHelperOwnerSHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

func TestPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8ProfileCryptographyOverlayV1(root, map[string]phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

func TestPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8WO801ThreatModelOverlayV1(root, map[string]phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
}

func TestM2HelperOwnerOverlayCompositionMutationsV2(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.HelperOwnerOverlays[helperOwnerOverlayNameV2]
	v1Raw, err := json.Marshal(manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
	if err != nil {
		t.Fatal(err)
	}
	mutations := []func(*helperOwnerOverlayV1){
		func(v *helperOwnerOverlayV1) { v.Version = "wrong" },
		func(v *helperOwnerOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) },
		func(v *helperOwnerOverlayV1) { v.Entries = v.Entries[:2] },
		func(v *helperOwnerOverlayV1) { v.Entries = append(v.Entries, helperOwnerOverlayEntryV1{}) },
		func(v *helperOwnerOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] },
		func(v *helperOwnerOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) },
		func(v *helperOwnerOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) },
	}
	for i, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Entries = append([]helperOwnerOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest := manifest
		copyManifest.HelperOwnerOverlays = map[string]helperOwnerOverlayV1{
			helperOwnerOverlayNameV1: manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1],
			helperOwnerOverlayNameV2: copyOverlay,
		}
		if _, err := validateEvidenceOverlaysV1(root, copyManifest); err == nil {
			t.Fatalf("helper-owner mutation %d accepted", i)
		}
		gotV1, _ := json.Marshal(copyManifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
		if string(gotV1) != string(v1Raw) {
			t.Fatalf("helper-owner v1 changed by mutation %d", i)
		}
	}
}

func TestEvidenceStateLoadsSuccessorOnceForManyHashes(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	loads := 0
	state, err := loadEvidenceStateV1(root, func(root, expectedVersion string) (map[string]string, error) {
		loads++
		return evidenceoverlay.LoadSuccessor(root, expectedVersion)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{
		"cmd/phase17field/main.go",
		"internal/audit/security.go",
		"go.mod",
	} {
		if _, err := state.resolve(path); err != nil {
			t.Fatal(err)
		}
	}
	if loads != 1 {
		t.Fatalf("successor loads=%d, want 1", loads)
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
func TestPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, committedEvidenceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	mutations := map[string]func(map[string]phase2CompleteOverlayV1){
		"missing-map": func(v map[string]phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") },
		"extra-map":   func(v map[string]phase2CompleteOverlayV1) { v["extra"] = base },
		"wrong-version": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Version = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-predecessor": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = x.Paths[:8]
			v["phase8-wo801-adoption-v1"] = x
		},
		"extra-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths = append(x.Paths, "extra")
			v["phase8-wo801-adoption-v1"] = x
		},
		"reordered": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-not-last": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"missing-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = x.Entries[:7]
			v["phase8-wo801-adoption-v1"] = x
		},
		"self-entry": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries = append(x.Entries, phase2CompleteOverlayEntryV1{})
			v["phase8-wo801-adoption-v1"] = x
		},
		"entry-path": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].Path = "wrong"
			v["phase8-wo801-adoption-v1"] = x
		},
		"malformed-hash": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PostSHA256 = "bad"
			v["phase8-wo801-adoption-v1"] = x
		},
		"evidence-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[0].PreEvidence = strings.Repeat("2", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"consumer-absent": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = "ABSENT"
			v["phase8-wo801-adoption-v1"] = x
		},
		"wrong-pre": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PreEvidence = strings.Repeat("3", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
		"current-drift": func(v map[string]phase2CompleteOverlayV1) {
			x := v["phase8-wo801-adoption-v1"]
			x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
			v["phase8-wo801-adoption-v1"] = x
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mutate(v)
			if _, err := validatePhase8WO801AdoptionOverlayV1(root, v); err == nil {
				t.Fatalf("accepted %s mutation", name)
			}
		})
	}
}
