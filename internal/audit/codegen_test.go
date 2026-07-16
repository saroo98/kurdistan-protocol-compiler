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
	Schema                      string                                   `json:"schema"`
	HashAlgorithm               string                                   `json:"hash_algorithm"`
	SourceCandidate             string                                   `json:"source_candidate"`
	Sets                        map[string][]committedEvidenceEntryV1    `json:"sets"`
	MaintenanceOverlays         map[string]committedMaintenanceOverlayV1 `json:"maintenance_overlays"`
	HelperOwnerOverlays         map[string]helperOwnerOverlayV1          `json:"helper_owner_overlays"`
	ValidatorOverlays           map[string]helperOwnerOverlayV1          `json:"validator_overlays"`
	ValidatorConsumerOverlays   map[string]helperOwnerOverlayV1          `json:"validator_consumer_overlays"`
	EvidenceConvergenceOverlays map[string]helperOwnerOverlayV1          `json:"evidence_convergence_overlays"`
	Phase2CompleteOverlays      map[string]phase2CompleteOverlayV1       `json:"phase2_complete_overlays"`
	Phase3ContractOverlays      map[string]phase2CompleteOverlayV1       `json:"phase3_contract_overlays"`
	Phase4FallbackOverlays      map[string]phase2CompleteOverlayV1       `json:"phase4_fallback_overlays"`
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
	Path       string `json:"path"`
	PreSHA256  string `json:"pre_sha256"`
	PostSHA256 string `json:"post_sha256"`
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

var maintenancePathsV1 = []string{"README.md", "ROADMAP.md", "docs/GOVERNANCE.md", "docs/safety.md", "internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}
var maintenancePreHashesV1 = []string{"68ebebb5c733c2c8aa31d9d67bed24489635c82e38a0451a9ca6e9e6e0adcb8b", "40e8f73ea355dd5de75faca8b50ebb9fc374ad6e041716d08390d648eca95e06", "867efaac1bb01cdfa62f954ead7deb895f827382c5075f969facb74a30fa3f57", "b9e571e290c46faf42d77eff7eec254b9d2870a4f26d7ddca8f649896fa55662", "18a050fdb8278db4ab71c61974d08db75e200a4e451067ab66ca669ade9543ea", "3ecb03c06bceae8ba073755a02d56a45fdfbb1899342958b1057214b304bf053", "eb04ddfd64ede4e3d1fab0ed53f008b31afcf18a2a3a157dcb21d296c77045d4", "1128d762990de6bac542df8afbbb08de06cc726c1117ecf55ec8feb69edfe167"}
var maintenancePostHashesV1 = []string{"2014b1d01767cd945f1a8196f90c327ceeadbf50da69eb5185cdd215d85f29d2", "77e6ded9aebca49b2d57138860c4b9131ae2e93683b6d59c858506862a47cc85", "3d12024c334399629bed5f9f4e41b21b3639aeab96448770e49609268010b3b6", "2fd18a43301b48f2f0cc43c542de044989173e0cae756bd417751ce0599454b8", "b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136", "3a170c4752fea63a728d55abff9b0c8a7c91e25e0c98d14bdd4c401e3b56a178"}
var validatorPathsV1 = []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go"}
var validatorPreHashesV1 = []string{"b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136"}
var convergencePathsV1 = []string{"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go"}
var convergencePreHashesV1 = []string{"aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0", "7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "985d46009b1ed6c0faade46de2574b940954de92ad6db8de3ddac0e29ea4a3ae", "f6b623b865407412856cbfc1c3748524b47ccae39ad3d33e40bd8977c9dbeab3", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "53f9635f8761701cd2a9ce2762b3004ff3a0143097cb7334930e7b6f086e33b9", "81ae4a98530acc4a643fd824a939aa658eba6f8f6c4857b7978c1ebeb6853c9f"}
var phase2CompletePathsV1 = []string{"README.md", "ROADMAP.md", "cmd/kgen/main_test.go", "docs/GOVERNANCE.md", "docs/KIP-0001-threat-model.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md", "docs/safety.md", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}

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
		current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(current)
		post := hex.EncodeToString(sum[:])
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
	currentAtM3, err := validatePhase4FallbackOverlayV1(root, manifest.Phase4FallbackOverlays)
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

func validatePhase4FallbackOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m4-permitted-fallback-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "772ae344c99edb21a4d04fadd77f51978a6e81aa4d555ec30190cb64e7a7c2d9" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase4 fallback overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase4 fallback entry %d", i)
		}
		actual, err := fileSHA256V1(root, entry.Path)
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase4 fallback hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
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

func fileSHA256V1(root, path string) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func validHelperOwnerSHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

func TestM2HelperOwnerOverlayCompositionMutationsV2(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
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
