package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

func captureCommandV1(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	oldErr, oldOut := commandStderr, commandStdout
	var stderr bytes.Buffer
	commandStderr, commandStdout = &stderr, io.Discard
	t.Cleanup(func() { commandStderr, commandStdout = oldErr, oldOut })
	return fn(), stderr.String()
}

func authorizationCatalogV1(t *testing.T, scope string, seed int64) []byte {
	t.Helper()
	pin := map[string]any{
		"profile_hash": "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", "effective_policy_hash": "9a208cab2e4393c3c6417fc1436a1a7c9959dce4a50ac435baaf5d8b72d5bad7",
		"framing_hash": "1e01c3b207af2122b5dff65f1945f7dbad96c288163e5deb65684e9ed297da6c", "state_machine_hash": "ccf2a4742252f71b3d4aaa5cc9c0e26f00222df81dd7c9020afb1ca6ae48489f",
		"scheduler_hash": "8c27f74766a072e98e7a3108c02dd1680f6381178e23323fc8422b3f5f574930", "padding_hash": "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36",
		"stream_hash": "2bf26abe3667e47418a4fc935f8aeb18f64620454dd1ee234faba4ddcd9e2c90", "proxy_hash": "3e4bbe2759342669767541930cda069f9bee0b3b419c3016b64ee05621124ebd",
		"carrier_context_hash": "f71bd073932bf7de9a4df9dd0f666827849f9a87f895de98c5813f7474a116b2", "effective_replay_window": 128, "effective_max_concurrent_streams": 8, "effective_max_frame_bytes": 65536, "effective_max_envelope_bytes": 8192,
	}
	raw, err := json.Marshal(map[string]any{"version": "profile-authorization-catalog-v1", "scope": scope, "entries": []any{map[string]any{"seed": seed, "client": pin, "relay": pin}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func authorizationCatalogForProfileV1(t *testing.T, p *ir.Profile) []byte {
	t.Helper()
	hash, err := ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	raw := authorizationCatalogV1(t, "explicit_v1", p.Seed)
	return []byte(strings.ReplaceAll(string(raw), "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", hash))
}

func profileForSeedV1(t *testing.T, seed int64) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(42)
	if err != nil {
		t.Fatal(err)
	}
	p.Seed = seed
	key := sha256.Sum256([]byte(fmt.Sprintf("test-only-key:%s:%d", p.ID, seed)))
	p.Auth.TestKeyHex = hex.EncodeToString(key[:])
	p.GenerationHash = ""
	hash, err := ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = hash
	return p
}

func strictInputs(t *testing.T) (string, string) {
	t.Helper()
	p, err := compiler.Generate(42)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.json")
	catalog := filepath.Join(dir, "catalog.json")
	if err := ir.SaveProfile(profile, p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalog, authorizationCatalogV1(t, "explicit_v1", 42), 0o600); err != nil {
		t.Fatal(err)
	}
	return profile, catalog
}

func TestProfileInputStrictLocalFile(t *testing.T) {
	profile, catalog := strictInputs(t)
	for _, args := range [][]string{{"--profile", "relative.json", "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}, {"--profile", filepath.Join(t.TempDir(), "missing"), "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}} {
		if run(args) == 0 {
			t.Fatal("unsafe profile input accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "profile-link.json")
	if err := os.Symlink(profile, link); err == nil && run([]string{"--profile", link, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}) == 0 {
		t.Fatal("symlink accepted")
	}
	oversize := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(oversize, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if run([]string{"--profile", oversize, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}) == 0 {
		t.Fatal("oversize profile accepted")
	}
	exact := filepath.Join(t.TempDir(), "exact.json")
	if err := os.WriteFile(exact, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readLocalRegularFile(exact); err != nil || len(raw) != 1<<20 {
		t.Fatalf("exact limit read=%d err=%v", len(raw), err)
	}
	parent := t.TempDir()
	realDir := filepath.Join(parent, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(parent, "link")
	if err := os.Symlink(realDir, parentLink); err == nil {
		inside := filepath.Join(realDir, "profile.json")
		if err := os.WriteFile(inside, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalRegularFile(filepath.Join(parentLink, "profile.json")); err == nil {
			t.Fatal("symlink component accepted")
		}
	}
}

func TestAuthorizationCatalogStrictLocalAndRange(t *testing.T) {
	profile, catalog := strictInputs(t)
	for name, raw := range map[string][]byte{"malformed": []byte("{"), "default scope": authorizationCatalogV1(t, "default_audit_v1", 42), "wrong seed": authorizationCatalogV1(t, "explicit_v1", 41)} {
		path := filepath.Join(t.TempDir(), strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "out")
		if run([]string{"--profile", profile, "--authorization-catalog", path, "--out", out}) == 0 {
			t.Fatalf("%s accepted", name)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s mutated output", name)
		}
	}
	if run([]string{"--profile", profile, "--authorization-catalog", "relative.json", "--out", filepath.Join(t.TempDir(), "out")}) == 0 {
		t.Fatal("relative catalog accepted")
	}
	exact := filepath.Join(t.TempDir(), "exact-catalog.json")
	if err := os.WriteFile(exact, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readLocalRegularFile(exact); err != nil || len(raw) != 1<<20 {
		t.Fatalf("exact catalog limit read=%d err=%v", len(raw), err)
	}
	_ = catalog
}

func TestStrictGenerationPreservesForceWrite(t *testing.T) {
	profile, catalog := strictInputs(t)
	out := filepath.Join(t.TempDir(), "generated")
	args := []string{"--profile", profile, "--authorization-catalog", catalog, "--out", out}
	if code := run(args); code != 0 {
		t.Fatalf("generate=%d", code)
	}
	if code := run(args); code == 0 {
		t.Fatal("overwrite accepted")
	}
	if code := run(append(args, "--force")); code != 0 {
		t.Fatalf("force=%d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestStrictGenerationSignedSeedBoundaries(t *testing.T) {
	for _, seed := range []int64{math.MinInt64, -1, math.MaxInt64 - 7} {
		p := profileForSeedV1(t, seed)
		dir := t.TempDir()
		profile := filepath.Join(dir, "profile.json")
		catalog := filepath.Join(dir, "catalog.json")
		if err := ir.SaveProfile(profile, p); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(catalog, authorizationCatalogForProfileV1(t, p), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", filepath.Join(dir, "out")}); code != 0 {
			t.Fatalf("seed %d exit=%d", seed, code)
		}
	}
	for _, seed := range []int64{math.MaxInt64 - 6, math.MaxInt64} {
		p := profileForSeedV1(t, seed)
		dir := t.TempDir()
		profile := filepath.Join(dir, "profile.json")
		catalog := filepath.Join(dir, "catalog.json")
		out := filepath.Join(dir, "out")
		if err := ir.SaveProfile(profile, p); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(catalog, authorizationCatalogForProfileV1(t, p), 0o600); err != nil {
			t.Fatal(err)
		}
		if run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", out}) == 0 {
			t.Fatalf("seed %d accepted", seed)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("seed %d mutated output", seed)
		}
	}
}

func TestNoImplicitPinsSource(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"Lstat", "os.Open", "f.Stat", "os.SameFile", "io.LimitReader", "ir.DecodeProfileV1", "codegen.ParseAuthorizationCatalogV1", "ValidateExactSeedRangeV1", "codegen.GenerateStrict"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"ir.LoadProfile", "codegen.Generate(", "http.", "net.", "os.Getenv", "LookupEnv"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden %s", forbidden)
		}
	}
}

func TestPreGenerationNoMutation(t *testing.T) {
	profile, _ := strictInputs(t)
	out := filepath.Join(t.TempDir(), "must-not-exist")
	if run([]string{"--profile", profile, "--authorization-catalog", filepath.Join(t.TempDir(), "missing"), "--out", out}) == 0 {
		t.Fatal("missing catalog accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("pre-generation failure mutated output")
	}
}

func TestProfileInputDecodeMatrixAndConstantDiagnostics(t *testing.T) {
	base, _ := compiler.Generate(42)
	legacy := *base
	legacy.Version, legacy.Compatibility.SchemaVersion = ir.LegacySchemaVersionV1, ir.LegacySchemaVersionV1
	legacy.Security.SecurityVersion, legacy.Compatibility.CompilerSecurityVersion, legacy.Compatibility.MinimumRuntimeVersion = ir.LegacySecurityVersionV1, ir.LegacySecurityVersionV1, ir.LegacySecurityVersionV1
	mixed := *base
	mixed.Version = ir.LegacySchemaVersionV1
	future := *base
	future.Version, future.Compatibility.SchemaVersion = "99", "99"
	future.Security.SecurityVersion, future.Compatibility.CompilerSecurityVersion, future.Compatibility.MinimumRuntimeVersion = "99", "99", "99"
	invalid := *base
	invalid.GenerationHash = strings.Repeat("0", 64)
	_, catalog := strictInputs(t)
	for name, raw := range map[string][]byte{"malformed": []byte("{"), "legacy": mustMarshalV1(t, &legacy), "mixed": mustMarshalV1(t, &mixed), "future": mustMarshalV1(t, &future), "current-invalid": mustMarshalV1(t, &invalid)} {
		path := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "out")
		code, stderr := captureCommandV1(t, func() int { return run([]string{"--profile", path, "--authorization-catalog", catalog, "--out", out}) })
		if code == 0 || stderr != errProfileInput.Error()+"\n" || strings.Contains(stderr, path) || strings.Contains(stderr, name) {
			t.Fatalf("%s code=%d stderr=%q", name, code, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s mutated output", name)
		}
	}
}

func mustMarshalV1(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthorizationCatalogParserRangeAndRoleMismatchMatrix(t *testing.T) {
	profile, good := strictInputs(t)
	p43 := profileForSeedV1(t, 43)
	var one, two map[string]any
	if err := json.Unmarshal(authorizationCatalogForProfileV1(t, p43), &two); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(authorizationCatalogV1(t, "explicit_v1", 42), &one); err != nil {
		t.Fatal(err)
	}
	extra := one
	extra["entries"] = append(extra["entries"].([]any), two["entries"].([]any)[0])
	cases := map[string][]byte{"missing": nil, "empty": []byte(`{"version":"profile-authorization-catalog-v1","scope":"explicit_v1","entries":[]}`), "extra": mustMarshalV1(t, extra), "wrong-range": authorizationCatalogV1(t, "explicit_v1", 41)}
	baseRaw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("1", 64)
	cases["client-mismatch"] = []byte(strings.Replace(string(baseRaw), "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", wrong, 1))
	last := strings.LastIndex(string(baseRaw), "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2")
	cases["relay-mismatch"] = append(append([]byte{}, baseRaw[:last]...), append([]byte(wrong), baseRaw[last+64:]...)...)
	for name, raw := range cases {
		path := filepath.Join(t.TempDir(), name+".json")
		if raw != nil {
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out := filepath.Join(t.TempDir(), "out")
		code, stderr := captureCommandV1(t, func() int { return run([]string{"--profile", profile, "--authorization-catalog", path, "--out", out}) })
		if code == 0 {
			t.Fatalf("%s accepted", name)
		}
		want := errAuthorizationCatalog.Error() + "\n"
		if strings.Contains(name, "mismatch") {
			want = errStrictGeneration.Error() + ": codegen authorization mismatch\n"
		}
		if stderr != want || strings.Contains(stderr, path) || strings.Contains(stderr, "42") {
			t.Fatalf("%s stderr=%q want=%q", name, stderr, want)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s mutated output", name)
		}
	}
}

func TestProfileInputAndAuthorizationCatalogExactLimitReachParsers(t *testing.T) {
	profile, catalog := strictInputs(t)
	pRaw, _ := os.ReadFile(profile)
	cRaw, _ := os.ReadFile(catalog)
	if err := os.WriteFile(profile, append(pRaw, bytes.Repeat([]byte(" "), (1<<20)-len(pRaw))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalog, append(cRaw, bytes.Repeat([]byte(" "), (1<<20)-len(cRaw))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}); code != 0 {
		t.Fatalf("exact limit command=%d", code)
	}
}

func TestProfileInputAuthorizationCatalogFilesystemFailureSeams(t *testing.T) {
	profile, catalog := strictInputs(t)
	for _, target := range []string{profile, catalog} {
		oldSame := sameLocalFile
		sameLocalFile = func(os.FileInfo, os.FileInfo) bool { return false }
		if _, err := readLocalRegularFile(target); err == nil {
			t.Fatal("identity mismatch accepted")
		}
		sameLocalFile = oldSame
		oldOpen := openLocal
		openLocal = func(path string) (*os.File, error) {
			f, err := os.Open(path)
			if err == nil {
				_ = f.Close()
			}
			return f, err
		}
		if _, err := readLocalRegularFile(target); err == nil {
			t.Fatal("read failure accepted")
		}
		openLocal = oldOpen
	}
	if _, err := readLocalRegularFile(filepath.Dir(profile)); err == nil {
		t.Fatal("directory accepted")
	}
	if filepath.IsAbs(os.DevNull) {
		if _, err := readLocalRegularFile(os.DevNull); err == nil {
			t.Fatal("irregular file accepted")
		}
	}
}

func TestStrictGenerationModulePathDeferredWO043(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "codegen.ErrStrictModulePath") {
		t.Fatal("WO-043 module-path sentinel not preserved")
	}
	// WO-041 only preserves the constant chain; WO-043 owns enforcement.
}

func TestNoImplicitPinsFourPathSHA256Evidence(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	verifyCommittedEvidenceSetV1(t, root, "WO-041", []committedEvidenceExpectationV1{
		{"cmd/kgen/main.go", "79c6bb76ae234e08b8f2b1e2248ea1e4d4d0770fa52e9fcab1aa3914618a3ed4"},
		{"cmd/kgen/main_test.go", "bf6f2a7e2840c12d56a652f486fecda8297f839d36697bef786b31cfd6e2273b"},
		{"internal/runtime/policy_enforcement_test.go", "ABSENT"},
		{"internal/runtime/profile_loader_test.go", "ABSENT"},
	})
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
	currentAtM2, err := validatePhase3ContractOverlayV1(root, manifest.Phase3ContractOverlays)
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

func validatePhase3ContractOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase3 contract overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validHelperOwnerSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase3 contract entry %d", i)
		}
		actual, err := fileSHA256V1(root, entry.Path)
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validHelperOwnerSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
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
	mutations := []func(*helperOwnerOverlayV1){func(v *helperOwnerOverlayV1) { v.Version = "wrong" }, func(v *helperOwnerOverlayV1) { v.PredecessorManifestSHA = strings.Repeat("1", 64) }, func(v *helperOwnerOverlayV1) { v.Entries = v.Entries[:2] }, func(v *helperOwnerOverlayV1) { v.Entries = append(v.Entries, helperOwnerOverlayEntryV1{}) }, func(v *helperOwnerOverlayV1) { v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0] }, func(v *helperOwnerOverlayV1) { v.Entries[0].PreSHA256 = strings.Repeat("2", 64) }, func(v *helperOwnerOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("3", 64) }}
	for i, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Entries = append([]helperOwnerOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		copyManifest := manifest
		copyManifest.HelperOwnerOverlays = map[string]helperOwnerOverlayV1{helperOwnerOverlayNameV1: manifest.HelperOwnerOverlays[helperOwnerOverlayNameV1], helperOwnerOverlayNameV2: copyOverlay}
		if _, err := validateEvidenceOverlaysV1(root, copyManifest); err == nil {
			t.Fatalf("helper-owner mutation %d accepted", i)
		}
		gotV1, _ := json.Marshal(copyManifest.HelperOwnerOverlays[helperOwnerOverlayNameV1])
		if string(gotV1) != string(v1Raw) {
			t.Fatalf("helper-owner v1 changed by mutation %d", i)
		}
	}
}

type modeFileInfoV1 struct {
	os.FileInfo
	mode os.FileMode
}

func (i modeFileInfoV1) Mode() os.FileMode { return i.mode }

func TestProfileInputAuthorizationCatalogMissingFlagsAndSurrogateSeams(t *testing.T) {
	profile, catalog := strictInputs(t)
	catalogDir := filepath.Join(t.TempDir(), "catalog-input")
	if err := os.Mkdir(catalogDir, 0o700); err != nil {
		t.Fatal(err)
	}
	catalogCopy := filepath.Join(catalogDir, "catalog.json")
	raw, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogCopy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog = catalogCopy
	out := filepath.Join(t.TempDir(), "out")
	for name, args := range map[string][]string{
		"profile":       {"--authorization-catalog", catalog, "--out", out},
		"authorization": {"--profile", profile, "--out", out},
		"out":           {"--profile", profile, "--authorization-catalog", catalog},
	} {
		code, stderr := captureCommandV1(t, func() int { return run(args) })
		if code != 2 || stderr != "--profile, --authorization-catalog, and --out are required\n" || strings.Contains(stderr, profile) || strings.Contains(stderr, catalog) || strings.Contains(stderr, out) {
			t.Fatalf("%s code=%d stderr=%q", name, code, stderr)
		}
	}
	for role, target := range map[string]string{"profile": profile, "catalog": catalog} {
		for _, tc := range []struct {
			name, path string
			mode       os.FileMode
		}{
			{"final-symlink", target, os.ModeSymlink},
			{"component-symlink", filepath.Dir(target), os.ModeDir | os.ModeSymlink},
			{"final-surrogate", target, os.ModeIrregular},
			{"component-surrogate", filepath.Dir(target), os.ModeDir | os.ModeIrregular},
		} {
			old := lstatLocal
			lstatLocal = func(path string) (os.FileInfo, error) {
				info, err := os.Lstat(path)
				if err == nil && filepath.Clean(path) == filepath.Clean(tc.path) {
					return modeFileInfoV1{info, tc.mode}, nil
				}
				return info, err
			}
			args := []string{"--profile", profile, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}
			code, stderr := captureCommandV1(t, func() int { return run(args) })
			lstatLocal = old
			want := errProfileInput.Error() + "\n"
			if role == "catalog" {
				want = errAuthorizationCatalog.Error() + "\n"
			}
			if code == 0 || stderr != want {
				t.Fatalf("%s/%s code=%d stderr=%q", role, tc.name, code, stderr)
			}
		}
	}
}

func TestAuthorizationCatalogCommandRejectsOverflowByte(t *testing.T) {
	profile, _ := strictInputs(t)
	catalog := filepath.Join(t.TempDir(), "oversize-catalog.json")
	out := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(catalog, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stderr := captureCommandV1(t, func() int {
		return run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", out})
	})
	if code == 0 || stderr != errAuthorizationCatalog.Error()+"\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("catalog overflow mutated output")
	}
}
