package codegen

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

var _ func(*ir.Profile, string, Options, AuthorizationCatalogV1) (Result, error) = GenerateStrict

func TestStrictGenerateAPISignatureV1(t *testing.T) {
	if AuthorizationCatalogVersionV1 == "" || AuthorizationCatalogScopeDefaultAuditV1 == "" || AuthorizationCatalogScopeExplicitV1 == "" {
		t.Fatal("strict authorization constants")
	}
}

func TestStrictGeneratedIdentifiersAndRoleSeparatedAuthorization(t *testing.T) {
	p, err := compiler.Generate(42)
	if err != nil {
		t.Fatal(err)
	}
	c := catalogFixtureV1(t, p)
	out := filepath.Join(t.TempDir(), "strict")
	if _, err := GenerateStrict(p, out, Options{GeneratedAt: fixedTime(t)}, c); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(out, "strictv1", "runtime.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, want := range []string{"package strictv1", "auth \"kurdistan/internal/crypto/auth\"", "kruntime \"kurdistan/internal/runtime\"", "ProtocolSchemaVersion", `"0.2.0-lab"`, "SecurityVersion", "RuntimeSecurityVersion", `"0.13.0-lab"`, "HandshakeVersion", `"kurdistan-handshake-v1"`, "PolicyEncodingVersion", `"policy-v1"`, "RecordVersion", `"record-v1"`, "func NewStrictRuntimeV1(client, relay auth.Dependencies", "kruntime.NewStrictHandshakeRuntimeV1(client, relay, clientRegistry, relayRegistry)"} {
		if !strings.Contains(text, want) {
			t.Fatalf("missing %q", want)
		}
	}
	legacy := filepath.Join(t.TempDir(), "legacy")
	if _, err := Generate(p, legacy, Options{}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(legacy, "strictv1", "runtime.go")); !os.IsNotExist(err) {
		t.Fatal("legacy Generate emitted strict surface")
	}
	cmd := exec.Command("go", "test", "./strictv1")
	cmd.Dir = out
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("strict package build: %v\n%s", err, output)
	}
	f, err := parser.ParseFile(token.NewFileSet(), "runtime.go", raw, parser.ParseComments)
	if err != nil {
		t.Fatal(err)
	}
	funcs, consts := 0, 0
	for _, decl := range f.Decls {
		switch x := decl.(type) {
		case *ast.FuncDecl:
			funcs++
			if x.Name.Name != "NewStrictRuntimeV1" || x.Recv != nil {
				t.Fatal("factory inventory")
			}
		case *ast.GenDecl:
			if x.Tok == token.CONST {
				for _, spec := range x.Specs {
					consts += len(spec.(*ast.ValueSpec).Names)
				}
			}
		}
	}
	if funcs != 1 || consts != 6 || len(f.Imports) != 2 {
		t.Fatalf("AST funcs=%d consts=%d imports=%d", funcs, consts, len(f.Imports))
	}
}

func TestModulePathSafety(t *testing.T) {
	for id, suffix := range map[string]string{"ABC__def": "abc-def", "---": "generated", "éA/../B": "a-b", "A  B": "a-b", "İ": "generated", "ＡＢＣ": "generated", "--A---B--": "a-b", "A💣💣B": "a-b", "a_b": "a-b", "a-b": "a-b"} {
		if got := strictModulePathV1(id); got != "kurdistan/generated/"+suffix {
			t.Fatalf("%q => %q", id, got)
		}
	}
	p, _ := compiler.Generate(42)
	c := catalogFixtureV1(t, p)
	exact := strictModulePathV1(p.ID)
	if _, err := GenerateStrict(p, filepath.Join(t.TempDir(), "ok"), Options{ModulePath: exact}, c); err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"example.com/external", exact + "/x", "kurdistan/generated/../x", strings.ToUpper(exact)} {
		out := filepath.Join(t.TempDir(), "bad")
		if _, err := GenerateStrict(p, out, Options{ModulePath: bad}, c); err != ErrStrictModulePath {
			t.Fatalf("%q err=%v", bad, err)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatal("module rejection mutated output")
		}
	}
}

func TestStrictGeneratedIdentifiersSixPathSHAEvidence(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	verifyCommittedEvidenceSetV1(t, root, "WO-043", []committedEvidenceExpectationV1{
		{"internal/codegen/generator.go", "06873bd0001f41d358cc21a9e2920ef1fc2c67b3e561141171ebed46f8da6142"},
		{"internal/codegen/generator_templates.go", "a0dfd4c908849a554e94a34db244f403253d30bdea23dca528efc6b13caf4c91"},
		{"internal/codegen/generator_test.go", "0dcbb2a95f14de69a198013bc7c64597716cf00f4f3b284f950e233571e0acbe"},
		{"internal/codegen/scanner.go", "fffcddbc632e5c2ceb418555ad8e571638e23843d04749e52c0a792a4687e960"},
		{"internal/codegen/scanner_test.go", "40ff6664134ed86769c5adf0c25b26b1690f50b55f7c8adfffee933f3a805306"},
		{"internal/runtime/policy_enforcement_test.go", "ABSENT"},
	})
}

func TestGenerateCreatesBuildableProfileSpecificModule(t *testing.T) {
	p := mustProfile(t, 12345)
	out := filepath.Join(t.TempDir(), "generated-profile")

	result, err := Generate(p, out, Options{GeneratedAt: fixedTime(t)})
	if err != nil {
		t.Fatalf("Generate() error = %v", err)
	}
	if result.Manifest.ProfileID != p.ID {
		t.Fatalf("manifest profile id = %q, want %q", result.Manifest.ProfileID, p.ID)
	}

	required := []string{
		"go.mod",
		"README.md",
		"manifest.json",
		"protocol/profile_static.go",
		"protocol/states_generated.go",
		"protocol/framing_generated.go",
		"protocol/stream_generated.go",
		"protocol/carrier_generated.go",
		"protocol/security_generated.go",
		"protocol/runtime_generated.go",
		"protocol/hardening_generated.go",
		"protocol/adapter_generated.go",
		"protocol/localadapter_generated.go",
		"protocol/bytetransport_generated.go",
		"protocol/protocorpus_generated.go",
		"protocol/wirefeatures_generated.go",
		"protocol/relayfleet_generated.go",
		"protocol/adaptivepath_generated.go",
		"protocol/transportbundle_generated.go",
		"protocol/pathrace_generated.go",
		"protocol/pathhealth_generated.go",
		"protocol/carrierreview_generated.go",
		"protocol/measurementreview_generated.go",
		"protocol/proxyegress_generated.go",
		"protocol/relaybridge_generated.go",
		"protocol/localpipeline_generated.go",
		"protocol/productionreadiness_generated.go",
		"protocol/concretelocaladapter_generated.go",
		"protocol/localprotocoladapter_generated.go",
		"protocol/loopbackrelay_generated.go",
		"protocol/labegress_generated.go",
		"protocol/carrierreadiness_generated.go",
		"protocol/httpscarrierreview_generated.go",
		"protocol/httpslikecarrier_generated.go",
		"protocol/scheduler_generated.go",
		"protocol/invalid_input_generated.go",
		"protocol/auth_generated.go",
		"protocol/protocol.go",
		"protocol/protocol_test.go",
		"protocol/multistream_test.go",
		"protocol/carrier_test.go",
		"protocol/carrieradversary_test.go",
		"protocol/security_test.go",
		"protocol/securityadversary_test.go",
		"protocol/runtime_test.go",
		"protocol/runtimeadversary_test.go",
		"protocol/hardening_test.go",
		"protocol/adapter_test.go",
		"protocol/adapteradversary_test.go",
		"protocol/localadapter_test.go",
		"protocol/localadapteradversary_test.go",
		"protocol/bytetransport_test.go",
		"protocol/bytetransportadversary_test.go",
		"protocol/bytepath_fixture_test.go",
		"protocol/bytepath_parity_test.go",
		"protocol/protocorpus_test.go",
		"protocol/wirefeatures_test.go",
		"protocol/relayfleet_test.go",
		"protocol/relayfleet_parity_test.go",
		"protocol/relayfleet_hygiene_test.go",
		"protocol/adaptivepath_test.go",
		"protocol/adaptivepath_parity_test.go",
		"protocol/adaptivepath_hygiene_test.go",
		"protocol/transportbundle_test.go",
		"protocol/transportbundle_parity_test.go",
		"protocol/transportbundle_hygiene_test.go",
		"protocol/pathrace_test.go",
		"protocol/pathrace_parity_test.go",
		"protocol/pathrace_hygiene_test.go",
		"protocol/pathhealth_test.go",
		"protocol/pathhealth_parity_test.go",
		"protocol/pathhealth_hygiene_test.go",
		"protocol/carrierreview_test.go",
		"protocol/carrierreview_parity_test.go",
		"protocol/carrierreview_hygiene_test.go",
		"protocol/measurementreview_test.go",
		"protocol/measurementreview_parity_test.go",
		"protocol/measurementreview_hygiene_test.go",
		"protocol/proxyegress_test.go",
		"protocol/proxyegress_parity_test.go",
		"protocol/proxyegress_hygiene_test.go",
		"protocol/relaybridge_test.go",
		"protocol/relaybridge_parity_test.go",
		"protocol/relaybridge_hygiene_test.go",
		"protocol/localpipeline_test.go",
		"protocol/localpipeline_parity_test.go",
		"protocol/localpipeline_hygiene_test.go",
		"protocol/productionreadiness_test.go",
		"protocol/productionreadiness_parity_test.go",
		"protocol/productionreadiness_hygiene_test.go",
		"protocol/concretelocaladapter_test.go",
		"protocol/concretelocaladapter_parity_test.go",
		"protocol/concretelocaladapter_hygiene_test.go",
		"protocol/localprotocoladapter_test.go",
		"protocol/localprotocoladapter_parity_test.go",
		"protocol/localprotocoladapter_hygiene_test.go",
		"protocol/loopbackrelay_test.go",
		"protocol/loopbackrelay_parity_test.go",
		"protocol/loopbackrelay_hygiene_test.go",
		"protocol/labegress_test.go",
		"protocol/labegress_parity_test.go",
		"protocol/labegress_hygiene_test.go",
		"protocol/carrierreadiness_test.go",
		"protocol/carrierreadiness_parity_test.go",
		"protocol/carrierreadiness_hygiene_test.go",
		"protocol/httpscarrierreview_test.go",
		"protocol/httpscarrierreview_parity_test.go",
		"protocol/httpscarrierreview_hygiene_test.go",
		"protocol/httpslikecarrier_test.go",
		"protocol/httpslikecarrier_parity_test.go",
		"protocol/httpslikecarrier_hygiene_test.go",
		"protocol/httpscarrieradversary_generated.go",
		"protocol/httpscarrieradversary_test.go",
		"protocol/httpscarrieradversary_parity_test.go",
		"protocol/httpscarrieradversary_hygiene_test.go",
		"protocol/constrainedcarrierreview_generated.go",
		"protocol/constrainedcarrierreview_test.go",
		"protocol/constrainedcarrierreview_parity_test.go",
		"protocol/constrainedcarrierreview_hygiene_test.go",
		"protocol/constrainedcarrier_generated.go",
		"protocol/constrainedcarrier_test.go",
		"protocol/constrainedcarrier_parity_test.go",
		"protocol/constrainedcarrier_hygiene_test.go",
		"protocol/multicarrierselect_generated.go",
		"protocol/multicarrierselect_test.go",
		"protocol/multicarrierselect_parity_test.go",
		"protocol/multicarrierselect_hygiene_test.go",
		"protocol/carriercollapse_generated.go",
		"protocol/carriercollapse_test.go",
		"protocol/carriercollapse_parity_test.go",
		"protocol/carriercollapse_hygiene_test.go",
		"protocol/localproxyadapterreview_generated.go",
		"protocol/localproxyadapterreview_test.go",
		"protocol/localproxyadapterreview_parity_test.go",
		"protocol/localproxyadapterreview_hygiene_test.go",
		"protocol/localproxyadapter_generated.go",
		"protocol/localproxyadapter_test.go",
		"protocol/localproxyadapter_parity_test.go",
		"protocol/localproxyadapter_hygiene_test.go",
		"protocol/vpnsemantics_generated.go",
		"protocol/vpnsemantics_test.go",
		"protocol/vpnsemantics_parity_test.go",
		"protocol/vpnsemantics_hygiene_test.go",
		"protocol/localvpnadapter_generated.go",
		"protocol/localvpnadapter_test.go",
		"protocol/localvpnadapter_parity_test.go",
		"protocol/localvpnadapter_hygiene_test.go",
		"protocol/relayprocess_generated.go",
		"protocol/relayprocess_test.go",
		"protocol/relayprocess_parity_test.go",
		"protocol/relayprocess_hygiene_test.go",
		"protocol/keyexchangeplan_generated.go",
		"protocol/keyexchangeplan_test.go",
		"protocol/keyexchangeplan_parity_test.go",
		"protocol/keyexchangeplan_hygiene_test.go",
		"protocol/relayauthplan_generated.go",
		"protocol/relayauthplan_test.go",
		"protocol/relayauthplan_parity_test.go",
		"protocol/relayauthplan_hygiene_test.go",
		"protocol/operationalhardening_generated.go",
		"protocol/operationalhardening_test.go",
		"protocol/operationalhardening_parity_test.go",
		"protocol/operationalhardening_hygiene_test.go",
		"protocol/androidreview_generated.go",
		"protocol/androidreview_test.go",
		"protocol/androidreview_parity_test.go",
		"protocol/androidreview_hygiene_test.go",
		"protocol/androidruntime_generated.go",
		"protocol/androidruntime_test.go",
		"protocol/androidruntime_parity_test.go",
		"protocol/androidruntime_hygiene_test.go",
		"protocol/androidvpnservice_generated.go",
		"protocol/androidvpnservice_test.go",
		"protocol/androidvpnservice_parity_test.go",
		"protocol/androidvpnservice_hygiene_test.go",
		"protocol/protocol_bench_test.go",
		"protocol/trace_capture_generated.go",
		"protocol/probe_test.go",
		"cmd/generated-client/main.go",
		"cmd/generated-server/main.go",
		"cmd/generated-echo/main.go",
		"cmd/generated-trace/main.go",
	}
	for _, rel := range required {
		if _, err := os.Stat(filepath.Join(out, filepath.FromSlash(rel))); err != nil {
			t.Fatalf("missing generated file %s: %v", rel, err)
		}
	}
	goModRaw, err := os.ReadFile(filepath.Join(out, "go.mod"))
	if err != nil {
		t.Fatal(err)
	}
	var goDirectives []string
	for _, line := range strings.Split(strings.ReplaceAll(string(goModRaw), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "go ") {
			goDirectives = append(goDirectives, line)
		}
	}
	if len(goDirectives) != 1 || goDirectives[0] != "go 1.24" {
		t.Fatalf("generated go.mod directives = %q, want exactly [go 1.24]", goDirectives)
	}

	manifestRaw, err := os.ReadFile(filepath.Join(out, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(manifestRaw), p.Auth.TestKeyHex) {
		t.Fatalf("manifest contains raw test key material")
	}
	var manifest Manifest
	if err := json.Unmarshal(manifestRaw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.SourceBackend != "go-static-v0" || manifest.GeneratorVersion != Version {
		t.Fatalf("unexpected manifest backend/version: %#v", manifest)
	}
	if manifest.Safety.ExternalNetworking || manifest.Safety.Deployment || manifest.Safety.PayloadLogging {
		t.Fatalf("manifest safety flags are not lab-only: %#v", manifest.Safety)
	}

	protocolSource := readGeneratedSource(t, out, "protocol")
	if strings.Contains(protocolSource, p.Auth.TestKeyHex) {
		t.Fatalf("generated protocol source contains raw test key material")
	}
	for _, forbidden := range []string{"LoadProfile", "cmd/kclient", "cmd/kserver", "kclient", "kserver", "profile.json"} {
		if strings.Contains(protocolSource, forbidden) {
			t.Fatalf("generated protocol source contains forbidden wrapper marker %q", forbidden)
		}
	}
	if strings.Contains(protocolSource, "hello generated") {
		t.Fatalf("generated protocol source contains runtime payload literal")
	}
	if !strings.Contains(protocolSource, "const ProfileID") ||
		!strings.Contains(protocolSource, "var transitionTable") ||
		!strings.Contains(protocolSource, "var semanticWireSymbols") ||
		!strings.Contains(protocolSource, "const StreamIDEncodingMode") ||
		!strings.Contains(protocolSource, "const CarrierFamily") ||
		!strings.Contains(protocolSource, "const SecurityTranscriptMode") ||
		!strings.Contains(protocolSource, "const RuntimeProfileID") ||
		!strings.Contains(protocolSource, "const HardeningProfileID") ||
		!strings.Contains(protocolSource, "const AdapterGeneratedProfileID") ||
		!strings.Contains(protocolSource, "const LocalAdapterGeneratedProfileID") ||
		!strings.Contains(protocolSource, "const ByteTransportGeneratedProfileID") ||
		!strings.Contains(protocolSource, "const BytePathFixtureSchemaVersion") ||
		!strings.Contains(protocolSource, "const ProtocolCorpusSchemaVersion") ||
		!strings.Contains(protocolSource, "const WireFeatureSchemaVersion") ||
		!strings.Contains(protocolSource, "const RelayFleetSchemaVersion") ||
		!strings.Contains(protocolSource, "const AdaptivePathSchemaVersion") ||
		!strings.Contains(protocolSource, "const TransportBundleSchemaVersion") ||
		!strings.Contains(protocolSource, "const PathRaceSchemaVersion") ||
		!strings.Contains(protocolSource, "const PathHealthSchemaVersion") ||
		!strings.Contains(protocolSource, "const CarrierReviewSchemaVersion") ||
		!strings.Contains(protocolSource, "const MeasurementReviewSchemaVersion") ||
		!strings.Contains(protocolSource, "const HTTPSCarrierAdversarySchemaVersion") ||
		!strings.Contains(protocolSource, "const ConstrainedCarrierReviewSchemaVersion") ||
		!strings.Contains(protocolSource, "const ConstrainedCarrierSchemaVersion") ||
		!strings.Contains(protocolSource, "const MultiCarrierSelectSchemaVersion") ||
		!strings.Contains(protocolSource, "const RelayProcessSchemaVersion") ||
		!strings.Contains(protocolSource, "const KeyExchangePlanSchemaVersion") ||
		!strings.Contains(protocolSource, "const RelayAuthPlanSchemaVersion") ||
		!strings.Contains(protocolSource, "const OperationalHardeningSchemaVersion") ||
		!strings.Contains(protocolSource, "func MultiStreamDemo") {
		t.Fatalf("generated source is missing profile-specific constants or tables")
	}

	cmd := exec.Command(goTool(t), "test", "./...")
	cmd.Dir = out
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("generated go test failed: %v\n%s", err, output)
	}
}

func TestGenerateRejectsInvalidProfileAndOverwrite(t *testing.T) {
	p := mustProfile(t, 42)
	out := filepath.Join(t.TempDir(), "out")
	if _, err := Generate(p, out, Options{GeneratedAt: fixedTime(t)}); err != nil {
		t.Fatalf("initial Generate() error = %v", err)
	}
	if _, err := Generate(p, out, Options{GeneratedAt: fixedTime(t)}); err == nil {
		t.Fatalf("Generate() overwrote output without force")
	}
	if _, err := Generate(p, out, Options{Force: true, GeneratedAt: fixedTime(t)}); err != nil {
		t.Fatalf("Generate(force) error = %v", err)
	}

	invalid := *p
	invalid.Version = "bad"
	if _, err := Generate(&invalid, filepath.Join(t.TempDir(), "invalid"), Options{GeneratedAt: fixedTime(t)}); err == nil {
		t.Fatalf("Generate() accepted invalid profile")
	}
}

func TestGeneratedConstantsDifferAcrossProfiles(t *testing.T) {
	a := mustProfile(t, 12345)
	b := mustProfile(t, 12346)
	root := t.TempDir()
	outA := filepath.Join(root, "a")
	outB := filepath.Join(root, "b")
	if _, err := Generate(a, outA, Options{GeneratedAt: fixedTime(t)}); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(b, outB, Options{GeneratedAt: fixedTime(t)}); err != nil {
		t.Fatal(err)
	}

	stateA := mustRead(t, filepath.Join(outA, "protocol", "states_generated.go"))
	stateB := mustRead(t, filepath.Join(outB, "protocol", "states_generated.go"))
	frameA := mustRead(t, filepath.Join(outA, "protocol", "framing_generated.go"))
	frameB := mustRead(t, filepath.Join(outB, "protocol", "framing_generated.go"))
	streamA := mustRead(t, filepath.Join(outA, "protocol", "stream_generated.go"))
	streamB := mustRead(t, filepath.Join(outB, "protocol", "stream_generated.go"))
	carrierA := mustRead(t, filepath.Join(outA, "protocol", "carrier_generated.go"))
	carrierB := mustRead(t, filepath.Join(outB, "protocol", "carrier_generated.go"))
	securityA := mustRead(t, filepath.Join(outA, "protocol", "security_generated.go"))
	securityB := mustRead(t, filepath.Join(outB, "protocol", "security_generated.go"))
	runtimeA := mustRead(t, filepath.Join(outA, "protocol", "runtime_generated.go"))
	runtimeB := mustRead(t, filepath.Join(outB, "protocol", "runtime_generated.go"))
	hardeningA := mustRead(t, filepath.Join(outA, "protocol", "hardening_generated.go"))
	hardeningB := mustRead(t, filepath.Join(outB, "protocol", "hardening_generated.go"))
	adapterA := mustRead(t, filepath.Join(outA, "protocol", "adapter_generated.go"))
	adapterB := mustRead(t, filepath.Join(outB, "protocol", "adapter_generated.go"))
	localAdapterA := mustRead(t, filepath.Join(outA, "protocol", "localadapter_generated.go"))
	localAdapterB := mustRead(t, filepath.Join(outB, "protocol", "localadapter_generated.go"))
	localProtocolAdapterA := mustRead(t, filepath.Join(outA, "protocol", "localprotocoladapter_generated.go"))
	localProtocolAdapterB := mustRead(t, filepath.Join(outB, "protocol", "localprotocoladapter_generated.go"))
	loopbackRelayA := mustRead(t, filepath.Join(outA, "protocol", "loopbackrelay_generated.go"))
	loopbackRelayB := mustRead(t, filepath.Join(outB, "protocol", "loopbackrelay_generated.go"))
	labEgressA := mustRead(t, filepath.Join(outA, "protocol", "labegress_generated.go"))
	labEgressB := mustRead(t, filepath.Join(outB, "protocol", "labegress_generated.go"))
	carrierReadinessA := mustRead(t, filepath.Join(outA, "protocol", "carrierreadiness_generated.go"))
	carrierReadinessB := mustRead(t, filepath.Join(outB, "protocol", "carrierreadiness_generated.go"))
	httpsCarrierReviewA := mustRead(t, filepath.Join(outA, "protocol", "httpscarrierreview_generated.go"))
	httpsCarrierReviewB := mustRead(t, filepath.Join(outB, "protocol", "httpscarrierreview_generated.go"))
	httpsLikeCarrierA := mustRead(t, filepath.Join(outA, "protocol", "httpslikecarrier_generated.go"))
	httpsLikeCarrierB := mustRead(t, filepath.Join(outB, "protocol", "httpslikecarrier_generated.go"))
	httpsCarrierAdversaryA := mustRead(t, filepath.Join(outA, "protocol", "httpscarrieradversary_generated.go"))
	httpsCarrierAdversaryB := mustRead(t, filepath.Join(outB, "protocol", "httpscarrieradversary_generated.go"))
	constrainedCarrierReviewA := mustRead(t, filepath.Join(outA, "protocol", "constrainedcarrierreview_generated.go"))
	constrainedCarrierReviewB := mustRead(t, filepath.Join(outB, "protocol", "constrainedcarrierreview_generated.go"))
	constrainedCarrierA := mustRead(t, filepath.Join(outA, "protocol", "constrainedcarrier_generated.go"))
	constrainedCarrierB := mustRead(t, filepath.Join(outB, "protocol", "constrainedcarrier_generated.go"))
	multiCarrierSelectA := mustRead(t, filepath.Join(outA, "protocol", "multicarrierselect_generated.go"))
	multiCarrierSelectB := mustRead(t, filepath.Join(outB, "protocol", "multicarrierselect_generated.go"))
	carrierCollapseA := mustRead(t, filepath.Join(outA, "protocol", "carriercollapse_generated.go"))
	carrierCollapseB := mustRead(t, filepath.Join(outB, "protocol", "carriercollapse_generated.go"))
	localProxyAdapterReviewA := mustRead(t, filepath.Join(outA, "protocol", "localproxyadapterreview_generated.go"))
	localProxyAdapterReviewB := mustRead(t, filepath.Join(outB, "protocol", "localproxyadapterreview_generated.go"))
	localProxyAdapterA := mustRead(t, filepath.Join(outA, "protocol", "localproxyadapter_generated.go"))
	localProxyAdapterB := mustRead(t, filepath.Join(outB, "protocol", "localproxyadapter_generated.go"))
	vpnSemanticsA := mustRead(t, filepath.Join(outA, "protocol", "vpnsemantics_generated.go"))
	vpnSemanticsB := mustRead(t, filepath.Join(outB, "protocol", "vpnsemantics_generated.go"))
	localVPNAdapterA := mustRead(t, filepath.Join(outA, "protocol", "localvpnadapter_generated.go"))
	localVPNAdapterB := mustRead(t, filepath.Join(outB, "protocol", "localvpnadapter_generated.go"))
	relayProcessA := mustRead(t, filepath.Join(outA, "protocol", "relayprocess_generated.go"))
	relayProcessB := mustRead(t, filepath.Join(outB, "protocol", "relayprocess_generated.go"))
	keyExchangePlanA := mustRead(t, filepath.Join(outA, "protocol", "keyexchangeplan_generated.go"))
	keyExchangePlanB := mustRead(t, filepath.Join(outB, "protocol", "keyexchangeplan_generated.go"))
	relayAuthPlanA := mustRead(t, filepath.Join(outA, "protocol", "relayauthplan_generated.go"))
	relayAuthPlanB := mustRead(t, filepath.Join(outB, "protocol", "relayauthplan_generated.go"))
	operationalHardeningA := mustRead(t, filepath.Join(outA, "protocol", "operationalhardening_generated.go"))
	operationalHardeningB := mustRead(t, filepath.Join(outB, "protocol", "operationalhardening_generated.go"))
	androidReviewA := mustRead(t, filepath.Join(outA, "protocol", "androidreview_generated.go"))
	androidReviewB := mustRead(t, filepath.Join(outB, "protocol", "androidreview_generated.go"))
	androidRuntimeA := mustRead(t, filepath.Join(outA, "protocol", "androidruntime_generated.go"))
	androidRuntimeB := mustRead(t, filepath.Join(outB, "protocol", "androidruntime_generated.go"))
	androidVPNServiceA := mustRead(t, filepath.Join(outA, "protocol", "androidvpnservice_generated.go"))
	androidVPNServiceB := mustRead(t, filepath.Join(outB, "protocol", "androidvpnservice_generated.go"))
	byteTransportA := mustRead(t, filepath.Join(outA, "protocol", "bytetransport_generated.go"))
	byteTransportB := mustRead(t, filepath.Join(outB, "protocol", "bytetransport_generated.go"))
	relayFleetA := mustRead(t, filepath.Join(outA, "protocol", "relayfleet_generated.go"))
	relayFleetB := mustRead(t, filepath.Join(outB, "protocol", "relayfleet_generated.go"))
	pathRaceA := mustRead(t, filepath.Join(outA, "protocol", "pathrace_generated.go"))
	pathRaceB := mustRead(t, filepath.Join(outB, "protocol", "pathrace_generated.go"))
	if stateA == stateB {
		t.Fatalf("state generation did not differ across profiles")
	}
	if frameA == frameB {
		t.Fatalf("framing generation did not differ across profiles")
	}
	if streamA == streamB {
		t.Fatalf("stream generation did not differ across profiles")
	}
	if carrierA == carrierB {
		t.Fatalf("carrier generation did not differ across profiles")
	}
	if securityA == securityB {
		t.Fatalf("security generation did not differ across profiles")
	}
	if runtimeA == runtimeB {
		t.Fatalf("runtime generation did not differ across profiles")
	}
	if hardeningA == hardeningB {
		t.Fatalf("hardening generation did not differ across profiles")
	}
	if adapterA == adapterB {
		t.Fatalf("adapter generation did not differ across profiles")
	}
	if localAdapterA == localAdapterB {
		t.Fatalf("local adapter generation did not differ across profiles")
	}
	if localProtocolAdapterA == localProtocolAdapterB {
		t.Fatalf("local protocol adapter generation did not differ across profiles")
	}
	if loopbackRelayA == loopbackRelayB {
		t.Fatalf("loopback relay generation did not differ across profiles")
	}
	if labEgressA == labEgressB {
		t.Fatalf("lab egress generation did not differ across profiles")
	}
	if carrierReadinessA == carrierReadinessB {
		t.Fatalf("carrier readiness generation did not differ across profiles")
	}
	if httpsCarrierReviewA == httpsCarrierReviewB {
		t.Fatalf("HTTPS carrier review generation did not differ across profiles")
	}
	if httpsLikeCarrierA == httpsLikeCarrierB {
		t.Fatalf("HTTPS-like carrier generation did not differ across profiles")
	}
	if httpsCarrierAdversaryA == httpsCarrierAdversaryB {
		t.Fatalf("HTTPS carrier adversary generation did not differ across profiles")
	}
	if constrainedCarrierReviewA == constrainedCarrierReviewB {
		t.Fatalf("constrained carrier review generation did not differ across profiles")
	}
	if constrainedCarrierA == constrainedCarrierB {
		t.Fatalf("constrained carrier generation did not differ across profiles")
	}
	if multiCarrierSelectA == multiCarrierSelectB {
		t.Fatalf("multi-carrier selection generation did not differ across profiles")
	}
	if carrierCollapseA == carrierCollapseB {
		t.Fatalf("carrier collapse generation did not differ across profiles")
	}
	if localProxyAdapterReviewA == localProxyAdapterReviewB {
		t.Fatalf("local proxy adapter review generation did not differ across profiles")
	}
	if localProxyAdapterA == localProxyAdapterB {
		t.Fatalf("local proxy adapter generation did not differ across profiles")
	}
	if vpnSemanticsA == vpnSemanticsB {
		t.Fatalf("VPN semantics generation did not differ across profiles")
	}
	if localVPNAdapterA == localVPNAdapterB {
		t.Fatalf("local packet adapter generation did not differ across profiles")
	}
	if relayProcessA == relayProcessB {
		t.Fatalf("relay process generation did not differ across profiles")
	}
	if keyExchangePlanA == keyExchangePlanB {
		t.Fatalf("key exchange plan generation did not differ across profiles")
	}
	if relayAuthPlanA == relayAuthPlanB {
		t.Fatalf("relay auth plan generation did not differ across profiles")
	}
	if operationalHardeningA == operationalHardeningB {
		t.Fatalf("operational hardening generation did not differ across profiles")
	}
	if androidReviewA == androidReviewB {
		t.Fatalf("Android review generation did not differ across profiles")
	}
	if androidRuntimeA == androidRuntimeB {
		t.Fatalf("Android runtime generation did not differ across profiles")
	}
	if androidVPNServiceA == androidVPNServiceB {
		t.Fatalf("Android VpnService generation did not differ across profiles")
	}
	if byteTransportA == byteTransportB {
		t.Fatalf("byte transport generation did not differ across profiles")
	}
	if relayFleetA == relayFleetB {
		t.Fatalf("relayfleet generation did not differ across profiles")
	}
	if pathRaceA == pathRaceB {
		t.Fatalf("pathrace generation did not differ across profiles")
	}
}

func TestSanitizeIdentifier(t *testing.T) {
	tests := map[string]string{
		"kp_abc-123": "KpAbc123",
		"123 bad id": "X123BadId",
		"":           "Generated",
	}
	for in, want := range tests {
		if got := SanitizeIdentifier(in); got != want {
			t.Fatalf("SanitizeIdentifier(%q) = %q, want %q", in, got, want)
		}
	}
}

func BenchmarkGenerateOneProfile(b *testing.B) {
	p, err := compiler.Generate(7001)
	if err != nil {
		b.Fatal(err)
	}
	for i := 0; i < b.N; i++ {
		out := filepath.Join(b.TempDir(), "profile")
		if _, err := Generate(p, out, Options{GeneratedAt: fixedBenchmarkTime()}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateHundredProfiles(b *testing.B) {
	for i := 0; i < b.N; i++ {
		root := b.TempDir()
		for seed := int64(1); seed <= 100; seed++ {
			p, err := compiler.Generate(seed)
			if err != nil {
				b.Fatal(err)
			}
			if _, err := Generate(p, filepath.Join(root, SanitizeIdentifier(p.ID)), Options{GeneratedAt: fixedBenchmarkTime()}); err != nil {
				b.Fatal(err)
			}
		}
	}
}

func mustProfile(t *testing.T, seed int64) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func fixedTime(t *testing.T) time.Time {
	t.Helper()
	return fixedBenchmarkTime()
}

func fixedBenchmarkTime() time.Time {
	return time.Date(2026, 6, 27, 12, 0, 0, 0, time.UTC)
}

func goTool(t *testing.T) string {
	t.Helper()
	if p := os.Getenv("GO"); p != "" {
		return p
	}
	if goroot := runtime.GOROOT(); goroot != "" {
		name := "go"
		if runtime.GOOS == "windows" {
			name = "go.exe"
		}
		candidate := filepath.Join(goroot, "bin", name)
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	return "go"
}

func readGeneratedSource(t *testing.T, root, subdir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(filepath.Join(root, subdir), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		b.WriteString(mustRead(t, path))
		b.WriteByte('\n')
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}

func mustRead(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}
