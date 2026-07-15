package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/protocol/compiler"
)

func TestGeneratedScannerStrictSurface(t *testing.T) {
	p, _ := compiler.Generate(42)
	c := catalogFixtureV1(t, p)
	out := filepath.Join(t.TempDir(), "strict")
	if _, err := GenerateStrict(p, out, Options{}, c); err != nil {
		t.Fatal(err)
	}
	report, err := ScanGeneratedOutputs([]string{out})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("%v", report.Failures)
	}
	runtimePath := filepath.Join(out, "strictv1", "runtime.go")
	raw, _ := os.ReadFile(runtimePath)
	if err := os.WriteFile(runtimePath, []byte(strings.Replace(string(raw), "return kruntime.NewStrictHandshakeRuntimeV1", "var x = 1\n\treturn kruntime.NewStrictHandshakeRuntimeV1", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	report, err = ScanGeneratedOutputs([]string{out})
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatal("strict mutant passed scanner")
	}
}

func TestTemplateScannerStrictInventory(t *testing.T) {
	formatted := strictRuntimeTemplateV1()
	if failures := validateStrictGeneratedSurfaceV1(map[string]string{"strictv1/runtime.go": formatted}); len(failures) != 0 {
		t.Fatal(failures)
	}
	for _, forbidden := range []string{"StaticProfile", "CanonicalHash", "AuthorizationFromProfile", "testkit", "observe", "init()", "var ", "type "} {
		if strings.Contains(formatted, forbidden) {
			t.Fatalf("template contains %q", forbidden)
		}
	}
	if failures := validateStrictGeneratedSurfaceV1(map[string]string{"protocol/escape.go": "package protocol\nconst ProtocolSchemaVersion = 1"}); len(failures) == 0 {
		t.Fatal("strict declaration outside surface accepted")
	}
}

func TestGeneratedScannerCompleteStrictMutantMatrix(t *testing.T) {
	base := strictRuntimeTemplateV1()
	mutants := map[string]string{
		"package":          strings.Replace(base, "package strictv1", "package protocol", 1),
		"import":           strings.Replace(base, `auth "kurdistan/internal/crypto/auth"`, `auth "kurdistan/internal/crypto/security"`, 1),
		"constant-name":    strings.Replace(base, "ProtocolSchemaVersion", "ProtocolVersion", 1),
		"constant-value":   strings.Replace(base, `"0.2.0-lab"`, `"0.1.0-lab"`, 1),
		"signature":        strings.Replace(base, "client, relay auth.Dependencies", "client auth.Dependencies", 1),
		"role-swap":        strings.Replace(base, "clientRegistry, relayRegistry)", "relayRegistry, clientRegistry)", 1),
		"generic-registry": base + "\ntype Registry interface{}\n",
		"cross-role":       strings.Replace(base, "relayRegistry kruntime.RelayProfile", "relayRegistry kruntime.ClientProfile", 1),
		"init":             base + "\nfunc init() {}\n",
		"global":           base + "\nvar global = 1\n",
		"type":             base + "\ntype Extra struct{}\n",
		"method":           base + "\nfunc (Extra) M() {}\n",
		"catalog":          base + "\nconst AuthorizationCatalogV1 = 1\n",
		"pins":             base + "\nconst AuthorizationPinV1 = 1\n",
		"registries":       base + "\nvar registry = kruntime.NewClientProfileAuthorization" + "RegistryV1\n",
		"static-profile":   base + "\nconst StaticProfile = 1\n",
		"canonical-hash":   base + "\nconst CanonicalHash = 1\n",
		"profile-derived":  base + "\nconst AuthorizationFromProfile = 1\n",
		"default":          base + "\nconst DefaultRegistry = 1\n",
		"secret":           base + "\nconst Secret = 1\n",
		"identity":         base + "\nconst Identity = 1\n",
		"entropy":          base + "\nconst Entropy = 1\n",
		"trust":            base + "\nconst Trust = 1\n",
		"lab-import":       strings.Replace(base, ")\n\nconst (", `\t"kurdistan/internal/`+"lab\""+")\n\nconst (", 1),
		"testkit-import":   strings.Replace(base, ")\n\nconst (", `\t"kurdistan/internal/`+"testkit\""+")\n\nconst (", 1),
		"observe-import":   strings.Replace(base, ")\n\nconst (", `\t"kurdistan/internal/`+"observe\""+")\n\nconst (", 1),
	}
	for name, source := range mutants {
		if failures := validateStrictGeneratedSurfaceV1(map[string]string{"strictv1/runtime.go": source}, true); len(failures) == 0 {
			t.Fatalf("mutant %s accepted", name)
		}
	}
	if failures := validateStrictGeneratedSurfaceV1(map[string]string{}, true); len(failures) == 0 {
		t.Fatal("missing strict runtime accepted")
	}
	if failures := validateStrictGeneratedSurfaceV1(map[string]string{"strictv1/runtime.go": base, "strictv1/extra.go": "package strictv1"}, true); len(failures) == 0 {
		t.Fatal("extra strict Go file accepted")
	}
}

func TestTemplateScannerRepositorySourceAndLegacyInventory(t *testing.T) {
	raw, err := os.ReadFile("generator_templates.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "func strictRuntimeTemplateV1() string") {
		t.Fatal("raw template owner missing")
	}
	if failures := validateStrictTemplateRepositorySourceV1(string(raw)); len(failures) != 0 {
		t.Fatal(failures)
	}
	duplicateOwner := string(raw) + "\nfunc strictRuntimeTemplateV1() string { return `package strictv1` }\n"
	if failures := validateStrictTemplateRepositorySourceV1(duplicateOwner); len(failures) == 0 {
		t.Fatal("duplicate strict template owner accepted")
	}
	hiddenTemplate := string(raw) + "\nfunc hiddenTemplateV1() string { return `package strictv1` }\n"
	if failures := validateStrictTemplateRepositorySourceV1(hiddenTemplate); len(failures) == 0 {
		t.Fatal("hidden strict template accepted")
	}
	base := strictRuntimeTemplateV1()
	if strings.Contains(base, "protocol/") && !strings.Contains(base, "legacy parity-only") {
		t.Fatal("legacy classification absent")
	}
	for _, forbidden := range []string{"StaticProfile", "AuthorizationPinV1", "AuthorizationCatalogV1", "NewClientProfileAuthorization" + "RegistryV1", "testkit", "internal/" + "lab", "internal/" + "observe"} {
		if strings.Contains(base, forbidden) {
			t.Fatalf("strict reachability contains %q", forbidden)
		}
	}
}

func TestGeneratedScannerOutsideFileEveryStrictSymbolPath(t *testing.T) {
	for symbol := range strictGeneratedSymbolsV1 {
		for _, path := range []string{"protocol/escape.go", "cmd/escape/main.go", "other/hidden.go"} {
			source := "package escape\n"
			if strings.HasPrefix(symbol, "New") {
				source += "func " + symbol + "() {}\n"
			} else {
				source += "const " + symbol + " = 1\n"
			}
			if !strictDeclarationsOutsideV1(path, source) {
				t.Fatalf("%s escaped at %s", symbol, path)
			}
			hidden := "package escape\nconst hidden = `package strictv1\\nconst " + symbol + " = 1`\n"
			if !strictDeclarationsOutsideV1(path, hidden) {
				t.Fatalf("hidden %s escaped at %s", symbol, path)
			}
		}
	}
	if strictDeclarationsOutsideV1("protocol/security_generated.go", "package protocol\nconst SecurityVersion = \"legacy\"") {
		t.Fatal("known legacy security identifier misclassified")
	}
	if strictDeclarationsOutsideV1("protocol/runtime_generated.go", "package protocol\nconst RuntimeSecurityVersion = \"legacy\"") {
		t.Fatal("known legacy runtime identifier misclassified")
	}
}

func TestScanGeneratedOutputsProfileSpecificAndNoInterpreterArtifacts(t *testing.T) {
	a, err := compiler.Generate(12345)
	if err != nil {
		t.Fatal(err)
	}
	b, err := compiler.Generate(12346)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	outA := filepath.Join(root, "a")
	outB := filepath.Join(root, "b")
	if _, err := Generate(a, outA, Options{GeneratedAt: fixedBenchmarkTime()}); err != nil {
		t.Fatal(err)
	}
	if _, err := Generate(b, outB, Options{GeneratedAt: fixedBenchmarkTime()}); err != nil {
		t.Fatal(err)
	}

	report, err := ScanGeneratedOutputs([]string{outA, outB})
	if err != nil {
		t.Fatal(err)
	}
	if !report.Passed {
		t.Fatalf("scan failed: %+v", report)
	}
	if !report.ProfileSpecificConstantsPresent {
		t.Fatalf("profile-specific constants were not detected: %+v", report)
	}
	if !report.SpecializedFilesDiffer {
		t.Fatalf("specialized generated files did not differ: %+v", report)
	}
	if report.DirectFSMUse || report.RuntimeProfileLoad || report.PayloadLogging || report.WrapperOnly {
		t.Fatalf("unexpected generated artifact detected: %+v", report)
	}
}

func TestScanGeneratedOutputsRejectsInterpreterWrapper(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "wrapper")
	if err := os.MkdirAll(filepath.Join(module, "protocol"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `package protocol

import (
	"fmt"
	"kurdistan/internal/protocol/fsm"
	"kurdistan/internal/protocol/ir"
)

func StaticProfile() *ir.Profile {
	p, _ := ir.LoadProfile("profile.json")
	_, _ = fsm.New(p, "client")
	fmt.Println("payload", []byte("secret payload"))
	return p
}
`
	if err := os.WriteFile(filepath.Join(module, "protocol", "profile_static.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	report, err := ScanGeneratedOutputs([]string{module})
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed {
		t.Fatalf("wrapper scan unexpectedly passed: %+v", report)
	}
	joined := strings.Join(report.Failures, "\n")
	for _, want := range []string{"internal/protocol/fsm", "profile.json", "payload logging", "wrapper"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scan failures missing %q: %+v", want, report.Failures)
		}
	}
}

func TestScanModuleRejectsRelocatedFSMImportWithoutInvocation(t *testing.T) {
	root := t.TempDir()
	module := filepath.Join(root, "import-only")
	if err := os.MkdirAll(filepath.Join(module, "protocol"), 0o755); err != nil {
		t.Fatal(err)
	}
	source := `package protocol

import _ "kurdistan/internal/protocol/fsm"
`
	if err := os.WriteFile(filepath.Join(module, "protocol", "profile_static.go"), []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}

	report, _, err := scanModule(module)
	if err != nil {
		t.Fatal(err)
	}
	if !report.DirectFSMUse {
		t.Fatalf("relocated FSM import was not detected: %+v", report)
	}
	if joined := strings.Join(report.Failures, "\n"); !strings.Contains(joined, "internal/protocol/fsm direct use") {
		t.Fatalf("relocated FSM failure missing from report: %+v", report.Failures)
	}
}

func BenchmarkScanGeneratedOutputsTwoModules(b *testing.B) {
	a, err := compiler.Generate(12345)
	if err != nil {
		b.Fatal(err)
	}
	c, err := compiler.Generate(12346)
	if err != nil {
		b.Fatal(err)
	}
	root := b.TempDir()
	outA := filepath.Join(root, "a")
	outB := filepath.Join(root, "b")
	if _, err := Generate(a, outA, Options{GeneratedAt: fixedBenchmarkTime()}); err != nil {
		b.Fatal(err)
	}
	if _, err := Generate(c, outB, Options{GeneratedAt: fixedBenchmarkTime()}); err != nil {
		b.Fatal(err)
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := ScanGeneratedOutputs([]string{outA, outB}); err != nil {
			b.Fatal(err)
		}
	}
}
