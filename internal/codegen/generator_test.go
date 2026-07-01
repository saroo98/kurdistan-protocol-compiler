package codegen

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

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
