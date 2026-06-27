package codegen

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/compiler"
)

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
	"kurdistan/internal/fsm"
	"kurdistan/internal/ir"
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
	for _, want := range []string{"internal/fsm", "profile.json", "payload logging", "wrapper"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("scan failures missing %q: %+v", want, report.Failures)
		}
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
