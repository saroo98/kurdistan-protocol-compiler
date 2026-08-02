// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestProofStepsSelectGoCoreWithoutOtherProofs(t *testing.T) {
	steps, err := proofSteps("go-core", false, "report.json", "status.md")
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"module-verify", "build", "vet", "test"}
	if len(steps) != len(want) {
		t.Fatalf("go-core steps = %v, want %v", stepNames(steps), want)
	}
	for index, name := range want {
		if steps[index].name != name {
			t.Fatalf("go-core steps = %v, want %v", stepNames(steps), want)
		}
	}
}

func TestGoCoreProofUsesPolicyExactJSONTestCommand(t *testing.T) {
	proof, err := proofSteps("go-core", false, "report.json", "status.md")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proof[3].args, []string{"test", "-json", "-count=1", "./..."}; !equalStrings(got, want) {
		t.Fatalf("go-core test command = %v, want %v", got, want)
	}
	legacy := gateSteps(false, "report.json", "status.md")
	if got, want := legacy[3].args, []string{"test", "-count=1", "./..."}; !equalStrings(got, want) {
		t.Fatalf("legacy test command = %v, want %v", got, want)
	}
}

func TestProofStepsSelectExactProofBoundary(t *testing.T) {
	tests := []struct {
		name  string
		proof string
		quick bool
		want  []string
		arg   string
	}{
		{name: "full audit", proof: "go-audit", want: []string{"audit"}, arg: "--full"},
		{name: "operator", proof: "operator", want: []string{"phase12-control-plane"}},
		{name: "documentation evidence", proof: "docs-evidence", want: []string{"phase15-evidence", "release-metadata"}},
		{name: "dependency freshness", proof: "dependency-freshness", want: []string{"build-govulncheck", "go-vulnerability-analysis", "fetch-osv-scanner", "dependency-manifest-scan"}},
		{name: "Android host", proof: "android-host", want: []string{"android-phase14"}},
		{name: "Android API 26 device", proof: "android-device-api26", want: []string{"android-device-api26"}},
		{name: "Android API 34 device", proof: "android-device-api34", want: []string{"android-device-api34"}},
		{name: "Android API 36 device", proof: "android-device-api36", want: []string{"android-device-api36"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			steps, err := proofSteps(test.proof, test.quick, "report.json", "status.md")
			if err != nil {
				t.Fatal(err)
			}
			if got := stepNames(steps); !equalStrings(got, test.want) {
				t.Fatalf("%s steps = %v, want %v", test.proof, got, test.want)
			}
			if test.arg != "" && !containsString(steps[0].args, test.arg) {
				t.Fatalf("%s args = %v, want %q", test.proof, steps[0].args, test.arg)
			}
		})
	}
}

func TestDependencyFreshnessProofUsesPolicyExactCommands(t *testing.T) {
	steps, err := proofSteps("dependency-freshness", false, "report.json", "status.md")
	if err != nil {
		t.Fatal(err)
	}
	want := []struct {
		program string
		args    []string
	}{
		{program: "go", args: []string{"-C", "tools", "build", "-trimpath", "-o", "../.tools/bin/govulncheck", "golang.org/x/vuln/cmd/govulncheck"}},
		{program: "./.tools/bin/govulncheck", args: []string{"./..."}},
		{program: "pwsh", args: []string{"-File", "tools/scripts/fetch-osv-scanner.ps1", "-RepositoryRoot", ".", "-OutputDirectory", ".tools/bin"}},
		{program: "./.tools/bin/osv-scanner_linux_amd64", args: []string{"-r", "."}},
	}
	if len(steps) != len(want) {
		t.Fatalf("dependency-freshness steps = %v, want %d steps", stepNames(steps), len(want))
	}
	for index := range want {
		if steps[index].program != want[index].program || !equalStrings(steps[index].args, want[index].args) {
			t.Fatalf("dependency-freshness step %d = %s %v, want %s %v", index, steps[index].program, steps[index].args, want[index].program, want[index].args)
		}
	}
}

func TestParseOptionsRejectsQuickProofReceiptAmbiguity(t *testing.T) {
	if _, err := parseOptions([]string{"-proof", "go-audit", "-quick"}); err == nil {
		t.Fatal("expected -quick with a policy proof to fail")
	}
}

func TestProofStepsRejectUnknownProof(t *testing.T) {
	if _, err := proofSteps("unknown", false, "report.json", "status.md"); err == nil {
		t.Fatal("expected unknown proof rejection")
	}
}

func TestParseOptionsAcceptsExactProofAndOutputHooks(t *testing.T) {
	options, err := parseOptions([]string{
		"-proof", "go-core",
		"-receipt", "receipt.json",
		"-timings", "timings.json",
	})
	if err != nil {
		t.Fatal(err)
	}
	if options.proof != "go-core" || options.receiptPath != "receipt.json" || options.timingsPath != "timings.json" {
		t.Fatalf("parsed options = %+v", options)
	}
}

func TestStepsForOptionsPreservesLegacyModesAndIsolatesAndroidOnly(t *testing.T) {
	tests := []struct {
		name    string
		options gateOptions
		want    []string
	}{
		{name: "default", want: []string{"module-verify", "build", "vet", "test", "audit", "phase12-control-plane"}},
		{name: "quick", options: gateOptions{quick: true}, want: []string{"module-verify", "build", "vet", "test", "audit", "phase12-control-plane"}},
		{name: "legacy Android", options: gateOptions{android: true}, want: []string{"module-verify", "build", "vet", "test", "audit", "phase12-control-plane", "android-phase14"}},
		{name: "Android only", options: gateOptions{androidOnly: true}, want: []string{"android-phase14"}},
		{name: "proof", options: gateOptions{proof: "operator"}, want: []string{"phase12-control-plane"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			steps, err := stepsForOptions(test.options, "report.json", "status.md")
			if err != nil {
				t.Fatal(err)
			}
			if got := stepNames(steps); !equalStrings(got, test.want) {
				t.Fatalf("steps = %v, want %v", got, test.want)
			}
			if test.options.quick && !containsString(steps[4].args, "--quick") {
				t.Fatalf("quick audit args = %v", steps[4].args)
			}
		})
	}
}

func TestParseOptionsRejectsAmbiguousOrUnknownSelection(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown proof", args: []string{"-proof", "unknown"}},
		{name: "proof plus legacy Android", args: []string{"-proof", "go-core", "-android"}},
		{name: "proof plus Android only", args: []string{"-proof", "go-core", "-android-only"}},
		{name: "both Android modes", args: []string{"-android", "-android-only"}},
		{name: "same output path", args: []string{"-receipt", "gate.json", "-timings", "gate.json"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseOptions(test.args); err == nil {
				t.Fatalf("parseOptions(%v) unexpectedly succeeded", test.args)
			}
		})
	}
}

func TestRunRejectsUnknownProofBeforeExecution(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"-proof", "unknown"}, io.Discard, &stderr); code != 2 {
		t.Fatalf("run exit code = %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), "unknown proof") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunWritesTerminalReceiptAndTimingsAfterStepFailure(t *testing.T) {
	root := t.TempDir()
	receiptPath := filepath.Join(root, "receipt.json")
	timingsPath := filepath.Join(root, "timings.json")
	code := runWithExecutor([]string{
		"-proof", "go-core",
		"-receipt", receiptPath,
		"-timings", timingsPath,
	}, io.Discard, io.Discard, func(value step, _, _ io.Writer) error {
		if value.name == "vet" {
			return errors.New("injected vet failure")
		}
		return nil
	})
	if code != 1 {
		t.Fatalf("run exit code = %d, want 1", code)
	}

	var receipt struct {
		Schema   string `json:"schema"`
		Proof    string `json:"proof"`
		Terminal bool   `json:"terminal"`
		Status   string `json:"status"`
		Steps    []struct {
			Name   string `json:"name"`
			Status string `json:"status"`
		} `json:"steps"`
	}
	decodeJSONFile(t, receiptPath, &receipt)
	if receipt.Schema != "kurdistan-gate-execution-v1" || receipt.Proof != "go-core" || !receipt.Terminal || receipt.Status != "FAIL" {
		t.Fatalf("receipt identity/status = %+v", receipt)
	}
	if got, want := receiptStepNames(receipt.Steps), []string{"module-verify", "build", "vet", "test"}; !equalStrings(got, want) {
		t.Fatalf("receipt steps = %v, want %v", got, want)
	}
	if receipt.Steps[2].Status != "FAIL" || receipt.Steps[3].Status != "PASS" {
		t.Fatalf("receipt did not preserve continue-after-failure: %+v", receipt.Steps)
	}

	var timings struct {
		Schema         string `json:"schema"`
		DurationMillis int64  `json:"durationMillis"`
		Steps          []struct {
			Name           string `json:"name"`
			Status         string `json:"status"`
			DurationMillis int64  `json:"durationMillis"`
		} `json:"steps"`
	}
	decodeJSONFile(t, timingsPath, &timings)
	if timings.Schema != "kurdistan-gate-timings-v1" || timings.DurationMillis < 0 || len(timings.Steps) != 4 {
		t.Fatalf("timings = %+v", timings)
	}
	if timings.Steps[2].Status != "FAIL" {
		t.Fatalf("failed step timing missing: %+v", timings.Steps)
	}
}

func TestRunFailsWhenRequestedReceiptCannotBeWritten(t *testing.T) {
	blockedParent := filepath.Join(t.TempDir(), "not-a-directory")
	if err := os.WriteFile(blockedParent, []byte("blocked"), 0o600); err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(blockedParent, "receipt.json")
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	code := runWithExecutor([]string{"-proof", "operator", "-receipt", receiptPath}, &stdout, &stderr, func(step, io.Writer, io.Writer) error {
		return nil
	})
	if code != 1 {
		t.Fatalf("run exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "write receipt") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func decodeJSONFile(t *testing.T, path string, target any) {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("decode %s: %v\n%s", path, err, raw)
	}
}

func receiptStepNames(steps []struct {
	Name   string `json:"name"`
	Status string `json:"status"`
}) []string {
	names := make([]string, len(steps))
	for index, value := range steps {
		names[index] = value.Name
	}
	return names
}

func stepNames(steps []step) []string {
	names := make([]string, len(steps))
	for index, value := range steps {
		names[index] = value.name
	}
	return names
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for index := range a {
		if a[index] != b[index] {
			return false
		}
	}
	return true
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func TestGateStepsRemainCacheProof(t *testing.T) {
	steps := gateSteps(false, "report.json", "status.md")
	if len(steps) != 6 {
		t.Fatalf("got %d Go gate steps", len(steps))
	}
	if got := steps[0].args; len(got) != 2 || got[0] != "mod" || got[1] != "verify" {
		t.Fatalf("module verification gate missing: %v", got)
	}
	if got := steps[3].args; len(got) < 2 || got[0] != "test" || got[1] != "-count=1" {
		t.Fatalf("test gate is not cache-proof: %v", got)
	}
	for _, value := range steps {
		if value.program != "go" {
			t.Fatalf("unexpected Go gate program %q", value.program)
		}
	}
	if got := steps[5].args; len(got) != 3 || got[0] != "run" || got[1] != "./cmd/koperator" || got[2] != "verify" {
		t.Fatalf("Phase 12 control-plane gate missing: %v", got)
	}
}

func TestAndroidStepUsesRepositoryWrapper(t *testing.T) {
	value := androidStep()
	if value.dir != "android" {
		t.Fatalf("Android gate working directory = %q, want android", value.dir)
	}
	found := value.program == "./gradlew"
	for _, argument := range value.args {
		found = found || argument == "gradlew.bat"
	}
	if !found {
		t.Fatalf("Android gate does not use the repository wrapper: %#v", value)
	}
	foundPhase14 := false
	for _, argument := range value.args {
		foundPhase14 = foundPhase14 || argument == "phase14Gate"
	}
	if value.name != "android-phase14" || !foundPhase14 {
		t.Fatalf("Android gate does not certify Phase 14: %#v", value)
	}
}
