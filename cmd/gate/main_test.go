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
	"runtime"
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

func TestGoCoreProofPreservesFrozenPolicyWhileFullGateDisablesVCSStamping(t *testing.T) {
	proof, err := proofSteps("go-core", false, "report.json", "status.md")
	if err != nil {
		t.Fatal(err)
	}
	if got, want := proof[1].args, []string{"build", "./..."}; !equalStrings(got, want) {
		t.Fatalf("go-core build command = %v, want %v", got, want)
	}
	if got, want := proof[3].args, []string{"test", "-json", "-timeout=15m", "-count=1", "./..."}; !equalStrings(got, want) {
		t.Fatalf("go-core test command = %v, want %v", got, want)
	}
	legacy := gateSteps(false, "report.json", "status.md")
	if got, want := legacy[1].args, []string{"build", "-buildvcs=false", "./..."}; !equalStrings(got, want) {
		t.Fatalf("full gate build command = %v, want %v", got, want)
	}
	if got, want := legacy[3].args, []string{"test", "-timeout=15m", "-count=1", "./..."}; !equalStrings(got, want) {
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
		{name: "executable evidence", proof: "go-executable-evidence", want: []string{"executable-evidence"}, arg: "./cmd/executableevidence"},
		{name: "operator", proof: "operator", want: []string{"phase12-control-plane", "phase16-offline-authority", "phase16-selfhost-tests", "phase16-selfhost-vet"}},
		{name: "documentation evidence", proof: "docs-evidence", want: []string{"phase15-evidence", "release-metadata"}},
		{name: "dependency freshness", proof: "dependency-freshness", want: []string{"build-govulncheck", "go-vulnerability-analysis", "fetch-osv-scanner", "android-runtime-vulnerability-analysis"}},
		{name: "Linux namespace", proof: "linux-netns", want: []string{"phase17-linux-netns"}, arg: "--preserve-env=PATH"},
		{name: "Linux namespace PR contract", proof: "linux-netns-contract", want: []string{"phase17-netns-shell", "phase17-netns-witness-cli", "phase17-netns-probe-cli", "phase17-netns-tagged-tests"}},
		{name: "Phase 17 qualification", proof: "phase17-qualification", want: []string{"phase17-qualification-tests", "phase17-qualification-vet", "phase17-workflow-contract", "phase17-qualification-verifier", "phase17-privacy-python", "phase17-wrapper-tests"}},
		{name: "Android host", proof: "android-host", want: []string{"android-assurance-host"}, arg: "ciAssuranceHostGate"},
		{name: "Android PR host", proof: "android-pr-host", want: []string{"android-pr-host"}, arg: "ciPrHostGate"},
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

func TestLinuxNamespaceProofUsesExplicitShellInterpreter(t *testing.T) {
	steps, err := proofSteps("linux-netns", false, "report.json", "status.md")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 {
		t.Fatalf("linux-netns steps = %v, want one step", stepNames(steps))
	}
	if got, want := steps[0].program, "sudo"; got != want {
		t.Fatalf("linux-netns program = %q, want %q", got, want)
	}
	if got, want := steps[0].args, []string{
		"--preserve-env=PATH",
		"bash",
		"./scripts/phase17/netns-e2e.sh",
		"--mode",
		"full",
		"--evidence-dir",
		".tools/phase17/netns",
	}; !equalStrings(got, want) {
		t.Fatalf("linux-netns args = %v, want %v", got, want)
	}
}

func TestLinuxNamespaceProofPolicyMatchesGateInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "ci", "proof-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Proofs []struct {
			ID       string     `json:"id"`
			Commands [][]string `json:"commands"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	for _, proof := range policy.Proofs {
		if proof.ID == "linux-netns" {
			commands = proof.Commands
			break
		}
	}
	if len(commands) != 1 {
		t.Fatalf("linux-netns policy commands = %v, want one command", commands)
	}
	steps, err := proofSteps("linux-netns", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(steps) != 1 {
		t.Fatalf("linux-netns steps = %v, want one step", stepNames(steps))
	}
	want := append([]string{steps[0].program}, steps[0].args...)
	if !equalStrings(commands[0], want) {
		t.Fatalf("linux-netns policy command = %v, gate command = %v", commands[0], want)
	}
}

func TestLinuxNamespaceProofReturnsPrivateEvidenceToSudoCaller(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "scripts", "phase17", "netns-e2e.sh"))
	if err != nil {
		t.Fatal(err)
	}
	script := string(raw)
	for _, required := range []string{
		"chmod chown",
		"local caller_uid=${SUDO_UID:-}",
		"local caller_gid=${SUDO_GID:-}",
		"chmod 0600 \"$EVIDENCE\"",
		"chown -- \"$caller_uid:$caller_gid\" \"$EVIDENCE\"",
		"handoff_evidence",
	} {
		if !strings.Contains(script, required) {
			t.Fatalf("namespace evidence handoff missing %q", required)
		}
	}
	if strings.Index(script, "handoff_evidence\nFAILURE=0") < strings.Index(script, "os.replace(temporary, path)") {
		t.Fatal("namespace evidence ownership must transfer only after the atomic evidence write")
	}
}

func TestOperatorProofPolicyMatchesGateInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "ci", "proof-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Proofs []struct {
			ID            string     `json:"id"`
			Commands      [][]string `json:"commands"`
			InvalidatedBy []string   `json:"invalidatedBy"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	var operator struct {
		Commands      [][]string
		InvalidatedBy []string
	}
	for _, proof := range policy.Proofs {
		if proof.ID == "operator" {
			operator.Commands = proof.Commands
			operator.InvalidatedBy = proof.InvalidatedBy
			break
		}
	}
	if operator.Commands == nil {
		t.Fatal("operator proof missing from policy")
	}
	steps, err := proofSteps("operator", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(operator.Commands) != len(steps) {
		t.Fatalf("operator policy command count = %d, gate command count = %d", len(operator.Commands), len(steps))
	}
	for index, step := range steps {
		want := append([]string{step.program}, step.args...)
		if !equalStrings(operator.Commands[index], want) {
			t.Fatalf("operator policy command %d = %v, gate command = %v", index, operator.Commands[index], want)
		}
	}
	for _, required := range []string{
		"README.md",
		"cmd/gate/**",
		"cmd/koperator/**",
		"cmd/phase16verify/**",
		"cmd/kurd-node/**",
		"cmd/kurdctl/**",
		"cmd/kurdpackage/**",
		"cmd/kandroidbridge/**",
		"cmd/phase16androidverify/**",
		"deploy/selfhost/**",
		"docs/**",
		"go.mod",
		"go.sum",
		"internal/operator/**",
		"internal/selfhost/**",
		"testdata/evidence/phase12/**",
		"testdata/evidence/phase16/**",
		"testdata/schemas/phase16-production-trust-status-v1.schema.json",
		"testdata/schemas/phase16-self-hosted-vps-qualification-v1.schema.json",
	} {
		if !containsString(operator.InvalidatedBy, required) {
			t.Fatalf("operator policy invalidation paths missing %q: %v", required, operator.InvalidatedBy)
		}
	}
}

func TestPhase17QualificationProofPolicyMatchesGateInventory(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "config", "ci", "proof-policy.json"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Proofs []struct {
			ID                        string                `json:"id"`
			CommandsByOperatingSystem map[string][][]string `json:"commandsByOperatingSystem"`
			InvalidatedBy             []string              `json:"invalidatedBy"`
		} `json:"proofs"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil {
		t.Fatal(err)
	}
	var commands [][]string
	var invalidatedBy []string
	for _, proof := range policy.Proofs {
		if proof.ID == "phase17-qualification" {
			commands = proof.CommandsByOperatingSystem[runtime.GOOS]
			invalidatedBy = proof.InvalidatedBy
			break
		}
	}
	if commands == nil {
		t.Fatal("Phase 17 qualification proof missing from policy")
	}
	steps, err := proofSteps("phase17-qualification", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != len(steps) {
		t.Fatalf("qualification policy command count = %d, gate command count = %d", len(commands), len(steps))
	}
	for index, step := range steps {
		want := append([]string{step.program}, step.args...)
		if !equalStrings(commands[index], want) {
			t.Fatalf("qualification policy command %d = %v, gate command = %v", index, commands[index], want)
		}
	}
	for _, required := range []string{
		".github/**", "android/**", "cmd/assure/**", "cmd/gate/**", "cmd/phase17boundary/**", "cmd/phase17evidence/**",
		"cmd/phase17field/**", "cmd/phase17qual/**", "cmd/phase17scan/**", "cmd/phase17verify/**",
		"config/ci/**", "config/phase17/**", "config/release/**", "go.mod", "go.sum", "internal/assurance/**",
		"internal/phase17boundary/**", "internal/phase17evidence/**",
		"internal/phase17privacy/**", "internal/phase17qualification/**", "internal/testkit/importrules/**",
		"scripts/phase17/**", "testdata/fixtures/phase17/privacy-scanner/**", "testdata/schemas/**",
	} {
		if !containsString(invalidatedBy, required) {
			t.Fatalf("qualification policy invalidation paths missing %q: %v", required, invalidatedBy)
		}
	}
}

func TestDefaultGateRunsExecutableEvidenceExactlyOnce(t *testing.T) {
	steps := gateSteps(false, "report.json", "status.md")
	count := 0
	for _, step := range steps {
		if step.name == "executable-evidence" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("default gate executable-evidence count = %d, want 1", count)
	}
}

func TestDependencyFreshnessProofUsesPolicyExactCommands(t *testing.T) {
	steps, err := proofSteps("dependency-freshness", false, "report.json", "status.md")
	if err != nil {
		t.Fatal(err)
	}
	govulncheckOutput := "../.tools/bin/govulncheck"
	govulncheckProgram := "./.tools/bin/govulncheck"
	osvScanner := "./.tools/bin/osv-scanner_linux_amd64"
	if runtime.GOOS == "windows" {
		govulncheckOutput += ".exe"
		govulncheckProgram += ".exe"
		osvScanner = ".tools\\bin\\osv-scanner_windows_amd64.exe"
	}
	want := []struct {
		program string
		args    []string
	}{
		{program: "go", args: []string{"-C", "tools", "build", "-trimpath", "-o", govulncheckOutput, "golang.org/x/vuln/cmd/govulncheck"}},
		{program: govulncheckProgram, args: []string{"./..."}},
		{program: "pwsh", args: []string{"-File", "tools/scripts/fetch-osv-scanner.ps1", "-RepositoryRoot", ".", "-OutputDirectory", ".tools/bin"}},
		{program: osvScanner, args: []string{"scan", "source", "-L", "testdata/evidence/phase9/android-sbom.cdx.json"}},
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
		{name: "default", want: []string{"module-verify", "build", "vet", "test", "executable-evidence", "audit", "phase12-control-plane", "phase16-offline-authority", "phase17-workflow-contract", "phase17-qualification-verifier", "phase17-privacy-python", "phase17-wrapper-tests"}},
		{name: "quick", options: gateOptions{quick: true}, want: []string{"module-verify", "build", "vet", "test", "executable-evidence", "audit", "phase12-control-plane", "phase16-offline-authority", "phase17-workflow-contract", "phase17-qualification-verifier", "phase17-privacy-python", "phase17-wrapper-tests"}},
		{name: "legacy Android", options: gateOptions{android: true}, want: []string{"module-verify", "build", "vet", "test", "executable-evidence", "audit", "phase12-control-plane", "phase16-offline-authority", "phase17-workflow-contract", "phase17-qualification-verifier", "phase17-privacy-python", "phase17-wrapper-tests", "android-assurance-host"}},
		{name: "Android only", options: gateOptions{androidOnly: true}, want: []string{"android-assurance-host"}},
		{name: "proof", options: gateOptions{proof: "operator"}, want: []string{"phase12-control-plane", "phase16-offline-authority", "phase16-selfhost-tests", "phase16-selfhost-vet"}},
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
			if test.options.quick && !containsString(namedStep(t, steps, "audit").args, "--quick") {
				t.Fatalf("quick audit args = %v", namedStep(t, steps, "audit").args)
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

func TestExecutableEvidenceProofFailureTurnsGateRed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithExecutor([]string{"-proof", "go-executable-evidence"}, &stdout, &stderr, func(step step, _, _ io.Writer) error {
		if step.name != "executable-evidence" {
			t.Fatalf("unexpected step %q", step.name)
		}
		return errors.New("injected executable-evidence failure")
	})
	if code != 1 || !strings.Contains(stdout.String(), "GATE FAILED: [executable-evidence]") {
		t.Fatalf("code = %d, stdout = %q, stderr = %q", code, stdout.String(), stderr.String())
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

func namedStep(t *testing.T, steps []step, name string) step {
	t.Helper()
	for _, value := range steps {
		if value.name == name {
			return value
		}
	}
	t.Fatalf("missing step %q", name)
	return step{}
}

func TestGateStepsRemainCacheProof(t *testing.T) {
	steps := gateSteps(false, "report.json", "status.md")
	wantNames := []string{"module-verify", "build", "vet", "test", "executable-evidence", "audit", "phase12-control-plane", "phase16-offline-authority", "phase17-workflow-contract", "phase17-qualification-verifier", "phase17-privacy-python", "phase17-wrapper-tests"}
	if !equalStrings(stepNames(steps), wantNames) {
		t.Fatalf("steps = %v, want %v", stepNames(steps), wantNames)
	}
	for name, want := range map[string][]string{
		"module-verify":                  {"mod", "verify"},
		"test":                           {"test", "-timeout=15m", "-count=1", "./..."},
		"vet":                            {"vet", "./..."},
		"phase12-control-plane":          {"run", "./cmd/koperator", "verify"},
		"phase16-offline-authority":      {"run", "./cmd/phase16verify", "-root", ".", "-mode", "offline"},
		"phase17-workflow-contract":      {"run", "./cmd/assure", "workflow", "-root", "."},
		"phase17-qualification-verifier": {"run", "./cmd/phase17verify", "-root", "."},
	} {
		value := namedStep(t, steps, name)
		if value.program != "go" || !equalStrings(value.args, want) {
			t.Fatalf("%s = %#v, want go %v", name, value, want)
		}
	}
	counts := map[string]int{}
	for _, value := range steps {
		if value.program == "go" && len(value.args) > 0 {
			if value.args[0] == "test" || value.args[0] == "vet" {
				counts[value.args[0]]++
				if !containsString(value.args, "./...") || containsString(value.args, "./internal/selfhost/...") {
					t.Fatalf("aggregate subset: %#v", value)
				}
			}
		}
	}
	if counts["test"] != 1 || counts["vet"] != 1 {
		t.Fatalf("root suite counts: %v", counts)
	}
	privacy := namedStep(t, steps, "phase17-privacy-python")
	if (privacy.program != "python" && privacy.program != "python3") || !equalStrings(privacy.args, []string{"-B", "-I", "scripts/phase17/privacy_scan_b_test.py"}) {
		t.Fatalf("privacy step = %#v", privacy)
	}
	wrapper := namedStep(t, steps, "phase17-wrapper-tests")
	if wrapper.program != "pwsh" || !equalStrings(wrapper.args, []string{"-NoProfile", "-File", "scripts/phase17/owned-vps-scripts.Tests.ps1"}) {
		t.Fatalf("wrapper step = %#v", wrapper)
	}
}

func TestStandaloneOperatorCommandsRemainComplete(t *testing.T) {
	steps, err := proofSteps("operator", false, "", "")
	if err != nil {
		t.Fatal(err)
	}
	want := []step{
		{"phase12-control-plane", "go", []string{"run", "./cmd/koperator", "verify"}, ""},
		{"phase16-offline-authority", "go", []string{"run", "./cmd/phase16verify", "-root", ".", "-mode", "offline"}, ""},
		{"phase16-selfhost-tests", "go", []string{"test", "-count=1", "./internal/selfhost/...", "./cmd/kurdctl", "./cmd/kurd-node", "./cmd/kurdpackage", "./cmd/kandroidbridge", "./cmd/phase16androidverify"}, ""},
		{"phase16-selfhost-vet", "go", []string{"vet", "./internal/selfhost/...", "./cmd/kurdctl", "./cmd/kurd-node", "./cmd/kurdpackage", "./cmd/kandroidbridge", "./cmd/phase16androidverify"}, ""},
	}
	if !equalStrings(stepNames(steps), stepNames(want)) {
		t.Fatalf("operator steps = %v", stepNames(steps))
	}
	for i, value := range steps {
		if value.program != want[i].program || value.dir != want[i].dir || !equalStrings(value.args, want[i].args) {
			t.Fatalf("operator step = %#v, want %#v", value, want[i])
		}
	}
}

func TestAndroidAssuranceStepUsesRepositoryWrapperWithoutCaches(t *testing.T) {
	value := androidAssuranceStep()
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
	foundTask := false
	foundNoBuildCache := false
	foundNoConfigurationCache := false
	foundRerunTasks := false
	for _, argument := range value.args {
		foundTask = foundTask || argument == "ciAssuranceHostGate"
		foundNoBuildCache = foundNoBuildCache || argument == "--no-build-cache"
		foundNoConfigurationCache = foundNoConfigurationCache || argument == "--no-configuration-cache"
		foundRerunTasks = foundRerunTasks || argument == "--rerun-tasks"
	}
	if value.name != "android-assurance-host" || !foundTask || !foundNoBuildCache || !foundNoConfigurationCache || !foundRerunTasks {
		t.Fatalf("Android assurance gate is not cache-independent: %#v", value)
	}
}

func TestAndroidPRStepUsesCacheEnabledFeedbackTask(t *testing.T) {
	value := androidPRStep()
	if value.name != "android-pr-host" || !containsString(value.args, "ciPrHostGate") {
		t.Fatalf("Android PR gate does not use feedback task: %#v", value)
	}
	for _, prohibited := range []string{"--no-build-cache", "--no-configuration-cache", "--rerun-tasks"} {
		if containsString(value.args, prohibited) {
			t.Fatalf("Android PR feedback unexpectedly disables cache with %q: %#v", prohibited, value)
		}
	}
}

func TestAndroidDeviceStepsBindTheCurrentRosterForEveryLane(t *testing.T) {
	for _, api := range []int{26, 34, 36} {
		step := androidDeviceStep(api)
		count := 0
		for i, arg := range step.args {
			if arg == "-expected-tests" {
				count++
				if i+1 >= len(step.args) || step.args[i+1] != "android/config/phase18-current-device-tests.txt" {
					t.Fatalf("API %d does not bind current roster: %v", api, step.args)
				}
			}
		}
		if count != 1 {
			t.Fatalf("API %d expected-tests count=%d", api, count)
		}
	}
}
