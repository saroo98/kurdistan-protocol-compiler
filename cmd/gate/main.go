// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command gate runs the repository's full validation bar in one step: the same
// gates documented in docs/GOVERNANCE.md. It exists to give a single
// reproducible pre-merge check locally and in the repository CI workflow.
//
// Usage:
//
//	go run ./cmd/gate                         # modules + build + vet + test + full audit + operator
//	go run ./cmd/gate -quick                  # complete Go gate with the quick audit
//	go run ./cmd/gate -android                # complete Go gate plus Android Phase 17
//	go run ./cmd/gate -android-only           # Android Phase 17 only
//	go run ./cmd/gate -proof go-core          # modules + build + vet + uncached tests
//	go run ./cmd/gate -proof go-executable-evidence # nested executable evidence only
//	go run ./cmd/gate -proof go-audit         # full audit only
//	go run ./cmd/gate -proof operator         # operator verification only
//	go run ./cmd/gate -proof linux-netns      # privileged Linux namespace proof
//	go run ./cmd/gate -proof linux-netns-contract # unprivileged PR contract proof
//	go run ./cmd/gate -proof android-host     # Android Phase 17 only
//	go run ./cmd/gate -proof android-pr-host  # cache-enabled PR feedback only
//
// It exits non-zero if any step fails.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type step struct {
	name    string
	program string
	args    []string
	dir     string
}

type gateOptions struct {
	quick       bool
	android     bool
	androidOnly bool
	proof       string
	receiptPath string
	timingsPath string
}

const (
	gateExecutionSchema = "kurdistan-gate-execution-v1"
	gateTimingsSchema   = "kurdistan-gate-timings-v1"
	goSuiteTimeout      = "15m"
)

type gateStepExecution struct {
	Name     string   `json:"name"`
	Command  []string `json:"command"`
	Status   string   `json:"status"`
	ExitCode int      `json:"exitCode"`
}

type gateExecution struct {
	Schema      string              `json:"schema"`
	Proof       string              `json:"proof,omitempty"`
	Quick       bool                `json:"quick"`
	Android     bool                `json:"android"`
	AndroidOnly bool                `json:"androidOnly"`
	StartedAt   string              `json:"startedAt"`
	FinishedAt  string              `json:"finishedAt"`
	Terminal    bool                `json:"terminal"`
	Status      string              `json:"status"`
	Steps       []gateStepExecution `json:"steps"`
}

type gateStepTiming struct {
	Name           string `json:"name"`
	Status         string `json:"status"`
	DurationMillis int64  `json:"durationMillis"`
}

type gateTimings struct {
	Schema         string           `json:"schema"`
	StartedAt      string           `json:"startedAt"`
	FinishedAt     string           `json:"finishedAt"`
	DurationMillis int64            `json:"durationMillis"`
	Steps          []gateStepTiming `json:"steps"`
}

type stepExecutor func(step, io.Writer, io.Writer) error

func parseOptions(args []string) (gateOptions, error) {
	var options gateOptions
	flags := flag.NewFlagSet("gate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.BoolVar(&options.quick, "quick", false, "run the quick audit mode")
	flags.BoolVar(&options.android, "android", false, "append Android Phase 17 assurance")
	flags.BoolVar(&options.androidOnly, "android-only", false, "run only Android Phase 17 assurance")
	flags.StringVar(&options.proof, "proof", "", "run one proof class")
	flags.StringVar(&options.receiptPath, "receipt", "", "write a gate execution receipt")
	flags.StringVar(&options.timingsPath, "timings", "", "write gate timing data")
	if err := flags.Parse(args); err != nil {
		return gateOptions{}, err
	}
	if flags.NArg() != 0 {
		return gateOptions{}, fmt.Errorf("unexpected arguments: %v", flags.Args())
	}
	if options.proof != "" {
		if options.quick {
			return gateOptions{}, fmt.Errorf("-proof cannot be combined with -quick")
		}
		if _, err := proofSteps(options.proof, options.quick, "", ""); err != nil {
			return gateOptions{}, err
		}
		if options.android || options.androidOnly {
			return gateOptions{}, fmt.Errorf("-proof cannot be combined with -android or -android-only")
		}
	}
	if options.android && options.androidOnly {
		return gateOptions{}, fmt.Errorf("-android and -android-only are mutually exclusive")
	}
	if options.receiptPath != "" && options.timingsPath != "" && filepath.Clean(options.receiptPath) == filepath.Clean(options.timingsPath) {
		return gateOptions{}, fmt.Errorf("-receipt and -timings require different paths")
	}
	return options, nil
}

func gateSteps(quick bool, jsonOut, statusOut string) []step {
	auditMode := "--full"
	if quick {
		auditMode = "--quick"
	}
	steps := []step{
		{"module-verify", "go", []string{"mod", "verify"}, ""},
		{"build", "go", []string{"build", "-buildvcs=false", "./..."}, ""},
		{"vet", "go", []string{"vet", "./..."}, ""},
		{"test", "go", []string{"test", "-timeout=" + goSuiteTimeout, "-count=1", "./..."}, ""},
		{"executable-evidence", "go", []string{"run", "./cmd/executableevidence"}, ""},
		{"audit", "go", []string{"run", "./cmd/kcheck", auditMode, "--out", jsonOut, "--status", statusOut}, ""},
		{"phase12-control-plane", "go", []string{"run", "./cmd/koperator", "verify"}, ""},
		{"phase16-offline-authority", "go", []string{"run", "./cmd/phase16verify", "-root", ".", "-mode", "offline"}, ""},
		{"phase16-selfhost-tests", "go", []string{"test", "-count=1", "./internal/selfhost/...", "./cmd/kurdctl", "./cmd/kurd-node", "./cmd/kurdpackage", "./cmd/kandroidbridge", "./cmd/phase16androidverify"}, ""},
		{"phase16-selfhost-vet", "go", []string{"vet", "./internal/selfhost/...", "./cmd/kurdctl", "./cmd/kurd-node", "./cmd/kurdpackage", "./cmd/kandroidbridge", "./cmd/phase16androidverify"}, ""},
	}
	return append(steps, phase17QualificationSourceSteps(false)...)
}

func phase17QualificationPackages() []string {
	return []string{
		"./internal/phase17qualification", "./internal/phase17evidence", "./internal/phase17privacy/...", "./internal/phase17boundary",
		"./cmd/phase17qual", "./cmd/phase17scan", "./cmd/phase17boundary", "./cmd/phase17field", "./cmd/phase17evidence", "./cmd/phase17verify",
		"./internal/testkit/importrules",
	}
}

func phase17QualificationSourceSteps(includeGo bool) []step {
	python := "python3"
	if runtime.GOOS == "windows" {
		python = "python"
	}
	steps := make([]step, 0, 6)
	if includeGo {
		steps = append(steps,
			step{name: "phase17-qualification-tests", program: "go", args: append([]string{"test", "-count=1"}, phase17QualificationPackages()...)},
			step{name: "phase17-qualification-vet", program: "go", args: append([]string{"vet"}, phase17QualificationPackages()...)},
		)
	}
	return append(steps,
		step{name: "phase17-workflow-contract", program: "go", args: []string{"run", "./cmd/assure", "workflow", "-root", "."}},
		step{name: "phase17-qualification-verifier", program: "go", args: []string{"run", "./cmd/phase17verify", "-root", "."}},
		step{name: "phase17-privacy-python", program: python, args: []string{"-B", "-I", "scripts/phase17/privacy_scan_b_test.py"}},
		step{name: "phase17-wrapper-tests", program: "pwsh", args: []string{"-NoProfile", "-File", "scripts/phase17/owned-vps-scripts.Tests.ps1"}},
	)
}

func proofSteps(proof string, quick bool, jsonOut, statusOut string) ([]step, error) {
	steps := gateSteps(quick, jsonOut, statusOut)
	switch proof {
	case "go-core":
		core := append([]step(nil), steps[:4]...)
		core[1].args = []string{"build", "./..."}
		core[3].args = []string{"test", "-json", "-timeout=" + goSuiteTimeout, "-count=1", "./..."}
		return core, nil
	case "go-executable-evidence":
		return steps[4:5], nil
	case "go-audit":
		audit := steps[5]
		audit.args = []string{"run", "./cmd/kcheck", "--full"}
		return []step{audit}, nil
	case "operator":
		return steps[6:10], nil
	case "docs-evidence":
		return []step{
			{name: "phase15-evidence", program: "go", args: []string{"run", "./cmd/phase15verify", "-root", "."}},
			{name: "release-metadata", program: "go", args: []string{"run", "./cmd/releaseverify", "-root", "."}},
		}, nil
	case "dependency-freshness":
		govulncheckOutput := "../.tools/bin/govulncheck"
		govulncheckProgram := "./.tools/bin/govulncheck"
		osvScanner := "./.tools/bin/osv-scanner_linux_amd64"
		if runtime.GOOS == "windows" {
			govulncheckOutput += ".exe"
			govulncheckProgram += ".exe"
			osvScanner = ".tools\\bin\\osv-scanner_windows_amd64.exe"
		}
		return []step{
			{name: "build-govulncheck", program: "go", args: []string{"-C", "tools", "build", "-trimpath", "-o", govulncheckOutput, "golang.org/x/vuln/cmd/govulncheck"}},
			{name: "go-vulnerability-analysis", program: govulncheckProgram, args: []string{"./..."}},
			{name: "fetch-osv-scanner", program: "pwsh", args: []string{"-File", "tools/scripts/fetch-osv-scanner.ps1", "-RepositoryRoot", ".", "-OutputDirectory", ".tools/bin"}},
			{name: "android-runtime-vulnerability-analysis", program: osvScanner, args: []string{"scan", "source", "-L", "testdata/evidence/phase9/android-sbom.cdx.json"}},
		}, nil
	case "linux-netns":
		return []step{{name: "phase17-linux-netns", program: "sudo", args: []string{"--preserve-env=PATH", "bash", "./scripts/phase17/netns-e2e.sh", "--mode", "full", "--evidence-dir", ".tools/phase17/netns"}}}, nil
	case "linux-netns-contract":
		return []step{
			{name: "phase17-netns-shell", program: "bash", args: []string{"-n", "scripts/phase17/netns-e2e.sh"}},
			{name: "phase17-netns-witness-cli", program: "python3", args: []string{"scripts/phase17/netns_witness.py", "--help"}},
			{name: "phase17-netns-probe-cli", program: "python3", args: []string{"scripts/phase17/netns_probe.py", "--help"}},
			{name: "phase17-netns-tagged-tests", program: "go", args: []string{"test", "-tags=phase17integration", "./internal/relay/...", "./internal/runtime", "-count=1"}},
		}, nil
	case "phase17-qualification":
		return phase17QualificationSourceSteps(true), nil
	case "android-host":
		return []step{androidAssuranceStep()}, nil
	case "android-pr-host":
		return []step{androidPRStep()}, nil
	case "android-device-api26":
		return []step{androidDeviceStep(26)}, nil
	case "android-device-api34":
		return []step{androidDeviceStep(34)}, nil
	case "android-device-api36":
		return []step{androidDeviceStep(36)}, nil
	default:
		return nil, fmt.Errorf("unknown proof %q", proof)
	}
}

func stepsForOptions(options gateOptions, jsonOut, statusOut string) ([]step, error) {
	if options.proof != "" {
		return proofSteps(options.proof, options.quick, jsonOut, statusOut)
	}
	if options.androidOnly {
		return []step{androidAssuranceStep()}, nil
	}
	steps := gateSteps(options.quick, jsonOut, statusOut)
	if options.android {
		steps = append(steps, androidAssuranceStep())
	}
	return steps, nil
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr io.Writer) int {
	return runWithExecutor(args, stdout, stderr, executeStep)
}

func runWithExecutor(args []string, stdout, stderr io.Writer, execute stepExecutor) int {
	options, err := parseOptions(args)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 2
	}
	statusOut := filepath.Join(os.TempDir(), "kcheck-gate-status.md")
	jsonOut := filepath.Join(os.TempDir(), "kcheck-gate-report.json")
	steps, err := stepsForOptions(options, jsonOut, statusOut)
	if err != nil {
		fmt.Fprintf(stderr, "gate: %v\n", err)
		return 2
	}

	startedAt := time.Now().UTC()
	execution := gateExecution{
		Schema:      gateExecutionSchema,
		Proof:       options.proof,
		Quick:       options.quick,
		Android:     options.android,
		AndroidOnly: options.androidOnly,
		StartedAt:   startedAt.Format(time.RFC3339Nano),
		Steps:       make([]gateStepExecution, 0, len(steps)),
	}
	timings := gateTimings{
		Schema:    gateTimingsSchema,
		StartedAt: execution.StartedAt,
		Steps:     make([]gateStepTiming, 0, len(steps)),
	}
	failed := []string{}
	for _, s := range steps {
		fmt.Fprintf(stdout, "== gate: %s (%s %v) ==\n", s.name, s.program, s.args)
		start := time.Now()
		err := execute(s, stdout, stderr)
		dur := time.Since(start).Round(time.Millisecond)
		status := "PASS"
		if err != nil {
			status = "FAIL"
			fmt.Fprintf(stdout, "-- gate: %s FAILED in %s: %v\n", s.name, dur, err)
			failed = append(failed, s.name)
		} else {
			fmt.Fprintf(stdout, "-- gate: %s ok in %s\n", s.name, dur)
		}
		command := append([]string{s.program}, s.args...)
		execution.Steps = append(execution.Steps, gateStepExecution{Name: s.name, Command: command, Status: status, ExitCode: exitCode(err)})
		timings.Steps = append(timings.Steps, gateStepTiming{Name: s.name, Status: status, DurationMillis: dur.Milliseconds()})
	}
	finishedAt := time.Now().UTC()
	execution.FinishedAt = finishedAt.Format(time.RFC3339Nano)
	execution.Terminal = true
	execution.Status = "PASS"
	if len(failed) > 0 {
		execution.Status = "FAIL"
	}
	timings.FinishedAt = execution.FinishedAt
	timings.DurationMillis = finishedAt.Sub(startedAt).Round(time.Millisecond).Milliseconds()
	outputFailed := false
	if options.receiptPath != "" {
		if err := writeJSONAtomic(options.receiptPath, execution); err != nil {
			fmt.Fprintf(stderr, "gate: write receipt: %v\n", err)
			outputFailed = true
		}
	}
	if options.timingsPath != "" {
		if err := writeJSONAtomic(options.timingsPath, timings); err != nil {
			fmt.Fprintf(stderr, "gate: write timings: %v\n", err)
			outputFailed = true
		}
	}

	fmt.Fprintln(stdout)
	if len(failed) > 0 {
		fmt.Fprintf(stdout, "GATE FAILED: %v\n", failed)
		return 1
	}
	if outputFailed {
		fmt.Fprintln(stdout, "GATE FAILED: execution record output")
		return 1
	}
	if options.android {
		fmt.Fprintln(stdout, "GATE PASSED: module verification, build, vet, test, audit, Phase 12 control plane, and Android Phase 17 live data-plane assurance all green")
	} else if options.androidOnly {
		fmt.Fprintln(stdout, "GATE PASSED: Android Phase 17 live data-plane assurance green")
	} else if options.proof != "" {
		fmt.Fprintf(stdout, "GATE PASSED: proof %s green\n", options.proof)
	} else {
		fmt.Fprintln(stdout, "GATE PASSED: module verification, build, vet, test, audit, and Phase 12 control plane all green")
	}
	return 0
}

func executeStep(value step, stdout, stderr io.Writer) error {
	cmd := exec.Command(value.program, value.args...)
	cmd.Dir = value.dir
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	return cmd.Run()
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}

func writeJSONAtomic(path string, value any) (err error) {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".gate-*.tmp")
	if err != nil {
		return err
	}
	temporaryPath := temporary.Name()
	defer func() {
		if temporary != nil {
			_ = temporary.Close()
		}
		_ = os.Remove(temporaryPath)
	}()
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	temporary = nil
	return os.Rename(temporaryPath, path)
}

func androidAssuranceStep() step {
	return androidStep("android-assurance-host", "ciAssuranceHostGate", "--no-build-cache", "--no-configuration-cache", "--rerun-tasks")
}

func androidPRStep() step {
	return androidStep("android-pr-host", "ciPrHostGate")
}

func androidStep(name, task string, extraArgs ...string) step {
	args := append([]string{task}, extraArgs...)
	if runtime.GOOS == "windows" {
		return step{
			name:    name,
			program: "cmd",
			args:    append([]string{"/c", "gradlew.bat"}, args...),
			dir:     "android",
		}
	}
	return step{
		name:    name,
		program: "./gradlew",
		args:    args,
		dir:     "android",
	}
}

func androidDeviceStep(api int) step {
	return step{
		name:    fmt.Sprintf("android-device-api%d", api),
		program: "go",
		args: []string{
			"run", "./cmd/phase17devicegate",
			"-evidence-dir", fmt.Sprintf(".tools/phase17/device-api%d", api),
			"-app-apk", ".tools/device/app-internal.apk",
			"-test-apk", ".tools/device/app-internal-androidTest.apk",
			"-app-package", "org.kurdistanvpn.app.internal",
			"-test-package", "org.kurdistanvpn.app.internal.test",
			"-conflicting-app-package", "org.kurdistanvpn.app.debug",
			"-minimum-tests", "1",
			"-expected-tests", "android/config/phase17-required-device-tests.txt",
			"-expected-api", fmt.Sprintf("%d", api),
			"-expected-abi", "x86_64",
		},
	}
}
