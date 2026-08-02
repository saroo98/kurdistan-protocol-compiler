// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"time"

	"kurdistan/internal/assurance"
)

type gateExecutionRecord struct {
	Schema      string `json:"schema"`
	Proof       string `json:"proof"`
	Quick       bool   `json:"quick"`
	Android     bool   `json:"android"`
	AndroidOnly bool   `json:"androidOnly"`
	StartedAt   string `json:"startedAt"`
	FinishedAt  string `json:"finishedAt"`
	Terminal    bool   `json:"terminal"`
	Status      string `json:"status"`
	Steps       []struct {
		Name     string   `json:"name"`
		Command  []string `json:"command"`
		Status   string   `json:"status"`
		ExitCode int      `json:"exitCode"`
	} `json:"steps"`
}

type namedPathValues []string

func (values *namedPathValues) String() string { return strings.Join(*values, ",") }
func (values *namedPathValues) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func runReceiptIssue(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("receipt issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "config/ci/proof-policy.json", "proof policy path under root")
	gatePath := flags.String("gate", "", "terminal gate execution record under root")
	workflowPath := flags.String("workflow", "", "trusted workflow path under root")
	workflowSourceCommit := flags.String("workflow-source-commit", envOr("GITHUB_WORKFLOW_SHA", ""), "commit containing the workflow definition GitHub executed")
	outPath := flags.String("out", "", "receipt output path under root")
	repository := flags.String("repository", envOr("GITHUB_REPOSITORY", "saroo98/kurdistan-protocol-compiler"), "repository owner/name")
	commit := flags.String("commit", envOr("GITHUB_SHA", ""), "exact subject commit")
	ref := flags.String("ref", envOr("GITHUB_REF", ""), "exact subject ref")
	runID := flags.String("run-id", envOr("GITHUB_RUN_ID", ""), "workflow run id")
	jobID := flags.String("job-id", envOr("GITHUB_JOB", "local-proof"), "workflow job id")
	attempt := flags.Int("attempt", envIntOr("GITHUB_RUN_ATTEMPT", 1), "workflow run attempt")
	trigger := flags.String("trigger", envOr("GITHUB_EVENT_NAME", "workflow_dispatch"), "workflow trigger")
	osName := flags.String("os", normalizedOS(runtime.GOOS), "runner operating system")
	arch := flags.String("arch", runtime.GOARCH, "runner architecture")
	runnerLabel := flags.String("runner-label", envOr("RUNNER_NAME", "local"), "requested runner label")
	image := flags.String("image", envOr("ImageOS", "local"), "runner image")
	imageVersion := flags.String("image-version", envOr("ImageVersion", "local"), "runner image version")
	var inventories namedPathValues
	var artifacts namedPathValues
	flags.Var(&inventories, "inventory", "name=path inventory under root; repeatable")
	flags.Var(&artifacts, "artifact", "artifact path under root; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *gatePath == "" || *workflowPath == "" || *outPath == "" {
		return errors.New("receipt issue requires -gate, -workflow, and -out")
	}

	policy, policyRaw, err := readProofPolicy(*root, *policyPath)
	if err != nil {
		return err
	}
	gateRaw, err := readRootFile(*root, *gatePath)
	if err != nil {
		return fmt.Errorf("read gate record: %w", err)
	}
	var gate gateExecutionRecord
	if err := assurance.DecodeStrict(bytes.NewReader(gateRaw), &gate); err != nil {
		return fmt.Errorf("decode gate record: %w", err)
	}
	if gate.Schema != "kurdistan-gate-execution-v1" || gate.Proof == "" || gate.Quick || gate.Android || gate.AndroidOnly || !gate.Terminal || (gate.Status != "PASS" && gate.Status != "FAIL") {
		return errors.New("gate record is not a terminal proof execution")
	}
	proof, err := proofByID(policy, gate.Proof)
	if err != nil {
		return err
	}
	commands, err := proof.CommandsForOperatingSystem(*osName)
	if err != nil {
		return err
	}
	if err := validateGateSteps(gate, commands); err != nil {
		return err
	}
	if *commit == "" {
		*commit, err = gitOutput(*root, "rev-parse", "HEAD")
		if err != nil {
			return err
		}
	}
	if *workflowSourceCommit == "" {
		*workflowSourceCommit = *commit
	}
	workflowRaw, err := readGitBlob(*root, *workflowSourceCommit, *workflowPath)
	if err != nil {
		return fmt.Errorf("read executed workflow: %w", err)
	}
	tree, err := gitOutput(*root, "rev-parse", *commit+"^{tree}")
	if err != nil {
		return err
	}
	if *ref == "" {
		branch, branchErr := gitOutput(*root, "symbolic-ref", "-q", "HEAD")
		if branchErr != nil {
			*ref = "refs/heads/detached"
		} else {
			*ref = branch
		}
	}
	if *runID == "" {
		*runID = strconv.FormatInt(time.Now().UTC().UnixNano(), 10)
	}
	started, err := time.Parse(time.RFC3339Nano, gate.StartedAt)
	if err != nil {
		return errors.New("gate startedAt is invalid")
	}
	finished, err := time.Parse(time.RFC3339Nano, gate.FinishedAt)
	if err != nil || finished.Before(started) {
		return errors.New("gate finishedAt is invalid")
	}

	policyDigest := digestBytes(policyRaw)
	namedDigests := []assurance.NamedDigest{
		{Name: "proof-policy", SHA256: policyDigest},
		{Name: "gate-execution", SHA256: digestBytes(gateRaw)},
	}
	for _, specification := range inventories {
		name, path, splitErr := splitNamedPath(specification)
		if splitErr != nil {
			return splitErr
		}
		raw, readErr := readRootFile(*root, path)
		if readErr != nil {
			return fmt.Errorf("read inventory %q: %w", name, readErr)
		}
		namedDigests = append(namedDigests, assurance.NamedDigest{Name: name, SHA256: digestBytes(raw)})
	}
	sort.Slice(namedDigests, func(i, j int) bool { return namedDigests[i].Name < namedDigests[j].Name })
	if duplicateNamedDigest(namedDigests) {
		return errors.New("duplicate inventory name")
	}

	artifactRecords := make([]assurance.Artifact, 0, len(artifacts))
	for _, path := range artifacts {
		record, digestErr := digestRootArtifact(*root, path)
		if digestErr != nil {
			return fmt.Errorf("digest artifact %q: %w", path, digestErr)
		}
		artifactRecords = append(artifactRecords, record)
	}
	sort.Slice(artifactRecords, func(i, j int) bool { return artifactRecords[i].Path < artifactRecords[j].Path })

	toolchain, err := proofToolchain(*root, gate.Proof, artifactRecords)
	if err != nil {
		return err
	}
	receipt := assurance.Receipt{
		Schema:    assurance.ReceiptSchema,
		ReceiptID: fmt.Sprintf("%s-%s-%d", gate.Proof, strings.ToLower(*osName), *attempt),
		Subject:   assurance.Subject{Repository: *repository, Commit: *commit, Tree: tree, Ref: *ref},
		Workflow: assurance.WorkflowIdentity{
			Path:         filepath.ToSlash(*workflowPath),
			SourceCommit: *workflowSourceCommit,
			SHA256:       digestBytes(workflowRaw),
		},
		Execution:   assurance.ExecutionIdentity{RunID: *runID, JobID: *jobID, Attempt: *attempt, Trigger: *trigger},
		Proof:       assurance.ProofIdentity{ID: gate.Proof, PolicySHA256: policyDigest},
		Inventories: namedDigests,
		Toolchain:   toolchain,
		Runner: assurance.RunnerIdentity{
			OperatingSystem: *osName, Architecture: *arch, RequestedLabel: *runnerLabel,
			Image: *image, ImageVersion: *imageVersion,
		},
		Commands:    commands,
		Timing:      assurance.Timing{StartedAt: gate.StartedAt, CompletedAt: gate.FinishedAt, DurationMillis: finished.Sub(started).Milliseconds()},
		CachePolicy: proof.CachePolicy,
		Result:      gate.Status,
		Terminal:    true,
		Artifacts:   artifactRecords,
		Limitations: []string{},
	}
	if !proof.Deterministic {
		receipt.ExpiresAt = finished.Add(time.Duration(proof.FreshnessSeconds) * time.Second).UTC().Format(time.RFC3339Nano)
	}
	if err := assurance.ValidateReceipt(receipt, policy, policyDigest, finished); err != nil {
		return fmt.Errorf("issued receipt is invalid: %w", err)
	}
	if err := writeJSONAtomicUnderRoot(*root, *outPath, receipt); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "issued terminal receipt %s (%s)\n", receipt.ReceiptID, receipt.Result)
	return err
}

const maxArtifactBytes int64 = 1 << 30

func digestRootArtifact(root, relative string) (assurance.Artifact, error) {
	return digestRootArtifactWithinLimit(root, relative, maxArtifactBytes)
}

func digestRootArtifactWithinLimit(root, relative string, maxBytes int64) (assurance.Artifact, error) {
	if maxBytes < 0 || maxBytes == math.MaxInt64 {
		return assurance.Artifact{}, fmt.Errorf("invalid artifact byte bound %d", maxBytes)
	}
	resolvedRoot, err := resolveRootDirectory(root, ".")
	if err != nil {
		return assurance.Artifact{}, err
	}
	if !safeRelativePath(relative) {
		return assurance.Artifact{}, fmt.Errorf("unsafe relative path %q", relative)
	}
	candidate := filepath.Join(resolvedRoot, filepath.FromSlash(relative))
	info, err := os.Lstat(candidate)
	if err != nil {
		return assurance.Artifact{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return assurance.Artifact{}, fmt.Errorf("path %q is not a regular non-symlink file", relative)
	}
	if info.Size() < 0 || info.Size() > maxBytes {
		return assurance.Artifact{}, fmt.Errorf("artifact %q size %d is outside the 0..%d byte bound", relative, info.Size(), maxBytes)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return assurance.Artifact{}, err
	}
	if !withinDirectory(resolvedRoot, resolvedCandidate) {
		return assurance.Artifact{}, fmt.Errorf("path %q escapes root", relative)
	}
	file, err := os.Open(resolvedCandidate)
	if err != nil {
		return assurance.Artifact{}, err
	}
	defer file.Close()
	opened, err := file.Stat()
	if err != nil {
		return assurance.Artifact{}, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return assurance.Artifact{}, fmt.Errorf("artifact %q changed while being opened", relative)
	}
	hash := sha256.New()
	written, err := io.Copy(hash, io.LimitReader(file, maxBytes+1))
	if err != nil {
		return assurance.Artifact{}, err
	}
	if written != opened.Size() || written > maxBytes {
		return assurance.Artifact{}, fmt.Errorf("artifact %q changed size while being hashed", relative)
	}
	finished, err := file.Stat()
	if err != nil {
		return assurance.Artifact{}, err
	}
	if finished.Size() != opened.Size() || !finished.ModTime().Equal(opened.ModTime()) {
		return assurance.Artifact{}, fmt.Errorf("artifact %q changed while being hashed", relative)
	}
	return assurance.Artifact{Path: relative, Size: written, SHA256: hex.EncodeToString(hash.Sum(nil))}, nil
}

func proofByID(policy assurance.ProofPolicy, id string) (assurance.Proof, error) {
	for _, proof := range policy.Proofs {
		if proof.ID == id {
			return proof, nil
		}
	}
	return assurance.Proof{}, fmt.Errorf("gate proof %q is not in proof policy", id)
}

func validateGateSteps(gate gateExecutionRecord, commands [][]string) error {
	if len(gate.Steps) != len(commands) {
		return errors.New("gate step inventory does not match proof policy")
	}
	failed := false
	for index, step := range gate.Steps {
		if step.Name == "" || (step.Status != "PASS" && step.Status != "FAIL") || step.ExitCode < 0 {
			return errors.New("gate step is invalid")
		}
		if !stringSlicesEqual(step.Command, commands[index]) {
			return errors.New("gate step command does not match proof policy")
		}
		if step.Status == "PASS" && step.ExitCode != 0 || step.Status == "FAIL" && step.ExitCode == 0 {
			return errors.New("gate step status and exit code disagree")
		}
		failed = failed || step.Status == "FAIL"
	}
	if failed != (gate.Status == "FAIL") {
		return errors.New("gate status does not match its steps")
	}
	return nil
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func goToolIdentity() (assurance.ToolIdentity, error) {
	path, err := exec.LookPath("go")
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	versionRaw, err := exec.Command("go", "version").Output()
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	return assurance.ToolIdentity{Name: "go", Version: strings.TrimSpace(string(versionRaw)), SHA256: digestBytes(raw)}, nil
}

func proofToolchain(root, proof string, artifacts []assurance.Artifact) ([]assurance.ToolIdentity, error) {
	goTool, err := goToolIdentity()
	if err != nil {
		return nil, err
	}
	tools := []assurance.ToolIdentity{goTool}
	switch proof {
	case "android-host":
		java, err := executableToolIdentity("java", "java", "-version")
		if err != nil {
			return nil, err
		}
		gradleVersion, err := gradleWrapperVersion(root)
		if err != nil {
			return nil, err
		}
		wrapper, err := repositoryToolIdentity(root, "gradle-wrapper", "android/gradle/wrapper/gradle-wrapper.jar", gradleVersion)
		if err != nil {
			return nil, err
		}
		tools = append(tools, java, wrapper)
	case "dependency-freshness":
		govulncheckPath := ".tools/bin/govulncheck"
		osvPath := ".tools/bin/osv-scanner_linux_amd64"
		if runtime.GOOS == "windows" {
			govulncheckPath += ".exe"
			osvPath = ".tools/bin/osv-scanner_windows_amd64.exe"
		}
		govulncheck, err := repositoryToolIdentity(root, "govulncheck", govulncheckPath, "v1.6.0")
		if err != nil {
			return nil, err
		}
		osv, err := repositoryToolIdentity(root, "osv-scanner", osvPath, "v2.4.0")
		if err != nil {
			return nil, err
		}
		tools = append(tools, govulncheck, osv)
	default:
		if strings.HasPrefix(proof, "android-device-api") {
			identityPath := ""
			for _, artifact := range artifacts {
				if strings.HasSuffix(artifact.Path, "-identity.json") {
					identityPath = artifact.Path
					break
				}
			}
			if identityPath == "" {
				return nil, errors.New("Android device receipt requires an emulator identity artifact")
			}
			identityRaw, err := readRootFile(root, identityPath)
			if err != nil {
				return nil, err
			}
			var identity emulatorPackageIdentity
			if err := assurance.DecodeStrict(bytes.NewReader(identityRaw), &identity); err != nil {
				return nil, fmt.Errorf("decode emulator identity: %w", err)
			}
			if err := identity.validate(proof); err != nil {
				return nil, err
			}
			tools = append(tools,
				assurance.ToolIdentity{Name: "android-emulator", Version: identity.Emulator.Version + "/" + identity.Emulator.PackageRevision, SHA256: identity.Emulator.ExecutableSHA256},
				assurance.ToolIdentity{Name: "adb", Version: identity.PlatformTools.ADBVersion + "/" + identity.PlatformTools.PackageRevision, SHA256: identity.PlatformTools.ADBSHA256},
			)
		}
	}
	sort.Slice(tools, func(left, right int) bool { return tools[left].Name < tools[right].Name })
	return tools, nil
}

type emulatorPackageIdentity struct {
	Schema   string `json:"schema"`
	API      int    `json:"api"`
	ABI      string `json:"abi"`
	Emulator struct {
		Version          string `json:"version"`
		PackageRevision  string `json:"packageRevision"`
		ExecutableSHA256 string `json:"executableSha256"`
		MetadataSHA256   string `json:"metadataSha256"`
	} `json:"emulator"`
	PlatformTools struct {
		ADBVersion      string `json:"adbVersion"`
		PackageRevision string `json:"packageRevision"`
		ADBSHA256       string `json:"adbSha256"`
		MetadataSHA256  string `json:"metadataSha256"`
	} `json:"platformTools"`
	SystemImage struct {
		Package        string `json:"package"`
		Revision       string `json:"revision"`
		MetadataSHA256 string `json:"metadataSha256"`
	} `json:"systemImage"`
	CommandLineTools struct {
		PackageRevision string `json:"packageRevision"`
		MetadataSHA256  string `json:"metadataSha256"`
	} `json:"commandLineTools"`
}

func (value emulatorPackageIdentity) validate(proof string) error {
	expectedAPI := strings.TrimPrefix(proof, "android-device-api")
	if value.Schema != "kurdistan-emulator-package-identity-v1" || strconv.Itoa(value.API) != expectedAPI || value.ABI != "x86_64" || value.SystemImage.Package != "system-images;android-"+expectedAPI+";google_apis;x86_64" {
		return errors.New("emulator identity does not match device proof")
	}
	for name, digest := range map[string]string{"emulator": value.Emulator.ExecutableSHA256, "emulator-metadata": value.Emulator.MetadataSHA256, "adb": value.PlatformTools.ADBSHA256, "platform-tools-metadata": value.PlatformTools.MetadataSHA256, "system-image-metadata": value.SystemImage.MetadataSHA256, "command-line-tools-metadata": value.CommandLineTools.MetadataSHA256} {
		if len(digest) != 64 || strings.Trim(digest, "0123456789abcdef") != "" {
			return fmt.Errorf("emulator identity %s digest is invalid", name)
		}
	}
	for name, version := range map[string]string{"emulator": value.Emulator.Version, "emulator-package": value.Emulator.PackageRevision, "adb": value.PlatformTools.ADBVersion, "platform-tools": value.PlatformTools.PackageRevision, "system-image": value.SystemImage.Revision, "command-line-tools": value.CommandLineTools.PackageRevision} {
		if version == "" || version != strings.TrimSpace(version) || len(version) > 64 {
			return fmt.Errorf("emulator identity %s version is invalid", name)
		}
	}
	return nil
}

func executableToolIdentity(name, executable string, versionArgs ...string) (assurance.ToolIdentity, error) {
	path, err := exec.LookPath(executable)
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	raw, err := os.ReadFile(resolved)
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	versionRaw, err := exec.Command(executable, versionArgs...).CombinedOutput()
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	version := strings.TrimSpace(strings.Split(strings.ReplaceAll(string(versionRaw), "\r\n", "\n"), "\n")[0])
	return assurance.ToolIdentity{Name: name, Version: version, SHA256: digestBytes(raw)}, nil
}

func repositoryToolIdentity(root, name, relative, version string) (assurance.ToolIdentity, error) {
	artifact, err := digestRootArtifact(root, relative)
	if err != nil {
		return assurance.ToolIdentity{}, err
	}
	return assurance.ToolIdentity{Name: name, Version: version, SHA256: artifact.SHA256}, nil
}

func gradleWrapperVersion(root string) (string, error) {
	raw, err := readRootFile(root, "android/gradle/wrapper/gradle-wrapper.properties")
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
		if strings.HasPrefix(line, "distributionUrl=") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "distributionUrl="))
			if start := strings.Index(value, "gradle-"); start >= 0 {
				value = value[start+len("gradle-"):]
				if end := strings.Index(value, "-"); end > 0 {
					return value[:end], nil
				}
			}
		}
	}
	return "", errors.New("Gradle wrapper distribution version is missing")
}

func splitNamedPath(value string) (string, string, error) {
	name, path, ok := strings.Cut(value, "=")
	if !ok || name == "" || path == "" || strings.Contains(name, "=") {
		return "", "", fmt.Errorf("invalid name=path value %q", value)
	}
	return name, path, nil
}

func duplicateNamedDigest(values []assurance.NamedDigest) bool {
	for index := 1; index < len(values); index++ {
		if values[index-1].Name == values[index].Name {
			return true
		}
	}
	return false
}

func gitOutput(root string, args ...string) (string, error) {
	command := exec.Command("git", args...)
	command.Dir = root
	raw, err := command.Output()
	if err != nil {
		return "", fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
	}
	return strings.TrimSpace(string(raw)), nil
}

func readGitBlob(root, commit, relative string) ([]byte, error) {
	if len(commit) != 40 || strings.Trim(commit, "0123456789abcdef") != "" {
		return nil, errors.New("workflow source commit must be a lowercase 40-hex object id")
	}
	if !safeRelativePath(relative) || !strings.HasPrefix(filepath.ToSlash(relative), ".github/workflows/") {
		return nil, fmt.Errorf("unsafe workflow path %q", relative)
	}
	command := exec.Command("git", "show", commit+":"+filepath.ToSlash(relative))
	command.Dir = root
	raw, err := command.Output()
	if err != nil {
		return nil, fmt.Errorf("git show workflow at %s: %w", commit, err)
	}
	return raw, nil
}

func digestBytes(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func writeJSONAtomicUnderRoot(root, relative string, value any) error {
	if !safeRelativePath(relative) {
		return fmt.Errorf("unsafe output path %q", relative)
	}
	resolvedRoot, err := resolveRootDirectory(root, ".")
	if err != nil {
		return err
	}
	path := filepath.Join(resolvedRoot, filepath.FromSlash(relative))
	if !withinDirectory(resolvedRoot, path) {
		return errors.New("output path escapes root")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(filepath.Dir(path), ".assure-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	defer os.Remove(temporaryName)
	encoder := json.NewEncoder(temporary)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, path); err != nil {
		return err
	}
	return nil
}

func envOr(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

func envIntOr(name string, fallback int) int {
	value, err := strconv.Atoi(os.Getenv(name))
	if err != nil || value < 1 {
		return fallback
	}
	return value
}

func normalizedOS(value string) string {
	if value == "darwin" {
		return "macos"
	}
	return value
}
