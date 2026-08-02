// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/assurance"
)

func TestReceiptIssueProducesValidPolicyBoundReceipt(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "config/ci/proof-policy.json", `{
  "schema":"kurdistan-proof-policy-v1",
  "proofs":[{
    "id":"go-audit",
    "commands":[["go","run","./cmd/kcheck","--full"]],
    "operatingSystems":["linux","windows"],
    "cachePolicy":"CACHE_INDEPENDENT",
    "deterministic":true,
    "invalidatedBy":["internal/audit/**"],
    "authorizedPhase":16
  }]
}`)
	writeTestFile(t, root, ".github/workflows/assurance.yml", "name: assurance\n")
	writeTestFile(t, root, "gate.json", `{
  "schema":"kurdistan-gate-execution-v1",
  "proof":"go-audit",
  "startedAt":"2026-08-02T10:00:00Z",
  "finishedAt":"2026-08-02T10:00:01Z",
  "terminal":true,
  "status":"PASS",
  "steps":[{"name":"audit","command":["go","run","./cmd/kcheck","--full"],"status":"PASS","exitCode":0}]
}`)
	gitTest(t, root, "init")
	gitTest(t, root, "config", "user.email", "test@example.invalid")
	gitTest(t, root, "config", "user.name", "Assure Test")
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "fixture")
	workflowSourceCommit, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "subject.txt", "new exact subject\n")
	gitTest(t, root, "add", "subject.txt")
	gitTest(t, root, "commit", "-m", "new subject")
	commit, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, ".github/workflows/assurance.yml", "name: uncommitted substitution\n")

	var stdout, stderr bytes.Buffer
	err = runReceiptIssue([]string{
		"-root", root,
		"-gate", "gate.json",
		"-workflow", ".github/workflows/assurance.yml",
		"-workflow-source-commit", workflowSourceCommit,
		"-out", ".tools/assurance/receipt.json",
		"-run-id", "123",
		"-job-id", "go-audit-linux",
		"-commit", commit,
		"-ref", "refs/heads/test",
		"-os", "linux",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("receipt issue: %v; stderr=%s", err, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(root, ".tools", "assurance", "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := assurance.DecodeReceipt(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if receipt.Proof.ID != "go-audit" || receipt.Result != "PASS" || receipt.Subject.Repository != "saroo98/kurdistan-protocol-compiler" {
		t.Fatalf("unexpected receipt: %+v", receipt)
	}
	if receipt.Subject.Commit != commit || receipt.Workflow.SourceCommit != workflowSourceCommit || receipt.Workflow.SHA256 != digestBytes([]byte("name: assurance\n")) {
		t.Fatalf("receipt did not preserve separate subject and executed-workflow identity: %+v", receipt)
	}
}

func TestReceiptIssueStreamsAndroidSizedArtifact(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "config/ci/proof-policy.json", `{
  "schema":"kurdistan-proof-policy-v1",
  "proofs":[{
    "id":"go-audit",
    "commands":[["go","run","./cmd/kcheck","--full"]],
    "operatingSystems":["linux"],
    "cachePolicy":"CACHE_INDEPENDENT",
    "deterministic":true,
    "invalidatedBy":["internal/audit/**"],
    "authorizedPhase":16
  }]
}`)
	writeTestFile(t, root, ".github/workflows/assurance.yml", "name: assurance\n")
	writeTestFile(t, root, "gate.json", `{
  "schema":"kurdistan-gate-execution-v1",
  "proof":"go-audit",
  "startedAt":"2026-08-02T10:00:00Z",
  "finishedAt":"2026-08-02T10:00:01Z",
  "terminal":true,
  "status":"PASS",
  "steps":[{"name":"audit","command":["go","run","./cmd/kcheck","--full"],"status":"PASS","exitCode":0}]
}`)
	artifact := bytes.Repeat([]byte{0xa5}, maxInputBytes+1)
	artifactPath := filepath.Join(root, "app.apk")
	if err := os.WriteFile(artifactPath, artifact, 0o600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, root, "init")
	gitTest(t, root, "config", "user.email", "test@example.invalid")
	gitTest(t, root, "config", "user.name", "Assure Test")
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "fixture")
	commit, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	err = runReceiptIssue([]string{
		"-root", root,
		"-gate", "gate.json",
		"-workflow", ".github/workflows/assurance.yml",
		"-out", ".tools/assurance/receipt.json",
		"-run-id", "123",
		"-job-id", "go-audit-linux",
		"-commit", commit,
		"-ref", "refs/heads/test",
		"-os", "linux",
		"-artifact", "app.apk",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("receipt issue: %v; stderr=%s", err, stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(root, ".tools", "assurance", "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := assurance.DecodeReceipt(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(receipt.Artifacts) != 1 || receipt.Artifacts[0].Size != int64(len(artifact)) || receipt.Artifacts[0].SHA256 != digestBytes(artifact) {
		t.Fatalf("unexpected artifact receipt: %+v", receipt.Artifacts)
	}
}

func TestDigestRootArtifactRejectsOversizedSparseFile(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "oversized.apk")
	file, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Truncate(maxArtifactBytes + 1); err != nil {
		file.Close()
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := digestRootArtifact(root, "oversized.apk"); err == nil {
		t.Fatal("expected oversized artifact to be rejected")
	}
}

func TestValidateGateStepsRejectsContradictoryResult(t *testing.T) {
	record := gateExecutionRecord{Status: "PASS", Steps: []struct {
		Name     string   `json:"name"`
		Command  []string `json:"command"`
		Status   string   `json:"status"`
		ExitCode int      `json:"exitCode"`
	}{{Name: "audit", Command: []string{"go", "test"}, Status: "FAIL", ExitCode: 1}}}
	if err := validateGateSteps(record, [][]string{{"go", "test"}}); err == nil {
		t.Fatal("expected contradictory gate result to fail")
	}
}

func TestTimingPercentilesUseNearestRank(t *testing.T) {
	got := percentiles([]int64{50, 10, 40, 20, 30})
	if got.P50Millis != 30 || got.P95Millis != 50 {
		t.Fatalf("percentiles = %+v", got)
	}
}

func TestEmulatorPackageIdentityRequiresExactProofAndDigests(t *testing.T) {
	digest := strings.Repeat("a", 64)
	identity := emulatorPackageIdentity{Schema: "kurdistan-emulator-package-identity-v1", API: 34, ABI: "x86_64"}
	identity.Emulator.Version = "36.2.12"
	identity.Emulator.PackageRevision = "36.2.12"
	identity.Emulator.ExecutableSHA256 = digest
	identity.Emulator.MetadataSHA256 = digest
	identity.PlatformTools.ADBVersion = "1.0.41"
	identity.PlatformTools.PackageRevision = "36.0.0"
	identity.PlatformTools.ADBSHA256 = digest
	identity.PlatformTools.MetadataSHA256 = digest
	identity.SystemImage.Package = "system-images;android-34;google_apis;x86_64"
	identity.SystemImage.Revision = "14"
	identity.SystemImage.MetadataSHA256 = digest
	identity.CommandLineTools.PackageRevision = "19.0"
	identity.CommandLineTools.MetadataSHA256 = digest
	if err := identity.validate("android-device-api34"); err != nil {
		t.Fatalf("valid emulator identity rejected: %v", err)
	}
	identity.API = 36
	if err := identity.validate("android-device-api34"); err == nil {
		t.Fatal("mismatched emulator API passed")
	}
}

func TestDeviceProofToolchainRequiresIdentityArtifact(t *testing.T) {
	if _, err := proofToolchain(t.TempDir(), "android-device-api34", nil); err == nil {
		t.Fatal("device proof without emulator identity artifact passed")
	}
}

func TestGradleWrapperVersionFailsClosed(t *testing.T) {
	root := t.TempDir()
	writeTestFile(t, root, "android/gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https\\://services.gradle.org/distributions/gradle-9.4.1-bin.zip\n")
	version, err := gradleWrapperVersion(root)
	if err != nil || version != "9.4.1" {
		t.Fatalf("Gradle version = %q, err = %v", version, err)
	}
	writeTestFile(t, root, "android/gradle/wrapper/gradle-wrapper.properties", "distributionUrl=https://example.invalid/not-gradle.zip\n")
	if _, err := gradleWrapperVersion(root); err == nil {
		t.Fatal("missing Gradle version passed")
	}
}

func writeTestFile(t *testing.T, root, relative, contents string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatal(err)
	}
}

func gitTest(t *testing.T, root string, args ...string) {
	t.Helper()
	command := exec.Command("git", args...)
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("git %v: %v\n%s", args, err, output)
	}
}
