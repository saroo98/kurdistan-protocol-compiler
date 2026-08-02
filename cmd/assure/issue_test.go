// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
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
