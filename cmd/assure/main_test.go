// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/assurance"
)

func TestRunReceiptValidate(t *testing.T) {
	root, policy, policyRaw := writeTestPolicy(t)
	receipt, receiptRaw := writeTestReceipt(t, root, policy, policyRaw)
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"receipt", "validate", "-root", root,
		"-policy", "config/ci/proof-policy.json",
		"-receipt", "receipts/go-core-linux.json",
		"-now", "2026-08-02T10:02:00Z",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run receipt validate: %v (stderr %q)", err, stderr.String())
	}
	if got, want := stdout.String(), "valid receipt "+receipt.ReceiptID+"\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
	if len(receiptRaw) == 0 {
		t.Fatal("empty receipt fixture")
	}
}

func TestRunCertificateValidate(t *testing.T) {
	root, policy, policyRaw := writeTestPolicy(t)
	receipt, receiptRaw := writeTestReceipt(t, root, policy, policyRaw)
	policyDigest := fmt.Sprintf("%x", sha256.Sum256(policyRaw))
	receiptDigest := fmt.Sprintf("%x", sha256.Sum256(receiptRaw))
	certificate := assurance.Certificate{
		Schema:         assurance.CertificateSchema,
		CertificateID:  "main-assurance",
		Subject:        receipt.Subject,
		PolicySHA256:   policyDigest,
		RequiredProofs: []string{"go-core"},
		Receipts: []assurance.ReceiptReference{{
			ProofID:         "go-core",
			OperatingSystem: "linux",
			ReceiptID:       receipt.ReceiptID,
			Path:            "receipts/go-core-linux.json",
			SHA256:          receiptDigest,
		}},
		IssuedAt: "2026-08-02T10:01:30Z",
		Status:   "PASS",
	}
	writeJSONFile(t, filepath.Join(root, "certificate.json"), certificate)
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"certificate", "validate", "-root", root,
		"-policy", "config/ci/proof-policy.json",
		"-certificate", "certificate.json",
		"-receipts-root", ".",
		"-required", "go-core",
		"-now", "2026-08-02T10:02:00Z",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run certificate validate: %v (stderr %q)", err, stderr.String())
	}
	if got, want := stdout.String(), "valid certificate main-assurance\n"; got != want {
		t.Fatalf("stdout = %q, want %q", got, want)
	}
}

func TestRunCertificateValidateRejectsUnexpectedWorkflowExecution(t *testing.T) {
	root, policy, policyRaw := writeTestPolicy(t)
	receipt, receiptRaw := writeTestReceipt(t, root, policy, policyRaw)
	certificate := assurance.Certificate{
		Schema: assurance.CertificateSchema, CertificateID: "main-assurance", Subject: receipt.Subject,
		PolicySHA256: receipt.Proof.PolicySHA256, RequiredProofs: []string{"go-core"},
		Receipts: []assurance.ReceiptReference{{
			ProofID: receipt.Proof.ID, OperatingSystem: receipt.Runner.OperatingSystem,
			ReceiptID: receipt.ReceiptID, Path: "receipts/go-core-linux.json", SHA256: fmt.Sprintf("%x", sha256.Sum256(receiptRaw)),
		}},
		IssuedAt: "2026-08-02T10:01:30Z", Status: "PASS",
	}
	writeJSONFile(t, filepath.Join(root, "certificate.json"), certificate)
	err := run([]string{
		"certificate", "validate", "-root", root,
		"-certificate", "certificate.json", "-receipts-root", ".", "-required", "go-core",
		"-expected-run-id", "999", "-now", "2026-08-02T10:02:00Z",
	}, &bytes.Buffer{}, &bytes.Buffer{})
	if err == nil {
		t.Fatal("expected workflow run mismatch rejection")
	}
}

func TestRunPolicyInventory(t *testing.T) {
	root, _, _ := writeTestPolicy(t)
	var stdout, stderr bytes.Buffer
	if err := run([]string{"policy", "inventory", "-root", root, "-policy", "config/ci/proof-policy.json"}, &stdout, &stderr); err != nil {
		t.Fatalf("run policy inventory: %v (stderr %q)", err, stderr.String())
	}
	inventory, err := assurance.DecodePolicyInventory(strings.NewReader(stdout.String()))
	if err != nil {
		t.Fatalf("decode inventory output: %v", err)
	}
	if len(inventory.Lanes) != 1 || inventory.Lanes[0].ProofID != "go-core" {
		t.Fatalf("unexpected inventory: %+v", inventory)
	}
}

func TestRunImpactCombinesExplicitAndFilePathsDenyByDefault(t *testing.T) {
	root := t.TempDir()
	proofPolicy := assurance.ProofPolicy{
		Schema: assurance.ProofPolicySchema,
		Proofs: []assurance.Proof{
			{ID: "docs-evidence", Commands: [][]string{{"go", "test", "./docs"}}, OperatingSystems: []string{"linux"}, CachePolicy: assurance.CacheIndependent, Deterministic: true, InvalidatedBy: []string{"docs/**"}, AuthorizedPhase: 16},
			{ID: "go-core", Commands: [][]string{{"go", "test", "./..."}}, OperatingSystems: []string{"linux"}, CachePolicy: assurance.CacheIndependent, Deterministic: true, InvalidatedBy: []string{"go.mod"}, AuthorizedPhase: 16},
		},
	}
	policy := assurance.ImpactPolicy{
		Schema:        assurance.ImpactPolicySchema,
		DefaultProofs: []string{"go-core"},
		Rules:         []assurance.ImpactRule{{Pattern: "docs/**", Proofs: []string{"docs-evidence"}}},
	}
	writeJSONFile(t, filepath.Join(root, "config", "ci", "proof-policy.json"), proofPolicy)
	writeJSONFile(t, filepath.Join(root, "config", "ci", "impact-policy.json"), policy)
	if err := os.WriteFile(filepath.Join(root, "changed-paths.txt"), []byte("new/unknown/file.txt\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	err := run([]string{
		"impact", "-root", root,
		"-path", "docs/guide.md",
		"-paths-file", "changed-paths.txt",
	}, &stdout, &stderr)
	if err != nil {
		t.Fatalf("run impact: %v (stderr %q)", err, stderr.String())
	}
	var output struct {
		Schema string   `json:"schema"`
		Paths  []string `json:"paths"`
		Proofs []string `json:"proofs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	if output.Schema != "kurdistan-impact-selection-v1" || !reflect.DeepEqual(output.Paths, []string{"docs/guide.md", "new/unknown/file.txt"}) || !reflect.DeepEqual(output.Proofs, []string{"docs-evidence", "go-core"}) {
		t.Fatalf("unexpected impact output: %+v", output)
	}
}

func TestRunImpactRejectsChangedPathTraversal(t *testing.T) {
	root := t.TempDir()
	proofPolicy := assurance.ProofPolicy{Schema: assurance.ProofPolicySchema, Proofs: []assurance.Proof{{ID: "go-core", Commands: [][]string{{"go", "test", "./..."}}, OperatingSystems: []string{"linux"}, CachePolicy: assurance.CacheIndependent, Deterministic: true, InvalidatedBy: []string{"go.mod"}, AuthorizedPhase: 16}}}
	policy := assurance.ImpactPolicy{Schema: assurance.ImpactPolicySchema, DefaultProofs: []string{"go-core"}, Rules: []assurance.ImpactRule{{Pattern: "docs/**", Proofs: []string{"go-core"}}}}
	writeJSONFile(t, filepath.Join(root, "config", "ci", "proof-policy.json"), proofPolicy)
	writeJSONFile(t, filepath.Join(root, "config", "ci", "impact-policy.json"), policy)
	if err := run([]string{"impact", "-root", root, "-path", "../outside.txt"}, &bytes.Buffer{}, &bytes.Buffer{}); err == nil {
		t.Fatal("expected changed path traversal rejection")
	}
}

func TestQualificationWorkflowImpactSelectsCompletePRProofSet(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{
		"impact", "-root", root,
		"-path", ".github/workflows/phase16-qualification.yml",
	}, &stdout, &stderr); err != nil {
		t.Fatalf("run qualification workflow impact: %v (stderr %q)", err, stderr.String())
	}
	var output struct {
		Proofs []string `json:"proofs"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"android-device-api26",
		"android-device-api34",
		"android-device-api36",
		"android-pr-host",
		"dependency-freshness",
		"docs-evidence",
		"go-audit",
		"go-core",
		"go-executable-evidence",
		"operator",
	}
	if !reflect.DeepEqual(output.Proofs, want) {
		t.Fatalf("qualification workflow proofs = %v, want %v", output.Proofs, want)
	}
}

func TestRepositoryImpactPolicyPreservesEvidenceInvalidators(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		path string
		want []string
	}{
		{
			name: "general evidence invalidates Go proof and audit",
			path: "testdata/evidence/phase16/example.json",
			want: []string{"docs-evidence", "go-audit", "go-core", "operator"},
		},
		{
			name: "operator evidence also invalidates operator proof",
			path: "testdata/evidence/phase12/example.json",
			want: []string{"docs-evidence", "go-audit", "go-core", "operator"},
		},
		{
			name: "Go dependencies require freshness",
			path: "go.mod",
			want: []string{"android-device-api26", "android-device-api34", "android-device-api36", "android-pr-host", "dependency-freshness", "go-audit", "go-core", "go-executable-evidence", "operator"},
		},
		{
			name: "evidence validator changes require their own proof",
			path: "cmd/phase15verify/main.go",
			want: []string{"docs-evidence", "go-audit", "go-core"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if err := run([]string{"impact", "-root", root, "-path", test.path}, &stdout, &stderr); err != nil {
				t.Fatalf("run impact: %v (stderr %q)", err, stderr.String())
			}
			var output struct {
				Proofs []string `json:"proofs"`
			}
			if err := json.Unmarshal(stdout.Bytes(), &output); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(output.Proofs, test.want) {
				t.Fatalf("proofs = %v, want %v", output.Proofs, test.want)
			}
		})
	}
}

func TestRepositoryAssurancePolicyDefinesExactCertificateLanes(t *testing.T) {
	policy, _, err := readProofPolicy("../..", "config/ci/proof-policy.json")
	if err != nil {
		t.Fatalf("read repository proof policy: %v", err)
	}
	required := map[string]bool{
		"android-device-api26":   true,
		"android-device-api34":   true,
		"android-device-api36":   true,
		"android-host":           true,
		"dependency-freshness":   true,
		"docs-evidence":          true,
		"go-audit":               true,
		"go-core":                true,
		"go-executable-evidence": true,
		"operator":               true,
	}
	laneCount := 0
	for _, proof := range policy.Proofs {
		if !required[proof.ID] {
			continue
		}
		laneCount += len(proof.OperatingSystems)
		if proof.ID == "dependency-freshness" && (len(proof.OperatingSystems) != 1 || proof.OperatingSystems[0] != "linux") {
			t.Fatalf("dependency-freshness operating systems = %v, want [linux]", proof.OperatingSystems)
		}
		delete(required, proof.ID)
	}
	if len(required) != 0 {
		t.Fatalf("repository policy is missing required certificate proofs: %v", required)
	}
	if laneCount != 15 {
		t.Fatalf("repository certificate lane count = %d, want 15", laneCount)
	}
}

func TestRunWorkflowVerifierAgainstRepository(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if err := run([]string{"workflow", "-root", root}, &stdout, &stderr); err != nil {
		t.Fatalf("run workflow: %v (stderr %q)", err, stderr.String())
	}
	if !strings.Contains(stdout.String(), "WORKFLOW VERIFICATION PASSED") {
		t.Fatalf("stdout = %q", stdout.String())
	}
}

func writeTestPolicy(t *testing.T) (string, assurance.ProofPolicy, []byte) {
	t.Helper()
	root := t.TempDir()
	policy := assurance.ProofPolicy{
		Schema: assurance.ProofPolicySchema,
		Proofs: []assurance.Proof{{
			ID: "go-core", Commands: [][]string{{"go", "test", "./..."}},
			OperatingSystems: []string{"linux"}, CachePolicy: assurance.CacheIndependent,
			Deterministic: true, InvalidatedBy: []string{"go.mod"}, AuthorizedPhase: 16,
		}},
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "config", "ci", "proof-policy.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, policy, raw
}

func writeTestReceipt(t *testing.T, root string, policy assurance.ProofPolicy, policyRaw []byte) (assurance.Receipt, []byte) {
	t.Helper()
	workflowRaw := []byte("name: test assurance\n")
	workflowPath := filepath.Join(root, ".github", "workflows", "assurance.yml")
	if err := os.MkdirAll(filepath.Dir(workflowPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(workflowPath, workflowRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	gitTest(t, root, "init")
	gitTest(t, root, "config", "user.email", "test@example.invalid")
	gitTest(t, root, "config", "user.name", "Assure Test")
	gitTest(t, root, "add", ".")
	gitTest(t, root, "commit", "-m", "fixture")
	workflowSourceCommit, err := gitOutput(root, "rev-parse", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	receipt := assurance.Receipt{
		Schema: assurance.ReceiptSchema, ReceiptID: "run-123-go-core-linux",
		Subject: assurance.Subject{Repository: "saroo98/kurdistan-protocol-compiler", Commit: strings.Repeat("1", 40), Tree: strings.Repeat("2", 40), Ref: "refs/heads/main"},
		Workflow: assurance.WorkflowIdentity{
			Path:         ".github/workflows/assurance.yml",
			SourceCommit: workflowSourceCommit,
			SHA256:       fmt.Sprintf("%x", sha256.Sum256(workflowRaw)),
		},
		Execution:   assurance.ExecutionIdentity{RunID: "123", JobID: "test-linux", Attempt: 1, Trigger: "push"},
		Proof:       assurance.ProofIdentity{ID: "go-core", PolicySHA256: fmt.Sprintf("%x", sha256.Sum256(policyRaw))},
		Inventories: []assurance.NamedDigest{{Name: "go-tests", SHA256: strings.Repeat("4", 64)}},
		Toolchain:   []assurance.ToolIdentity{{Name: "go", Version: "go1.26.5", SHA256: strings.Repeat("5", 64)}},
		Runner:      assurance.RunnerIdentity{OperatingSystem: "linux", Architecture: "amd64", RequestedLabel: "ubuntu-24.04", Image: "ubuntu", ImageVersion: "20260801.1"},
		Commands:    policy.Proofs[0].Commands,
		Timing:      assurance.Timing{StartedAt: "2026-08-02T10:00:00Z", CompletedAt: "2026-08-02T10:01:00Z", DurationMillis: int64(time.Minute / time.Millisecond)},
		CachePolicy: assurance.CacheIndependent, Result: "PASS", Terminal: true,
		Artifacts: []assurance.Artifact{}, Limitations: []string{},
	}
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "receipts", "go-core-linux.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return receipt, raw
}

func writeJSONFile(t *testing.T, path string, value any) {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestInventoryDirectAliasMatchesPolicyInventory(t *testing.T) {
	var direct, legacy, stderr bytes.Buffer
	root := filepath.Join("..", "..")
	if err := run([]string{"inventory", "-root", root}, &direct, &stderr); err != nil {
		t.Fatalf("direct inventory: %v (stderr %q)", err, stderr.String())
	}
	stderr.Reset()
	if err := run([]string{"policy", "inventory", "-root", root}, &legacy, &stderr); err != nil {
		t.Fatalf("legacy inventory: %v (stderr %q)", err, stderr.String())
	}
	if direct.String() != legacy.String() {
		t.Fatal("direct and legacy inventory commands differ")
	}
}
