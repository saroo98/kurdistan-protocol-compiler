// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestVerifyRepositoryOffline(t *testing.T) {
	if err := verify(repositoryRoot(t), "offline", ownerInputDefault); err != nil {
		t.Fatal(err)
	}
}

func TestRejectDuplicateKeys(t *testing.T) {
	if err := rejectDuplicateKeys([]byte(`{"schema":"x","schema":"y"}`)); err == nil {
		t.Fatal("duplicate key accepted")
	}
}

func TestRejectUnknownStatusField(t *testing.T) {
	root := copyRepositoryAuthority(t)
	path := filepath.Join(root, filepath.FromSlash(statusPath))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = []byte(strings.Replace(string(raw), `"phase": 16,`, `"phase": 16, "unknown": true,`, 1))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verify(root, "offline", ownerInputDefault); err == nil {
		t.Fatal("unknown status field accepted")
	}
}

func TestValidateOwnerRejectsProjectReuseAndApprovalCollision(t *testing.T) {
	var value ownerInputs
	root := repositoryRoot(t)
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.ProductionProjects.Trust = value.QualificationProjects.Trust
	if err := validateOwner(value); err == nil {
		t.Fatal("project reuse accepted")
	}
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.ApprovalClasses[0].ExecutorActorRef = value.ApprovalClasses[0].ApproverActorRefs[0]
	if err := validateOwner(value); err == nil {
		t.Fatal("approver/executor collision accepted")
	}
}

func TestValidateOwnerRequiresExactProtectedWorkflowAndEnvironmentSet(t *testing.T) {
	var value ownerInputs
	root := repositoryRoot(t)
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.WIF.Environments[0] = "phase16-production"
	if err := validateOwner(value); err == nil {
		t.Fatal("duplicate protected environment accepted")
	}
	if err := decodeFile(root, "testdata/fixtures/phase16/owner-inputs.example.json", &value); err != nil {
		t.Fatal(err)
	}
	value.WIF.WorkflowPaths[0] = ".github/workflows/ordinary.yml"
	if err := validateOwner(value); err == nil {
		t.Fatal("unapproved production workflow accepted")
	}
}

func TestValidateStatusRejectsFalseCompletion(t *testing.T) {
	var value status
	root := repositoryRoot(t)
	if err := decodeFile(root, statusPath, &value); err != nil {
		t.Fatal(err)
	}
	value.State = "COMPLETE"
	if err := validateStatus(root, value); err == nil {
		t.Fatal("local-only completion accepted")
	}
}

func TestRejectSecretCanaries(t *testing.T) {
	for _, value := range []string{"-----BEGIN PRIVATE KEY-----", `{"access_token":"value"}`, "github_pat_example"} {
		if err := rejectSecretMaterial([]byte(value)); err == nil {
			t.Fatalf("secret canary accepted: %q", value)
		}
	}
}

func TestRejectPrivateTerraformPlanInGitHubArtifacts(t *testing.T) {
	root := copyRepositoryAuthority(t)
	path := filepath.Join(root, filepath.FromSlash(".github/workflows/phase16-production-plan.yml"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\n# actions/upload-artifact must remain forbidden here\n")...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyImplementationAuthority(root); err == nil {
		t.Fatal("private Terraform plan artifact exposure accepted")
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func copyRepositoryAuthority(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	root := t.TempDir()
	for _, path := range requiredFiles {
		from := filepath.Join(source, filepath.FromSlash(path))
		to := filepath.Join(root, filepath.FromSlash(path))
		raw, err := os.ReadFile(from)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.MkdirAll(filepath.Dir(to), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(to, raw, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	gitDir := filepath.Join(root, ".git")
	if err := os.MkdirAll(gitDir, 0o755); err != nil {
		t.Fatal(err)
	}
	// validateStatus calls git. Use the real repository for mutation-oriented
	// tests that do not need baseline validation by replacing the status commit
	// check through a worktree file would weaken production behavior, so this
	// helper is used only to exercise strict decode before that point.
	return root
}
