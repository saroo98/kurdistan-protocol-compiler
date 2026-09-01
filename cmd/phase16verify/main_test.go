// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestVerifyRepositoryOffline(t *testing.T) {
	if err := verify(repositoryRoot(t), "offline", ownerInputDefault); err != nil && !errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatal(err)
	}
}

func TestVerifySelfHostedQualification(t *testing.T) {
	if err := verifySelfHostedQualification(repositoryRoot(t)); err != nil && !errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatal(err)
	}
}

func TestUnavailableHistoricalCommitIsExplicitAndKeepsOfflineGateBlocked(t *testing.T) {
	root := copyRepositoryAuthority(t)
	initEmptyGitRepository(t, root)
	copyPhase16PolicyFiles(t, root)
	var value status
	if err := decodeFile(repositoryRoot(t), statusPath, &value); err != nil {
		t.Fatal(err)
	}
	value.BaselineCommit = strings.Repeat("f", 40)
	err := validateStatus(root, value, "offline")
	if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatalf("missing immutable baseline classification = %v", err)
	}
	if !strings.Contains(err.Error(), value.BaselineCommit) || strings.Contains(err.Error(), root) {
		t.Fatalf("unavailable evidence error is not bounded and identity-specific: %v", err)
	}
}

func TestUnavailableHistoricalCommitDoesNotHideInvalidReleaseBoundary(t *testing.T) {
	root := copyRepositoryAuthority(t)
	initEmptyGitRepository(t, root)
	copyPhase16PolicyFiles(t, root)
	var value status
	if err := decodeFile(repositoryRoot(t), statusPath, &value); err != nil {
		t.Fatal(err)
	}
	value.BaselineCommit = strings.Repeat("f", 40)
	value.ReleaseDecision = "GO"
	err := validateStatus(root, value, "offline")
	if err == nil || errors.Is(err, errHistoricalEvidenceNotAvailable) || !strings.Contains(err.Error(), "cannot widen") {
		t.Fatalf("invalid release boundary was hidden by unavailable history: %v", err)
	}
}

func TestUnavailableClassificationDoesNotMaskAnUnboundRepository(t *testing.T) {
	root := t.TempDir()
	command := exec.Command("git", "init", "--quiet")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize unbound Git fixture: %v: %s", err, output)
	}
	err := historicalCommitAvailability(root, strings.Repeat("f", 40), "synthetic baseline")
	if err == nil || errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatalf("unbound repository was misclassified as absent historical evidence: %v", err)
	}
}

func TestUnavailableSelfHostedBaselineStillValidatesTheStaticRecord(t *testing.T) {
	root := copyRepositoryAuthority(t)
	initEmptyGitRepository(t, root)
	err := verifySelfHostedQualification(root)
	if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatalf("missing self-hosted historical subject classification = %v", err)
	}

	path := filepath.Join(root, filepath.FromSlash(selfHostedQualificationPath))
	raw, readErr := os.ReadFile(path)
	if readErr != nil {
		t.Fatal(readErr)
	}
	raw = []byte(strings.Replace(string(raw), `"releaseDecision": "NO_GO"`, `"releaseDecision": "GO"`, 1))
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	err = verifySelfHostedQualification(root)
	if err == nil || errors.Is(err, errHistoricalEvidenceNotAvailable) {
		t.Fatalf("invalid static record was hidden by unavailable history: %v", err)
	}
}

func TestRunReportsNotAvailableWithoutOpeningQualification(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithVerifier([]string{"-root", ".", "-mode", "offline"}, &stdout, &stderr, func(string, string, string) error {
		return errHistoricalEvidenceNotAvailable
	})
	if code != 0 || stderr.Len() != 0 {
		t.Fatalf("NOT_AVAILABLE run = code %d stderr %q", code, stderr.String())
	}
	if output := stdout.String(); !strings.Contains(output, "NOT_AVAILABLE") || !strings.Contains(output, "BLOCKED") || strings.Contains(output, "PASSED") {
		t.Fatalf("NOT_AVAILABLE output opened or obscured the gate: %q", output)
	}
}

func TestRunKeepsOrdinaryVerificationFailureRed(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := runWithVerifier([]string{"-root", ".", "-mode", "offline"}, &stdout, &stderr, func(string, string, string) error {
		return errors.New("synthetic verifier failure")
	})
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "VERIFICATION FAILED") {
		t.Fatalf("ordinary failure = code %d stdout %q stderr %q", code, stdout.String(), stderr.String())
	}
}

func TestPortableServiceAndContainerHardeningRejectAuthorityWidening(t *testing.T) {
	root := t.TempDir()
	servicePath := filepath.Join(root, filepath.FromSlash("deploy/selfhost/native/kurd-node.service"))
	containerPath := filepath.Join(root, filepath.FromSlash("deploy/selfhost/container/compose.yml"))
	if err := os.MkdirAll(filepath.Dir(servicePath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(containerPath), 0o755); err != nil {
		t.Fatal(err)
	}
	service, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash("deploy/selfhost/native/kurd-node.service")))
	if err != nil {
		t.Fatal(err)
	}
	container, err := os.ReadFile(filepath.Join(repositoryRoot(t), filepath.FromSlash("deploy/selfhost/container/compose.yml")))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servicePath, service, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(containerPath, container, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyServiceUnit(root); err != nil {
		t.Fatal(err)
	}
	if err := verifyContainerDefinition(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(servicePath, append(service, []byte("\nAmbientCapabilities=CAP_NET_ADMIN\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyServiceUnit(root); err == nil {
		t.Fatal("network-capable Phase 16 service accepted")
	}
	if err := os.WriteFile(containerPath, append(container, []byte("\n    privileged: true\n")...), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyContainerDefinition(root); err == nil {
		t.Fatal("privileged Phase 16 container accepted")
	}
}

func TestVerifyDecentralizedAuthority(t *testing.T) {
	if err := verifyDecentralizedAuthority(repositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyDecentralizedAuthorityRejectsMandatoryCloud(t *testing.T) {
	root := copyDecentralizedAuthority(t)
	path := filepath.Join(root, "README.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\nGoogle Cloud is mandatory for every deployment.\n")...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDecentralizedAuthority(root); err == nil {
		t.Fatal("mandatory cloud dependency accepted")
	}
}

func TestVerifyPublicationBoundaryRejectsUnexpectedArtifact(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "RZ-evidence-ref-069"), []byte("retired publication artifact\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyPublicationBoundary(root); err == nil {
		t.Fatal("retired publication artifact accepted")
	}
}

func TestVerifyDecentralizedAuthorityRejectsGlobalRoot(t *testing.T) {
	root := copyDecentralizedAuthority(t)
	path := filepath.Join(root, filepath.FromSlash("docs/self-hosting/SECURITY.md"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	raw = append(raw, []byte("\nKurdistan VPN requires a global Kurdistan root.\n")...)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyDecentralizedAuthority(root); err == nil {
		t.Fatal("global authority dependency accepted")
	}
}

func TestMandatoryPhase16AuthorityExcludesSupersededCloudTopology(t *testing.T) {
	for _, path := range requiredFiles {
		path = filepath.ToSlash(path)
		for _, forbidden := range []string{
			"production/",
			"infra/terraform/",
			"phase16-production-plan.yml",
			"phase16-production-apply.yml",
		} {
			if strings.Contains(path, forbidden) {
				t.Fatalf("mandatory Phase 16 authority still requires superseded cloud path %q", path)
			}
		}
	}
}

func TestPhase16WorkflowsCannotRequireCloudIdentityOrMutationTools(t *testing.T) {
	if err := verifyNoMandatoryCloudWorkflows(repositoryRoot(t)); err != nil {
		t.Fatal(err)
	}
}

func TestQualificationWorkflowFetchesFullEvidenceHistory(t *testing.T) {
	root := repositoryRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, ".github", "workflows", "phase16-qualification.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{
		"actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd",
		"persist-credentials: false",
		"fetch-depth: 0",
		"go run ./cmd/phase16verify -root . -mode offline",
	} {
		if !strings.Contains(string(raw), required) {
			t.Fatalf("qualification workflow missing %q", required)
		}
	}
}

func TestPortableDrillWorkflowCannotPassWithZeroSelectedTests(t *testing.T) {
	root := repositoryRoot(t)
	path := filepath.Join(root, filepath.FromSlash(".github/workflows/phase16-drill.yml"))
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	broken := strings.Replace(string(raw),
		"LISTED=$(go test ./internal/selfhost -list",
		"LISTED=$(printf '%s\\n' \"$TEST\") # hollow selector",
		1,
	)
	temporary := t.TempDir()
	temporaryPath := filepath.Join(temporary, filepath.FromSlash(".github/workflows/phase16-drill.yml"))
	if err := os.MkdirAll(filepath.Dir(temporaryPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(temporaryPath, []byte(broken), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := verifyPortableDrillWorkflow(temporary); err == nil {
		t.Fatal("drill workflow without an executable test-inventory guard was accepted")
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
	if err := validateStatus(root, value, "offline"); err == nil {
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

func TestLegacyCloudMutationWorkflowsRemainDisabled(t *testing.T) {
	root := repositoryRoot(t)
	for _, relative := range []string{
		".github/workflows/phase16-production-plan.yml",
		".github/workflows/phase16-production-apply.yml",
	} {
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			t.Fatal(err)
		}
		text := strings.ToLower(string(raw))
		if !strings.Contains(text, "phase16-cloud-experiment-disabled") ||
			strings.Contains(text, "id-token: write") || strings.Contains(text, "google-github-actions/") {
			t.Fatalf("legacy workflow is not safely disabled: %s", relative)
		}
	}
}

func TestValidateExternalReceiptBindsExactSubjectPolicyAndFreshness(t *testing.T) {
	now := time.Date(2026, 8, 6, 12, 0, 0, 0, time.UTC)
	receipt := externalReceipt{
		Schema: "phase16-external-receipt-v1", Kind: "CLOUD_IDENTITY_READBACK",
		SubjectCommit: strings.Repeat("a", 40), SubjectTree: strings.Repeat("b", 40), PolicyDigest: strings.Repeat("c", 64),
		StartedAt: now.Add(-time.Hour).Format(time.RFC3339), FinishedAt: now.Add(-time.Minute).Format(time.RFC3339), Result: "PASS",
		ArtifactDigests: []string{strings.Repeat("d", 64)},
	}
	if err := validateExternalReceipt("cloud-identity-readback", receipt, receipt.SubjectCommit, receipt.SubjectTree, receipt.PolicyDigest, now); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*externalReceipt){
		"wrong subject": func(value *externalReceipt) { value.SubjectTree = strings.Repeat("e", 40) },
		"wrong policy":  func(value *externalReceipt) { value.PolicyDigest = strings.Repeat("e", 64) },
		"failed":        func(value *externalReceipt) { value.Result = "FAIL" },
		"stale":         func(value *externalReceipt) { value.FinishedAt = now.Add(-15 * 24 * time.Hour).Format(time.RFC3339) },
		"duplicate": func(value *externalReceipt) {
			value.ArtifactDigests = append(value.ArtifactDigests, value.ArtifactDigests[0])
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := receipt
			candidate.ArtifactDigests = append([]string(nil), receipt.ArtifactDigests...)
			mutate(&candidate)
			if err := validateExternalReceipt("cloud-identity-readback", candidate, receipt.SubjectCommit, receipt.SubjectTree, receipt.PolicyDigest, now); err == nil {
				t.Fatal("invalid external receipt accepted")
			}
		})
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

func initEmptyGitRepository(t *testing.T, root string) {
	t.Helper()
	command := exec.Command("git", "init", "--quiet")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("initialize isolated Git subject: %v: %s", err, output)
	}
	command = exec.Command("git", "-c", "user.name=phase16-test", "-c", "user.email=phase16-test.invalid", "commit", "--quiet", "--allow-empty", "-m", "fixture subject")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("commit isolated Git subject: %v: %s", err, output)
	}
}

func copyPhase16PolicyFiles(t *testing.T, root string) {
	t.Helper()
	source := repositoryRoot(t)
	for _, path := range []string{
		"config/production/actions.json",
		"config/production/key-policy.json",
		"config/production/regions.json",
		"config/production/retention.json",
		"config/production/roles.json",
		"config/production/services.json",
		"config/production/tools.json",
	} {
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
}

func copyDecentralizedAuthority(t *testing.T) string {
	t.Helper()
	source := repositoryRoot(t)
	root := t.TempDir()
	for _, path := range decentralizedAuthorityFiles {
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
	return root
}
