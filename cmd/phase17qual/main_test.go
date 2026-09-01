// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	phase17evidence "kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
)

func TestRunVerifiesRepositoryPolicy(t *testing.T) {
	root := filepath.Join("..", "..")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"policy", "verify", "-root", root,
		"-policy", "config/phase17/qualification-policy-v1.json",
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_QUALIFICATION_POLICY_PASS\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunGeneratesExclusiveKeyPairWithoutPrintingMaterial(t *testing.T) {
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "key.ed25519")
	publicPath := filepath.Join(directory, "key.ed25519.pub")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"key", "generate", "-private", privatePath, "-public", publicPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_QUALIFICATION_KEY_CREATED\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	privateKey, err := phase17qualification.LoadPrivateKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	defer phase17qualification.Clear(privateKey)
	publicKey, err := phase17qualification.LoadPublicKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	combinedOutput := stdout.String() + stderr.String()
	if bytes.Contains([]byte(combinedOutput), privateKey) || bytes.Contains([]byte(combinedOutput), publicKey) {
		t.Fatal("qualification key material was printed")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"key", "generate", "-private", privatePath, "-public", publicPath}, &stdout, &stderr); code == 0 {
		t.Fatal("existing qualification key pair was overwritten")
	}
}

func TestPublishLedgerStatementNeverMutatesLedgerBeforeReceiptPublication(t *testing.T) {
	injected := errors.New("injected publication failure")
	appendCalls := 0
	err := publishLedgerStatement(
		"receipt.json", "ledger", []byte("signed"), []byte("public"),
		func(string, []byte) error { return injected },
		func(string, []byte, []byte) (string, error) { appendCalls++; return "", nil },
		func(string) error { return nil },
	)
	if !errors.Is(err, injected) || appendCalls != 0 {
		t.Fatalf("error=%v appendCalls=%d", err, appendCalls)
	}
}

func TestPublishLedgerStatementRemovesProvisionalReceiptWhenAppendFails(t *testing.T) {
	injected := errors.New("injected append failure")
	wrote := false
	removed := false
	err := publishLedgerStatement(
		"receipt.json", "ledger", []byte("signed"), []byte("public"),
		func(string, []byte) error { wrote = true; return nil },
		func(string, []byte, []byte) (string, error) { return "", injected },
		func(string) error { removed = true; return nil },
	)
	if !errors.Is(err, injected) || !wrote || !removed {
		t.Fatalf("error=%v wrote=%t removed=%t", err, wrote, removed)
	}
}

func TestRunIssuesAndVerifiesSaltedPrivateEnvironmentWithoutPrintingSelectors(t *testing.T) {
	originalBootReader := readCurrentHostBootIdentity
	defer func() { readCurrentHostBootIdentity = originalBootReader }()
	bootIdentity := []byte("2026-08-14T05:06:07.1234567Z")
	readCurrentHostBootIdentity = func(context.Context, string) ([]byte, error) {
		return bytes.Clone(bootIdentity), nil
	}
	directory := t.TempDir()
	candidatePath, candidate := writeCandidateManifestFixture(t, directory)
	privatePath, privateValue := writePrivateEnvironmentFixture(t, directory, "api36-field")
	saltPath := filepath.Join(directory, "environment-salt.bin")
	environmentPath := filepath.Join(directory, "environment.json")
	var stdout, stderr bytes.Buffer

	code := run([]string{"environment", "salt", "generate", "-out", saltPath}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_ENVIRONMENT_SALT_CREATED\n" || stderr.Len() != 0 {
		t.Fatalf("salt code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	salt, err := os.ReadFile(saltPath)
	if err != nil {
		t.Fatal(err)
	}
	if len(salt) != phase17qualification.PrivateEnvironmentSaltSize {
		t.Fatalf("salt length=%d", len(salt))
	}
	if bytes.Contains(stdout.Bytes(), salt) || bytes.Contains(stderr.Bytes(), salt) {
		t.Fatal("private environment salt was printed")
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{"environment", "salt", "generate", "-out", saltPath}, &stdout, &stderr); code == 0 {
		t.Fatal("existing private environment salt was overwritten")
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"environment", "issue",
		"-candidate", candidatePath,
		"-private-environment", privatePath,
		"-salt", saltPath,
		"-android-class", "EMULATOR",
		"-android-api", "36",
		"-android-abi", "x86_64",
		"-provider-class", "PRIMARY",
		"-out", environmentPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_ENVIRONMENT_CONTEXT_CREATED\n" || stderr.Len() != 0 {
		t.Fatalf("issue code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	combined := stdout.String() + stderr.String()
	if strings.Contains(combined, privateValue.SSHAlias) || strings.Contains(combined, privateValue.AVDName) {
		t.Fatal("private environment selector was printed")
	}
	environmentRaw, err := os.ReadFile(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	environment, err := phase17qualification.DecodeEnvironmentContext(bytes.NewReader(environmentRaw))
	if err != nil {
		t.Fatal(err)
	}
	if environment.HostOS != runtime.GOOS || environment.HostArch != runtime.GOARCH ||
		environment.AndroidClass != "EMULATOR" || environment.AndroidAPI != 36 || environment.AndroidABI != "x86_64" ||
		environment.VPSOS != "linux" || environment.VPSArch != "amd64" || environment.ProviderClass != "PRIMARY" {
		t.Fatalf("environment=%+v", environment)
	}
	probeURL, err := os.ReadFile(privateValue.ProbeURLFile)
	if err != nil {
		t.Fatal(err)
	}
	probeDigest, err := os.ReadFile(privateValue.ProbeDigestFile)
	if err != nil {
		t.Fatal(err)
	}
	wantCommitment, err := phase17qualification.ComputePrivateEnvironmentCommitment(
		candidate.Roots.CandidateID, "EMULATOR", salt, privateValue,
		bytes.TrimSpace(probeURL), bytes.TrimSpace(probeDigest),
		bootIdentity,
	)
	if err != nil {
		t.Fatal(err)
	}
	if environment.PrivateCommitment != wantCommitment {
		t.Fatal("issued environment is not committed to the owner-private inputs")
	}

	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"environment", "verify", "-candidate", candidatePath, "-environment", environmentPath,
		"-private-environment", privatePath, "-salt", saltPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_ENVIRONMENT_CONTEXT_PASS\n" || stderr.Len() != 0 {
		t.Fatalf("verify code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}

	bootIdentity = []byte("2026-08-14T06:07:08.2345678Z")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"environment", "verify", "-candidate", candidatePath, "-environment", environmentPath,
		"-private-environment", privatePath, "-salt", saltPath,
	}, &stdout, &stderr); code == 0 {
		t.Fatal("host reboot preserved environment verification")
	}
	bootIdentity = []byte("2026-08-14T05:06:07.1234567Z")

	privatePath, _ = writePrivateEnvironmentFixtureAt(t, privatePath, directory, "api36-other")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"environment", "verify", "-candidate", candidatePath, "-environment", environmentPath,
		"-private-environment", privatePath, "-salt", saltPath,
	}, &stdout, &stderr); code == 0 {
		t.Fatal("mutated private selector preserved environment verification")
	}
}

func TestRunVerifiesSignedStatementAndLedgerWithoutPrintingPayload(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x31}, ed25519.SeedSize))
	defer phase17qualification.Clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	publicPath := filepath.Join(directory, "trusted.pub")
	if err := os.WriteFile(publicPath, publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	candidatePath, candidate := writeCandidateManifestFixture(t, directory)
	roots := candidate.Roots
	receipt, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementRCLocked, phase17qualification.RCLockedPayload{
		Schema: phase17qualification.RCLockedSchema,
		Candidate: phase17qualification.CandidateIdentity{
			Repository: "saroo98/kurdistan-protocol-compiler",
			CommitSHA:  strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
			Roots: roots, ComparisonSHA256: strings.Repeat("c", 64),
		},
		AuthorizationID: strings.Repeat("d", 32), IssuedAt: "2026-08-14T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	receiptPath := filepath.Join(directory, "receipt.json")
	if err := os.WriteFile(receiptPath, receipt, 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{"verify", "-trusted-public-key", publicPath, "-statement", receiptPath}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_QUALIFICATION_STATEMENT_PASS\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if bytes.Contains(stdout.Bytes(), receipt) {
		t.Fatal("qualification receipt payload was printed")
	}

	ledger := filepath.Join(directory, "ledger")
	attempt := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: roots.CandidateID,
		Sequence: 1, PreviousEntrySHA256: "", State: phase17qualification.AttemptBegin,
		AttemptID: strings.Repeat("e", 32), Mode: "Functional",
		RCLockedSHA256: strings.Repeat("f", 64), AuthorizationSHA256: strings.Repeat("f", 64), EnvironmentSHA256: strings.Repeat("0", 64),
		PreflightSHA256: strings.Repeat("1", 64),
		Outcome:         "", ResultSHA256: "", RecordedAt: "2026-08-14T12:01:00Z",
	}
	attemptRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, attempt)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phase17qualification.AppendLedger(ledger, attemptRaw, publicKey); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"ledger", "verify", "-candidate", candidatePath,
		"-trusted-public-key", publicPath, "-ledger", ledger,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_QUALIFICATION_LEDGER_PASS\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestRunLocksCandidateConsumesAuthorizationOnceAndBeginsFinalSoak(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x41}, ed25519.SeedSize))
	defer phase17qualification.Clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(directory, "key.ed25519")
	publicPath := filepath.Join(directory, "key.ed25519.pub")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(publicPath, publicKey, 0o644); err != nil {
		t.Fatal(err)
	}
	candidatePath, candidate := writeCandidateManifestFixture(t, directory)
	roots := candidate.Roots
	lockPath := filepath.Join(directory, "rc-locked.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"lock", "-candidate", candidatePath, "-private-key", privatePath, "-out", lockPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_RC_LOCKED\n" || stderr.Len() != 0 {
		t.Fatalf("lock code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	lockRaw, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	locked, err := phase17qualification.VerifyStatement(lockRaw, publicKey)
	if err != nil || locked.StatementType != phase17qualification.StatementRCLocked {
		t.Fatalf("locked=%+v err=%v", locked, err)
	}

	ledger := filepath.Join(directory, "ledger")
	seedCompletedStressLedger(t, ledger, roots.CandidateID, privateKey, publicKey)
	state, err := phase17qualification.VerifyLedger(ledger, roots.CandidateID, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	readyRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementSoakReady, phase17qualification.SoakReadyPayload{
		Schema: phase17qualification.SoakReadySchema, CandidateID: roots.CandidateID,
		RCLockedSHA256: locked.DigestSHA256, EvidenceIndexSHA256: strings.Repeat("6", 64),
		PriorStressResultSHA256: strings.Repeat("8", 64),
		LedgerHeadSHA256:        state.HeadSHA256, AuthorizationID: strings.Repeat("7", 32),
		IssuedAt: "2026-08-14T13:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(directory, "soak-ready.json")
	if err := os.WriteFile(readyPath, readyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	environmentPath := writeEnvironmentFixture(t, directory)
	preflightPath := writePreflightFixture(t, directory, environmentPath)
	consumedPath := filepath.Join(directory, "soak-consumed.json")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"soak", "consume", "-authorization", readyPath, "-environment", environmentPath,
		"-preflight-result", preflightPath,
		"-ledger", ledger, "-private-key", privatePath, "-out", consumedPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_SOAK_AUTHORIZATION_CONSUMED\n" || stderr.Len() != 0 {
		t.Fatalf("consume code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	consumedRaw, err := os.ReadFile(consumedPath)
	if err != nil {
		t.Fatal(err)
	}
	consumed, err := phase17qualification.VerifyStatement(consumedRaw, publicKey)
	if err != nil || consumed.StatementType != phase17qualification.StatementSoakConsumed {
		t.Fatalf("consumed=%+v err=%v", consumed, err)
	}
	preflightRaw, err := os.ReadFile(preflightPath)
	if err != nil {
		t.Fatal(err)
	}
	changedPreflight := bytes.Replace(preflightRaw, []byte(strings.Repeat("1", 32)), []byte(strings.Repeat("2", 32)), 1)
	if err := os.WriteFile(preflightPath, changedPreflight, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"attempt", "begin", "-authorization", consumedPath, "-environment", environmentPath,
		"-preflight-result", preflightPath, "-mode", "Soak12h", "-ledger", ledger,
		"-private-key", privatePath, "-out", filepath.Join(directory, "changed-preflight-begin.json"),
	}, &stdout, &stderr); code == 0 {
		t.Fatal("final soak began from preflight evidence other than the consumed evidence")
	}
	if err := os.WriteFile(preflightPath, preflightRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	beginPath := filepath.Join(directory, "soak-attempt-begin.json")
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"attempt", "begin", "-authorization", consumedPath, "-environment", environmentPath,
		"-preflight-result", preflightPath,
		"-mode", "Soak12h", "-ledger", ledger, "-private-key", privatePath, "-out", beginPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_ATTEMPT_BEGAN\n" || stderr.Len() != 0 {
		t.Fatalf("begin code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	beginRaw, err := os.ReadFile(beginPath)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := phase17qualification.VerifyStatement(beginRaw, publicKey)
	if err != nil || begin.StatementType != phase17qualification.StatementAttempt {
		t.Fatalf("begin=%+v err=%v", begin, err)
	}
	beginPayload := begin.Payload.(phase17qualification.AttemptPayload)
	consumedPayload := consumed.Payload.(phase17qualification.SoakConsumedPayload)
	if beginPayload.AttemptID != consumedPayload.AttemptID || beginPayload.AuthorizationSHA256 != consumedPayload.SoakReadySHA256 ||
		beginPayload.RCLockedSHA256 != consumedPayload.RCLockedSHA256 || beginPayload.EnvironmentSHA256 != consumedPayload.EnvironmentSHA256 ||
		beginPayload.PreflightSHA256 != consumedPayload.PreflightSHA256 {
		t.Fatalf("begin=%+v consumed=%+v", beginPayload, consumedPayload)
	}

	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"soak", "consume", "-authorization", readyPath, "-environment", environmentPath,
		"-preflight-result", preflightPath,
		"-ledger", ledger, "-private-key", privatePath, "-out", filepath.Join(directory, "duplicate.json"),
	}, &stdout, &stderr); code == 0 {
		t.Fatal("the same final-soak authorization was consumed twice")
	}
}

func TestRunAttemptBeginRequiresConsumptionReceiptForFinalSoak(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x51}, ed25519.SeedSize))
	defer phase17qualification.Clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(directory, "key.ed25519")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	roots, err := phase17qualification.NewSubjectRoots(
		strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64),
		strings.Repeat("4", 64), strings.Repeat("5", 64),
	)
	if err != nil {
		t.Fatal(err)
	}
	readyRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementSoakReady, phase17qualification.SoakReadyPayload{
		Schema: phase17qualification.SoakReadySchema, CandidateID: roots.CandidateID,
		RCLockedSHA256: strings.Repeat("6", 64), EvidenceIndexSHA256: strings.Repeat("7", 64),
		PriorStressResultSHA256: strings.Repeat("a", 64),
		LedgerHeadSHA256:        strings.Repeat("8", 64), AuthorizationID: strings.Repeat("9", 32),
		IssuedAt: "2026-08-14T13:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(directory, "ready.json")
	if err := os.WriteFile(readyPath, readyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	environmentPath := writeEnvironmentFixture(t, directory)
	preflightPath := writePreflightFixture(t, directory, environmentPath)
	var stdout, stderr bytes.Buffer
	if code := run([]string{
		"attempt", "begin", "-authorization", readyPath, "-environment", environmentPath,
		"-preflight-result", preflightPath,
		"-mode", "Soak12h", "-ledger", filepath.Join(directory, "ledger"), "-private-key", privatePath,
		"-out", filepath.Join(directory, "begin.json"),
	}, &stdout, &stderr); code == 0 {
		t.Fatal("final soak began from an unconsumed readiness receipt")
	}
	_ = publicKey
}

func TestRunCreatesCandidateOnlyFromCleanExactGitRootAndFourSubjects(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, ".gitignore"), []byte(".tools/\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("source"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.mod"), []byte("module example.invalid/phase17\n\ngo 1.26.0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "go.sum"), []byte("example.invalid/module v1.0.0 h1:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, root, "init")
	runGitTest(t, root, "config", "user.name", "Phase17 Test")
	runGitTest(t, root, "config", "user.email", "phase17@example.invalid")
	runGitTest(t, root, "remote", "add", "origin", "https://github.com/saroo98/kurdistan-protocol-compiler.git")
	runGitTest(t, root, "add", ".gitignore", "tracked.txt", "go.mod", "go.sum")
	runGitTest(t, root, "-c", "commit.gpgsign=false", "commit", "-m", "baseline")
	baseline := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD"))
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("phase17"), 0o600); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, root, "add", "tracked.txt")
	runGitTest(t, root, "-c", "commit.gpgsign=false", "commit", "-m", "candidate")
	commit := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD"))
	tree := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD^{tree}"))

	artifactsRelative := ".tools/candidate-A"
	artifacts := filepath.Join(root, filepath.FromSlash(artifactsRelative))
	for index, subject := range []string{"PQS", "QHS", "QWS", "OVS"} {
		path := filepath.Join(artifacts, subject, "artifact.bin")
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte{byte(index + 1)}, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"source", "create", "-root", root, "-baseline", baseline,
		"-out", filepath.ToSlash(filepath.Join(artifactsRelative, "source-provenance.json")),
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_SOURCE_PROVENANCE_CREATED\n" || stderr.Len() != 0 {
		t.Fatalf("source code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	comparisonArtifactsRelative := ".tools/candidate-B"
	comparisonArtifacts := filepath.Join(root, filepath.FromSlash(comparisonArtifactsRelative))
	if err := copyTestTree(artifacts, comparisonArtifacts); err != nil {
		t.Fatal(err)
	}
	comparisonRelative := ".tools/candidate-comparison.json"
	outputRelative := ".tools/candidate-manifest.json"
	stdout.Reset()
	stderr.Reset()
	code = run([]string{
		"candidate", "create", "-root", root, "-artifacts", artifactsRelative,
		"-comparison-artifacts", comparisonArtifactsRelative, "-comparison", comparisonRelative, "-out", outputRelative,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_CANDIDATE_CREATED\n" || stderr.Len() != 0 {
		t.Fatalf("create code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(outputRelative)))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := phase17qualification.DecodeCandidateManifest(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Source.CommitSHA != commit || manifest.Source.TreeSHA != tree || len(manifest.Subjects) != 4 {
		t.Fatalf("candidate manifest=%+v", manifest)
	}
	if manifest.Source.BaselineCommitSHA != baseline {
		t.Fatalf("baseline=%q want=%q", manifest.Source.BaselineCommitSHA, baseline)
	}
	sourcePath := filepath.Join(artifacts, "source-provenance.json")
	sourceRaw, err := os.ReadFile(sourcePath)
	if err != nil {
		t.Fatal(err)
	}
	tamperedSource := manifest.Source
	tamperedSource.ChangedPathsSHA256 = strings.Repeat("0", 64)
	tamperedRaw, err := phase17qualification.MarshalSourceProvenance(tamperedSource)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sourcePath, tamperedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"candidate", "create", "-root", root, "-artifacts", artifactsRelative,
		"-comparison-artifacts", comparisonArtifactsRelative, "-comparison", ".tools/tampered-source-comparison.json", "-out", ".tools/tampered-source-candidate.json",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("candidate accepted fabricated source-provenance digests")
	}
	if err := os.WriteFile(sourcePath, sourceRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	comparisonArtifactPath := filepath.Join(comparisonArtifacts, "QHS", "artifact.bin")
	comparisonArtifactRaw, err := os.ReadFile(comparisonArtifactPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(comparisonArtifactPath, []byte("different"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"candidate", "create", "-root", root, "-artifacts", artifactsRelative,
		"-comparison-artifacts", comparisonArtifactsRelative, "-comparison", ".tools/different-comparison.json", "-out", ".tools/different-candidate.json",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("byte-different candidate B compared as PASS")
	}
	if err := os.WriteFile(comparisonArtifactPath, comparisonArtifactRaw, 0o600); err != nil {
		t.Fatal(err)
	}

	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("dirty"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"candidate", "create", "-root", root, "-artifacts", artifactsRelative,
		"-comparison-artifacts", comparisonArtifactsRelative, "-comparison", ".tools/dirty-comparison.json", "-out", ".tools/dirty-candidate.json",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("dirty source tree produced a qualification candidate")
	}
	runGitTest(t, root, "checkout", "--", "tracked.txt")
	if err := os.WriteFile(filepath.Join(root, "untracked-source.txt"), []byte("untracked"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"candidate", "create", "-root", root, "-artifacts", artifactsRelative,
		"-comparison-artifacts", comparisonArtifactsRelative, "-comparison", ".tools/untracked-comparison.json", "-out", ".tools/untracked-candidate.json",
	}, &stdout, &stderr); code == 0 {
		t.Fatal("untracked source tree produced a qualification candidate")
	}
}

func TestRunVerifiesExactCandidateArtifactBeforeUse(t *testing.T) {
	directory := t.TempDir()
	candidatePath, manifest := writeCandidateManifestFixture(t, directory)
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(directory, "qualification.pub")
	if err := os.WriteFile(publicPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	lockRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementRCLocked, phase17qualification.RCLockedPayload{
		Schema: phase17qualification.RCLockedSchema, Candidate: candidate,
		AuthorizationID: strings.Repeat("1", 32), IssuedAt: "2026-08-14T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	lockPath := filepath.Join(directory, "rc-locked.json")
	if err := os.WriteFile(lockPath, lockRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	artifact := filepath.Join(directory, "subject-fixture", "QHS", "qhs.bin")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"candidate", "artifact", "verify", "-candidate", candidatePath,
		"-rc-lock", lockPath, "-trusted-public-key", publicPath,
		"-subject", "QHS", "-entry", "qhs.bin", "-path", artifact,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_CANDIDATE_ARTIFACT_VERIFIED\n" || stderr.Len() != 0 {
		t.Fatalf("code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	if err := os.WriteFile(artifact, []byte("mutated"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"candidate", "artifact", "verify", "-candidate", candidatePath,
		"-rc-lock", lockPath, "-trusted-public-key", publicPath,
		"-subject", "QHS", "-entry", "qhs.bin", "-path", artifact,
	}, &stdout, &stderr); code == 0 {
		t.Fatal("mutated candidate artifact was accepted")
	}
}

func TestReadBoundedRegularFileRejectsReplacementBetweenMetadataAndOpen(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "input.json")
	replacement := filepath.Join(directory, "replacement.json")
	if err := os.WriteFile(path, []byte("first"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(replacement, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := readBoundedRegularFileWithOpener(path, 64, func(openPath string) (*os.File, error) {
		if err := os.Remove(openPath); err != nil {
			return nil, err
		}
		if err := os.Rename(replacement, openPath); err != nil {
			return nil, err
		}
		return os.Open(openPath)
	})
	if err == nil {
		t.Fatal("replacement between metadata validation and open was accepted")
	}
}

func copyTestTree(source, destination string) error {
	return filepath.WalkDir(source, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		if entry.IsDir() {
			return os.MkdirAll(target, 0o700)
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(target, raw, 0o600)
	})
}

func TestRunFinishesAttemptOnlyFromExactBoundV3Result(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x61}, ed25519.SeedSize))
	defer phase17qualification.Clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(directory, "key.ed25519")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	candidatePath, manifest := writeCandidateManifestFixture(t, directory)
	lockPath := filepath.Join(directory, "lock.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"lock", "-candidate", candidatePath, "-private-key", privatePath, "-out", lockPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	environmentPath := writeEnvironmentFixture(t, directory)
	preflightPath := writePreflightFixture(t, directory, environmentPath)
	ledger := filepath.Join(directory, "ledger")
	beginPath := filepath.Join(directory, "begin.json")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"attempt", "begin", "-authorization", lockPath, "-environment", environmentPath,
		"-preflight-result", preflightPath,
		"-mode", "Functional", "-ledger", ledger, "-private-key", privatePath, "-out", beginPath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("begin code=%d stderr=%q", code, stderr.String())
	}
	beginRaw, err := os.ReadFile(beginPath)
	if err != nil {
		t.Fatal(err)
	}
	begin, err := phase17qualification.VerifyStatement(beginRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	beginPayload := begin.Payload.(phase17qualification.AttemptPayload)
	policyPath := filepath.Join("..", "..", "config", "phase17", "qualification-policy-v1.json")
	policyRaw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := sha256.Sum256(policyRaw)
	result := validFieldResultForAttempt(t, manifest, beginPayload, hex.EncodeToString(policyDigest[:]))
	resultRaw, err := phase17evidence.MarshalOwnedVPSRawV3(result)
	if err != nil {
		t.Fatal(err)
	}
	resultPath := filepath.Join(directory, "field-result.json")
	if err := os.WriteFile(resultPath, resultRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	terminalPath := filepath.Join(directory, "terminal.json")
	stdout.Reset()
	stderr.Reset()
	code := run([]string{
		"attempt", "finish", "-attempt", beginPath, "-candidate", candidatePath, "-result", resultPath, "-policy", policyPath,
		"-ledger", ledger, "-private-key", privatePath, "-out", terminalPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_ATTEMPT_FINISHED\n" || stderr.Len() != 0 {
		t.Fatalf("finish code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	terminalRaw, err := os.ReadFile(terminalPath)
	if err != nil {
		t.Fatal(err)
	}
	terminal, err := phase17qualification.VerifyStatement(terminalRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	terminalPayload := terminal.Payload.(phase17qualification.AttemptPayload)
	resultDigest := sha256.Sum256(resultRaw)
	if terminalPayload.State != phase17qualification.AttemptTerminal || terminalPayload.Outcome != "PASS" ||
		terminalPayload.ResultSHA256 != hex.EncodeToString(resultDigest[:]) || terminalPayload.AttemptID != beginPayload.AttemptID {
		t.Fatalf("terminal=%+v", terminalPayload)
	}
	state, err := phase17qualification.VerifyLedger(ledger, manifest.Roots.CandidateID, publicKey)
	if err != nil || state.Entries != 2 || state.HeadSHA256 != terminal.DigestSHA256 {
		t.Fatalf("ledger=%+v err=%v", state, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"attempt", "finish", "-attempt", beginPath, "-candidate", candidatePath, "-result", resultPath, "-policy", policyPath,
		"-ledger", ledger, "-private-key", privatePath, "-out", filepath.Join(directory, "duplicate-terminal.json"),
	}, &stdout, &stderr); code == 0 {
		t.Fatal("attempt was finished twice")
	}
}

func TestRunClosesMissingRunnerResultCategoricallyWithoutLeavingLedgerBeginUnresolved(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x71}, ed25519.SeedSize))
	defer phase17qualification.Clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(directory, "key.ed25519")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	candidatePath, manifest := writeCandidateManifestFixture(t, directory)
	lockPath := filepath.Join(directory, "lock.json")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"lock", "-candidate", candidatePath, "-private-key", privatePath, "-out", lockPath}, &stdout, &stderr); code != 0 {
		t.Fatalf("lock code=%d stderr=%q", code, stderr.String())
	}
	environmentPath := writeEnvironmentFixture(t, directory)
	preflightPath := writePreflightFixture(t, directory, environmentPath)
	ledger := filepath.Join(directory, "ledger")
	beginPath := filepath.Join(directory, "begin.json")
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"attempt", "begin", "-authorization", lockPath, "-environment", environmentPath,
		"-preflight-result", preflightPath,
		"-mode", "Functional", "-ledger", ledger, "-private-key", privatePath, "-out", beginPath,
	}, &stdout, &stderr); code != 0 {
		t.Fatalf("begin code=%d stderr=%q", code, stderr.String())
	}
	resultPath := filepath.Join(directory, "wrapper-result.json")
	terminalPath := filepath.Join(directory, "terminal.json")
	policyPath := filepath.Join("..", "..", "config", "phase17", "qualification-policy-v1.json")
	stdout.Reset()
	stderr.Reset()
	code := run([]string{
		"attempt", "close", "-attempt", beginPath, "-candidate", candidatePath, "-environment", environmentPath,
		"-policy", policyPath, "-package-entry", "package/candidate-linux-amd64.tar.gz",
		"-app-entry", "android/app-internal.apk", "-test-entry", "android/app-internal-androidTest.apk",
		"-reason", "RUNNER_RESULT_MISSING", "-ledger", ledger, "-private-key", privatePath,
		"-result-out", resultPath, "-out", terminalPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_ATTEMPT_CLOSED\n" || stderr.Len() != 0 {
		t.Fatalf("close code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	resultRaw, err := os.ReadFile(resultPath)
	if err != nil {
		t.Fatal(err)
	}
	result, err := phase17evidence.DecodeOwnedVPSRawV3(resultRaw)
	if err != nil {
		t.Fatal(err)
	}
	if result.Outcome != "INCONCLUSIVE" || result.Campaign.Mode != "Functional" ||
		result.Subject.PackageSHA256 != candidateManifestEntryDigestForTest(t, manifest, "PQS", "package/candidate-linux-amd64.tar.gz") ||
		result.Subject.AppAPKSHA256 != candidateManifestEntryDigestForTest(t, manifest, "PQS", "android/app-internal.apk") ||
		result.Subject.TestAPKSHA256 != candidateManifestEntryDigestForTest(t, manifest, "QHS", "android/app-internal-androidTest.apk") {
		t.Fatalf("categorical result=%+v", result)
	}
	for _, check := range result.Checks {
		if check.Result != "NOT_RUN" {
			t.Fatalf("missing-result close invented completed check %+v", check)
		}
	}
	state, attempts, err := phase17qualification.VerifyLedgerAttempts(ledger, manifest.Roots.CandidateID, publicKey)
	if err != nil || state.Entries != 2 || len(attempts) != 1 || !attempts[0].Completed || attempts[0].Terminal.Outcome != "INCONCLUSIVE" {
		t.Fatalf("state=%+v attempts=%+v err=%v", state, attempts, err)
	}
	stdout.Reset()
	stderr.Reset()
	if code := run([]string{
		"attempt", "close", "-attempt", beginPath, "-candidate", candidatePath, "-environment", environmentPath,
		"-policy", policyPath, "-package-entry", "package/candidate-linux-amd64.tar.gz",
		"-app-entry", "android/app-internal.apk", "-test-entry", "android/app-internal-androidTest.apk",
		"-reason", "UNTRUSTED_REASON", "-ledger", ledger, "-private-key", privatePath,
		"-result-out", filepath.Join(directory, "invalid-result.json"), "-out", filepath.Join(directory, "invalid-terminal.json"),
	}, &stdout, &stderr); code == 0 {
		t.Fatal("unrecognized attempt-closure reason was accepted")
	}
}

func candidateManifestEntryDigestForTest(t *testing.T, manifest phase17qualification.CandidateManifest, subjectName, entryPath string) string {
	t.Helper()
	for _, subject := range manifest.Subjects {
		if subject.Name != subjectName {
			continue
		}
		for _, entry := range subject.Entries {
			if entry.Path == entryPath {
				return entry.SHA256
			}
		}
	}
	t.Fatalf("missing fixture entry %s/%s", subjectName, entryPath)
	return ""
}

func TestRunIssuesEvidenceFinalOnlyForExactTerminalSoakAndSanitizedTwin(t *testing.T) {
	directory := t.TempDir()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x72}, ed25519.SeedSize))
	defer phase17qualification.Clear(privateKey)
	publicKey := privateKey.Public().(ed25519.PublicKey)
	privatePath := filepath.Join(directory, "key.ed25519")
	if err := os.WriteFile(privatePath, privateKey, 0o600); err != nil {
		t.Fatal(err)
	}
	candidatePath, manifest := writeCandidateManifestFixture(t, directory)
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	lockRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementRCLocked, phase17qualification.RCLockedPayload{
		Schema: phase17qualification.RCLockedSchema, Candidate: candidate,
		AuthorizationID: strings.Repeat("1", 32), IssuedAt: "2026-08-14T12:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	locked, err := phase17qualification.VerifyStatement(lockRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join("..", "..", "config", "phase17", "qualification-policy-v1.json")
	policyRaw, err := os.ReadFile(policyPath)
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := sha256.Sum256(policyRaw)
	stressAttempt := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidate.Roots.CandidateID,
		Sequence: 1, State: phase17qualification.AttemptBegin, AttemptID: strings.Repeat("5", 32), Mode: "Stress",
		RCLockedSHA256: locked.DigestSHA256, AuthorizationSHA256: locked.DigestSHA256,
		EnvironmentSHA256: strings.Repeat("6", 64), PreflightSHA256: strings.Repeat("0", 64),
		RecordedAt: "2026-08-14T12:02:00Z",
	}
	stress := validFieldResultForAttempt(t, manifest, stressAttempt, hex.EncodeToString(policyDigest[:]))
	stressRaw, err := phase17evidence.MarshalOwnedVPSRawV3(stress)
	if err != nil {
		t.Fatal(err)
	}
	stressPath := filepath.Join(directory, "stress-result.json")
	if err := os.WriteFile(stressPath, stressRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	stressDigest := sha256.Sum256(stressRaw)
	readyRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementSoakReady, phase17qualification.SoakReadyPayload{
		Schema: phase17qualification.SoakReadySchema, CandidateID: candidate.Roots.CandidateID,
		RCLockedSHA256: locked.DigestSHA256, EvidenceIndexSHA256: strings.Repeat("2", 64),
		PriorStressResultSHA256: hex.EncodeToString(stressDigest[:]),
		LedgerHeadSHA256:        strings.Repeat("3", 64), AuthorizationID: strings.Repeat("4", 32),
		IssuedAt: "2026-08-14T12:01:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	ready, err := phase17qualification.VerifyStatement(readyRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	attemptID := strings.Repeat("7", 32)
	environmentDigest := strings.Repeat("8", 64)
	ledger := filepath.Join(directory, "ledger")
	consumedPayload := phase17qualification.SoakConsumedPayload{
		Schema: phase17qualification.SoakConsumedSchema, CandidateID: candidate.Roots.CandidateID,
		Sequence: 1, PreviousEntrySHA256: "", SoakReadySHA256: ready.DigestSHA256,
		RCLockedSHA256: locked.DigestSHA256, AttemptID: attemptID, EnvironmentSHA256: environmentDigest,
		PreflightSHA256: strings.Repeat("9", 64),
		ConsumedAt:      "2026-08-14T12:03:00Z",
	}
	consumedRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementSoakConsumed, consumedPayload)
	if err != nil {
		t.Fatal(err)
	}
	consumedDigest, err := phase17qualification.AppendLedger(ledger, consumedRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	begin := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidate.Roots.CandidateID,
		Sequence: 2, PreviousEntrySHA256: consumedDigest, State: phase17qualification.AttemptBegin,
		AttemptID: attemptID, Mode: "Soak12h", RCLockedSHA256: locked.DigestSHA256,
		AuthorizationSHA256: ready.DigestSHA256, EnvironmentSHA256: environmentDigest,
		PreflightSHA256: strings.Repeat("9", 64),
		RecordedAt:      "2026-08-14T12:04:00Z",
	}
	beginRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, begin)
	if err != nil {
		t.Fatal(err)
	}
	beginDigest, err := phase17qualification.AppendLedger(ledger, beginRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	soak := validFieldResultForAttempt(t, manifest, begin, hex.EncodeToString(policyDigest[:]))
	soak.Attempt.PriorStressResultSHA256 = hex.EncodeToString(stressDigest[:])
	soakRaw, err := phase17evidence.MarshalOwnedVPSRawV3(soak)
	if err != nil {
		t.Fatal(err)
	}
	soakPath := filepath.Join(directory, "soak-result.json")
	if err := os.WriteFile(soakPath, soakRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	soakDigest := sha256.Sum256(soakRaw)
	terminal := begin
	terminal.Sequence = 3
	terminal.PreviousEntrySHA256 = beginDigest
	terminal.State = phase17qualification.AttemptTerminal
	terminal.Outcome = "PASS"
	terminal.ResultSHA256 = hex.EncodeToString(soakDigest[:])
	terminal.RecordedAt = "2026-08-15T00:05:00Z"
	terminalRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phase17qualification.AppendLedger(ledger, terminalRaw, publicKey); err != nil {
		t.Fatal(err)
	}
	sanitizedRaw, err := phase17evidence.SanitizeOwnedVPSV3(soakRaw)
	if err != nil {
		t.Fatal(err)
	}
	sanitizedPath := filepath.Join(directory, "sanitized.json")
	if err := os.WriteFile(sanitizedPath, sanitizedRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	readyPath := filepath.Join(directory, "soak-ready.json")
	if err := os.WriteFile(readyPath, readyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	finalPath := filepath.Join(directory, "evidence-final.json")
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"evidence", "final", "-candidate", candidatePath, "-soak-result", soakPath,
		"-soak-ready", readyPath, "-prior-stress-result", stressPath, "-sanitized-evidence", sanitizedPath,
		"-policy", policyPath, "-ledger", ledger, "-private-key", privatePath, "-out", finalPath,
	}, &stdout, &stderr)
	if code != 0 || stdout.String() != "PHASE17_EVIDENCE_FINAL\n" || stderr.Len() != 0 {
		t.Fatalf("final code=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	finalRaw, err := os.ReadFile(finalPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := phase17qualification.VerifyStatement(finalRaw, publicKey)
	if err != nil || verified.StatementType != phase17qualification.StatementEvidenceFinal {
		t.Fatalf("verified=%+v err=%v", verified, err)
	}
	payload := verified.Payload.(phase17qualification.EvidenceFinalPayload)
	sanitizedDigest := sha256.Sum256(sanitizedRaw)
	if payload.SoakResultSHA256 != hex.EncodeToString(soakDigest[:]) ||
		payload.SanitizedEvidenceSHA256 != hex.EncodeToString(sanitizedDigest[:]) {
		t.Fatalf("payload=%+v", payload)
	}
}

func TestReadinessEvidenceVerifierRequiresCandidateBoundProofAndLedgeredCampaignPass(t *testing.T) {
	directory := t.TempDir()
	_, manifest := writeCandidateManifestFixture(t, directory)
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	proofRaw, err := phase17qualification.MarshalReadinessProof(phase17qualification.ReadinessProof{
		Schema: phase17qualification.ReadinessProofSchema, Kind: "SOURCE_GATES",
		CandidateID: candidate.Roots.CandidateID, Roots: candidate.Roots, Result: "PASS",
	})
	if err != nil {
		t.Fatal(err)
	}
	begin := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidate.Roots.CandidateID,
		Sequence: 1, State: phase17qualification.AttemptBegin, AttemptID: strings.Repeat("8", 32), Mode: "Functional",
		RCLockedSHA256: strings.Repeat("9", 64), AuthorizationSHA256: strings.Repeat("9", 64),
		EnvironmentSHA256: strings.Repeat("a", 64), PreflightSHA256: strings.Repeat("c", 64),
		RecordedAt: "2026-08-14T12:00:00Z",
	}
	result := validFieldResultForAttempt(t, manifest, begin, strings.Repeat("b", 64))
	resultRaw, err := phase17evidence.MarshalOwnedVPSRawV3(result)
	if err != nil {
		t.Fatal(err)
	}
	resultDigest := sha256.Sum256(resultRaw)
	terminal := begin
	terminal.State = phase17qualification.AttemptTerminal
	terminal.Outcome = "PASS"
	terminal.ResultSHA256 = hex.EncodeToString(resultDigest[:])
	terminal.RecordedAt = "2026-08-14T12:01:00Z"
	verify := readinessEvidenceVerifier([]phase17qualification.LedgerAttemptRecord{{Begin: begin, Terminal: terminal, Completed: true}})
	if err := verify("SOURCE_GATES", proofRaw, candidate); err != nil {
		t.Fatal(err)
	}
	if err := verify("FUNCTIONAL", resultRaw, candidate); err != nil {
		t.Fatal(err)
	}
	if err := readinessEvidenceVerifier(nil)("FUNCTIONAL", resultRaw, candidate); err == nil {
		t.Fatal("unledgered Functional result accepted")
	}
	if err := verify("STRESS", resultRaw, candidate); err == nil {
		t.Fatal("cross-mode campaign result accepted")
	}
}

func TestReadinessEvidenceVerifierAcceptsOnlyCurrentPhysicalFunctionalEvidence(t *testing.T) {
	directory := t.TempDir()
	_, manifest := writeCandidateManifestFixture(t, directory)
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	begin := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidate.Roots.CandidateID,
		Sequence: 1, State: phase17qualification.AttemptBegin, AttemptID: strings.Repeat("8", 32), Mode: "Functional",
		RCLockedSHA256: strings.Repeat("9", 64), AuthorizationSHA256: strings.Repeat("9", 64),
		EnvironmentSHA256: strings.Repeat("a", 64), PreflightSHA256: strings.Repeat("c", 64),
		RecordedAt: "2026-08-14T12:00:00Z",
	}
	verifyResult := func(result phase17evidence.OwnedVPSEvidenceV3) error {
		raw, marshalErr := phase17evidence.MarshalOwnedVPSRawV3(result)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		digest := sha256.Sum256(raw)
		terminal := begin
		terminal.State = phase17qualification.AttemptTerminal
		terminal.Outcome = "PASS"
		terminal.ResultSHA256 = hex.EncodeToString(digest[:])
		terminal.RecordedAt = "2026-08-14T12:01:00Z"
		verify := readinessEvidenceVerifier([]phase17qualification.LedgerAttemptRecord{{Begin: begin, Terminal: terminal, Completed: true}})
		return verify("PHYSICAL_CURRENT", raw, candidate)
	}
	physical := validFieldResultForAttempt(t, manifest, begin, strings.Repeat("b", 64))
	physical.Environment.AndroidClass = "PHYSICAL"
	physical.Environment.AndroidAPI = 36
	physical.Environment.AndroidABI = "arm64-v8a"
	if err := verifyResult(physical); err != nil {
		t.Fatalf("current physical Functional evidence rejected: %v", err)
	}
	emulator := validFieldResultForAttempt(t, manifest, begin, strings.Repeat("b", 64))
	if err := verifyResult(emulator); err == nil {
		t.Fatal("emulator satisfied current physical readiness")
	}
	legacyPhysical := validFieldResultForAttempt(t, manifest, begin, strings.Repeat("b", 64))
	legacyPhysical.Environment.AndroidClass = "PHYSICAL"
	legacyPhysical.Environment.AndroidAPI = 26
	legacyPhysical.Environment.AndroidABI = "arm64-v8a"
	if err := verifyResult(legacyPhysical); err == nil {
		t.Fatal("legacy physical device satisfied current physical readiness")
	}
}

func TestParseChangedPathsRequiresSortedSafeUniqueInventory(t *testing.T) {
	valid := []byte("testdata/evidence/phase17/acceptance-status.json\ntestdata/evidence/phase17/live-data-plane-overlay.json\n")
	paths, err := parseChangedPaths(valid)
	if err != nil || len(paths) != 2 {
		t.Fatalf("paths=%v err=%v", paths, err)
	}
	for name, raw := range map[string][]byte{
		"unsorted":  []byte("z\na\n"),
		"duplicate": []byte("a\na\n"),
		"traversal": []byte("../a\n"),
		"backslash": []byte("a\\b\n"),
		"crlf":      []byte("a\r\n"),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseChangedPaths(raw); err == nil {
				t.Fatal("invalid changed paths accepted")
			}
		})
	}
}

func TestEvidenceOnlyVerificationRequiresCandidateAncestryAndExactAllowlistedDelta(t *testing.T) {
	for name, changedPath := range map[string]string{
		"product":  "internal/product/source.go",
		"harness":  "android/harness.txt",
		"workload": "scripts/workload.txt",
		"verifier": "cmd/verifier/main.go",
		"unlisted": "README.md",
	} {
		t.Run("rejects_"+name+"_change", func(t *testing.T) {
			root, candidatePath, _, beforeTree := writeEvidenceOnlyRepositoryFixture(t)
			writeTestFile(t, root, changedPath, []byte("changed\n"))
			runGitTest(t, root, "add", "--", changedPath)
			runGitTest(t, root, "commit", "-m", "change "+name)
			afterTree := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD^{tree}"))
			if code := runEvidenceOnlyVerificationForTest(t, root, candidatePath, beforeTree, afterTree, changedPath+"\n"); code == 0 {
				t.Fatalf("evidence-only verification accepted %s change", name)
			}
		})
	}

	t.Run("accepts_exact_allowlisted_evidence_delta", func(t *testing.T) {
		root, candidatePath, _, beforeTree := writeEvidenceOnlyRepositoryFixture(t)
		path := "testdata/evidence/phase17/acceptance-status.json"
		writeTestFile(t, root, path, []byte("{\"result\":\"PASS\"}\n"))
		runGitTest(t, root, "add", "--", path)
		runGitTest(t, root, "commit", "-m", "promote evidence")
		afterTree := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD^{tree}"))
		if code := runEvidenceOnlyVerificationForTest(t, root, candidatePath, beforeTree, afterTree, path+"\n"); code != 0 {
			t.Fatal("exact allowlisted evidence delta was rejected")
		}
		if code := runEvidenceOnlyVerificationForTest(t, root, candidatePath, beforeTree, afterTree,
			"testdata/evidence/phase17/live-data-plane-overlay.json\n"); code == 0 {
			t.Fatal("declared changed-path inventory that differs from Git was accepted")
		}
	})

	t.Run("rejects_unrelated_history_even_when_tree_delta_is_allowlisted", func(t *testing.T) {
		root, candidatePath, candidateCommit, beforeTree := writeEvidenceOnlyRepositoryFixture(t)
		runGitTest(t, root, "checkout", "--orphan", "unrelated-evidence")
		path := "testdata/evidence/phase17/acceptance-status.json"
		writeTestFile(t, root, path, []byte("{\"result\":\"PASS\"}\n"))
		runGitTest(t, root, "add", "-A")
		runGitTest(t, root, "commit", "-m", "unrelated evidence tree")
		if err := runGitSuccess(root, "merge-base", "--is-ancestor", candidateCommit, "HEAD"); err == nil {
			t.Fatal("test fixture unexpectedly retained candidate ancestry")
		}
		afterTree := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD^{tree}"))
		if code := runEvidenceOnlyVerificationForTest(t, root, candidatePath, beforeTree, afterTree, path+"\n"); code == 0 {
			t.Fatal("evidence-only verification accepted an unrelated history")
		}
	})
}

func writeEvidenceOnlyRepositoryFixture(t *testing.T) (root, candidatePath, candidateCommit, candidateTree string) {
	t.Helper()
	directory := t.TempDir()
	root = filepath.Join(directory, "repo")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	runGitTest(t, root, "init", "--quiet")
	runGitTest(t, root, "config", "core.longpaths", "true")
	runGitTest(t, root, "config", "user.name", "Phase 17 Test")
	runGitTest(t, root, "config", "user.email", "phase17-test@example.invalid")
	writeTestFile(t, root, "README.md", []byte("baseline\n"))
	runGitTest(t, root, "add", "-A")
	runGitTest(t, root, "commit", "-m", "baseline")
	baseline := strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD"))

	policyRaw, err := os.ReadFile(filepath.Join("..", "..", "config", "phase17", "qualification-policy-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, root, "config/phase17/qualification-policy-v1.json", policyRaw)
	for path, contents := range map[string][]byte{
		"testdata/evidence/phase17/acceptance-status.json":       []byte("{\"result\":\"PENDING\"}\n"),
		"testdata/evidence/phase17/live-data-plane-overlay.json": []byte("{\"result\":\"PENDING\"}\n"),
		"internal/product/source.go":                             []byte("package product\n"),
		"android/harness.txt":                                    []byte("harness\n"),
		"scripts/workload.txt":                                   []byte("workload\n"),
		"cmd/verifier/main.go":                                   []byte("package main\n"),
	} {
		writeTestFile(t, root, path, contents)
	}
	runGitTest(t, root, "add", "-A")
	runGitTest(t, root, "commit", "-m", "candidate")
	candidateCommit = strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD"))
	candidateTree = strings.TrimSpace(runGitTest(t, root, "rev-parse", "HEAD^{tree}"))

	_, fixture := writeCandidateManifestFixture(t, directory)
	source := phase17qualification.SourceProvenance{
		Repository: "saroo98/kurdistan-protocol-compiler", BaselineCommitSHA: baseline,
		CommitSHA: candidateCommit, TreeSHA: candidateTree,
		ChangedPathsSHA256: strings.Repeat("c", 64), ToolchainDeclarationsSHA256: strings.Repeat("d", 64),
		DependencyLocksSHA256: strings.Repeat("e", 64),
	}
	manifest, err := phase17qualification.NewCandidateManifest(source, strings.Repeat("f", 64), fixture.Subjects)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := phase17qualification.MarshalCandidateManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	candidatePath = filepath.Join(directory, "evidence-only-candidate.json")
	if err := os.WriteFile(candidatePath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return root, candidatePath, candidateCommit, candidateTree
}

func writeTestFile(t *testing.T, root, relative string, contents []byte) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, contents, 0o600); err != nil {
		t.Fatal(err)
	}
}

func runEvidenceOnlyVerificationForTest(t *testing.T, root, candidatePath, beforeTree, afterTree, changedPaths string) int {
	t.Helper()
	changedPath := filepath.Join(filepath.Dir(candidatePath), "changed-paths-"+afterTree+".txt")
	if err := os.WriteFile(changedPath, []byte(changedPaths), 0o600); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	code := run([]string{
		"evidence-only", "verify", "-root", root, "-candidate", candidatePath,
		"-before-tree", beforeTree, "-after-tree", afterTree, "-changed-paths", changedPath,
	}, &stdout, &stderr)
	if code == 0 && (stdout.String() != "PHASE17_EVIDENCE_ONLY_PASS\n" || stderr.Len() != 0) {
		t.Fatalf("successful evidence-only verification emitted stdout=%q stderr=%q", stdout.String(), stderr.String())
	}
	return code
}

func writeCandidateManifestFixture(t *testing.T, directory string) (string, phase17qualification.CandidateManifest) {
	t.Helper()
	entries := []phase17qualification.SubjectManifest{
		{Name: "PQS"}, {Name: "QHS"}, {Name: "QWS"}, {Name: "OVS"},
	}
	for index := range entries {
		inputRoot := filepath.Join(directory, "subject-fixture", entries[index].Name)
		if err := os.MkdirAll(inputRoot, 0o700); err != nil {
			t.Fatal(err)
		}
		paths := []string{strings.ToLower(entries[index].Name) + ".bin"}
		switch entries[index].Name {
		case "PQS":
			paths = []string{"android/app-internal.apk", "package/candidate-linux-amd64.tar.gz"}
		case "QHS":
			paths = []string{"android/app-internal-androidTest.apk", "qhs.bin"}
		}
		for pathIndex, path := range paths {
			absolute := filepath.Join(inputRoot, filepath.FromSlash(path))
			if err := os.MkdirAll(filepath.Dir(absolute), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(absolute, []byte{byte(index + 1), byte(pathIndex + 1)}, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		manifest, err := phase17qualification.BuildSubjectManifest(entries[index].Name, inputRoot, paths)
		if err != nil {
			t.Fatal(err)
		}
		entries[index] = manifest
	}
	source := phase17qualification.SourceProvenance{
		Repository: "saroo98/kurdistan-protocol-compiler", BaselineCommitSHA: strings.Repeat("9", 40), CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
		ChangedPathsSHA256: strings.Repeat("c", 64), ToolchainDeclarationsSHA256: strings.Repeat("d", 64), DependencyLocksSHA256: strings.Repeat("e", 64),
	}
	manifest, err := phase17qualification.NewCandidateManifest(source, strings.Repeat("f", 64), entries)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := phase17qualification.MarshalCandidateManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "candidate-manifest.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, manifest
}

func writeEnvironmentFixture(t *testing.T, directory string) string {
	t.Helper()
	raw, err := phase17qualification.MarshalEnvironmentContext(phase17qualification.EnvironmentContext{
		Schema: phase17qualification.EnvironmentSchema, HostOS: "windows", HostArch: "amd64", HostBootClass: "BOUND_CURRENT_BOOT",
		AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64", VPSOS: "linux", VPSArch: "amd64",
		ProviderClass: "PRIMARY", TimeSource: "OWNER_VPS_INTERVAL_REQUIRED", PowerPolicy: "RUNNER_SYSTEM_REQUIRED",
		PythonSHA256: strings.Repeat("1", 64), ADBSHA256: strings.Repeat("2", 64),
		SSHSHA256: strings.Repeat("3", 64), SCPSHA256: strings.Repeat("4", 64),
		PowerShellSHA256: strings.Repeat("5", 64), PrivateCommitment: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "environment.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePreflightFixture(t *testing.T, directory, environmentPath string) string {
	t.Helper()
	environmentSHA256, err := loadEnvironmentDigest(environmentPath)
	if err != nil {
		t.Fatal(err)
	}
	value := phase17qualification.OwnerVPSPreflight{
		Schema: phase17qualification.OwnerVPSPreflightSchema, PreflightID: strings.Repeat("1", 32),
		EnvironmentSHA256: environmentSHA256, Status: "PASS", HostClass: "OWNER_CONTROLLED_VPS", OS: "linux", Arch: "amd64",
		Systemd: true, Networkd: true, NFT: true, Unbound: true, TUN: true, TimeSynchronized: true, HostClockToVPS: true,
		Memory: true, Disk: true, IPv4: true, IPv6: true, IPv6Global: true, IPv6DefaultRoute: true,
		IPv6Forwarding: true, IPv6NFTPolicy: true, IPv6External: true, Sudo: true, RawLogRetained: false,
	}
	raw, err := phase17qualification.MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(directory, "preflight.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func writePrivateEnvironmentFixture(t *testing.T, directory, avdName string) (string, phase17qualification.PrivateEnvironment) {
	t.Helper()
	return writePrivateEnvironmentFixtureAt(t, filepath.Join(directory, "private-environment.json"), directory, avdName)
}

func writePrivateEnvironmentFixtureAt(t *testing.T, path, directory, avdName string) (string, phase17qualification.PrivateEnvironment) {
	t.Helper()
	value := phase17qualification.PrivateEnvironment{
		Schema:   phase17qualification.PrivateEnvironmentSchema,
		SSHAlias: "owner-node", AVDName: avdName, DeviceSerial: "",
		ProbeURLFile: filepath.Join(directory, "probe-url.txt"), ProbeDigestFile: filepath.Join(directory, "probe-digest.txt"),
		IPv6ProbeAddress: "2001:db8::1", RelayPort: 8443,
		PythonExecutable: filepath.Join(directory, "python.exe"), ADBExecutable: filepath.Join(directory, "adb.exe"),
		SSHExecutable: filepath.Join(directory, "ssh.exe"), SCPExecutable: filepath.Join(directory, "scp.exe"),
		PowerShellExecutable: filepath.Join(directory, "powershell.exe"),
	}
	files := map[string][]byte{
		value.ProbeURLFile:         []byte("https://probe.invalid/check\n"),
		value.ProbeDigestFile:      []byte(strings.Repeat("22", 32) + "\n"),
		value.PythonExecutable:     []byte("python tool fixture"),
		value.ADBExecutable:        []byte("adb tool fixture"),
		value.SSHExecutable:        []byte("ssh tool fixture"),
		value.SCPExecutable:        []byte("scp tool fixture"),
		value.PowerShellExecutable: []byte("powershell tool fixture"),
	}
	for file, raw := range files {
		if err := os.WriteFile(file, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	raw, err := phase17qualification.MarshalCanonical(value)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path, value
}

func seedCompletedStressLedger(t *testing.T, ledger, candidateID string, privateKey, publicKey []byte) {
	t.Helper()
	begin := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidateID, Sequence: 1, PreviousEntrySHA256: "",
		State: phase17qualification.AttemptBegin, AttemptID: strings.Repeat("a", 32), Mode: "Stress",
		RCLockedSHA256: strings.Repeat("b", 64), AuthorizationSHA256: strings.Repeat("b", 64), EnvironmentSHA256: strings.Repeat("c", 64),
		PreflightSHA256: strings.Repeat("e", 64),
		Outcome:         "", ResultSHA256: "", RecordedAt: "2026-08-14T12:00:00Z",
	}
	beginRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, begin)
	if err != nil {
		t.Fatal(err)
	}
	head, err := phase17qualification.AppendLedger(ledger, beginRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	terminal := begin
	terminal.Sequence = 2
	terminal.PreviousEntrySHA256 = head
	terminal.State = phase17qualification.AttemptTerminal
	terminal.Outcome = "PASS"
	terminal.ResultSHA256 = strings.Repeat("d", 64)
	terminal.RecordedAt = "2026-08-14T12:30:00Z"
	terminalRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phase17qualification.AppendLedger(ledger, terminalRaw, publicKey); err != nil {
		t.Fatal(err)
	}
}

func runGitTest(t *testing.T, root string, arguments ...string) string {
	t.Helper()
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v: %v (%s)", arguments, err, output)
	}
	return string(output)
}

func validFieldResultForAttempt(
	t *testing.T,
	manifest phase17qualification.CandidateManifest,
	attempt phase17qualification.AttemptPayload,
	policySHA256 string,
) phase17evidence.OwnedVPSEvidenceV3 {
	t.Helper()
	checks := make([]phase17evidence.FieldCheckV3, 0, len(phase17evidence.RequiredOwnedVPSChecks()))
	for _, name := range phase17evidence.RequiredOwnedVPSChecks() {
		checks = append(checks, phase17evidence.FieldCheckV3{Name: name, Result: "PASS"})
	}
	campaignPolicy, found := phase17qualification.CampaignPolicyForMode(attempt.Mode)
	if !found {
		t.Fatalf("unknown campaign mode %s", attempt.Mode)
	}
	campaign := phase17evidence.FieldCampaignV3{
		Mode: campaignPolicy.Mode, RestartReconnectCycles: campaignPolicy.RestartReconnectCycles,
		ProfileRotationCycles: campaignPolicy.ProfileRotationCycles, Impairments: append([]string{}, campaignPolicy.Impairments...),
		SoakDurationMS: campaignPolicy.MinimumDurationMS, CadenceMS: campaignPolicy.CadenceMS, SoakCycles: campaignPolicy.MinimumCycles,
	}
	durationMS := uint64(1_200)
	priorStress := ""
	soakReady := ""
	if campaignPolicy.MinimumDurationMS > 0 {
		durationMS = campaignPolicy.MinimumDurationMS
	}
	if attempt.Mode == "Soak12h" {
		priorStress = strings.Repeat("8", 64)
		soakReady = attempt.AuthorizationSHA256
	}
	return phase17evidence.OwnedVPSEvidenceV3{
		Schema: phase17evidence.OwnedVPSRawSchemaV3, Outcome: "PASS",
		Subject: phase17evidence.FieldSubjectV3{
			Repository: manifest.Source.Repository, CommitSHA: manifest.Source.CommitSHA, TreeSHA: manifest.Source.TreeSHA,
			CandidateID: manifest.Roots.CandidateID, SourceSHA256: manifest.Roots.SourceSHA256,
			ProductSHA256: manifest.Roots.ProductSHA256, HarnessSHA256: manifest.Roots.HarnessSHA256,
			WorkloadSHA256: manifest.Roots.WorkloadSHA256, VerifierSHA256: manifest.Roots.VerifierSHA256,
			ComparisonSHA256: manifest.ComparisonSHA256, PolicySHA256: policySHA256,
			PackageSHA256: strings.Repeat("1", 64), AppAPKSHA256: strings.Repeat("2", 64), TestAPKSHA256: strings.Repeat("3", 64),
		},
		Attempt: phase17evidence.FieldAttemptV3{
			AttemptID: attempt.AttemptID, RCLockedSHA256: attempt.RCLockedSHA256,
			AuthorizationSHA256: attempt.AuthorizationSHA256, EnvironmentSHA256: attempt.EnvironmentSHA256,
			PreflightSHA256:         attempt.PreflightSHA256,
			PriorStressResultSHA256: priorStress, SoakReadySHA256: soakReady,
		},
		Environment: phase17evidence.FieldEnvironmentV3{
			HostOS: "windows", HostArch: "amd64", AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64",
			VPSOS: "linux", VPSArch: "amd64", ProviderClass: "PRIMARY", IPv4: true, IPv6: true,
		},
		Checks: checks,
		Metrics: phase17evidence.FieldMetricsV3{
			DurationMS: durationMS, PeakRSSBytes: 1 << 20, PeakFileDescriptors: 12,
			PeakSwapBytes: 0, OOMKills: 0, Reconnects: 2, TerminalGaps: 0,
		},
		Privacy: phase17evidence.FieldPrivacyV3{},
		Scanners: []phase17evidence.FieldScannerV3{
			{Name: "GO_A", IdentitySHA256: strings.Repeat("4", 64), InputSHA256: strings.Repeat("5", 64), BytesConsumed: 1024, RecordsConsumed: 12, Result: "PASS", Privacy: phase17evidence.FieldPrivacyV3{}},
			{Name: "PYTHON_B", IdentitySHA256: strings.Repeat("6", 64), InputSHA256: strings.Repeat("5", 64), BytesConsumed: 1024, RecordsConsumed: 12, Result: "PASS", Privacy: phase17evidence.FieldPrivacyV3{}},
		},
		Boundary: phase17evidence.FieldBoundaryV3{Result: "PASS", MonitorSHA256: strings.Repeat("7", 64)},
		Campaign: campaign,
	}
}
