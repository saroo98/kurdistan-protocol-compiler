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
	"os"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/phase17qualification"
)

func TestLoadQualifiedRunBindsEveryCandidateInputAndLedgerHead(t *testing.T) {
	fixture := newQualifiedRunFixture(t, "Functional")
	loaded, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.candidate.Roots.CandidateID != fixture.candidate.Roots.CandidateID || loaded.attempt.Mode != "Functional" ||
		loaded.attemptDigest == "" || loaded.policyDigest == "" || loaded.environmentDigest == "" || loaded.wrapperDigest == "" {
		t.Fatalf("qualified run=%+v", loaded)
	}

	if err := os.WriteFile(fixture.artifacts.runnerPath, []byte("changed-runner"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts); err == nil {
		t.Fatal("runner bytes outside the locked QHS were accepted")
	}
	fixture = newQualifiedRunFixture(t, "Functional")
	if err := os.WriteFile(fixture.artifacts.wrapperPath, []byte("changed-wrapper"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts); err == nil {
		t.Fatal("active wrapper bytes outside the locked QHS were accepted")
	}
	fixture = newQualifiedRunFixture(t, "Functional")
	if err := os.WriteFile(fixture.artifacts.preflightPath, []byte("changed-preflight"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts); err == nil {
		t.Fatal("active preflight bytes outside the locked QHS were accepted")
	}
	fixture = newQualifiedRunFixture(t, "Functional")
	if err := os.WriteFile(fixture.inputs.preflightResultPath, []byte("changed-preflight-result"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts); err == nil {
		t.Fatal("preflight evidence other than the attempt-bound bytes was accepted")
	}
}

func TestLoadQualifiedRunRejectsStaleAttemptAndCrossModeUse(t *testing.T) {
	fixture := newQualifiedRunFixture(t, "Stress")
	if _, err := loadQualifiedRun("Soak60m", fixture.inputs, fixture.artifacts); err == nil {
		t.Fatal("attempt receipt was reused for another mode")
	}

	terminal := fixture.attempt
	terminal.Sequence++
	terminal.PreviousEntrySHA256 = fixture.attemptDigest
	terminal.State = phase17qualification.AttemptTerminal
	terminal.Outcome = "FAIL_HARNESS"
	terminal.ResultSHA256 = strings.Repeat("f", 64)
	terminal.RecordedAt = "2026-08-14T00:01:00Z"
	raw, err := phase17qualification.SignStatement(fixture.privateKey, phase17qualification.StatementAttempt, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := phase17qualification.AppendLedger(fixture.inputs.ledgerPath, raw, fixture.publicKey); err != nil {
		t.Fatal(err)
	}
	if _, err := loadQualifiedRun("Stress", fixture.inputs, fixture.artifacts); err == nil {
		t.Fatal("attempt that is no longer the ledger head was accepted")
	}
}

func TestLoadPrivateRuntimeVerifiesEnvironmentCommitmentBeforeCampaignUse(t *testing.T) {
	originalBootReader := readCurrentHostBootIdentity
	defer func() { readCurrentHostBootIdentity = originalBootReader }()
	bootIdentity := []byte("2026-08-14T05:06:07.1234567Z")
	readCurrentHostBootIdentity = func(context.Context, string) ([]byte, error) {
		return bytes.Clone(bootIdentity), nil
	}
	fixture := newQualifiedRunFixture(t, "Functional")
	qualified, err := loadQualifiedRun("Functional", fixture.inputs, fixture.artifacts)
	if err != nil {
		t.Fatal(err)
	}
	value, salt, probeURL, probeDigest, err := loadPrivateRuntime(config{
		privateEnvironmentPath: fixture.privateEnvironmentPath,
		environmentSaltPath:    fixture.environmentSaltPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer phase17qualification.Clear(salt)
	defer phase17qualification.Clear(probeURL)
	defer phase17qualification.Clear(probeDigest)
	if value.sshAlias != fixture.privateEnvironment.SSHAlias || value.avdName != fixture.privateEnvironment.AVDName ||
		value.probeURLFile != fixture.privateEnvironment.ProbeURLFile || value.pythonPath != fixture.privateEnvironment.PythonExecutable {
		t.Fatal("owner-private runtime inputs were not loaded exactly")
	}
	if err := verifyPrivateEnvironmentCommitment(context.Background(), qualified, value, salt, probeURL, probeDigest); err != nil {
		t.Fatal(err)
	}
	bootIdentity = []byte("2026-08-14T06:07:08.2345678Z")
	if err := verifyPrivateEnvironmentCommitment(context.Background(), qualified, value, salt, probeURL, probeDigest); err == nil {
		t.Fatal("host reboot preserved locked environment verification")
	}
	bootIdentity = []byte("2026-08-14T05:06:07.1234567Z")

	mutated := fixture.privateEnvironment
	mutated.AVDName = "api36-other"
	raw, err := phase17qualification.MarshalCanonical(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(fixture.privateEnvironmentPath, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	value, changedSalt, changedURL, changedDigest, err := loadPrivateRuntime(config{
		privateEnvironmentPath: fixture.privateEnvironmentPath,
		environmentSaltPath:    fixture.environmentSaltPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer phase17qualification.Clear(changedSalt)
	defer phase17qualification.Clear(changedURL)
	defer phase17qualification.Clear(changedDigest)
	if err := verifyPrivateEnvironmentCommitment(context.Background(), qualified, value, changedSalt, changedURL, changedDigest); err == nil {
		t.Fatal("mutated private selector preserved locked environment verification")
	}
}

type qualifiedRunFixture struct {
	inputs                 qualifiedInputPaths
	artifacts              qualifiedArtifactPaths
	candidate              phase17qualification.CandidateIdentity
	attempt                phase17qualification.AttemptPayload
	attemptDigest          string
	publicKey              ed25519.PublicKey
	privateKey             ed25519.PrivateKey
	privateEnvironmentPath string
	environmentSaltPath    string
	privateEnvironment     phase17qualification.PrivateEnvironment
}

func newQualifiedRunFixture(t *testing.T, mode string) qualifiedRunFixture {
	t.Helper()
	root := t.TempDir()
	artifactRoot := filepath.Join(root, "candidate")
	paths := map[string]string{
		"package":          filepath.Join(artifactRoot, "PQS", "node.tar.gz"),
		"app":              filepath.Join(artifactRoot, "PQS", "app.apk"),
		"runner":           filepath.Join(artifactRoot, "QHS", "phase17field.exe"),
		"wrapper":          filepath.Join(artifactRoot, "QHS", "run-qualified-campaign.ps1"),
		"preflight":        filepath.Join(artifactRoot, "QHS", "owned-vps-preflight.ps1"),
		"package-verifier": filepath.Join(artifactRoot, "QHS", "kurdpackage.exe"),
		"scanner-a":        filepath.Join(artifactRoot, "QHS", "phase17scan.exe"),
		"scanner-b":        filepath.Join(artifactRoot, "QHS", "privacy_scanner_b.py"),
		"boundary":         filepath.Join(artifactRoot, "QHS", "phase17boundary.exe"),
		"test":             filepath.Join(artifactRoot, "QHS", "test.apk"),
		"policy":           filepath.Join(artifactRoot, "QWS", "qualification-policy-v1.json"),
		"verifier":         filepath.Join(artifactRoot, "OVS", "phase17qual.exe"),
		"python":           filepath.Join(root, "tools", "python.exe"),
		"adb":              filepath.Join(root, "tools", "adb.exe"),
		"ssh":              filepath.Join(root, "tools", "ssh.exe"),
		"scp":              filepath.Join(root, "tools", "scp.exe"),
		"powershell":       filepath.Join(root, "tools", "powershell.exe"),
	}
	for name, path := range paths {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		content := []byte("fixture-" + name)
		if name == "policy" {
			repositoryRoot, err := filepath.Abs(filepath.Join("..", ".."))
			if err != nil {
				t.Fatal(err)
			}
			content, err = os.ReadFile(filepath.Join(repositoryRoot, "config", "phase17", "qualification-policy-v1.json"))
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	subjects := make([]phase17qualification.SubjectManifest, 0, 4)
	for _, name := range []string{"PQS", "QHS", "QWS", "OVS"} {
		manifest, err := phase17qualification.BuildSubjectManifestTree(name, filepath.Join(artifactRoot, name))
		if err != nil {
			t.Fatal(err)
		}
		subjects = append(subjects, manifest)
	}
	manifest, err := phase17qualification.NewCandidateManifest(phase17qualification.SourceProvenance{
		Repository: "saroo98/kurdistan-protocol-compiler", BaselineCommitSHA: strings.Repeat("c", 40), CommitSHA: strings.Repeat("a", 40), TreeSHA: strings.Repeat("b", 40),
		ChangedPathsSHA256: strings.Repeat("1", 64), ToolchainDeclarationsSHA256: strings.Repeat("2", 64), DependencyLocksSHA256: strings.Repeat("3", 64),
	}, strings.Repeat("4", 64), subjects)
	if err != nil {
		t.Fatal(err)
	}
	candidateRaw, err := phase17qualification.MarshalCandidateManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	candidatePath := filepath.Join(root, "candidate.json")
	if err := os.WriteFile(candidatePath, candidateRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		t.Fatal(err)
	}
	probeURLPath := filepath.Join(root, "private", "probe-url.txt")
	probeDigestPath := filepath.Join(root, "private", "probe-digest.txt")
	if err := os.MkdirAll(filepath.Dir(probeURLPath), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probeURLPath, []byte("https://probe.invalid/check\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probeDigestPath, []byte(strings.Repeat("8", 64)+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	privateEnvironment := phase17qualification.PrivateEnvironment{
		Schema:   phase17qualification.PrivateEnvironmentSchema,
		SSHAlias: "owner-node", AVDName: "api36-field", DeviceSerial: "",
		ProbeURLFile: probeURLPath, ProbeDigestFile: probeDigestPath,
		IPv6ProbeAddress: "2001:db8::1", RelayPort: 8443,
		PythonExecutable: paths["python"], ADBExecutable: paths["adb"],
		SSHExecutable: paths["ssh"], SCPExecutable: paths["scp"],
		PowerShellExecutable: paths["powershell"],
	}
	privateEnvironmentRaw, err := phase17qualification.MarshalCanonical(privateEnvironment)
	if err != nil {
		t.Fatal(err)
	}
	privateEnvironmentPath := filepath.Join(root, "private", "environment.json")
	if err := os.WriteFile(privateEnvironmentPath, privateEnvironmentRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	environmentSalt := make([]byte, phase17qualification.PrivateEnvironmentSaltSize)
	for index := range environmentSalt {
		environmentSalt[index] = byte(index + 1)
	}
	environmentSaltPath := filepath.Join(root, "private", "environment-salt.bin")
	if err := os.WriteFile(environmentSaltPath, environmentSalt, 0o600); err != nil {
		t.Fatal(err)
	}
	privateCommitment, err := phase17qualification.ComputePrivateEnvironmentCommitment(
		candidate.Roots.CandidateID, "EMULATOR", environmentSalt, privateEnvironment,
		[]byte("https://probe.invalid/check"), []byte(strings.Repeat("8", 64)),
		[]byte("2026-08-14T05:06:07.1234567Z"),
	)
	phase17qualification.Clear(environmentSalt)
	if err != nil {
		t.Fatal(err)
	}

	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	publicPath := filepath.Join(root, "qualification.pub")
	if err := os.WriteFile(publicPath, publicKey, 0o600); err != nil {
		t.Fatal(err)
	}
	rcRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementRCLocked, phase17qualification.RCLockedPayload{
		Schema: phase17qualification.RCLockedSchema, Candidate: candidate,
		AuthorizationID: strings.Repeat("5", 32), IssuedAt: "2026-08-14T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	rcPath := filepath.Join(root, "rc-locked.json")
	if err := os.WriteFile(rcPath, rcRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	rcDigest := sha256.Sum256(rcRaw)
	rcDigestHex := hex.EncodeToString(rcDigest[:])
	environment := phase17qualification.EnvironmentContext{
		Schema: phase17qualification.EnvironmentSchema, HostOS: "windows", HostArch: "amd64", HostBootClass: "BOUND_CURRENT_BOOT",
		AndroidClass: "EMULATOR", AndroidAPI: 36, AndroidABI: "x86_64", VPSOS: "linux", VPSArch: "amd64",
		ProviderClass: "PRIMARY", TimeSource: "OWNER_VPS_INTERVAL_REQUIRED", PowerPolicy: "RUNNER_SYSTEM_REQUIRED",
		PythonSHA256: fileDigestHexForFixture(t, paths["python"]), ADBSHA256: fileDigestHexForFixture(t, paths["adb"]),
		SSHSHA256: fileDigestHexForFixture(t, paths["ssh"]), SCPSHA256: fileDigestHexForFixture(t, paths["scp"]),
		PowerShellSHA256:  fileDigestHexForFixture(t, paths["powershell"]),
		PrivateCommitment: privateCommitment,
	}
	environmentRaw, err := phase17qualification.MarshalEnvironmentContext(environment)
	if err != nil {
		t.Fatal(err)
	}
	environmentPath := filepath.Join(root, "environment.json")
	if err := os.WriteFile(environmentPath, environmentRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	environmentDigest, err := phase17qualification.EnvironmentDigest(environment)
	if err != nil {
		t.Fatal(err)
	}
	preflightRaw, err := phase17qualification.MarshalCanonical(phase17qualification.OwnerVPSPreflight{
		Schema: phase17qualification.OwnerVPSPreflightSchema, PreflightID: strings.Repeat("6", 32),
		EnvironmentSHA256: environmentDigest, Status: "PASS", HostClass: "OWNER_CONTROLLED_VPS", OS: "linux", Arch: "amd64",
		Systemd: true, Networkd: true, NFT: true, Unbound: true, TUN: true, TimeSynchronized: true, HostClockToVPS: true,
		Memory: true, Disk: true, IPv4: true, IPv6: true, IPv6Global: true, IPv6DefaultRoute: true,
		IPv6Forwarding: true, IPv6NFTPolicy: true, IPv6External: true, Sudo: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	preflightResultPath := filepath.Join(root, "preflight-result.json")
	if err := os.WriteFile(preflightResultPath, preflightRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	preflightResultDigest := sha256.Sum256(preflightRaw)
	attempt := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidate.Roots.CandidateID,
		Sequence: 1, PreviousEntrySHA256: "", State: phase17qualification.AttemptBegin,
		AttemptID: strings.Repeat("7", 32), Mode: mode, RCLockedSHA256: rcDigestHex,
		AuthorizationSHA256: rcDigestHex, EnvironmentSHA256: environmentDigest,
		PreflightSHA256: hex.EncodeToString(preflightResultDigest[:]), RecordedAt: "2026-08-14T00:00:01Z",
	}
	attemptRaw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, attempt)
	if err != nil {
		t.Fatal(err)
	}
	ledgerPath := filepath.Join(root, "ledger")
	attemptDigest, err := phase17qualification.AppendLedger(ledgerPath, attemptRaw, publicKey)
	if err != nil {
		t.Fatal(err)
	}
	attemptPath := filepath.Join(root, "attempt.json")
	if err := os.WriteFile(attemptPath, attemptRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	return qualifiedRunFixture{
		inputs: qualifiedInputPaths{
			candidatePath: candidatePath, rcLockedPath: rcPath, attemptPath: attemptPath,
			environmentPath: environmentPath, preflightResultPath: preflightResultPath,
			policyPath: paths["policy"], ledgerPath: ledgerPath, trustedPublicKeyPath: publicPath,
		},
		artifacts: qualifiedArtifactPaths{
			packagePath: paths["package"], packageEntry: "node.tar.gz", appPath: paths["app"], appEntry: "app.apk",
			testPath: paths["test"], testEntry: "test.apk", runnerPath: paths["runner"], runnerEntry: "phase17field.exe",
			wrapperPath: paths["wrapper"], wrapperEntry: "run-qualified-campaign.ps1",
			preflightPath: paths["preflight"], preflightEntry: "owned-vps-preflight.ps1",
			packageVerifierPath: paths["package-verifier"], packageVerifierEntry: "kurdpackage.exe",
			scannerAPath: paths["scanner-a"], scannerAEntry: "phase17scan.exe",
			scannerBPath: paths["scanner-b"], scannerBEntry: "privacy_scanner_b.py",
			boundaryPath: paths["boundary"], boundaryEntry: "phase17boundary.exe",
			pythonPath: paths["python"], adbPath: paths["adb"], sshPath: paths["ssh"], scpPath: paths["scp"], powershellPath: paths["powershell"],
			policyPath: paths["policy"], policyEntry: "qualification-policy-v1.json",
		},
		candidate: candidate, attempt: attempt, attemptDigest: attemptDigest, publicKey: publicKey, privateKey: privateKey,
		privateEnvironmentPath: privateEnvironmentPath, environmentSaltPath: environmentSaltPath,
		privateEnvironment: privateEnvironment,
	}
}

func fileDigestHexForFixture(t *testing.T, path string) string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
