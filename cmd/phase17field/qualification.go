// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"

	"kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
)

var readCurrentHostBootIdentity = phase17qualification.ReadCurrentHostBootIdentity

func loadPrivateRuntime(value config) (config, []byte, []byte, []byte, error) {
	privateRaw, err := readQualifiedRegular(value.privateEnvironmentPath, 64<<10)
	if err != nil {
		return value, nil, nil, nil, err
	}
	defer phase17qualification.Clear(privateRaw)
	privateEnvironment, err := phase17qualification.DecodePrivateEnvironment(bytes.NewReader(privateRaw))
	if err != nil {
		return value, nil, nil, nil, err
	}
	salt, err := readQualifiedRegular(value.environmentSaltPath, phase17qualification.PrivateEnvironmentSaltSize)
	if err != nil || len(salt) != phase17qualification.PrivateEnvironmentSaltSize {
		phase17qualification.Clear(salt)
		return value, nil, nil, nil, errors.New("qualification environment salt rejected")
	}
	probeURL, err := readTrimmedSecret(privateEnvironment.ProbeURLFile, 2048)
	if err != nil {
		phase17qualification.Clear(salt)
		return value, nil, nil, nil, err
	}
	probeDigest, err := readTrimmedSecret(privateEnvironment.ProbeDigestFile, 64)
	if err != nil {
		phase17qualification.Clear(salt)
		phase17qualification.Clear(probeURL)
		return value, nil, nil, nil, err
	}
	value.sshAlias = privateEnvironment.SSHAlias
	value.avdName = privateEnvironment.AVDName
	value.deviceSerial = privateEnvironment.DeviceSerial
	value.probeURLFile = privateEnvironment.ProbeURLFile
	value.probeDigestFile = privateEnvironment.ProbeDigestFile
	value.ipv6ProbeAddress = privateEnvironment.IPv6ProbeAddress
	value.relayPort = privateEnvironment.RelayPort
	value.pythonPath = privateEnvironment.PythonExecutable
	value.adbPath = privateEnvironment.ADBExecutable
	value.sshPath = privateEnvironment.SSHExecutable
	value.scpPath = privateEnvironment.SCPExecutable
	value.powershellPath = privateEnvironment.PowerShellExecutable
	return value, salt, probeURL, probeDigest, nil
}

func verifyPrivateEnvironmentCommitment(
	ctx context.Context,
	qualified qualifiedRun,
	value config,
	salt, probeURL, probeDigest []byte,
) error {
	privateEnvironment := phase17qualification.PrivateEnvironment{
		Schema:   phase17qualification.PrivateEnvironmentSchema,
		SSHAlias: value.sshAlias, AVDName: value.avdName, DeviceSerial: value.deviceSerial,
		ProbeURLFile: value.probeURLFile, ProbeDigestFile: value.probeDigestFile,
		IPv6ProbeAddress: value.ipv6ProbeAddress, RelayPort: value.relayPort,
		PythonExecutable: value.pythonPath, ADBExecutable: value.adbPath,
		SSHExecutable: value.sshPath, SCPExecutable: value.scpPath,
		PowerShellExecutable: value.powershellPath,
	}
	hostBootIdentity, err := readCurrentHostBootIdentity(ctx, value.powershellPath)
	if err != nil {
		return errors.New("qualification host boot identity unavailable")
	}
	defer phase17qualification.Clear(hostBootIdentity)
	commitment, err := phase17qualification.ComputePrivateEnvironmentCommitment(
		qualified.candidate.Roots.CandidateID, qualified.environment.AndroidClass,
		salt, privateEnvironment, probeURL, probeDigest, hostBootIdentity,
	)
	if err != nil || !hmac.Equal([]byte(commitment), []byte(qualified.environment.PrivateCommitment)) {
		return errors.New("qualification private environment commitment rejected")
	}
	return nil
}

type qualifiedInputPaths struct {
	candidatePath        string
	rcLockedPath         string
	attemptPath          string
	environmentPath      string
	preflightResultPath  string
	policyPath           string
	ledgerPath           string
	trustedPublicKeyPath string
	soakReadyPath        string
	priorStressPath      string
}

type qualifiedArtifactPaths struct {
	packagePath, packageEntry                             string
	appPath, appEntry                                     string
	testPath, testEntry                                   string
	runnerPath, runnerEntry                               string
	wrapperPath, wrapperEntry                             string
	preflightPath, preflightEntry                         string
	packageVerifierPath, packageVerifierEntry             string
	scannerAPath, scannerAEntry                           string
	scannerBPath, scannerBEntry                           string
	boundaryPath, boundaryEntry                           string
	pythonPath, adbPath, sshPath, scpPath, powershellPath string
	policyPath, policyEntry                               string
}

type qualifiedRun struct {
	candidate             phase17qualification.CandidateIdentity
	manifest              phase17qualification.CandidateManifest
	policy                phase17qualification.Policy
	campaign              phase17qualification.CampaignPolicy
	policyDigest          string
	attempt               phase17qualification.AttemptPayload
	attemptDigest         string
	rcLockedDigest        string
	environment           phase17qualification.EnvironmentContext
	environmentDigest     string
	soakReadyDigest       string
	priorStressDigest     string
	packageDigest         string
	appDigest             string
	testDigest            string
	runnerDigest          string
	wrapperDigest         string
	preflightDigest       string
	packageVerifierDigest string
	scannerADigest        string
	scannerBDigest        string
	boundaryDigest        string
}

func loadQualifiedRun(mode string, inputs qualifiedInputPaths, artifacts qualifiedArtifactPaths) (qualifiedRun, error) {
	var result qualifiedRun
	for _, required := range []string{
		inputs.candidatePath, inputs.rcLockedPath, inputs.attemptPath, inputs.environmentPath, inputs.preflightResultPath,
		inputs.policyPath, inputs.ledgerPath, inputs.trustedPublicKeyPath,
		artifacts.packagePath, artifacts.packageEntry, artifacts.appPath, artifacts.appEntry,
		artifacts.testPath, artifacts.testEntry, artifacts.runnerPath, artifacts.runnerEntry,
		artifacts.wrapperPath, artifacts.wrapperEntry,
		artifacts.preflightPath, artifacts.preflightEntry,
		artifacts.packageVerifierPath, artifacts.packageVerifierEntry,
		artifacts.scannerAPath, artifacts.scannerAEntry, artifacts.scannerBPath, artifacts.scannerBEntry,
		artifacts.boundaryPath, artifacts.boundaryEntry, artifacts.pythonPath, artifacts.adbPath, artifacts.sshPath, artifacts.scpPath,
		artifacts.powershellPath,
		artifacts.policyPath, artifacts.policyEntry,
	} {
		if required == "" {
			return result, errors.New("qualification input path rejected")
		}
	}
	candidateRaw, err := readQualifiedRegular(inputs.candidatePath, 4<<20)
	if err != nil {
		return result, err
	}
	manifest, err := phase17qualification.DecodeCandidateManifest(bytes.NewReader(candidateRaw))
	if err != nil {
		return result, err
	}
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		return result, err
	}
	policyRaw, err := readQualifiedRegular(inputs.policyPath, 1<<20)
	if err != nil {
		return result, err
	}
	policy, err := phase17qualification.DecodePolicy(bytes.NewReader(policyRaw))
	if err != nil {
		return result, err
	}
	campaign, found := policy.Campaign(mode)
	if !found {
		return result, errors.New("qualification campaign unavailable")
	}
	policySum := sha256.Sum256(policyRaw)
	policyDigest := hex.EncodeToString(policySum[:])
	publicKey, err := phase17qualification.LoadPublicKey(inputs.trustedPublicKeyPath)
	if err != nil {
		return result, err
	}
	rcRaw, err := readQualifiedRegular(inputs.rcLockedPath, 1<<20)
	if err != nil {
		return result, err
	}
	rcStatement, err := phase17qualification.VerifyStatement(rcRaw, publicKey)
	if err != nil || rcStatement.StatementType != phase17qualification.StatementRCLocked {
		return result, errors.New("qualification RC lock rejected")
	}
	rcPayload := rcStatement.Payload.(phase17qualification.RCLockedPayload)
	if rcPayload.Candidate != candidate {
		return result, errors.New("qualification RC lock candidate differs from manifest")
	}
	environmentRaw, err := readQualifiedRegular(inputs.environmentPath, 64<<10)
	if err != nil {
		return result, err
	}
	environment, err := phase17qualification.DecodeEnvironmentContext(bytes.NewReader(environmentRaw))
	if err != nil {
		return result, err
	}
	environmentDigest, err := phase17qualification.EnvironmentDigest(environment)
	if err != nil {
		return result, err
	}
	preflightRaw, err := readQualifiedRegular(inputs.preflightResultPath, 64<<10)
	if err != nil {
		return result, err
	}
	preflightResultDigest, err := phase17qualification.VerifyOwnerVPSPreflight(preflightRaw, environmentDigest)
	if err != nil {
		return result, err
	}
	for path, wanted := range map[string]string{
		artifacts.pythonPath:     environment.PythonSHA256,
		artifacts.adbPath:        environment.ADBSHA256,
		artifacts.sshPath:        environment.SSHSHA256,
		artifacts.scpPath:        environment.SCPSHA256,
		artifacts.powershellPath: environment.PowerShellSHA256,
	} {
		digest, err := digestQualifiedTool(path)
		if err != nil || digest != wanted {
			return result, errors.New("qualification environment tool identity rejected")
		}
	}
	attemptRaw, err := readQualifiedRegular(inputs.attemptPath, 1<<20)
	if err != nil {
		return result, err
	}
	attemptStatement, err := phase17qualification.VerifyStatement(attemptRaw, publicKey)
	if err != nil || attemptStatement.StatementType != phase17qualification.StatementAttempt {
		return result, errors.New("qualification attempt receipt rejected")
	}
	attempt := attemptStatement.Payload.(phase17qualification.AttemptPayload)
	if attempt.State != phase17qualification.AttemptBegin || attempt.Mode != mode || attempt.CandidateID != candidate.Roots.CandidateID ||
		attempt.RCLockedSHA256 != rcStatement.DigestSHA256 || attempt.EnvironmentSHA256 != environmentDigest ||
		attempt.PreflightSHA256 != preflightResultDigest {
		return result, errors.New("qualification attempt identity rejected")
	}
	ledger, err := phase17qualification.VerifyLedger(inputs.ledgerPath, candidate.Roots.CandidateID, publicKey)
	if err != nil || ledger.HeadSHA256 != attemptStatement.DigestSHA256 {
		return result, errors.New("qualification attempt is not the ledger head")
	}

	packageDigest, err := verifyQualifiedArtifact(manifest, "PQS", artifacts.packageEntry, artifacts.packagePath)
	if err != nil {
		return result, err
	}
	appDigest, err := verifyQualifiedArtifact(manifest, "PQS", artifacts.appEntry, artifacts.appPath)
	if err != nil {
		return result, err
	}
	testDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.testEntry, artifacts.testPath)
	if err != nil {
		return result, err
	}
	runnerDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.runnerEntry, artifacts.runnerPath)
	if err != nil {
		return result, err
	}
	wrapperDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.wrapperEntry, artifacts.wrapperPath)
	if err != nil {
		return result, err
	}
	preflightDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.preflightEntry, artifacts.preflightPath)
	if err != nil {
		return result, err
	}
	packageVerifierDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.packageVerifierEntry, artifacts.packageVerifierPath)
	if err != nil {
		return result, err
	}
	scannerADigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.scannerAEntry, artifacts.scannerAPath)
	if err != nil {
		return result, err
	}
	scannerBDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.scannerBEntry, artifacts.scannerBPath)
	if err != nil {
		return result, err
	}
	boundaryDigest, err := verifyQualifiedArtifact(manifest, "QHS", artifacts.boundaryEntry, artifacts.boundaryPath)
	if err != nil {
		return result, err
	}
	verifiedPolicyDigest, err := verifyQualifiedArtifact(manifest, "QWS", artifacts.policyEntry, artifacts.policyPath)
	if err != nil || verifiedPolicyDigest != policyDigest {
		return result, errors.New("qualification policy differs from locked QWS")
	}

	soakReadyDigest := ""
	priorStressDigest := ""
	if mode == "Soak12h" {
		if inputs.soakReadyPath == "" || inputs.priorStressPath == "" {
			return result, errors.New("qualification final soak prerequisites unavailable")
		}
		readyRaw, err := readQualifiedRegular(inputs.soakReadyPath, 1<<20)
		if err != nil {
			return result, err
		}
		ready, err := phase17qualification.VerifyStatement(readyRaw, publicKey)
		if err != nil || ready.StatementType != phase17qualification.StatementSoakReady {
			return result, errors.New("qualification SOAK_READY receipt rejected")
		}
		readyPayload := ready.Payload.(phase17qualification.SoakReadyPayload)
		if readyPayload.CandidateID != candidate.Roots.CandidateID || readyPayload.RCLockedSHA256 != rcStatement.DigestSHA256 ||
			attempt.AuthorizationSHA256 != ready.DigestSHA256 {
			return result, errors.New("qualification final soak authorization chain rejected")
		}
		stressRaw, err := readQualifiedRegular(inputs.priorStressPath, 4<<20)
		if err != nil {
			return result, err
		}
		stress, err := phase17evidence.DecodeOwnedVPSRawV3(stressRaw)
		if err != nil || stress.Outcome != "PASS" || stress.Campaign.Mode != "Stress" {
			return result, errors.New("qualification prior Stress result rejected")
		}
		if err := phase17evidence.ValidateOwnedVPSV3Candidate(stress, candidate, policyDigest); err != nil {
			return result, err
		}
		stressSum := sha256.Sum256(stressRaw)
		priorStressDigest = hex.EncodeToString(stressSum[:])
		if priorStressDigest != readyPayload.PriorStressResultSHA256 {
			return result, errors.New("qualification prior Stress result differs from SOAK_READY")
		}
		soakReadyDigest = ready.DigestSHA256
	} else {
		if inputs.soakReadyPath != "" || inputs.priorStressPath != "" || attempt.AuthorizationSHA256 != rcStatement.DigestSHA256 {
			return result, errors.New("qualification non-final authorization chain rejected")
		}
	}

	result = qualifiedRun{
		candidate: candidate, manifest: manifest, policy: policy, campaign: campaign, policyDigest: policyDigest,
		attempt: attempt, attemptDigest: attemptStatement.DigestSHA256, rcLockedDigest: rcStatement.DigestSHA256,
		environment: environment, environmentDigest: environmentDigest, soakReadyDigest: soakReadyDigest,
		priorStressDigest: priorStressDigest, packageDigest: packageDigest, appDigest: appDigest,
		testDigest: testDigest, runnerDigest: runnerDigest, wrapperDigest: wrapperDigest, preflightDigest: preflightDigest,
		packageVerifierDigest: packageVerifierDigest,
		scannerADigest:        scannerADigest, scannerBDigest: scannerBDigest, boundaryDigest: boundaryDigest,
	}
	return result, nil
}

func digestQualifiedTool(path string) (string, error) {
	raw, err := readQualifiedRegular(path, 1<<30)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]), nil
}

func verifyQualifiedArtifact(manifest phase17qualification.CandidateManifest, subjectName, entryPath, actualPath string) (string, error) {
	return phase17qualification.VerifyCandidateArtifact(manifest, subjectName, entryPath, actualPath, 1<<30)
}

func readQualifiedRegular(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, errors.New("qualification file path rejected")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > maximum {
		return nil, errors.New("qualification file rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("qualification file changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closedInfo, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(raw)) > maximum || int64(len(raw)) != opened.Size() || !os.SameFile(opened, closedInfo) ||
		opened.Size() != closedInfo.Size() || opened.ModTime() != closedInfo.ModTime() {
		return nil, errors.New("qualification file changed while reading")
	}
	return raw, nil
}
