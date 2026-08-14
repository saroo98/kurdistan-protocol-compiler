// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17qual manages the private, owner-local Phase 17 qualification
// policy, keys, signed statements, and append-only attempt ledger. It never
// prints receipt payloads or key material.
package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	phase17evidence "kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
)

var readCurrentHostBootIdentity = phase17qualification.ReadCurrentHostBootIdentity

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(arguments []string, stdout, stderr io.Writer) int {
	if len(arguments) == 0 {
		return fail(stderr, 2)
	}
	var err error
	switch arguments[0] {
	case "policy":
		err = runPolicy(arguments[1:], stdout)
	case "key":
		err = runKey(arguments[1:], stdout)
	case "lock":
		err = runLock(arguments[1:], stdout)
	case "candidate":
		err = runCandidate(arguments[1:], stdout)
	case "source":
		err = runSource(arguments[1:], stdout)
	case "environment":
		err = runEnvironment(arguments[1:], stdout)
	case "attempt":
		err = runAttempt(arguments[1:], stdout)
	case "soak":
		err = runSoak(arguments[1:], stdout)
	case "verify":
		err = runVerify(arguments[1:], stdout)
	case "ledger":
		err = runLedger(arguments[1:], stdout)
	case "readiness":
		err = runReadiness(arguments[1:], stdout)
	case "evidence-only":
		err = runEvidenceOnly(arguments[1:], stdout)
	case "evidence":
		err = runEvidence(arguments[1:], stdout)
	default:
		return fail(stderr, 2)
	}
	if err != nil {
		return fail(stderr, 1)
	}
	return 0
}

func runEnvironment(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("qualification environment command rejected")
	}
	switch arguments[0] {
	case "salt":
		if len(arguments) == 1 || arguments[1] != "generate" {
			return errors.New("qualification environment salt command rejected")
		}
		flags := flag.NewFlagSet("phase17qual environment salt generate", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		outputPath := flags.String("out", "", "owner-local environment commitment salt")
		if err := flags.Parse(arguments[2:]); err != nil || flags.NArg() != 0 || *outputPath == "" {
			return errors.New("qualification environment salt arguments rejected")
		}
		salt := make([]byte, phase17qualification.PrivateEnvironmentSaltSize)
		defer phase17qualification.Clear(salt)
		if _, err := rand.Read(salt); err != nil {
			return errors.New("qualification environment salt generation failed")
		}
		if err := writeExclusiveOutput(*outputPath, salt); err != nil {
			return err
		}
		_, err := fmt.Fprintln(stdout, "PHASE17_ENVIRONMENT_SALT_CREATED")
		return err
	case "issue":
		flags := flag.NewFlagSet("phase17qual environment issue", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		candidatePath := flags.String("candidate", "", "locked candidate manifest")
		privatePath := flags.String("private-environment", "", "owner-local private environment")
		saltPath := flags.String("salt", "", "owner-local environment commitment salt")
		androidClass := flags.String("android-class", "", "EMULATOR or PHYSICAL")
		androidAPI := flags.Int("android-api", 0, "exact Android API")
		androidABI := flags.String("android-abi", "", "exact Android ABI")
		providerClass := flags.String("provider-class", "", "PRIMARY or UNRELATED_SECONDARY")
		outputPath := flags.String("out", "", "canonical environment context output")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" ||
			*privatePath == "" || *saltPath == "" || *androidClass == "" || *androidAPI == 0 ||
			*androidABI == "" || *providerClass == "" || *outputPath == "" {
			return errors.New("qualification environment issue arguments rejected")
		}
		candidate, err := loadCandidateIdentity(*candidatePath)
		if err != nil {
			return err
		}
		value, err := buildCurrentEnvironmentContext(
			candidate.Roots.CandidateID, *privatePath, *saltPath,
			*androidClass, *androidAPI, *androidABI, *providerClass,
		)
		if err != nil {
			return err
		}
		raw, err := phase17qualification.MarshalEnvironmentContext(value)
		if err != nil {
			return err
		}
		if err := writeExclusiveOutput(*outputPath, raw); err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, "PHASE17_ENVIRONMENT_CONTEXT_CREATED")
		return err
	case "verify":
		flags := flag.NewFlagSet("phase17qual environment verify", flag.ContinueOnError)
		flags.SetOutput(io.Discard)
		candidatePath := flags.String("candidate", "", "locked candidate manifest")
		environmentPath := flags.String("environment", "", "canonical environment context")
		privatePath := flags.String("private-environment", "", "owner-local private environment")
		saltPath := flags.String("salt", "", "owner-local environment commitment salt")
		if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" ||
			*environmentPath == "" || *privatePath == "" || *saltPath == "" {
			return errors.New("qualification environment verify arguments rejected")
		}
		candidate, err := loadCandidateIdentity(*candidatePath)
		if err != nil {
			return err
		}
		observed, _, err := loadEnvironment(*environmentPath)
		if err != nil {
			return err
		}
		expected, err := buildCurrentEnvironmentContext(
			candidate.Roots.CandidateID, *privatePath, *saltPath,
			observed.AndroidClass, observed.AndroidAPI, observed.AndroidABI, observed.ProviderClass,
		)
		if err != nil || expected != observed {
			return errors.New("qualification environment context differs from current private inputs")
		}
		_, err = fmt.Fprintln(stdout, "PHASE17_ENVIRONMENT_CONTEXT_PASS")
		return err
	default:
		return errors.New("qualification environment command rejected")
	}
}

func buildCurrentEnvironmentContext(
	candidateID, privatePath, saltPath, androidClass string,
	androidAPI int,
	androidABI, providerClass string,
) (phase17qualification.EnvironmentContext, error) {
	privateRaw, err := readBoundedRegularFile(privatePath, 64<<10)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, err
	}
	defer phase17qualification.Clear(privateRaw)
	privateEnvironment, err := phase17qualification.DecodePrivateEnvironment(bytes.NewReader(privateRaw))
	if err != nil {
		return phase17qualification.EnvironmentContext{}, err
	}
	salt, err := readBoundedRegularFile(saltPath, phase17qualification.PrivateEnvironmentSaltSize)
	if err != nil || len(salt) != phase17qualification.PrivateEnvironmentSaltSize {
		phase17qualification.Clear(salt)
		return phase17qualification.EnvironmentContext{}, errors.New("qualification environment salt rejected")
	}
	defer phase17qualification.Clear(salt)
	hostBootIdentity, err := readCurrentHostBootIdentity(context.Background(), privateEnvironment.PowerShellExecutable)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, err
	}
	defer phase17qualification.Clear(hostBootIdentity)
	probeURL, err := readTrimmedPrivateInput(privateEnvironment.ProbeURLFile, 2048)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, err
	}
	defer phase17qualification.Clear(probeURL)
	probeDigest, err := readTrimmedPrivateInput(privateEnvironment.ProbeDigestFile, 64)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, err
	}
	defer phase17qualification.Clear(probeDigest)
	commitment, err := phase17qualification.ComputePrivateEnvironmentCommitment(
		candidateID, androidClass, salt, privateEnvironment, probeURL, probeDigest, hostBootIdentity,
	)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, err
	}
	toolDigests := make([]string, 0, 5)
	for _, path := range []string{
		privateEnvironment.PythonExecutable, privateEnvironment.ADBExecutable,
		privateEnvironment.SSHExecutable, privateEnvironment.SCPExecutable,
		privateEnvironment.PowerShellExecutable,
	} {
		raw, err := readBoundedRegularFile(path, 1<<30)
		if err != nil {
			return phase17qualification.EnvironmentContext{}, err
		}
		digest := sha256.Sum256(raw)
		phase17qualification.Clear(raw)
		toolDigests = append(toolDigests, hex.EncodeToString(digest[:]))
	}
	return phase17qualification.EnvironmentContext{
		Schema: phase17qualification.EnvironmentSchema,
		HostOS: runtime.GOOS, HostArch: runtime.GOARCH, HostBootClass: "BOUND_CURRENT_BOOT",
		AndroidClass: androidClass, AndroidAPI: androidAPI, AndroidABI: androidABI,
		VPSOS: "linux", VPSArch: "amd64", ProviderClass: providerClass,
		TimeSource: "OWNER_VPS_INTERVAL_REQUIRED", PowerPolicy: "RUNNER_SYSTEM_REQUIRED",
		PythonSHA256: toolDigests[0], ADBSHA256: toolDigests[1],
		SSHSHA256: toolDigests[2], SCPSHA256: toolDigests[3], PowerShellSHA256: toolDigests[4],
		PrivateCommitment: commitment,
	}, nil
}

func readTrimmedPrivateInput(path string, maximum int) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("qualification private input rejected")
	}
	raw, err := readBoundedRegularFile(path, int64(maximum+2))
	if err != nil {
		return nil, err
	}
	defer phase17qualification.Clear(raw)
	value := bytes.Clone(bytes.TrimSpace(raw))
	if len(value) == 0 || len(value) > maximum || bytes.ContainsAny(value, "\r\n\x00") {
		phase17qualification.Clear(value)
		return nil, errors.New("qualification private input rejected")
	}
	return value, nil
}

func runEvidence(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "final" {
		return errors.New("qualification evidence command rejected")
	}
	flags := flag.NewFlagSet("phase17qual evidence final", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "candidate manifest")
	soakResultPath := flags.String("soak-result", "", "exact raw Soak12h v3 PASS result")
	soakReadyPath := flags.String("soak-ready", "", "exact SOAK_READY receipt")
	priorStressPath := flags.String("prior-stress-result", "", "exact prior Stress v3 PASS result")
	sanitizedPath := flags.String("sanitized-evidence", "", "exact sanitized v3 evidence")
	policyPath := flags.String("policy", "", "qualification policy")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	privatePath := flags.String("private-key", "", "qualification private key")
	outputPath := flags.String("out", "", "EVIDENCE_FINAL output")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" || *soakResultPath == "" ||
		*soakReadyPath == "" || *priorStressPath == "" ||
		*sanitizedPath == "" || *policyPath == "" || *ledgerPath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("qualification evidence final arguments rejected")
	}
	candidate, err := loadCandidateIdentity(*candidatePath)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	policyRaw, err := readBoundedRegularFile(*policyPath, 1<<20)
	if err != nil {
		return err
	}
	if _, err := phase17qualification.DecodePolicy(bytes.NewReader(policyRaw)); err != nil {
		return err
	}
	policyDigest := sha256.Sum256(policyRaw)
	soakRaw, err := readBoundedRegularFile(*soakResultPath, 4<<20)
	if err != nil {
		return err
	}
	soak, err := phase17evidence.DecodeOwnedVPSRawV3(soakRaw)
	if err != nil || soak.Outcome != "PASS" || soak.Campaign.Mode != "Soak12h" {
		return errors.New("qualification final evidence soak result rejected")
	}
	if err := phase17evidence.ValidateOwnedVPSV3Candidate(soak, candidate, hex.EncodeToString(policyDigest[:])); err != nil {
		return err
	}
	sanitizedRaw, err := readBoundedRegularFile(*sanitizedPath, 4<<20)
	if err != nil {
		return err
	}
	_, err = phase17evidence.DecodeOwnedVPSSanitizedV3(sanitizedRaw)
	if err != nil {
		return err
	}
	wantSanitized := soak
	wantSanitized.Schema = phase17evidence.OwnedVPSSchemaV3
	wantSanitizedRaw, err := phase17evidence.MarshalOwnedVPSSanitizedV3(wantSanitized)
	if err != nil || !bytes.Equal(sanitizedRaw, wantSanitizedRaw) {
		return errors.New("qualification sanitized evidence differs from exact soak result")
	}
	state, attempts, err := phase17qualification.VerifyLedgerAttempts(*ledgerPath, candidate.Roots.CandidateID, publicKey)
	if err != nil {
		return err
	}
	soakDigest := sha256.Sum256(soakRaw)
	soakDigestHex := hex.EncodeToString(soakDigest[:])
	matched := 0
	var matchedBegin phase17qualification.AttemptPayload
	for _, attempt := range attempts {
		if !attempt.Completed {
			return errors.New("qualification final evidence ledger contains an unresolved attempt")
		}
		if attempt.Begin.AttemptID == soak.Attempt.AttemptID && attempt.Begin.Mode == "Soak12h" &&
			attempt.Terminal.Outcome == "PASS" && attempt.Terminal.ResultSHA256 == soakDigestHex {
			matched++
			matchedBegin = attempt.Begin
			if attempt.Terminal.Sequence != state.Entries {
				return errors.New("qualification final soak is not the terminal ledger entry")
			}
		}
	}
	if matched != 1 {
		return errors.New("qualification final soak ledger binding rejected")
	}
	priorStressDigest, soakReadyDigest, err := terminalPrerequisiteDigests(
		matchedBegin, candidate, hex.EncodeToString(policyDigest[:]), publicKey, *soakReadyPath, *priorStressPath,
	)
	if err != nil || soak.Attempt.PriorStressResultSHA256 != priorStressDigest || soak.Attempt.SoakReadySHA256 != soakReadyDigest {
		return errors.New("qualification final soak prerequisite binding rejected")
	}
	sanitizedDigest := sha256.Sum256(sanitizedRaw)
	payload := phase17qualification.EvidenceFinalPayload{
		Schema: phase17qualification.EvidenceFinalSchema, CandidateID: candidate.Roots.CandidateID,
		SoakResultSHA256: soakDigestHex, SanitizedEvidenceSHA256: hex.EncodeToString(sanitizedDigest[:]),
		LedgerHeadSHA256: state.HeadSHA256, IssuedAt: currentTimestamp(),
	}
	receipt, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementEvidenceFinal, payload)
	if err != nil {
		return err
	}
	if err := writeExclusiveOutput(*outputPath, receipt); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_EVIDENCE_FINAL")
	return err
}

func runSource(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "create" {
		return errors.New("qualification source command rejected")
	}
	flags := flag.NewFlagSet("phase17qual source create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	baseline := flags.String("baseline", "", "exact baseline commit")
	outputRelative := flags.String("out", "", "source provenance output under root")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || !validLowerHex(*baseline, 40) || *outputRelative == "" {
		return errors.New("qualification source arguments rejected")
	}
	rootAbs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil || !sameFilesystemPath(rootAbs, resolvedRoot) {
		return errors.New("qualification repository root rejected")
	}
	outputPath, err := resolveRootPath(rootAbs, *outputRelative)
	if err != nil {
		return err
	}
	value, err := buildRepositorySourceProvenance(rootAbs, *baseline)
	if err != nil {
		return err
	}
	raw, err := phase17qualification.MarshalSourceProvenance(value)
	if err != nil {
		return err
	}
	if err := writeExclusiveOutput(outputPath, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_SOURCE_PROVENANCE_CREATED")
	return err
}

type qualificationGitTreeEntry struct {
	mode, objectID, path string
}

func buildRepositorySourceProvenance(root, baseline string) (phase17qualification.SourceProvenance, error) {
	if !validLowerHex(baseline, 40) {
		return phase17qualification.SourceProvenance{}, errors.New("qualification source baseline rejected")
	}
	if status, err := runGitBounded(root, "status", "--porcelain=v1", "--untracked-files=no"); err != nil || strings.TrimSpace(status) != "" {
		return phase17qualification.SourceProvenance{}, errors.New("qualification source tree is not clean")
	}
	resolvedBaseline, err := runGitBounded(root, "rev-parse", baseline+"^{commit}")
	if err != nil || strings.TrimSpace(resolvedBaseline) != baseline {
		return phase17qualification.SourceProvenance{}, errors.New("qualification source baseline identity rejected")
	}
	commitRaw, err := runGitBounded(root, "rev-parse", "HEAD")
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	commit := strings.TrimSpace(commitRaw)
	if !validLowerHex(commit, 40) || commit == baseline || runGitSuccess(root, "merge-base", "--is-ancestor", baseline, commit) != nil {
		return phase17qualification.SourceProvenance{}, errors.New("qualification source baseline is not a strict ancestor")
	}
	treeRaw, err := runGitBounded(root, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	tree := strings.TrimSpace(treeRaw)
	if !validLowerHex(tree, 40) {
		return phase17qualification.SourceProvenance{}, errors.New("qualification source tree identity rejected")
	}
	remoteRaw, err := runGitBounded(root, "remote", "get-url", "origin")
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	repository, err := githubRepository(strings.TrimSpace(remoteRaw))
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	changedRaw, err := runGitBytesBounded(root, 4<<20, "diff", "--name-only", "--no-renames", "--diff-filter=ACDMRTUXB", "-z", baseline, commit)
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	changedPaths, err := parseNULTerminatedPaths(changedRaw)
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	treeListing, err := runGitBytesBounded(root, 16<<20, "ls-tree", "-rz", "--full-tree", commit)
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	treeEntries, err := parseQualificationGitTree(treeListing)
	if err != nil {
		return phase17qualification.SourceProvenance{}, err
	}
	toolchains := make([]phase17qualification.ManifestEntry, 0)
	locks := make([]phase17qualification.ManifestEntry, 0)
	for _, entry := range treeEntries {
		toolchain := sourceToolchainDeclaration(entry.path)
		dependencyLock := sourceDependencyLock(entry.path)
		if !toolchain && !dependencyLock {
			continue
		}
		if toolchain && dependencyLock {
			return phase17qualification.SourceProvenance{}, errors.New("qualification source inventory selectors overlap")
		}
		if entry.mode != "100644" && entry.mode != "100755" {
			return phase17qualification.SourceProvenance{}, errors.New("qualification source inventory contains a non-regular Git entry")
		}
		blob, err := runGitBytesBounded(root, 32<<20, "cat-file", "blob", entry.objectID)
		if err != nil {
			return phase17qualification.SourceProvenance{}, err
		}
		digest := sha256.Sum256(blob)
		manifestEntry := phase17qualification.ManifestEntry{
			Path: entry.path, Size: uint64(len(blob)), SHA256: hex.EncodeToString(digest[:]),
		}
		if toolchain {
			toolchains = append(toolchains, manifestEntry)
		} else {
			locks = append(locks, manifestEntry)
		}
	}
	sort.Slice(toolchains, func(left, right int) bool { return toolchains[left].Path < toolchains[right].Path })
	sort.Slice(locks, func(left, right int) bool { return locks[left].Path < locks[right].Path })
	return phase17qualification.NewSourceProvenance(repository, baseline, commit, tree, changedPaths, toolchains, locks)
}

func parseNULTerminatedPaths(raw []byte) ([]string, error) {
	if len(raw) < 2 || raw[len(raw)-1] != 0 {
		return nil, errors.New("qualification Git path inventory rejected")
	}
	parts := bytes.Split(raw[:len(raw)-1], []byte{0})
	paths := make([]string, 0, len(parts))
	for _, part := range parts {
		if len(part) == 0 {
			return nil, errors.New("qualification Git path inventory rejected")
		}
		paths = append(paths, string(part))
	}
	sort.Strings(paths)
	return paths, nil
}

func parseQualificationGitTree(raw []byte) ([]qualificationGitTreeEntry, error) {
	if len(raw) < 2 || raw[len(raw)-1] != 0 {
		return nil, errors.New("qualification Git tree inventory rejected")
	}
	records := bytes.Split(raw[:len(raw)-1], []byte{0})
	result := make([]qualificationGitTreeEntry, 0, len(records))
	last := ""
	for _, record := range records {
		separator := bytes.IndexByte(record, '\t')
		if separator < 1 || separator == len(record)-1 {
			return nil, errors.New("qualification Git tree inventory rejected")
		}
		header := strings.Fields(string(record[:separator]))
		path := string(record[separator+1:])
		if len(header) != 3 || header[1] != "blob" ||
			(len(header[2]) != 40 && len(header[2]) != 64) || !validLowerHex(header[2], len(header[2])) || path <= last {
			return nil, errors.New("qualification Git tree entry rejected")
		}
		result = append(result, qualificationGitTreeEntry{mode: header[0], objectID: header[2], path: path})
		last = path
	}
	return result, nil
}

func sourceToolchainDeclaration(path string) bool {
	base := filepath.Base(filepath.FromSlash(path))
	if base == "go.mod" {
		return true
	}
	if strings.HasPrefix(path, "android/") && strings.HasSuffix(path, ".gradle.kts") {
		return true
	}
	switch path {
	case "android/gradle.properties", "android/gradle/libs.versions.toml",
		"android/gradle/wrapper/gradle-wrapper.properties", "android/gradlew", "android/gradlew.bat",
		".github/actions/setup-go/action.yml", ".github/actions/setup-android/action.yml":
		return true
	default:
		return false
	}
}

func sourceDependencyLock(path string) bool {
	base := filepath.Base(filepath.FromSlash(path))
	return base == "go.sum" || strings.HasSuffix(path, ".lock") ||
		path == "android/gradle/verification-metadata.xml" || path == "android/gradle/wrapper/gradle-wrapper.jar"
}

func runGitSuccess(root string, arguments ...string) error {
	command := exec.Command("git", arguments...)
	command.Dir = root
	if err := command.Run(); err != nil {
		return errors.New("qualification git predicate failed")
	}
	return nil
}

func runEvidenceOnly(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "verify" {
		return errors.New("qualification evidence-only command rejected")
	}
	flags := flag.NewFlagSet("phase17qual evidence-only verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	candidatePath := flags.String("candidate", "", "locked candidate manifest")
	policyRelative := flags.String("policy", "config/phase17/qualification-policy-v1.json", "qualification policy")
	beforeTree := flags.String("before-tree", "", "candidate source tree")
	afterTree := flags.String("after-tree", "", "evidence-only source tree")
	changedPathsPath := flags.String("changed-paths", "", "sorted exact changed-path inventory")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" ||
		!validLowerHex(*beforeTree, 40) || !validLowerHex(*afterTree, 40) || *changedPathsPath == "" {
		return errors.New("qualification evidence-only arguments rejected")
	}
	rootAbs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil || !sameFilesystemPath(rootAbs, resolvedRoot) {
		return errors.New("qualification repository root rejected")
	}
	candidate, err := loadCandidateIdentity(*candidatePath)
	if err != nil {
		return err
	}
	if candidate.TreeSHA != *beforeTree || *beforeTree == *afterTree {
		return errors.New("qualification evidence-only tree identity rejected")
	}
	resolvedCandidate, err := runGitBounded(rootAbs, "rev-parse", candidate.CommitSHA+"^{commit}")
	if err != nil || strings.TrimSpace(resolvedCandidate) != candidate.CommitSHA {
		return errors.New("qualification evidence-only candidate commit rejected")
	}
	resolvedCandidateTree, err := runGitBounded(rootAbs, "rev-parse", candidate.CommitSHA+"^{tree}")
	if err != nil || strings.TrimSpace(resolvedCandidateTree) != *beforeTree {
		return errors.New("qualification evidence-only candidate tree rejected")
	}
	if err := runGitSuccess(rootAbs, "merge-base", "--is-ancestor", candidate.CommitSHA, "HEAD"); err != nil {
		return errors.New("qualification evidence-only history rejected")
	}
	policyPath, err := resolveRootPath(rootAbs, *policyRelative)
	if err != nil {
		return err
	}
	policy, err := phase17qualification.LoadPolicy(policyPath)
	if err != nil {
		return err
	}
	declaredRaw, err := readBoundedRegularFile(*changedPathsPath, 64<<10)
	if err != nil {
		return err
	}
	declared, err := parseChangedPaths(declaredRaw)
	if err != nil {
		return err
	}
	actualRaw, err := runGitBounded(rootAbs, "diff-tree", "--no-commit-id", "--name-only", "-r", *beforeTree, *afterTree)
	if err != nil {
		return err
	}
	actual, err := parseChangedPaths([]byte(actualRaw))
	if err != nil || !equalPathInventory(declared, actual) {
		return errors.New("qualification evidence-only changed paths differ from Git")
	}
	headTree, err := runGitBounded(rootAbs, "rev-parse", "HEAD^{tree}")
	if err != nil || strings.TrimSpace(headTree) != *afterTree {
		return errors.New("qualification evidence-only after tree is not current HEAD")
	}
	allowed := make(map[string]struct{}, len(policy.EvidenceOnlyPaths))
	for _, path := range policy.EvidenceOnlyPaths {
		allowed[path] = struct{}{}
	}
	for _, path := range declared {
		if _, found := allowed[path]; !found {
			return errors.New("qualification evidence-only path is not allowlisted")
		}
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_EVIDENCE_ONLY_PASS")
	return err
}

func parseChangedPaths(raw []byte) ([]string, error) {
	if len(raw) == 0 || len(raw) > 64<<10 || bytes.ContainsAny(raw, "\r\x00") {
		return nil, errors.New("qualification changed-path inventory rejected")
	}
	lines := strings.Split(strings.TrimSuffix(string(raw), "\n"), "\n")
	if len(lines) == 0 || len(lines) > 64 {
		return nil, errors.New("qualification changed-path inventory rejected")
	}
	prior := ""
	for _, path := range lines {
		if path == "" || filepath.IsAbs(path) || strings.Contains(path, "\\") || filepath.ToSlash(filepath.Clean(filepath.FromSlash(path))) != path ||
			path == "." || path == ".." || strings.HasPrefix(path, "../") || (prior != "" && path <= prior) {
			return nil, errors.New("qualification changed-path inventory rejected")
		}
		prior = path
	}
	return lines, nil
}

func equalPathInventory(left, right []string) bool {
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

func validLowerHex(value string, size int) bool {
	if len(value) != size || strings.ToLower(value) != value {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func runReadiness(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "issue" {
		return errors.New("qualification readiness command rejected")
	}
	flags := flag.NewFlagSet("phase17qual readiness issue", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "candidate manifest")
	rcLockedPath := flags.String("rc-lock", "", "signed RC_LOCKED receipt")
	indexPath := flags.String("evidence-index", "", "canonical readiness evidence index")
	evidenceRoot := flags.String("evidence-root", "", "readiness evidence root")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	privatePath := flags.String("private-key", "", "qualification private key")
	outputPath := flags.String("out", "", "SOAK_READY output")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" || *rcLockedPath == "" ||
		*indexPath == "" || *evidenceRoot == "" || *ledgerPath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("qualification readiness arguments rejected")
	}
	candidate, err := loadCandidateIdentity(*candidatePath)
	if err != nil {
		return err
	}
	privateKey, publicKey, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	rcLockedRaw, err := readBoundedRegularFile(*rcLockedPath, 1<<20)
	if err != nil {
		return err
	}
	indexRaw, err := readBoundedRegularFile(*indexPath, 1<<20)
	if err != nil {
		return err
	}
	state, attempts, err := phase17qualification.VerifyLedgerAttempts(*ledgerPath, candidate.Roots.CandidateID, publicKey)
	if err != nil {
		return err
	}
	for _, attempt := range attempts {
		if !attempt.Completed {
			return errors.New("qualification readiness ledger contains an unresolved attempt")
		}
	}
	authorizationID, err := randomID()
	if err != nil {
		return err
	}
	ready, err := phase17qualification.BuildSoakReadyPayload(
		candidate, rcLockedRaw, indexRaw, *evidenceRoot, state, publicKey,
		readinessEvidenceVerifier(attempts), authorizationID, currentTimestamp(),
	)
	if err != nil {
		return err
	}
	raw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementSoakReady, ready)
	if err != nil {
		return err
	}
	if err := writeExclusiveOutput(*outputPath, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_SOAK_READY")
	return err
}

func readinessEvidenceVerifier(attempts []phase17qualification.LedgerAttemptRecord) phase17qualification.ReadinessEvidenceVerifier {
	terminalByResult := make(map[string]phase17qualification.LedgerAttemptRecord, len(attempts))
	for _, attempt := range attempts {
		if attempt.Completed && attempt.Terminal.Outcome == "PASS" {
			terminalByResult[attempt.Terminal.ResultSHA256] = attempt
		}
	}
	return func(kind string, raw []byte, candidate phase17qualification.CandidateIdentity) error {
		expectedMode, campaign := readinessCampaignMode(kind)
		if !campaign {
			proof, err := phase17qualification.DecodeReadinessProof(bytes.NewReader(raw))
			if err != nil || proof.Kind != kind || proof.CandidateID != candidate.Roots.CandidateID || proof.Roots != candidate.Roots {
				return errors.New("qualification readiness categorical proof rejected")
			}
			return nil
		}
		result, err := phase17evidence.DecodeOwnedVPSRawV3(raw)
		if err != nil || result.Outcome != "PASS" || result.Campaign.Mode != expectedMode {
			return errors.New("qualification readiness campaign result rejected")
		}
		if err := phase17evidence.ValidateOwnedVPSV3Candidate(result, candidate, result.Subject.PolicySHA256); err != nil {
			return err
		}
		digest := sha256.Sum256(raw)
		record, found := terminalByResult[hex.EncodeToString(digest[:])]
		if !found || record.Begin.AttemptID != result.Attempt.AttemptID || record.Begin.Mode != result.Campaign.Mode {
			return errors.New("qualification readiness campaign is not a completed PASS ledger result")
		}
		switch kind {
		case "PHYSICAL_API26":
			if result.Environment.AndroidClass != "PHYSICAL" || result.Environment.AndroidAPI != 26 {
				return errors.New("qualification readiness API 26 physical result rejected")
			}
		case "PHYSICAL_CURRENT":
			if result.Environment.AndroidClass != "PHYSICAL" || result.Environment.AndroidAPI < 34 {
				return errors.New("qualification readiness current physical result rejected")
			}
		case "SECOND_PROVIDER":
			if result.Environment.ProviderClass != "UNRELATED_SECONDARY" || result.Campaign.Mode != "Soak120m" {
				return errors.New("qualification readiness second-provider result rejected")
			}
		}
		return nil
	}
}

func readinessCampaignMode(kind string) (string, bool) {
	switch kind {
	case "FUNCTIONAL", "PHYSICAL_API26", "PHYSICAL_CURRENT":
		return "Functional", true
	case "STRESS":
		return "Stress", true
	case "SOAK_60M":
		return "Soak60m", true
	case "SOAK_90M":
		return "Soak90m", true
	case "SOAK_120M", "SECOND_PROVIDER":
		return "Soak120m", true
	default:
		return "", false
	}
}

func runCandidate(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("qualification candidate command rejected")
	}
	switch arguments[0] {
	case "create":
		return runCandidateCreate(arguments[1:], stdout)
	case "artifact":
		return runCandidateArtifact(arguments[1:], stdout)
	default:
		return errors.New("qualification candidate command rejected")
	}
}

func runCandidateArtifact(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "verify" {
		return errors.New("qualification candidate artifact command rejected")
	}
	flags := flag.NewFlagSet("phase17qual candidate artifact verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "locked candidate manifest")
	rcLockedPath := flags.String("rc-lock", "", "signed RC_LOCKED receipt")
	trustedPublicKeyPath := flags.String("trusted-public-key", "", "trusted qualification public key")
	subject := flags.String("subject", "", "candidate subject name")
	entry := flags.String("entry", "", "candidate subject entry")
	path := flags.String("path", "", "artifact path")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" || *rcLockedPath == "" ||
		*trustedPublicKeyPath == "" || *subject == "" || *entry == "" || *path == "" {
		return errors.New("qualification candidate artifact arguments rejected")
	}
	candidateRaw, err := readBoundedRegularFile(*candidatePath, 4<<20)
	if err != nil {
		return err
	}
	manifest, err := phase17qualification.DecodeCandidateManifest(bytes.NewReader(candidateRaw))
	if err != nil {
		return err
	}
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		return err
	}
	publicKey, err := phase17qualification.LoadPublicKey(*trustedPublicKeyPath)
	if err != nil {
		return err
	}
	lockRaw, err := readBoundedRegularFile(*rcLockedPath, 1<<20)
	if err != nil {
		return err
	}
	locked, err := phase17qualification.VerifyStatement(lockRaw, publicKey)
	if err != nil || locked.StatementType != phase17qualification.StatementRCLocked {
		return errors.New("qualification candidate RC lock rejected")
	}
	lockPayload := locked.Payload.(phase17qualification.RCLockedPayload)
	if lockPayload.Candidate != candidate {
		return errors.New("qualification candidate differs from RC lock")
	}
	if _, err := phase17qualification.VerifyCandidateArtifact(manifest, *subject, *entry, *path, 1<<30); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_CANDIDATE_ARTIFACT_VERIFIED")
	return err
}

func runCandidateCreate(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("phase17qual candidate create", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	artifactsRelative := flags.String("artifacts", "", "candidate A artifact root")
	comparisonArtifactsRelative := flags.String("comparison-artifacts", "", "candidate B comparison-only artifact root")
	comparisonRelative := flags.String("comparison", "", "candidate A/B comparison output")
	outputRelative := flags.String("out", "", "candidate manifest output")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *artifactsRelative == "" ||
		*comparisonArtifactsRelative == "" || *comparisonRelative == "" || *outputRelative == "" {
		return errors.New("qualification candidate arguments rejected")
	}
	rootAbs, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	resolvedRoot, err := filepath.EvalSymlinks(rootAbs)
	if err != nil || !sameFilesystemPath(rootAbs, resolvedRoot) {
		return errors.New("qualification repository root rejected")
	}
	artifactsPath, err := resolveRootPath(rootAbs, *artifactsRelative)
	if err != nil {
		return err
	}
	comparisonArtifactsPath, err := resolveRootPath(rootAbs, *comparisonArtifactsRelative)
	if err != nil {
		return err
	}
	comparisonPath, err := resolveRootPath(rootAbs, *comparisonRelative)
	if err != nil {
		return err
	}
	outputPath, err := resolveRootPath(rootAbs, *outputRelative)
	if err != nil {
		return err
	}
	if pathsOverlap(artifactsPath, comparisonArtifactsPath) || sameFilesystemPath(artifactsPath, outputPath) ||
		sameFilesystemPath(comparisonArtifactsPath, outputPath) || sameFilesystemPath(comparisonPath, outputPath) ||
		sameFilesystemPath(artifactsPath, comparisonPath) || sameFilesystemPath(comparisonArtifactsPath, comparisonPath) {
		return errors.New("qualification candidate output aliases an input")
	}
	if status, err := runGitBounded(rootAbs, "status", "--porcelain=v1", "--untracked-files=all"); err != nil || strings.TrimSpace(status) != "" {
		return errors.New("qualification source tree is not clean")
	}
	commit, err := runGitBounded(rootAbs, "rev-parse", "HEAD")
	if err != nil {
		return err
	}
	tree, err := runGitBounded(rootAbs, "rev-parse", "HEAD^{tree}")
	if err != nil {
		return err
	}
	remote, err := runGitBounded(rootAbs, "remote", "get-url", "origin")
	if err != nil {
		return err
	}
	repository, err := githubRepository(strings.TrimSpace(remote))
	if err != nil {
		return err
	}
	entries, err := os.ReadDir(artifactsPath)
	if err != nil {
		return err
	}
	wantEntries := map[string]bool{"OVS": false, "PQS": false, "QHS": false, "QWS": false, "source-provenance.json": false}
	for _, entry := range entries {
		if _, found := wantEntries[entry.Name()]; !found || entry.Type()&os.ModeSymlink != 0 {
			return errors.New("qualification artifact root contains an unexpected entry")
		}
		if entry.Name() == "source-provenance.json" {
			if entry.IsDir() {
				return errors.New("qualification source provenance entry rejected")
			}
		} else if !entry.IsDir() {
			return errors.New("qualification subject root entry rejected")
		}
		wantEntries[entry.Name()] = true
	}
	for _, found := range wantEntries {
		if !found {
			return errors.New("qualification artifact root is incomplete")
		}
	}
	sourceRaw, err := readBoundedRegularFile(filepath.Join(artifactsPath, "source-provenance.json"), 64<<10)
	if err != nil {
		return err
	}
	source, err := phase17qualification.DecodeSourceProvenance(strings.NewReader(string(sourceRaw)))
	if err != nil {
		return err
	}
	verifiedSource, err := buildRepositorySourceProvenance(rootAbs, source.BaselineCommitSHA)
	if err != nil {
		return err
	}
	if source != verifiedSource || source.Repository != repository || source.CommitSHA != strings.TrimSpace(commit) || source.TreeSHA != strings.TrimSpace(tree) {
		return errors.New("qualification source provenance differs from the repository")
	}
	subjects := make([]phase17qualification.SubjectManifest, 0, 4)
	for _, name := range []string{"PQS", "QHS", "QWS", "OVS"} {
		manifest, err := phase17qualification.BuildSubjectManifestTree(name, filepath.Join(artifactsPath, name))
		if err != nil {
			return err
		}
		subjects = append(subjects, manifest)
	}
	comparison, err := phase17qualification.BuildCandidateComparison(
		strings.TrimSpace(commit), strings.TrimSpace(tree), artifactsPath, comparisonArtifactsPath,
	)
	if err != nil {
		return err
	}
	comparisonRaw, err := phase17qualification.MarshalCandidateComparison(comparison)
	if err != nil {
		return err
	}
	comparisonDigest := sha256.Sum256(comparisonRaw)
	manifest, err := phase17qualification.NewCandidateManifest(source, hex.EncodeToString(comparisonDigest[:]), subjects)
	if err != nil {
		return err
	}
	raw, err := phase17qualification.MarshalCandidateManifest(manifest)
	if err != nil {
		return err
	}
	if err := writeExclusiveOutput(comparisonPath, comparisonRaw); err != nil {
		return err
	}
	if err := writeExclusiveOutput(outputPath, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_CANDIDATE_CREATED")
	return err
}

func runLock(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("phase17qual lock", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "candidate manifest")
	privatePath := flags.String("private-key", "", "qualification private key")
	outputPath := flags.String("out", "", "RC lock output")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *candidatePath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("qualification lock arguments rejected")
	}
	candidate, err := loadCandidateIdentity(*candidatePath)
	if err != nil {
		return err
	}
	privateKey, _, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	authorizationID, err := randomID()
	if err != nil {
		return err
	}
	raw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementRCLocked, phase17qualification.RCLockedPayload{
		Schema: phase17qualification.RCLockedSchema, Candidate: candidate,
		AuthorizationID: authorizationID, IssuedAt: currentTimestamp(),
	})
	if err != nil {
		return err
	}
	if err := writeExclusiveOutput(*outputPath, raw); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_RC_LOCKED")
	return err
}

func runAttempt(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 {
		return errors.New("qualification attempt command rejected")
	}
	if arguments[0] == "finish" {
		return runAttemptFinish(arguments[1:], stdout)
	}
	if arguments[0] == "close" {
		return runAttemptClose(arguments[1:], stdout)
	}
	if arguments[0] != "begin" {
		return errors.New("qualification attempt command rejected")
	}
	flags := flag.NewFlagSet("phase17qual attempt begin", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	authorizationPath := flags.String("authorization", "", "signed authorization or consumption receipt")
	environmentPath := flags.String("environment", "", "canonical environment context")
	preflightResultPath := flags.String("preflight-result", "", "fresh owner-VPS preflight evidence")
	mode := flags.String("mode", "", "qualification campaign mode")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	privatePath := flags.String("private-key", "", "qualification private key")
	outputPath := flags.String("out", "", "attempt begin output")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *authorizationPath == "" || *environmentPath == "" || *preflightResultPath == "" ||
		*mode == "" || *ledgerPath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("qualification attempt arguments rejected")
	}
	if _, found := phase17qualification.CampaignPolicyForMode(*mode); !found {
		return errors.New("qualification attempt mode rejected")
	}
	privateKey, publicKey, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	authorizationRaw, err := readBoundedRegularFile(*authorizationPath, 1<<20)
	if err != nil {
		return err
	}
	authorization, err := phase17qualification.VerifyStatement(authorizationRaw, publicKey)
	if err != nil {
		return err
	}
	environmentSHA256, err := loadEnvironmentDigest(*environmentPath)
	if err != nil {
		return err
	}
	preflightSHA256, err := loadPreflightDigest(*preflightResultPath, environmentSHA256)
	if err != nil {
		return err
	}
	var candidateID, attemptID, rcLockedSHA256, authorizationSHA256 string
	switch payload := authorization.Payload.(type) {
	case phase17qualification.RCLockedPayload:
		if *mode == "Soak12h" {
			return errors.New("qualification final soak requires a consumed readiness receipt")
		}
		candidateID = payload.Candidate.Roots.CandidateID
		rcLockedSHA256 = authorization.DigestSHA256
		authorizationSHA256 = authorization.DigestSHA256
		attemptID, err = randomID()
	case phase17qualification.SoakConsumedPayload:
		if *mode != "Soak12h" || payload.EnvironmentSHA256 != environmentSHA256 || payload.PreflightSHA256 != preflightSHA256 {
			return errors.New("qualification final soak consumption identity rejected")
		}
		candidateID = payload.CandidateID
		rcLockedSHA256 = payload.RCLockedSHA256
		authorizationSHA256 = payload.SoakReadySHA256
		attemptID = payload.AttemptID
	default:
		return errors.New("qualification attempt authorization type rejected")
	}
	if err != nil {
		return err
	}
	state, err := phase17qualification.VerifyLedger(*ledgerPath, candidateID, publicKey)
	if err != nil {
		return err
	}
	if authorization.StatementType == phase17qualification.StatementSoakConsumed && state.HeadSHA256 != authorization.DigestSHA256 {
		return errors.New("qualification final soak consumption is not the ledger head")
	}
	payload := phase17qualification.AttemptPayload{
		Schema: phase17qualification.AttemptSchema, CandidateID: candidateID,
		Sequence: state.Entries + 1, PreviousEntrySHA256: state.HeadSHA256, State: phase17qualification.AttemptBegin,
		AttemptID: attemptID, Mode: *mode, RCLockedSHA256: rcLockedSHA256, AuthorizationSHA256: authorizationSHA256,
		EnvironmentSHA256: environmentSHA256, PreflightSHA256: preflightSHA256,
		Outcome: "", ResultSHA256: "", RecordedAt: currentTimestamp(),
	}
	raw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, payload)
	if err != nil {
		return err
	}
	if err := publishQualificationLedgerStatement(*outputPath, *ledgerPath, raw, publicKey); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_ATTEMPT_BEGAN")
	return err
}

func runAttemptClose(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("phase17qual attempt close", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	attemptPath := flags.String("attempt", "", "signed attempt begin receipt")
	candidatePath := flags.String("candidate", "", "candidate manifest")
	environmentPath := flags.String("environment", "", "canonical environment context")
	policyPath := flags.String("policy", "", "qualification policy")
	packageEntry := flags.String("package-entry", "", "locked PQS package entry")
	appEntry := flags.String("app-entry", "", "locked PQS app entry")
	testEntry := flags.String("test-entry", "", "locked QHS test entry")
	reason := flags.String("reason", "", "fixed categorical closure reason")
	soakReadyPath := flags.String("soak-ready", "", "SOAK_READY receipt for final soak")
	priorStressPath := flags.String("prior-stress-result", "", "exact prior Stress v3 result")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	privatePath := flags.String("private-key", "", "qualification private key")
	resultOutputPath := flags.String("result-out", "", "categorical raw v3 result output")
	terminalOutputPath := flags.String("out", "", "terminal attempt output")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *attemptPath == "" || *candidatePath == "" ||
		*environmentPath == "" || *policyPath == "" || *packageEntry == "" || *appEntry == "" || *testEntry == "" ||
		*reason == "" || *ledgerPath == "" || *privatePath == "" || *resultOutputPath == "" || *terminalOutputPath == "" ||
		pathsOverlap(*resultOutputPath, *terminalOutputPath) {
		return errors.New("qualification attempt close arguments rejected")
	}
	privateKey, publicKey, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	beginRaw, err := readBoundedRegularFile(*attemptPath, 1<<20)
	if err != nil {
		return err
	}
	beginStatement, err := phase17qualification.VerifyStatement(beginRaw, publicKey)
	if err != nil || beginStatement.StatementType != phase17qualification.StatementAttempt {
		return errors.New("qualification attempt close begin receipt rejected")
	}
	begin := beginStatement.Payload.(phase17qualification.AttemptPayload)
	if begin.State != phase17qualification.AttemptBegin {
		return errors.New("qualification attempt close requires a begin receipt")
	}
	manifest, candidate, err := loadCandidateManifest(*candidatePath)
	if err != nil {
		return err
	}
	if candidate.Roots.CandidateID != begin.CandidateID {
		return errors.New("qualification attempt close candidate differs from begin")
	}
	environment, environmentDigest, err := loadEnvironment(*environmentPath)
	if err != nil {
		return err
	}
	if environmentDigest != begin.EnvironmentSHA256 {
		return errors.New("qualification attempt close environment differs from begin")
	}
	policyRaw, err := readBoundedRegularFile(*policyPath, 1<<20)
	if err != nil {
		return err
	}
	policy, err := phase17qualification.DecodePolicy(bytes.NewReader(policyRaw))
	if err != nil {
		return err
	}
	campaign, found := policy.Campaign(begin.Mode)
	if !found {
		return errors.New("qualification attempt close campaign rejected")
	}
	policyDigest := sha256.Sum256(policyRaw)
	packageDigest, err := candidateEntryDigest(manifest, "PQS", *packageEntry)
	if err != nil {
		return err
	}
	appDigest, err := candidateEntryDigest(manifest, "PQS", *appEntry)
	if err != nil {
		return err
	}
	testDigest, err := candidateEntryDigest(manifest, "QHS", *testEntry)
	if err != nil {
		return err
	}
	priorStressDigest, soakReadyDigest, err := terminalPrerequisiteDigests(
		begin, candidate, hex.EncodeToString(policyDigest[:]), publicKey, *soakReadyPath, *priorStressPath,
	)
	if err != nil {
		return err
	}
	outcome, failingCheck, err := attemptClosureClassification(*reason)
	if err != nil {
		return err
	}
	checks := make([]phase17evidence.FieldCheckV3, 0, len(phase17qualification.RequiredChecks()))
	for _, name := range phase17qualification.RequiredChecks() {
		result := "NOT_RUN"
		if name == failingCheck {
			result = "FAIL"
		}
		checks = append(checks, phase17evidence.FieldCheckV3{Name: name, Result: result})
	}
	result := phase17evidence.OwnedVPSEvidenceV3{
		Schema: phase17evidence.OwnedVPSRawSchemaV3, Outcome: outcome,
		Subject: phase17evidence.FieldSubjectV3{
			Repository: candidate.Repository, CommitSHA: candidate.CommitSHA, TreeSHA: candidate.TreeSHA,
			CandidateID: candidate.Roots.CandidateID, SourceSHA256: candidate.Roots.SourceSHA256,
			ProductSHA256: candidate.Roots.ProductSHA256, HarnessSHA256: candidate.Roots.HarnessSHA256,
			WorkloadSHA256: candidate.Roots.WorkloadSHA256, VerifierSHA256: candidate.Roots.VerifierSHA256,
			ComparisonSHA256: candidate.ComparisonSHA256, PolicySHA256: hex.EncodeToString(policyDigest[:]),
			PackageSHA256: packageDigest, AppAPKSHA256: appDigest, TestAPKSHA256: testDigest,
		},
		Attempt: phase17evidence.FieldAttemptV3{
			AttemptID: begin.AttemptID, RCLockedSHA256: begin.RCLockedSHA256,
			AuthorizationSHA256: begin.AuthorizationSHA256, EnvironmentSHA256: begin.EnvironmentSHA256,
			PreflightSHA256:         begin.PreflightSHA256,
			PriorStressResultSHA256: priorStressDigest, SoakReadySHA256: soakReadyDigest,
		},
		Environment: phase17evidence.FieldEnvironmentV3{
			HostOS: environment.HostOS, HostArch: environment.HostArch,
			AndroidClass: environment.AndroidClass, AndroidAPI: environment.AndroidAPI, AndroidABI: environment.AndroidABI,
			VPSOS: environment.VPSOS, VPSArch: environment.VPSArch, ProviderClass: environment.ProviderClass,
			IPv4: true, IPv6: false,
		},
		Checks: checks, Metrics: phase17evidence.FieldMetricsV3{}, Privacy: phase17evidence.FieldPrivacyV3{},
		Scanners: []phase17evidence.FieldScannerV3{{Name: "GO_A", Result: "NOT_RUN"}, {Name: "PYTHON_B", Result: "NOT_RUN"}},
		Boundary: phase17evidence.FieldBoundaryV3{Result: "NOT_RUN"},
		Campaign: phase17evidence.FieldCampaignV3{
			Mode: campaign.Mode, Impairments: []string{},
		},
	}
	resultRaw, err := phase17evidence.MarshalOwnedVPSRawV3(result)
	if err != nil {
		return err
	}
	if err := writeExclusiveOutput(*resultOutputPath, resultRaw); err != nil {
		return err
	}
	if err := finishAttempt(beginStatement, candidate, result, resultRaw, *ledgerPath, privateKey, publicKey, *terminalOutputPath); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_ATTEMPT_CLOSED")
	return err
}

func attemptClosureClassification(reason string) (string, string, error) {
	switch reason {
	case "RUNNER_LAUNCH_FAILED":
		return "FAIL_HARNESS", "androidCrashFree", nil
	case "IDENTITY_REJECTED":
		return "INVALID_IDENTITY", "preflight", nil
	case "ENVIRONMENT_ABORTED":
		return "ABORT_ENVIRONMENT", "", nil
	case "RUNNER_RESULT_MISSING", "RUNNER_RESULT_AMBIGUOUS", "RUNNER_RESULT_INVALID", "WRAPPER_INTERRUPTED":
		return "INCONCLUSIVE", "", nil
	default:
		return "", "", errors.New("qualification attempt close reason rejected")
	}
}

func candidateEntryDigest(manifest phase17qualification.CandidateManifest, subjectName, entryPath string) (string, error) {
	for _, subject := range manifest.Subjects {
		if subject.Name != subjectName {
			continue
		}
		for _, entry := range subject.Entries {
			if entry.Path == entryPath {
				return entry.SHA256, nil
			}
		}
		break
	}
	return "", errors.New("qualification attempt close artifact entry rejected")
}

func terminalPrerequisiteDigests(
	begin phase17qualification.AttemptPayload,
	candidate phase17qualification.CandidateIdentity,
	policyDigest string,
	publicKey []byte,
	soakReadyPath, priorStressPath string,
) (string, string, error) {
	if begin.Mode != "Soak12h" {
		if soakReadyPath != "" || priorStressPath != "" {
			return "", "", errors.New("qualification non-final close carried final-soak prerequisites")
		}
		return "", "", nil
	}
	if soakReadyPath == "" || priorStressPath == "" {
		return "", "", errors.New("qualification final-soak close lacks prerequisites")
	}
	readyRaw, err := readBoundedRegularFile(soakReadyPath, 1<<20)
	if err != nil {
		return "", "", err
	}
	ready, err := phase17qualification.VerifyStatement(readyRaw, publicKey)
	if err != nil || ready.StatementType != phase17qualification.StatementSoakReady || ready.DigestSHA256 != begin.AuthorizationSHA256 {
		return "", "", errors.New("qualification final-soak close readiness rejected")
	}
	readyPayload := ready.Payload.(phase17qualification.SoakReadyPayload)
	if readyPayload.CandidateID != candidate.Roots.CandidateID || readyPayload.RCLockedSHA256 != begin.RCLockedSHA256 {
		return "", "", errors.New("qualification final-soak close readiness identity rejected")
	}
	stressRaw, err := readBoundedRegularFile(priorStressPath, 4<<20)
	if err != nil {
		return "", "", err
	}
	stress, err := phase17evidence.DecodeOwnedVPSRawV3(stressRaw)
	if err != nil || stress.Outcome != "PASS" || stress.Campaign.Mode != "Stress" {
		return "", "", errors.New("qualification final-soak close prior Stress rejected")
	}
	if err := phase17evidence.ValidateOwnedVPSV3Candidate(stress, candidate, policyDigest); err != nil {
		return "", "", err
	}
	stressDigest := sha256.Sum256(stressRaw)
	stressDigestHex := hex.EncodeToString(stressDigest[:])
	if stressDigestHex != readyPayload.PriorStressResultSHA256 {
		return "", "", errors.New("qualification prior Stress result differs from SOAK_READY")
	}
	return stressDigestHex, ready.DigestSHA256, nil
}

func runAttemptFinish(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("phase17qual attempt finish", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	attemptPath := flags.String("attempt", "", "signed attempt begin receipt")
	candidatePath := flags.String("candidate", "", "candidate manifest")
	resultPath := flags.String("result", "", "raw v3 field result")
	policyPath := flags.String("policy", "", "qualification policy")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	privatePath := flags.String("private-key", "", "qualification private key")
	outputPath := flags.String("out", "", "terminal attempt output")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *attemptPath == "" || *candidatePath == "" ||
		*resultPath == "" || *policyPath == "" || *ledgerPath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("qualification attempt finish arguments rejected")
	}
	privateKey, publicKey, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	beginRaw, err := readBoundedRegularFile(*attemptPath, 1<<20)
	if err != nil {
		return err
	}
	beginStatement, err := phase17qualification.VerifyStatement(beginRaw, publicKey)
	if err != nil || beginStatement.StatementType != phase17qualification.StatementAttempt {
		return errors.New("qualification attempt begin receipt rejected")
	}
	begin := beginStatement.Payload.(phase17qualification.AttemptPayload)
	if begin.State != phase17qualification.AttemptBegin {
		return errors.New("qualification attempt finish requires a begin receipt")
	}
	candidate, err := loadCandidateIdentity(*candidatePath)
	if err != nil {
		return err
	}
	if candidate.Roots.CandidateID != begin.CandidateID {
		return errors.New("qualification attempt candidate differs from begin")
	}
	policyRaw, err := readBoundedRegularFile(*policyPath, 1<<20)
	if err != nil {
		return err
	}
	if _, err := phase17qualification.DecodePolicy(bytes.NewReader(policyRaw)); err != nil {
		return err
	}
	policyDigest := sha256.Sum256(policyRaw)
	resultRaw, err := readBoundedRegularFile(*resultPath, 4<<20)
	if err != nil {
		return err
	}
	result, err := phase17evidence.DecodeOwnedVPSRawV3(resultRaw)
	if err != nil {
		return err
	}
	if err := phase17evidence.ValidateOwnedVPSV3Candidate(result, candidate, hex.EncodeToString(policyDigest[:])); err != nil {
		return err
	}
	if result.Attempt.AttemptID != begin.AttemptID || result.Attempt.RCLockedSHA256 != begin.RCLockedSHA256 ||
		result.Attempt.AuthorizationSHA256 != begin.AuthorizationSHA256 || result.Attempt.EnvironmentSHA256 != begin.EnvironmentSHA256 ||
		result.Attempt.PreflightSHA256 != begin.PreflightSHA256 ||
		result.Campaign.Mode != begin.Mode {
		return errors.New("qualification field result differs from attempt begin")
	}
	if err := finishAttempt(beginStatement, candidate, result, resultRaw, *ledgerPath, privateKey, publicKey, *outputPath); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_ATTEMPT_FINISHED")
	return err
}

func finishAttempt(
	beginStatement phase17qualification.VerifiedStatement,
	candidate phase17qualification.CandidateIdentity,
	result phase17evidence.OwnedVPSEvidenceV3,
	resultRaw []byte,
	ledgerPath string,
	privateKey, publicKey []byte,
	outputPath string,
) error {
	begin, ok := beginStatement.Payload.(phase17qualification.AttemptPayload)
	if !ok || beginStatement.StatementType != phase17qualification.StatementAttempt || begin.State != phase17qualification.AttemptBegin ||
		candidate.Roots.CandidateID != begin.CandidateID || result.Attempt.AttemptID != begin.AttemptID || result.Campaign.Mode != begin.Mode {
		return errors.New("qualification attempt finish identity rejected")
	}
	state, err := phase17qualification.VerifyLedger(ledgerPath, begin.CandidateID, publicKey)
	if err != nil {
		return err
	}
	if state.HeadSHA256 != beginStatement.DigestSHA256 {
		return errors.New("qualification attempt begin is not the ledger head")
	}
	resultDigest := sha256.Sum256(resultRaw)
	terminal := begin
	terminal.Sequence = state.Entries + 1
	terminal.PreviousEntrySHA256 = state.HeadSHA256
	terminal.State = phase17qualification.AttemptTerminal
	terminal.Outcome = result.Outcome
	terminal.ResultSHA256 = hex.EncodeToString(resultDigest[:])
	terminal.RecordedAt = terminalTimestamp(begin.RecordedAt)
	raw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementAttempt, terminal)
	if err != nil {
		return err
	}
	return publishQualificationLedgerStatement(outputPath, ledgerPath, raw, publicKey)
}

func runSoak(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "consume" {
		return errors.New("qualification soak command rejected")
	}
	flags := flag.NewFlagSet("phase17qual soak consume", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	authorizationPath := flags.String("authorization", "", "SOAK_READY receipt")
	environmentPath := flags.String("environment", "", "canonical environment context")
	preflightResultPath := flags.String("preflight-result", "", "fresh owner-VPS preflight evidence")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	privatePath := flags.String("private-key", "", "qualification private key")
	outputPath := flags.String("out", "", "consumption receipt output")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *authorizationPath == "" || *environmentPath == "" || *preflightResultPath == "" ||
		*ledgerPath == "" || *privatePath == "" || *outputPath == "" {
		return errors.New("qualification soak consume arguments rejected")
	}
	privateKey, publicKey, err := loadSigningKey(*privatePath)
	if err != nil {
		return err
	}
	defer phase17qualification.Clear(privateKey)
	readyRaw, err := readBoundedRegularFile(*authorizationPath, 1<<20)
	if err != nil {
		return err
	}
	ready, err := phase17qualification.VerifyStatement(readyRaw, publicKey)
	if err != nil || ready.StatementType != phase17qualification.StatementSoakReady {
		return errors.New("qualification soak readiness receipt rejected")
	}
	readyPayload := ready.Payload.(phase17qualification.SoakReadyPayload)
	state, err := phase17qualification.VerifyLedger(*ledgerPath, readyPayload.CandidateID, publicKey)
	if err != nil {
		return err
	}
	if state.Entries == 0 || state.HeadSHA256 != readyPayload.LedgerHeadSHA256 {
		return errors.New("qualification soak readiness ledger head is stale")
	}
	environmentSHA256, err := loadEnvironmentDigest(*environmentPath)
	if err != nil {
		return err
	}
	preflightSHA256, err := loadPreflightDigest(*preflightResultPath, environmentSHA256)
	if err != nil {
		return err
	}
	attemptID, err := randomID()
	if err != nil {
		return err
	}
	payload := phase17qualification.SoakConsumedPayload{
		Schema: phase17qualification.SoakConsumedSchema, CandidateID: readyPayload.CandidateID,
		Sequence: state.Entries + 1, PreviousEntrySHA256: state.HeadSHA256,
		SoakReadySHA256: ready.DigestSHA256, RCLockedSHA256: readyPayload.RCLockedSHA256,
		AttemptID: attemptID, EnvironmentSHA256: environmentSHA256, PreflightSHA256: preflightSHA256,
		ConsumedAt: currentTimestamp(),
	}
	raw, err := phase17qualification.SignStatement(privateKey, phase17qualification.StatementSoakConsumed, payload)
	if err != nil {
		return err
	}
	if err := publishQualificationLedgerStatement(*outputPath, *ledgerPath, raw, publicKey); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_SOAK_AUTHORIZATION_CONSUMED")
	return err
}

func runPolicy(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "verify" {
		return errors.New("qualification policy command rejected")
	}
	flags := flag.NewFlagSet("phase17qual policy verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	policy := flags.String("policy", "config/phase17/qualification-policy-v1.json", "repository-relative policy path")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 {
		return errors.New("qualification policy arguments rejected")
	}
	path, err := resolveRootPath(*root, *policy)
	if err != nil {
		return err
	}
	if _, err := phase17qualification.LoadPolicy(path); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_QUALIFICATION_POLICY_PASS")
	return err
}

func runKey(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "generate" {
		return errors.New("qualification key command rejected")
	}
	flags := flag.NewFlagSet("phase17qual key generate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	privatePath := flags.String("private", "", "private key output")
	publicPath := flags.String("public", "", "public key output")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *privatePath == "" || *publicPath == "" {
		return errors.New("qualification key arguments rejected")
	}
	if err := phase17qualification.GenerateAndWriteKeyPair(*privatePath, *publicPath, rand.Reader); err != nil {
		return err
	}
	_, err := fmt.Fprintln(stdout, "PHASE17_QUALIFICATION_KEY_CREATED")
	return err
}

func runVerify(arguments []string, stdout io.Writer) error {
	flags := flag.NewFlagSet("phase17qual verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	publicPath := flags.String("trusted-public-key", "", "trusted qualification public key")
	statementPath := flags.String("statement", "", "signed qualification statement")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *publicPath == "" || *statementPath == "" {
		return errors.New("qualification verify arguments rejected")
	}
	publicKey, err := phase17qualification.LoadPublicKey(*publicPath)
	if err != nil {
		return err
	}
	raw, err := readBoundedRegularFile(*statementPath, 1<<20)
	if err != nil {
		return err
	}
	if _, err := phase17qualification.VerifyStatement(raw, publicKey); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_QUALIFICATION_STATEMENT_PASS")
	return err
}

func runLedger(arguments []string, stdout io.Writer) error {
	if len(arguments) == 0 || arguments[0] != "verify" {
		return errors.New("qualification ledger command rejected")
	}
	flags := flag.NewFlagSet("phase17qual ledger verify", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidatePath := flags.String("candidate", "", "candidate manifest")
	publicPath := flags.String("trusted-public-key", "", "trusted qualification public key")
	ledgerPath := flags.String("ledger", "", "qualification ledger directory")
	if err := flags.Parse(arguments[1:]); err != nil || flags.NArg() != 0 || *candidatePath == "" || *publicPath == "" || *ledgerPath == "" {
		return errors.New("qualification ledger arguments rejected")
	}
	candidate, err := loadCandidateIdentity(*candidatePath)
	if err != nil {
		return err
	}
	publicKey, err := phase17qualification.LoadPublicKey(*publicPath)
	if err != nil {
		return err
	}
	if _, err := phase17qualification.VerifyLedger(*ledgerPath, candidate.Roots.CandidateID, publicKey); err != nil {
		return err
	}
	_, err = fmt.Fprintln(stdout, "PHASE17_QUALIFICATION_LEDGER_PASS")
	return err
}

func loadCandidateIdentity(path string) (phase17qualification.CandidateIdentity, error) {
	_, candidate, err := loadCandidateManifest(path)
	return candidate, err
}

func loadCandidateManifest(path string) (phase17qualification.CandidateManifest, phase17qualification.CandidateIdentity, error) {
	raw, err := readBoundedRegularFile(path, 4<<20)
	if err != nil {
		return phase17qualification.CandidateManifest{}, phase17qualification.CandidateIdentity{}, err
	}
	manifest, err := phase17qualification.DecodeCandidateManifest(strings.NewReader(string(raw)))
	if err != nil {
		return phase17qualification.CandidateManifest{}, phase17qualification.CandidateIdentity{}, err
	}
	candidate, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil {
		return phase17qualification.CandidateManifest{}, phase17qualification.CandidateIdentity{}, err
	}
	return manifest, candidate, nil
}

func loadEnvironmentDigest(path string) (string, error) {
	_, digest, err := loadEnvironment(path)
	return digest, err
}

func loadPreflightDigest(path, environmentSHA256 string) (string, error) {
	raw, err := readBoundedRegularFile(path, 64<<10)
	if err != nil {
		return "", err
	}
	return phase17qualification.VerifyOwnerVPSPreflight(raw, environmentSHA256)
}

func loadEnvironment(path string) (phase17qualification.EnvironmentContext, string, error) {
	raw, err := readBoundedRegularFile(path, 64<<10)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, "", err
	}
	value, err := phase17qualification.DecodeEnvironmentContext(strings.NewReader(string(raw)))
	if err != nil {
		return phase17qualification.EnvironmentContext{}, "", err
	}
	digest, err := phase17qualification.EnvironmentDigest(value)
	if err != nil {
		return phase17qualification.EnvironmentContext{}, "", err
	}
	return value, digest, nil
}

func loadSigningKey(path string) ([]byte, []byte, error) {
	privateKey, err := phase17qualification.LoadPrivateKey(path)
	if err != nil {
		return nil, nil, err
	}
	publicKey := append([]byte(nil), ed25519.PrivateKey(privateKey).Public().(ed25519.PublicKey)...)
	return privateKey, publicKey, nil
}

func randomID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}

func currentTimestamp() string {
	return time.Now().UTC().Truncate(time.Second).Format(time.RFC3339)
}

func terminalTimestamp(begin string) string {
	minimum, err := time.Parse(time.RFC3339, begin)
	if err != nil {
		return currentTimestamp()
	}
	minimum = minimum.Add(time.Second)
	now := time.Now().UTC().Truncate(time.Second)
	if now.Before(minimum) {
		now = minimum
	}
	return now.Format(time.RFC3339)
}

func writeExclusiveOutput(path string, raw []byte) (resultErr error) {
	if path == "" || len(raw) == 0 {
		return errors.New("qualification output rejected")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	directoryAbs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(directoryAbs)
	if err != nil || !sameFilesystemPath(directoryAbs, resolved) {
		return errors.New("qualification output directory rejected")
	}
	return phase17qualification.WriteExclusiveFile(path, raw)
}

type qualificationOutputWriter func(string, []byte) error
type qualificationLedgerAppender func(string, []byte, []byte) (string, error)
type qualificationOutputRemover func(string) error

func publishQualificationLedgerStatement(outputPath, ledgerPath string, raw, publicKey []byte) error {
	return publishLedgerStatement(
		outputPath, ledgerPath, raw, publicKey,
		writeExclusiveOutput, phase17qualification.AppendLedger, os.Remove,
	)
}

func publishLedgerStatement(
	outputPath, ledgerPath string,
	raw, publicKey []byte,
	write qualificationOutputWriter,
	appendLedger qualificationLedgerAppender,
	remove qualificationOutputRemover,
) error {
	if write == nil || appendLedger == nil || remove == nil {
		return errors.New("qualification ledger publication rejected")
	}
	if err := write(outputPath, raw); err != nil {
		return err
	}
	if _, err := appendLedger(ledgerPath, raw, publicKey); err != nil {
		cleanupErr := remove(outputPath)
		if cleanupErr != nil && !errors.Is(cleanupErr, os.ErrNotExist) {
			return errors.Join(err, cleanupErr)
		}
		return err
	}
	return nil
}

func sameFilesystemPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func pathsOverlap(left, right string) bool {
	leftAbs, leftErr := filepath.Abs(left)
	rightAbs, rightErr := filepath.Abs(right)
	if leftErr != nil || rightErr != nil {
		return true
	}
	if sameFilesystemPath(leftAbs, rightAbs) {
		return true
	}
	leftToRight, leftErr := filepath.Rel(leftAbs, rightAbs)
	rightToLeft, rightErr := filepath.Rel(rightAbs, leftAbs)
	return leftErr != nil || rightErr != nil || (leftToRight != ".." && !strings.HasPrefix(leftToRight, ".."+string(filepath.Separator))) ||
		(rightToLeft != ".." && !strings.HasPrefix(rightToLeft, ".."+string(filepath.Separator)))
}

func runGitBounded(root string, arguments ...string) (string, error) {
	output, err := runGitBytesBounded(root, 1<<20, arguments...)
	return string(output), err
}

func runGitBytesBounded(root string, maximum int, arguments ...string) ([]byte, error) {
	if maximum <= 0 {
		return nil, errors.New("qualification git output limit rejected")
	}
	command := exec.Command("git", arguments...)
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		return nil, errors.New("qualification git command failed")
	}
	if len(output) > maximum {
		return nil, errors.New("qualification git output exceeds limit")
	}
	return output, nil
}

func githubRepository(remote string) (string, error) {
	value := strings.TrimSuffix(strings.TrimSpace(remote), ".git")
	switch {
	case strings.HasPrefix(value, "https://github.com/"):
		value = strings.TrimPrefix(value, "https://github.com/")
	case strings.HasPrefix(value, "ssh://git@github.com/"):
		value = strings.TrimPrefix(value, "ssh://git@github.com/")
	case strings.HasPrefix(value, "git@github.com:"):
		value = strings.TrimPrefix(value, "git@github.com:")
	default:
		return "", errors.New("qualification repository remote rejected")
	}
	parts := strings.Split(value, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", errors.New("qualification repository identity rejected")
	}
	return value, nil
}

func resolveRootPath(root, relative string) (string, error) {
	if filepath.IsAbs(relative) || relative == "" {
		return "", errors.New("qualification repository path rejected")
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	candidate, err := filepath.Abs(filepath.Join(rootAbs, filepath.FromSlash(relative)))
	if err != nil {
		return "", err
	}
	rel, err := filepath.Rel(rootAbs, candidate)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", errors.New("qualification repository path escapes root")
	}
	return candidate, nil
}

func readBoundedRegularFile(path string, maximum int64) ([]byte, error) {
	return readBoundedRegularFileWithOpener(path, maximum, os.Open)
}

func readBoundedRegularFileWithOpener(path string, maximum int64, opener func(string) (*os.File, error)) ([]byte, error) {
	if path == "" || maximum <= 0 || opener == nil {
		return nil, errors.New("qualification input file rejected")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("qualification input file rejected")
	}
	file, err := opener(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(info, opened) || info.Size() != opened.Size() || info.ModTime() != opened.ModTime() {
		_ = file.Close()
		return nil, errors.New("qualification input changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
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
	if int64(len(raw)) != opened.Size() || int64(len(raw)) > maximum || !os.SameFile(opened, after) ||
		opened.Size() != after.Size() || opened.ModTime() != after.ModTime() {
		return nil, errors.New("qualification input changed while reading")
	}
	return raw, nil
}

func fail(stderr io.Writer, code int) int {
	_, _ = fmt.Fprintln(stderr, "PHASE17_QUALIFICATION_FAILED")
	return code
}
