// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase15verify validates the fail-closed Phase 15 production-contract
// freeze. It authorizes bounded infrastructure engineering without permitting
// production activation or weakening the Phase 14 NO_GO decision.
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
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"kurdistan/internal/testkit/evidenceoverlay"
)

const contractPath = "testdata/evidence/phase15/production-contract.json"

var errHistoricalEvidenceNotAvailable = errors.New("historical evidence not available")

var historicalEvidenceFiles = []string{
	"docs/KZ-evidence-ref-044",
	"docs/PZ-evidence-ref-059",
}

var requiredFiles = []string{
	contractPath,
	evidenceoverlay.SuccessorPath,
}

var requiredAuthorized = []string{
	"VERSIONED_PRODUCTION_API_DESIGN",
	"PROVIDER_NEUTRAL_INFRASTRUCTURE_CODE",
	"POLICY_AS_CODE",
	"DISPOSABLE_NON_PRODUCTION_VALIDATION",
	"SECRET_REFERENCE_INTERFACES",
	"FAILURE_INJECTION_AND_RECOVERY_TESTING",
	"CAPACITY_COST_AND_ROLLBACK_MODELS",
	"EVIDENCE_SCHEMA_IMPLEMENTATION",
}

var requiredProhibited = []string{
	"PRODUCTION_ACCOUNT_OR_RESOURCE_MUTATION_WITHOUT_EXECUTION_AUTHORIZATION",
	"PRODUCTION_KEY_ISSUANCE",
	"PRODUCTION_DNS_OR_CERTIFICATE_ACTIVATION",
	"PUBLIC_ENDPOINT_OR_RELAY_ACTIVATION",
	"PUBLIC_OR_USER_TRAFFIC",
	"PRODUCTION_PROFILE_ISSUANCE",
	"PILOT_ACTIVATION",
	"PRODUCTION_SIGNING",
	"STORE_SUBMISSION",
	"PUBLIC_RELEASE",
}

var requiredForbiddenData = []string{
	"PAYLOAD",
	"DESTINATION_HISTORY",
	"CREDENTIAL",
	"PRIVATE_KEY",
	"RAW_FRAME",
	"PACKAGE_INVENTORY",
	"STABLE_HARDWARE_ID",
}

var requiredCIJobs = []string{
	"Android Phase 14 local assurance (ubuntu-latest)",
	"Android Phase 14 local assurance (windows-latest)",
	"gate (ubuntu-latest)",
	"gate (windows-latest)",
}

type contract struct {
	Schema          string            `json:"schema"`
	Phase           int               `json:"phase"`
	Status          string            `json:"status"`
	ReleaseDecision string            `json:"releaseDecision"`
	Baseline        baseline          `json:"baseline"`
	Android         androidContract   `json:"android"`
	Versions        map[string]string `json:"versions"`
	AuthorizedWork  []string          `json:"authorizedWork"`
	Prohibited      []string          `json:"prohibitedActions"`
	Privacy         privacyContract   `json:"privacy"`
	TargetsEvidence bool              `json:"targetsAreEvidence"`
	Limitations     []string          `json:"limitations"`
}

type baseline struct {
	SourceCommit          string   `json:"sourceCommit"`
	CandidateCIRun        string   `json:"candidateCiRun"`
	MainCIRun             string   `json:"mainCiRun"`
	CandidateCIConclusion string   `json:"candidateCiConclusion"`
	MainCIConclusion      string   `json:"mainCiConclusion"`
	WorkflowPath          string   `json:"workflowPath"`
	WorkflowSHA256        string   `json:"workflowSha256"`
	CIJobs                []string `json:"ciJobs"`
}

type androidContract struct {
	MinAPI         int      `json:"minApi"`
	TargetAPI      int      `json:"targetApi"`
	CompileAPI     int      `json:"compileApi"`
	ProductionABIs []string `json:"productionAbis"`
	TestOnlyABIs   []string `json:"testOnlyAbis"`
}

type privacyContract struct {
	TelemetryDefault string   `json:"telemetryDefault"`
	ForbiddenData    []string `json:"forbiddenData"`
}

func main() {
	os.Exit(runWithVerifier(os.Args[1:], os.Stdout, os.Stderr, verify))
}

func runWithVerifier(args []string, stdout, stderr io.Writer, verifier func(string) error) int {
	flags := flag.NewFlagSet("phase15verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "PHASE 15 VERIFICATION FAILED: unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if err := verifier(*root); err != nil {
		if errors.Is(err, errHistoricalEvidenceNotAvailable) {
			fmt.Fprintln(stdout, "PHASE 15 VERIFICATION NOT_AVAILABLE; CURRENT QUALIFICATION REMAINS BLOCKED")
			return 0
		}
		fmt.Fprintf(stderr, "PHASE 15 VERIFICATION FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PHASE 15 VERIFICATION PASSED")
	return 0
}

func verify(root string) error {
	for _, relative := range requiredFiles {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("required file %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("required file %s is not a non-empty regular file", relative)
		}
	}
	encoded, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(contractPath)))
	if err != nil {
		return err
	}
	value, err := decodeContract(encoded)
	if err != nil {
		return err
	}
	if err := validate(value); err != nil {
		return err
	}
	if err := verifyBaselineCommit(root, value.Baseline.SourceCommit); err != nil {
		return err
	}
	if err := verifyBaselineWorkflow(root, value.Baseline); err != nil {
		return err
	}
	if err := verifyReleaseBoundary(root, value); err != nil {
		return err
	}
	unavailable := make([]string, 0, 2)
	if err := verifyHumanParity(root, value); err != nil {
		if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
			return err
		}
		unavailable = append(unavailable, err.Error())
	}
	if err := verifyPhase14Reconciliation(root); err != nil {
		if !errors.Is(err, errHistoricalEvidenceNotAvailable) {
			return err
		}
		unavailable = append(unavailable, err.Error())
	}
	predecessors, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return fmt.Errorf("verify Phase 15 successor overlay: %w", err)
	}
	for _, required := range []string{
		"RZ-evidence-ref-069",
		"docs/KZ-evidence-ref-043",
		"docs/PZ-evidence-ref-052",
		"docs/PZ-evidence-ref-056",
		"testdata/evidence/phase14/acceptance-status.json",
	} {
		if predecessors[required] == "" {
			return fmt.Errorf("Phase 15 successor overlay is missing %s", required)
		}
	}
	if len(unavailable) != 0 {
		return fmt.Errorf("%w: %s", errHistoricalEvidenceNotAvailable, strings.Join(unavailable, "; "))
	}
	return nil
}

func decodeContract(encoded []byte) (contract, error) {
	var value contract
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return contract{}, fmt.Errorf("decode production contract: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return contract{}, errors.New("decode production contract: trailing JSON value")
		}
		return contract{}, fmt.Errorf("decode production contract: trailing JSON: %w", err)
	}
	return value, nil
}

func verifyBaselineCommit(root, sha string) error {
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(sha) {
		return errors.New("baseline source commit is not a full SHA-1")
	}
	command := exec.Command("git", "cat-file", "-e", sha+"^{commit}")
	command.Dir = root
	if output, err := command.CombinedOutput(); err != nil {
		return fmt.Errorf("baseline commit %s does not exist: %w: %s", sha, err, strings.TrimSpace(string(output)))
	}
	return nil
}

func verifyBaselineWorkflow(root string, value baseline) error {
	if value.WorkflowPath != ".github/workflows/ci.yml" || strings.Contains(value.WorkflowPath, "..") {
		return errors.New("baseline workflow path is invalid")
	}
	command := exec.Command("git", "show", value.SourceCommit+":"+value.WorkflowPath)
	command.Dir = root
	content, err := command.Output()
	if err != nil {
		return fmt.Errorf("read baseline workflow from %s: %w", value.SourceCommit, err)
	}
	digest := sha256.Sum256(content)
	actual := hex.EncodeToString(digest[:])
	if actual != value.WorkflowSHA256 {
		return fmt.Errorf("baseline workflow digest = %s, want %s", actual, value.WorkflowSHA256)
	}
	return nil
}

func verifyReleaseBoundary(root string, value contract) error {
	raw, err := os.ReadFile(filepath.Join(root, "RZ-evidence-ref-069"))
	if errors.Is(err, os.ErrNotExist) {
		predecessors, overlayErr := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
		if overlayErr != nil {
			return overlayErr
		}
		if predecessors["RZ-evidence-ref-069"] == "" {
			return errors.New("retired public RZ-evidence-ref-069 lacks authenticated predecessor evidence")
		}
		return nil
	}
	if err != nil {
		return err
	}
	text := string(raw)
	for _, required := range []string{
		"Phases 1-15 are integrated on `main` at",
		value.Baseline.SourceCommit,
		"Phase 16 is active. Its evidence-preserving CI",
		"| 13 | Integrated |",
		"| 14 | Integrated |",
		"| 15 | Integrated |",
		"| 16 | Active |",
		"The current release decision is `NO_GO`",
	} {
		if !strings.Contains(text, required) {
			return fmt.Errorf("RZ-evidence-ref-069 is missing Phase 15 authority %q", required)
		}
	}
	return nil
}

func verifyHumanParity(root string, value contract) error {
	unavailable := make([]string, 0, len(historicalEvidenceFiles))
	requirements := map[string][]string{
		"docs/PZ-evidence-ref-059": {
			value.Baseline.SourceCommit,
			"`NO_GO`",
			fmt.Sprintf("API %d", value.Android.MinAPI),
			fmt.Sprintf("API %d", value.Android.TargetAPI),
			value.Android.ProductionABIs[0],
			value.Android.TestOnlyABIs[0],
			value.Baseline.WorkflowPath,
			value.Baseline.WorkflowSHA256,
		},
		"docs/KZ-evidence-ref-044": {
			value.Baseline.SourceCommit,
			"`NO_GO`",
			value.Baseline.CandidateCIRun,
			value.Baseline.MainCIRun,
			value.Baseline.WorkflowSHA256,
		},
	}
	for relative, snippets := range requirements {
		raw, available, err := readHistoricalEvidenceFile(root, relative)
		if err != nil {
			return err
		}
		if !available {
			unavailable = append(unavailable, relative)
			continue
		}
		for _, snippet := range snippets {
			if !strings.Contains(string(raw), snippet) {
				return fmt.Errorf("%s disagrees with the machine contract: missing %q", relative, snippet)
			}
		}
	}
	if len(unavailable) != 0 {
		sort.Strings(unavailable)
		return fmt.Errorf("%w: human-parity documents unavailable in the sanitized subject: %s", errHistoricalEvidenceNotAvailable, strings.Join(unavailable, ", "))
	}
	return nil
}

func verifyPhase14Reconciliation(root string) error {
	unavailable := make([]string, 0, 3)
	for _, relative := range []string{
		"docs/KZ-evidence-ref-043",
		"docs/PZ-evidence-ref-052",
		"docs/PZ-evidence-ref-056",
	} {
		raw, available, err := readHistoricalEvidenceFile(root, relative)
		if err != nil {
			return err
		}
		if !available {
			unavailable = append(unavailable, relative)
			continue
		}
		lower := strings.ToLower(string(raw))
		for _, stale := range []string{"integration pending", "not yet integrated", "ready for integration"} {
			if strings.Contains(lower, stale) {
				return fmt.Errorf("%s contains stale Phase 14 state %q", relative, stale)
			}
		}
		if !strings.Contains(lower, "integrated") || !strings.Contains(string(raw), "NO_GO") {
			return fmt.Errorf("%s must record integrated local assurance and NO_GO", relative)
		}
	}
	raw, err := os.ReadFile(filepath.Join(root, "testdata", "evidence", "phase14", "acceptance-status.json"))
	if err != nil {
		return err
	}
	var status struct {
		ReleaseDecision string `json:"releaseDecision"`
		PriorPhase      struct {
			IntegrationState string `json:"integrationState"`
		} `json:"priorPhaseBaseline"`
	}
	if err := json.Unmarshal(raw, &status); err != nil {
		return fmt.Errorf("decode Phase 14 acceptance status: %w", err)
	}
	if status.ReleaseDecision != "NO_GO" || status.PriorPhase.IntegrationState != "INTEGRATED_ON_MAIN" {
		return errors.New("Phase 14 acceptance status must preserve NO_GO and record INTEGRATED_ON_MAIN")
	}
	if len(unavailable) != 0 {
		return fmt.Errorf("%w: Phase 14 reconciliation documents unavailable in the sanitized subject: %s", errHistoricalEvidenceNotAvailable, strings.Join(unavailable, ", "))
	}
	return nil
}

func readHistoricalEvidenceFile(root, relative string) ([]byte, bool, error) {
	raw, err := evidenceoverlay.ReadSubjectFile(root, relative)
	if err == nil {
		if len(raw) == 0 {
			return nil, false, fmt.Errorf("historical evidence file %s is empty", relative)
		}
		return raw, true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, false, fmt.Errorf("read historical evidence file %s: %w", relative, err)
	}
	digest, err := evidenceoverlay.ResolveCurrentSHA256(root, relative)
	if err != nil {
		return nil, false, fmt.Errorf("authenticate sanitized historical evidence file %s: %w", relative, err)
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256.Size {
		return nil, false, fmt.Errorf("invalid authenticated predecessor digest for %s", relative)
	}
	return nil, false, nil
}

func validate(value contract) error {
	if value.Schema != "kurdistan-phase15-production-contract-v1" || value.Phase != 15 {
		return errors.New("unexpected Phase 15 contract schema or phase")
	}
	if value.Status != "FROZEN_FOR_IMPLEMENTATION" || value.ReleaseDecision != "NO_GO" {
		return errors.New("contract must be frozen for implementation and remain NO_GO")
	}
	if !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(value.Baseline.SourceCommit) {
		return errors.New("baseline source commit is not a full SHA-1")
	}
	if value.Baseline.CandidateCIRun == "" || value.Baseline.MainCIRun == "" ||
		value.Baseline.CandidateCIConclusion != "SUCCESS" || value.Baseline.MainCIConclusion != "SUCCESS" {
		return errors.New("candidate and main CI success receipts are required")
	}
	if value.Baseline.WorkflowPath != ".github/workflows/ci.yml" || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(value.Baseline.WorkflowSHA256) {
		return errors.New("baseline workflow identity is incomplete")
	}
	if err := exactSet("baseline CI job", value.Baseline.CIJobs, requiredCIJobs); err != nil {
		return err
	}
	if value.Android.MinAPI != 26 || value.Android.TargetAPI != 36 || value.Android.CompileAPI != 36 {
		return errors.New("unexpected Android API contract")
	}
	if err := exactSet("production ABI", value.Android.ProductionABIs, []string{"arm64-v8a"}); err != nil {
		return err
	}
	if err := exactSet("test-only ABI", value.Android.TestOnlyABIs, []string{"x86_64"}); err != nil {
		return err
	}
	for _, key := range []string{"androidBridge", "profileAdmission", "strategyRegistry", "relayAdmission", "diagnostics", "cryptographicSuite"} {
		if strings.TrimSpace(value.Versions[key]) == "" {
			return fmt.Errorf("version %s is missing", key)
		}
	}
	if err := exactSet("authorized work", value.AuthorizedWork, requiredAuthorized); err != nil {
		return err
	}
	if err := exactSet("prohibited action", value.Prohibited, requiredProhibited); err != nil {
		return err
	}
	if value.Privacy.TelemetryDefault != "OFF" {
		return errors.New("telemetry must remain off by default")
	}
	if err := exactSet("forbidden data", value.Privacy.ForbiddenData, requiredForbiddenData); err != nil {
		return err
	}
	if value.TargetsEvidence {
		return errors.New("production targets cannot be recorded as evidence")
	}
	if len(value.Limitations) < 3 {
		return errors.New("contract limitations are incomplete")
	}
	return nil
}

func exactSet(name string, got, want []string) error {
	got = append([]string(nil), got...)
	want = append([]string(nil), want...)
	sort.Strings(got)
	sort.Strings(want)
	if len(got) != len(want) {
		return fmt.Errorf("%s set has %d entries, want %d", name, len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			return fmt.Errorf("%s set differs at %d: got %q want %q", name, i, got[i], want[i])
		}
	}
	return nil
}
