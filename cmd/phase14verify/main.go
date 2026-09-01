// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase14verify enforces the fail-closed Phase 14 release-decision
// boundary. It validates evidence shape and prevents a GO decision while any
// mandatory local or external evidence remains pending or unverified.
package main

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kurdistan/internal/testkit/evidenceoverlay"
)

const acceptancePath = "testdata/evidence/phase14/acceptance-status.json"

var errHistoricalEvidenceNotAvailable = errors.New("historical evidence not available")

var historicalEvidenceFiles = []string{
	"docs/KZ-evidence-ref-043",
	"docs/PZ-evidence-ref-056",
	"docs/PZ-evidence-ref-052",
	"docs/PZ-evidence-ref-053",
	"docs/PZ-evidence-ref-054",
	"docs/PZ-evidence-ref-057",
	"docs/PZ-evidence-ref-058",
	"docs/PZ-evidence-ref-055",
}

var requiredFiles = []string{
	"testdata/evidence/phase14/reproducibility.json",
	"testdata/evidence/phase14/recovery-drills.json",
	"testdata/evidence/phase14/longevity.json",
	acceptancePath,
}

var localEvidenceReports = map[string]string{
	"releaseArtifactReproducibility": "testdata/evidence/phase14/reproducibility.json",
	"rollbackAndRecoveryDrills":      "testdata/evidence/phase14/recovery-drills.json",
	"performanceAndLongevity":        "testdata/evidence/phase14/longevity.json",
}

var requiredLocalEvidence = []string{
	"phase14Verifier",
	"phase14HostGate",
	"phase14DeviceGate",
	"featureInventoryReconciliation",
	"releaseArtifactReproducibility",
	"rollbackAndRecoveryDrills",
	"performanceAndLongevity",
}

var requiredExternalEvidence = []string{
	"productionAuthorityAndKeyCustody",
	"ownedProductionRelayFleet",
	"productionProviderAndOperator",
	"physicalDeviceAndOemMatrix",
	"cellularWifiHandoverAndSleep",
	"authorizedHostileNetworkFieldValidation",
	"independentAssuranceReviews",
	"productionSigningAndDistribution",
	"playVpnServiceDeclarationAndReview",
	"productionMonitoringIncidentAndDisasterRecovery",
}

var forbiddenReleaseClaims = []string{
	"uncensorable",
	"undetectable",
	"guaranteed bypass",
	"impossible to block",
	"fully anonymous",
	"production-ready",
}

type blocker struct {
	ID               string `json:"id"`
	Severity         string `json:"severity"`
	Category         string `json:"category"`
	ConditionToClear string `json:"conditionToClear"`
}

type acceptance struct {
	Schema             string            `json:"schema"`
	Phase              int               `json:"phase"`
	Complete           bool              `json:"complete"`
	ReadinessStatus    string            `json:"readinessStatus"`
	ReleaseDecision    string            `json:"releaseDecision"`
	PriorPhaseBaseline map[string]string `json:"priorPhaseBaseline"`
	Local              map[string]string `json:"local"`
	External           map[string]string `json:"external"`
	Blockers           []blocker         `json:"blockers"`
	Limitations        []string          `json:"limitations"`
}

type localEvidenceReport struct {
	Schema      string   `json:"schema"`
	EvidenceKey string   `json:"evidenceKey"`
	Status      string   `json:"status"`
	Scope       string   `json:"scope"`
	Commands    []string `json:"commands"`
	Evidence    []string `json:"evidence"`
	Limitations []string `json:"limitations"`
}

func main() {
	os.Exit(runWithVerifier(os.Args[1:], os.Stdout, os.Stderr, verify))
}

func runWithVerifier(args []string, stdout, stderr io.Writer, verifier func(string) error) int {
	flags := flag.NewFlagSet("phase14verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "PHASE 14 VERIFICATION FAILED: unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if err := verifier(*root); err != nil {
		if errors.Is(err, errHistoricalEvidenceNotAvailable) {
			fmt.Fprintln(stdout, "PHASE 14 VERIFICATION NOT_AVAILABLE; CURRENT QUALIFICATION REMAINS BLOCKED")
			return 0
		}
		fmt.Fprintf(stderr, "PHASE 14 VERIFICATION FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PHASE 14 VERIFICATION PASSED")
	return 0
}

func verify(root string) error {
	unavailable := make([]string, 0, len(historicalEvidenceFiles))
	for _, relative := range historicalEvidenceFiles {
		available, err := verifyHistoricalEvidenceFile(root, relative)
		if err != nil {
			return err
		}
		if !available {
			unavailable = append(unavailable, relative)
		}
	}
	for _, relative := range requiredFiles {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("required file %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("required file %s is not a non-empty regular file", relative)
		}
	}
	encoded, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(acceptancePath)))
	if err != nil {
		return err
	}
	var decision acceptance
	decoder := json.NewDecoder(strings.NewReader(string(encoded)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&decision); err != nil {
		return fmt.Errorf("decode acceptance status: %w", err)
	}
	if err := validateDecision(decision); err != nil {
		return err
	}
	if err := verifyLocalEvidenceReports(root, decision); err != nil {
		return err
	}
	if err := verifyNoReleaseSecrets(filepath.Join(root, "android")); err != nil {
		return err
	}
	if err := verifyProductClaims(filepath.Join(root, "android")); err != nil {
		return err
	}
	if len(unavailable) != 0 {
		return fmt.Errorf("%w: authenticated historical documents are unavailable in the sanitized subject: %s", errHistoricalEvidenceNotAvailable, strings.Join(unavailable, ", "))
	}
	return nil
}

func verifyHistoricalEvidenceFile(root, relative string) (bool, error) {
	raw, err := evidenceoverlay.ReadSubjectFile(root, relative)
	if err == nil {
		if len(raw) == 0 {
			return false, fmt.Errorf("historical evidence file %s is empty", relative)
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read historical evidence file %s: %w", relative, err)
	}
	digest, err := evidenceoverlay.ResolveCurrentSHA256(root, relative)
	if err != nil {
		return false, fmt.Errorf("authenticate sanitized historical evidence file %s: %w", relative, err)
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256DigestBytes {
		return false, fmt.Errorf("invalid authenticated predecessor digest for %s", relative)
	}
	return false, nil
}

const sha256DigestBytes = 32

func verifyLocalEvidenceReports(root string, decision acceptance) error {
	for key, relative := range localEvidenceReports {
		encoded, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil {
			return fmt.Errorf("read local evidence report %s: %w", key, err)
		}
		var report localEvidenceReport
		decoder := json.NewDecoder(strings.NewReader(string(encoded)))
		decoder.DisallowUnknownFields()
		if err := decoder.Decode(&report); err != nil {
			return fmt.Errorf("decode local evidence report %s: %w", key, err)
		}
		if err := validateLocalEvidenceReport(decision, key, report); err != nil {
			return err
		}
	}
	return nil
}

func validateLocalEvidenceReport(decision acceptance, key string, report localEvidenceReport) error {
	if report.Schema != "kurdistan-phase14-local-evidence-v1" || report.EvidenceKey != key {
		return fmt.Errorf("local evidence report %s has unexpected schema or evidence key", key)
	}
	if report.Status != "PASS" && report.Status != "PENDING" && report.Status != "FAIL" {
		return fmt.Errorf("local evidence report %s has unsupported status %q", key, report.Status)
	}
	if strings.TrimSpace(report.Scope) == "" || len(report.Commands) == 0 || len(report.Evidence) == 0 || len(report.Limitations) == 0 {
		return fmt.Errorf("local evidence report %s is incomplete", key)
	}
	if decision.Local[key] != report.Status {
		return fmt.Errorf("local evidence %s is %s in acceptance status but %s in its report", key, decision.Local[key], report.Status)
	}
	return nil
}

func validateDecision(value acceptance) error {
	if value.Schema != "kurdistan-phase14-acceptance-v1" || value.Phase != 14 {
		return errors.New("unexpected Phase 14 acceptance schema or phase")
	}
	if len(value.PriorPhaseBaseline) == 0 {
		return errors.New("prior-phase baseline is empty")
	}
	if len(value.Limitations) == 0 {
		return errors.New("limitations must be explicit")
	}
	if err := requireEvidenceKeys("local", value.Local, requiredLocalEvidence); err != nil {
		return err
	}
	if err := requireEvidenceKeys("external", value.External, requiredExternalEvidence); err != nil {
		return err
	}
	if err := validateBlockers(value.Blockers); err != nil {
		return err
	}
	switch value.ReleaseDecision {
	case "NO_GO":
		if value.Complete {
			return errors.New("NO_GO decision cannot be marked complete")
		}
		if value.ReadinessStatus != "IN_PROGRESS" && value.ReadinessStatus != "BLOCKED" {
			return errors.New("NO_GO decision requires IN_PROGRESS or BLOCKED readiness")
		}
		if len(value.Blockers) == 0 {
			return errors.New("NO_GO decision must identify a clearing condition")
		}
	case "GO":
		if !value.Complete || value.ReadinessStatus != "READY" {
			return errors.New("GO decision requires complete=true and READY status")
		}
		if len(value.Blockers) != 0 {
			return errors.New("GO decision cannot contain blockers")
		}
		if err := requireAllPass("local", value.Local); err != nil {
			return err
		}
		if err := requireAllPass("external", value.External); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported release decision %q", value.ReleaseDecision)
	}
	return nil
}

func requireEvidenceKeys(kind string, values map[string]string, required []string) error {
	if values == nil {
		return fmt.Errorf("%s evidence is missing", kind)
	}
	for _, key := range required {
		status, ok := values[key]
		if !ok || strings.TrimSpace(status) == "" {
			return fmt.Errorf("%s evidence %s is missing", kind, key)
		}
		if !validEvidenceStatus(status) {
			return fmt.Errorf("%s evidence %s has unsupported status %q", kind, key, status)
		}
	}
	return nil
}

func validEvidenceStatus(value string) bool {
	return value == "PASS" || value == "PENDING" || value == "UNVERIFIED" || value == "FAIL"
}

func requireAllPass(kind string, values map[string]string) error {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		if values[key] != "PASS" {
			return fmt.Errorf("%s evidence %s is %s, not PASS", kind, key, values[key])
		}
	}
	return nil
}

func validateBlockers(values []blocker) error {
	seen := map[string]bool{}
	for _, item := range values {
		if strings.TrimSpace(item.ID) == "" || seen[item.ID] {
			return errors.New("blocker IDs must be non-empty and unique")
		}
		seen[item.ID] = true
		if item.Severity != "CRITICAL" && item.Severity != "HIGH" && item.Severity != "MEDIUM" {
			return fmt.Errorf("blocker %s has unsupported severity %q", item.ID, item.Severity)
		}
		if strings.TrimSpace(item.Category) == "" || strings.TrimSpace(item.ConditionToClear) == "" {
			return fmt.Errorf("blocker %s lacks category or clearing condition", item.ID)
		}
	}
	return nil
}

func verifyNoReleaseSecrets(androidRoot string) error {
	forbiddenExtensions := map[string]bool{
		".jks": true, ".keystore": true, ".p12": true, ".pfx": true,
	}
	return filepath.WalkDir(androidRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "build" || entry.Name() == ".gradle" || entry.Name() == ".kotlin" {
				return filepath.SkipDir
			}
			return nil
		}
		if forbiddenExtensions[strings.ToLower(filepath.Ext(path))] {
			return fmt.Errorf("release credential material must not be committed: %s", path)
		}
		return nil
	})
}

func verifyProductClaims(androidRoot string) error {
	return filepath.WalkDir(androidRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == "build" || entry.Name() == ".gradle" || entry.Name() == ".kotlin" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".kt" && filepath.Ext(path) != ".xml" {
			return nil
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(encoded))
		for _, claim := range forbiddenReleaseClaims {
			if strings.Contains(lower, claim) {
				return fmt.Errorf("unsupported release claim %q in %s", claim, path)
			}
		}
		return nil
	})
}
