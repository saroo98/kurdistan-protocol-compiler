// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17devicegate runs the exact current Phase 17 instrumentation
// inventory through the hardened Android device runner.
package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
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
	"strconv"
	"strings"

	"kurdistan/internal/phase17qualification"
)

var requiredPhase17DeviceTests = []string{
	"minSdk=26 org.kurdistanvpn.app.Phase17FieldActionDeviceTest#runRequestedFieldAction",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#ownerUnderlayReachabilityProtectsBeforeBindingAndFailsClosed",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#liveIpv4LifecycleProtectsSocketBeforeConnectAndStopsCleanly",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#permissionRevocationAndProcessDeathRequireFreshAuthority",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#emergencyStopLeavesNoRuntimeOrSecretEvidence",
	"minSdk=34 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#dualStackDnsHandoverAndReconnectRemainPolicyBound",
	"minSdk=34 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#fieldProbeReacquiresOnlyAfterFreshControlledReconnect",
	"minSdk=34 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#networkScopedDnsReadinessWaitsForResolverAfterRapidVpnTransitions",
	"minSdk=34 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#profileRevocationAndBackupRestoreFailClosed",
	"minSdk=36 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#completeCurrentManifestAccessibilityAndLifecycleRemainTruthful",
	// These are compile-only evidence-admission and integrity contracts. They
	// are required inventory entries, not claims that D01-D08 executed.
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d01RequiresExternalColdStartObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d02RequiresExternalDefaultDeathObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d03RequiresExternalVpnReissueObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d04RequiresExternalNegativeMatrixObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d05RequiresExternalOverlapObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d06RequiresExternalDeathRecoveryObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d07RequiresExternalBootUnlockObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d08RequiresExternalFailureCleanupObservers",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d01AdmitsOnlyExternallySuppliedColdStartEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d02AdmitsOnlyExternallySuppliedDeathEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d03AdmitsOnlyExternallySuppliedReissueEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d04AdmitsOnlyExternallySuppliedNegativeEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d05AdmitsOnlyExternallySuppliedOverlapEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d06AdmitsOnlyExternallySuppliedRecoveryEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d07AdmitsOnlyExternallySuppliedBootEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d08AdmitsOnlyExternallySuppliedCleanupEnvelopeFixture",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d04SourceContractNamesEveryUnauthorizedAndInvalidAuthorityCase",
	"org.kurdistanvpn.app.Phase17BootQualificationDeviceTest#d08SourceContractNamesEveryFallibleActivationBoundary",
	"org.kurdistanvpn.app.Phase9FoundationUiTest#protectedRecoveryUiRequiresCurrentConfirmationAndRejectsUnsupportedRepairActions",
	"org.kurdistanvpn.app.Phase17CanonicalDeviceEvidenceHarnessContractTest#signedBytesHaveDefensiveOwnershipAndNoSuccessConclusion",
	"org.kurdistanvpn.app.Phase17CanonicalDeviceEvidenceHarnessContractTest#roleConfusionAndNumericBoundsAreRejectedBeforeRetention",
	"org.kurdistanvpn.app.Phase17ProtectedStateIntegrityDeviceTest#nativeLeafAndOwnerChecksCannotEscapeTheSuppliedDirectory",
	"org.kurdistanvpn.app.Phase17ProtectedStateIntegrityDeviceTest#nativeWriterReplacementSyncAndDeletionRequireExactOldIdentity",
	"org.kurdistanvpn.app.Phase17ProtectedStateIntegrityDeviceTest#nativeReadsRejectSymlinkHardLinkAndChangedDirectoryIdentity",
	"org.kurdistanvpn.app.Phase17ProtectedStateIntegrityDeviceTest#existingDirectoryOpenNeverCreatesOrAdoptsAnUnprovenLeaf",
}

type options struct {
	adbPath            string
	serial             string
	appAPK             string
	testAPK            string
	appPackage         string
	testPackage        string
	conflictingPackage string
	expectedTests      string
	evidenceDir        string
	minimumTests       int
	expectedAPI        int
	expectedABI        string
}

func main() {
	// This subcommand is strictly offline and read-only. It never delegates to a
	// device runner. A result JSON or a caller-authored PASS is not an input.
	if len(os.Args) > 1 && os.Args[1] == "verify-canonical" {
		os.Exit(runCanonicalGate(os.Args[2:], os.Stdout))
	}
	var value options
	flag.StringVar(&value.adbPath, "adb", "", "adb executable")
	flag.StringVar(&value.serial, "serial", "", "connected Android device serial")
	flag.StringVar(&value.appAPK, "app-apk", "", "internal application APK")
	flag.StringVar(&value.testAPK, "test-apk", "", "internal instrumentation APK")
	flag.StringVar(&value.appPackage, "app-package", "org.kurdistanvpn.app.internal", "application package")
	flag.StringVar(&value.testPackage, "test-package", "org.kurdistanvpn.app.internal.test", "instrumentation package")
	flag.StringVar(&value.conflictingPackage, "conflicting-app-package", "org.kurdistanvpn.app.debug", "sibling package to stop")
	flag.StringVar(&value.expectedTests, "expected-tests", "android/config/phase17-required-device-tests.txt", "exact Phase 17 test manifest")
	flag.StringVar(&value.evidenceDir, "evidence-dir", ".tools/phase17/device-gate/latest", "bounded raw device evidence directory")
	flag.IntVar(&value.minimumTests, "minimum-tests", 1, "minimum completed tests")
	flag.IntVar(&value.expectedAPI, "expected-api", 0, "exact Android API lane")
	flag.StringVar(&value.expectedABI, "expected-abi", "", "exact primary ABI lane")
	flag.Parse()

	if err := validateOptions(value); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 DEVICE GATE FAILED: %v\n", err)
		os.Exit(2)
	}
	if err := validatePhase17Inventory(value.expectedTests); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 DEVICE GATE FAILED: %v\n", err)
		os.Exit(1)
	}
	command := exec.Command("go", buildDelegateArgs(value)...)
	command.Stdout = os.Stdout
	command.Stderr = os.Stderr
	command.Stdin = os.Stdin
	if err := command.Run(); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 DEVICE GATE FAILED: %v\n", err)
		os.Exit(1)
	}
}

const canonicalGateRosterSchema = "kurdistan-phase17-device-gate-roster-v1"
const canonicalGateRosterDomain = "kurdistan-phase17-device-gate-roster-signature-v1\x00"

type canonicalGateObserver struct {
	Role      string `json:"role"`
	PublicKey string `json:"publicKey"`
}
type canonicalGateEntry struct {
	JourneyID    string                  `json:"journeyId"`
	InvocationID string                  `json:"invocationId"`
	File         string                  `json:"file"`
	SHA256       string                  `json:"sha256"`
	Observers    []canonicalGateObserver `json:"observers"`
}

// Provisioning is external. This command neither creates keys nor promotes
// evidence provenance. The owner-authenticated roster pins each observer and
// invocation; signatures prove origin, not honesty or capture completeness.
type canonicalGateRoster struct {
	Schema    string                                     `json:"schema"`
	Purpose   string                                     `json:"purpose"`
	Subject   phase17qualification.DeviceEvidenceSubject `json:"subject"`
	Entries   []canonicalGateEntry                       `json:"entries"`
	Signature string                                     `json:"signature"`
}

func canonicalGateJourneys(purpose string) []string {
	switch purpose {
	case "ENGINEERING_REHEARSAL":
		return []string{"D01", "D07"}
	case "CANDIDATE_CAMPAIGN":
		return []string{"D01", "D02", "D03", "D04", "D05", "D06", "D07", "D08"}
	default:
		return nil
	}
}
func canonicalGateRosterMessage(value canonicalGateRoster) []byte {
	value.Signature = ""
	raw, err := phase17qualification.MarshalCanonical(value)
	if err != nil {
		return nil
	}
	return append([]byte(canonicalGateRosterDomain), raw...)
}
func authenticateCanonicalGateRoster(raw, ownerPublic []byte, purpose string) (canonicalGateRoster, error) {
	var value canonicalGateRoster
	if len(raw) == 0 || len(raw) > 128<<10 || len(ownerPublic) != ed25519.PublicKeySize {
		return value, errors.New("gate roster bounds rejected")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, errors.New("gate roster decode rejected")
	}
	canonical, err := phase17qualification.MarshalCanonical(value)
	if err != nil || !bytes.Equal(canonical, raw) {
		return value, errors.New("gate roster is not canonical")
	}
	want := canonicalGateJourneys(purpose)
	if value.Schema != canonicalGateRosterSchema || value.Purpose != purpose || len(want) == 0 || len(value.Entries) != len(want) {
		return value, errors.New("gate journey inventory rejected")
	}
	signature, err := hex.DecodeString(value.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize || !ed25519.Verify(ed25519.PublicKey(ownerPublic), canonicalGateRosterMessage(value), signature) {
		return value, errors.New("gate roster owner signature rejected")
	}
	hex128 := regexp.MustCompile(`^[0-9a-f]{32}$`)
	hex256 := regexp.MustCompile(`^[0-9a-f]{64}$`)
	invocations := map[string]bool{}
	for i, entry := range value.Entries {
		if entry.JourneyID != want[i] || entry.File != want[i]+".json" || !hex128.MatchString(entry.InvocationID) || invocations[entry.InvocationID] || !hex256.MatchString(entry.SHA256) || len(entry.Observers) < 3 || len(entry.Observers) > 16 {
			return value, errors.New("gate invocation inventory rejected")
		}
		invocations[entry.InvocationID] = true
		for _, observer := range entry.Observers {
			if !hex256.MatchString(observer.PublicKey) {
				return value, errors.New("gate observer key rejected")
			}
		}
	}
	return value, nil
}
func readCanonicalGateFile(path string, maximum int64) ([]byte, error) {
	if maximum < 1 || maximum > phase17qualification.MaxDeviceEvidenceBytes {
		return nil, errors.New("gate file bound rejected")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	for current := absolute; ; current = filepath.Dir(current) {
		info, err := os.Lstat(current)
		if err != nil || info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("gate linked or unavailable path rejected")
		}
		if filepath.Dir(current) == current {
			break
		}
	}
	before, err := os.Lstat(absolute)
	if err != nil || !before.Mode().IsRegular() || before.Size() < 1 || before.Size() > maximum {
		return nil, errors.New("gate regular input rejected")
	}
	file, err := os.Open(absolute)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil || !os.SameFile(before, opened) {
		_ = file.Close()
		return nil, errors.New("gate input substituted")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	after, statErr := file.Stat()
	closeErr := file.Close()
	entry, entryErr := os.Lstat(absolute)
	if readErr != nil || statErr != nil || closeErr != nil || entryErr != nil || int64(len(raw)) != before.Size() || int64(len(raw)) > maximum || !os.SameFile(before, after) || !os.SameFile(before, entry) || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
		return nil, errors.New("gate input read unproven")
	}
	return raw, nil
}
func runCanonicalGate(arguments []string, output io.Writer) int {
	flags := flag.NewFlagSet("phase17devicegate verify-canonical", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	manifestPath := flags.String("manifest", "", "exact preserved engineering or candidate manifest")
	rosterPath := flags.String("roster", "", "owner-authenticated canonical observer roster")
	publicPath := flags.String("trusted-public-key", "", "independently pinned existing owner public key")
	purpose := flags.String("purpose", "", "ENGINEERING_REHEARSAL or CANDIDATE_CAMPAIGN")
	commit := flags.String("expected-commit", "", "exact immutable source commit")
	tree := flags.String("expected-tree", "", "exact immutable source tree")
	fail := func() int { _, _ = fmt.Fprintln(output, "PHASE17_CANONICAL_GATE_BLOCKED"); return 1 }
	if flags.Parse(arguments) != nil || flags.NArg() != 0 || *manifestPath == "" || *rosterPath == "" || *publicPath == "" || len(canonicalGateJourneys(*purpose)) == 0 || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*commit) || !regexp.MustCompile(`^[0-9a-f]{40}$`).MatchString(*tree) {
		return fail()
	}
	manifestRaw, err := readCanonicalGateFile(*manifestPath, phase17qualification.MaxDeviceEvidenceBytes)
	if err != nil {
		return fail()
	}
	manifest, err := phase17qualification.DecodeCandidateManifest(bytes.NewReader(manifestRaw))
	if err != nil || manifest.Source.CommitSHA != *commit || manifest.Source.TreeSHA != *tree {
		return fail()
	}
	// The existing qualification public-key file is exactly 32 raw bytes. Consume
	// this checked snapshot; do not reopen the path after validation.
	public, err := readCanonicalGateFile(*publicPath, ed25519.PublicKeySize)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return fail()
	}
	rosterRaw, err := readCanonicalGateFile(*rosterPath, 128<<10)
	if err != nil {
		return fail()
	}
	roster, err := authenticateCanonicalGateRoster(rosterRaw, public, *purpose)
	if err != nil {
		return fail()
	}
	identity, err := phase17qualification.CandidateIdentityFromManifest(manifest)
	if err != nil || identity != roster.Subject.Candidate {
		return fail()
	}
	for _, entry := range roster.Entries {
		raw, err := readCanonicalGateFile(filepath.Join(filepath.Dir(*rosterPath), entry.File), phase17qualification.MaxDeviceEvidenceBytes)
		if err != nil {
			return fail()
		}
		sum := sha256.Sum256(raw)
		if hex.EncodeToString(sum[:]) != entry.SHA256 {
			return fail()
		}
		keys := make([]phase17qualification.DeviceObserverKey, 0, len(entry.Observers))
		for _, observer := range entry.Observers {
			key, _ := hex.DecodeString(observer.PublicKey)
			keys = append(keys, phase17qualification.DeviceObserverKey{Role: observer.Role, PublicKey: key, InvocationID: entry.InvocationID})
		}
		trust, err := phase17qualification.NewAuthorizedDeviceEvidenceTrust(manifestRaw, keys)
		if err != nil {
			return fail()
		}
		verified, err := phase17qualification.VerifyDeviceEvidence(raw, roster.Subject, trust)
		if err != nil {
			return fail()
		}
		result := verified.Result()
		if result.InvocationID != entry.InvocationID || result.JourneyID != entry.JourneyID || result.Provenance != "AUTHORIZED_DEVICE" {
			return fail()
		}
		tiers := []string{"CONTROLLED_PROBE", "ROUTE_TUN", "DNS_TRANSACTION"}
		if entry.JourneyID == "D04" || entry.JourneyID == "D08" {
			tiers = []string{"PER_UID"}
		}
		if entry.JourneyID == "D06" {
			tiers = nil
			if result.Outcome != "PASS" || len(result.ProcessDeaths) == 0 {
				return fail()
			}
		}
		for _, tier := range tiers {
			if !verified.AllowsOperationalTier(tier) {
				return fail()
			}
		}
	}
	_, _ = fmt.Fprintln(output, "PHASE17_CANONICAL_GATE_VERIFIED")
	return 0
}

func validateOptions(value options) error {
	if strings.TrimSpace(value.appAPK) == "" || strings.TrimSpace(value.testAPK) == "" {
		return errors.New("app-apk and test-apk are required")
	}
	if strings.TrimSpace(value.expectedTests) == "" {
		return errors.New("expected-tests is required")
	}
	if value.minimumTests < 1 {
		return errors.New("minimum-tests must be positive")
	}
	if (value.expectedAPI == 0) != (value.expectedABI == "") {
		return errors.New("expected-api and expected-abi must be supplied together")
	}
	if value.expectedAPI != 0 && value.expectedAPI != 26 && value.expectedAPI != 34 && value.expectedAPI != 36 {
		return fmt.Errorf("unsupported Phase 17 API lane %d", value.expectedAPI)
	}
	if value.expectedABI != "" && value.expectedABI != "x86_64" && value.expectedABI != "arm64-v8a" {
		return fmt.Errorf("unsupported Phase 17 ABI lane %q", value.expectedABI)
	}
	return nil
}

func validatePhase17Inventory(path string) error {
	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open exact test inventory: %w", err)
	}
	defer file.Close()
	seen := make(map[string]struct{})
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if _, duplicate := seen[line]; duplicate {
			return fmt.Errorf("duplicate required test %q", line)
		}
		seen[line] = struct{}{}
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("read exact test inventory: %w", err)
	}
	for _, required := range requiredPhase17DeviceTests {
		if _, ok := seen[required]; !ok {
			return fmt.Errorf("exact test inventory is missing %q", required)
		}
	}
	return nil
}

func buildDelegateArgs(value options) []string {
	arguments := []string{
		"run", "./cmd/phase9devicegate",
		"-label", "PHASE 17",
	}
	if value.adbPath != "" {
		arguments = append(arguments, "-adb", value.adbPath)
	}
	if value.serial != "" {
		arguments = append(arguments, "-serial", value.serial)
	}
	arguments = append(arguments,
		"-app-apk", value.appAPK,
		"-test-apk", value.testAPK,
		"-app-package", value.appPackage,
		"-test-package", value.testPackage,
	)
	if value.conflictingPackage != "" {
		arguments = append(arguments, "-conflicting-app-package", value.conflictingPackage)
	}
	arguments = append(arguments, "-minimum-tests", strconv.Itoa(value.minimumTests))
	if value.expectedAPI != 0 {
		arguments = append(arguments,
			"-expected-api", strconv.Itoa(value.expectedAPI),
			"-expected-abi", value.expectedABI,
		)
	}
	return append(arguments,
		"-expected-tests", value.expectedTests,
		"-evidence-dir", value.evidenceDir,
	)
}
