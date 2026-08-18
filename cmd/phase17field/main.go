// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17field runs the bounded owner-controlled VPS and Android
// emulator acceptance sequence. It retains only categorical, redacted evidence.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"kurdistan/internal/phase17evidence"
	"kurdistan/internal/phase17qualification"
)

const (
	rawSchema                    = "kurdistan-phase17-owned-vps-raw-v2"
	maxOutputBytes               = 2 << 20
	maxAndroidPrivacyLogBytes    = 16 << 20
	appPackage                   = "org.kurdistanvpn.app.internal"
	testPackage                  = "org.kurdistanvpn.app.internal.test"
	probeNetworkStatePermission  = "android.permission.ACCESS_NETWORK_STATE"
	testRunner                   = "org.kurdistanvpn.app.internal.test/androidx.test.runner.AndroidJUnitRunner"
	fieldTest                    = "org.kurdistanvpn.app.Phase17FieldActionDeviceTest#runRequestedFieldAction"
	remoteDataDir                = "/var/lib/kurd-node"
	remoteRegistry               = "/var/lib/kurd-node/recipient-registry"
	remoteControl                = "/run/kurd-node/control.sock"
	remotePassFile               = "/root/.kurd-node-field/current-passphrase"
	remoteRecovery               = "/root/.kurd-node-field/current.kurd-recovery"
	fieldDirectory               = "files/phase17-field"
	recipientFile                = fieldDirectory + "/recipient-request.bin"
	profileFile                  = fieldDirectory + "/sealed-profile.bin"
	fieldResultFile              = fieldDirectory + "/result.txt"
	fieldAttemptFile             = fieldDirectory + "/attempt.txt"
	fieldEvidenceResetAttempts   = 31
	fieldEvidenceResetDelay      = time.Second
	fieldEvidenceResetTimeout    = 30 * time.Second
	fieldEvidenceAttemptTimeout  = 10 * time.Second
	androidPackageCompileTimeout = 2 * time.Minute
	impairmentVerificationTries  = 3
	impairmentRetryDelay         = 250 * time.Millisecond
	fieldActionLaunchAttempts    = 2
	frozenRestartCycles          = 100
	frozenProfileRotationCycles  = 100
	maximumRelayRSSBytes         = 384 << 20
	maximumRelayFileDescriptors  = 1024
	maximumRelaySwapBytes        = 64 << 20
)

type fieldActionFailure struct {
	action   string
	category string
}

func (failure *fieldActionFailure) Error() string {
	return fmt.Sprintf("Android field action %s failed: %s", failure.action, failure.category)
}

var requiredChecks = []string{
	"preflight", "packageVerification", "install", "serviceHealth", "enrollment",
	"sealedImport", "connect", "ipv4Tcp", "ipv4Udp", "dnsHealthy", "dnsFailClosed",
	"egressIdentity", "ipv6", "routeDnsLeak", "boundedFallback", "revocation",
	"restart", "drainResume", "emergencyDisable", "backupRestore", "upgradeRollback",
	"androidCrashFree", "privacy",
}

var (
	selectorPattern        = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,64}$`)
	hex40Pattern           = regexp.MustCompile(`^[0-9a-f]{40}$`)
	hex64Pattern           = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fieldAttemptIDPattern  = regexp.MustCompile(`^[0-9a-f]{32}$`)
	terminalFailurePattern = regexp.MustCompile(`^[A-Za-z0-9 _():/-]{1,512}$`)
	remotePackagePattern   = regexp.MustCompile(`^/var/tmp/phase17-package-[0-9a-f]{1,16}$`)
	remoteArchivePattern   = regexp.MustCompile(`^/tmp/phase17-package-[0-9a-f]{1,16}\.tar\.gz$`)
	instrumentCategoryV1   = regexp.MustCompile(`[A-Z][A-Z0-9_]{2,63}(?::[A-Z0-9_-]{1,64}){0,7}`)
	frameTrackerCUJLineV1  = regexp.MustCompile(`(?m)^[A-Z]/FrameTracker\(\s*[0-9]+\):[^\r\n]*CUJ=J<[A-Z0-9_]+::[0-9]{1,3}@[0-9]{1,3}@org\.kurdistanvpn\.app\.internal>[^\r\n]*\r?$`)
	frameTrackerCUJIndexV1 = regexp.MustCompile(`::[0-9]{1,3}@`)
	frozenImpairmentMatrix = []impairmentScenario{
		{name: "bandwidth", netem: "rate 5mbit"},
		{name: "latency", netem: "delay 150ms 25ms distribution normal"},
		{name: "loss", netem: "loss 1%"},
		{name: "combined", netem: "delay 100ms 20ms distribution normal loss 1% rate 5mbit"},
		{name: "carrier-reset", carrierReset: true},
	}
	errProfileIssuanceTransport      = errors.New("profile issuance transport failed")
	errAndroidEnvironmentUnavailable = errors.New("authorized Android environment unavailable")
	errVPSEnvironmentUnavailable     = errors.New("owner VPS environment unavailable")
	errFieldCleanup                  = errors.New("field campaign cleanup failed")
	errFieldEvidenceInvalid          = errors.New("field evidence invalid")
)

type impairmentScenario struct {
	name         string
	netem        string
	carrierReset bool
}

type stressActions struct {
	restartReconnect func(context.Context, int) error
	rotateReissue    func(context.Context, int) error
	impair           func(context.Context, string) error
	sample           func(context.Context) error
	progress         func(category string, completed, total int)
}

type resourceSample struct {
	rss, fds, swapBytes, oomKills, threads uint64
	ipv6                                   bool
}

type resourceTracker struct {
	samples               []resourceSample
	peakRSS, peakFDs      uint64
	peakSwap, peakThreads uint64
	peakOOMKills          uint64
}

func (tracker *resourceTracker) observe(sample resourceSample) error {
	if sample.rss == 0 || sample.rss > maximumRelayRSSBytes ||
		sample.fds == 0 || sample.fds > maximumRelayFileDescriptors ||
		sample.swapBytes > maximumRelaySwapBytes || sample.oomKills != 0 ||
		sample.threads > 512 {
		return errors.New("remote resource limits rejected")
	}
	tracker.samples = append(tracker.samples, sample)
	tracker.peakRSS = max(tracker.peakRSS, sample.rss)
	tracker.peakFDs = max(tracker.peakFDs, sample.fds)
	tracker.peakSwap = max(tracker.peakSwap, sample.swapBytes)
	tracker.peakThreads = max(tracker.peakThreads, sample.threads)
	tracker.peakOOMKills = max(tracker.peakOOMKills, sample.oomKills)
	if len(tracker.samples) < 8 {
		return nil
	}
	recent := tracker.samples[len(tracker.samples)-8:]
	rssRising, fdsRising := true, true
	for index := 1; index < len(recent); index++ {
		rssRising = rssRising && recent[index].rss > recent[index-1].rss
		fdsRising = fdsRising && recent[index].fds > recent[index-1].fds
	}
	if rssRising && recent[len(recent)-1].rss-recent[0].rss > 16<<20 {
		return errors.New("remote RSS shows persistent monotonic growth")
	}
	if fdsRising && recent[len(recent)-1].fds-recent[0].fds > 32 {
		return errors.New("remote file descriptors show persistent monotonic growth")
	}
	return nil
}

func executeStressCampaign(ctx context.Context, policy phase17qualification.CampaignPolicy, actions stressActions) error {
	if policy.Mode != "Stress" || policy.MinimumDurationMS != 0 || policy.CadenceMS != 0 || policy.MinimumCycles != 0 ||
		policy.RestartReconnectCycles == 0 || policy.ProfileRotationCycles == 0 || len(policy.Impairments) == 0 {
		return errors.New("stress campaign policy rejected")
	}
	for cycle := uint64(0); cycle < policy.RestartReconnectCycles; cycle++ {
		if err := actions.restartReconnect(ctx, int(cycle)); err != nil {
			return fmt.Errorf("restart/reconnect cycle %d failed: %w", cycle, err)
		}
		if err := actions.sample(ctx); err != nil {
			return fmt.Errorf("restart/reconnect resource sample %d failed: %w", cycle, err)
		}
		if actions.progress != nil {
			actions.progress("restart-reconnect", int(cycle+1), int(policy.RestartReconnectCycles))
		}
	}
	for cycle := uint64(0); cycle < policy.ProfileRotationCycles; cycle++ {
		if err := actions.rotateReissue(ctx, int(cycle)); err != nil {
			return fmt.Errorf("profile revoke/reissue cycle %d failed: %w", cycle, err)
		}
		if err := actions.sample(ctx); err != nil {
			return fmt.Errorf("profile revoke/reissue resource sample %d failed: %w", cycle, err)
		}
		if actions.progress != nil {
			actions.progress("profile-rotation", int(cycle+1), int(policy.ProfileRotationCycles))
		}
	}
	for index, impairment := range policy.Impairments {
		if err := actions.impair(ctx, impairment); err != nil {
			return fmt.Errorf("impairment %s failed: %w", impairment, err)
		}
		if err := actions.sample(ctx); err != nil {
			return fmt.Errorf("impairment %s resource sample failed: %w", impairment, err)
		}
		if actions.progress != nil {
			actions.progress("impairment", index+1, len(policy.Impairments))
		}
	}
	return nil
}

type config struct {
	sshAlias, avdName, deviceSerial, evidenceRoot, mode      string
	privateEnvironmentPath, environmentSaltPath              string
	packagePath, appAPK, testAPK, adbPath, sshPath, scpPath  string
	policyPath                                               string
	packageEntry, appEntry, testEntry, runnerEntry           string
	policyEntry, packageVerifierPath, packageVerifierEntry   string
	scannerAPath, scannerAEntry, scannerBPath, scannerBEntry string
	boundaryPath, boundaryEntry, pythonPath, powershellPath  string
	runnerPath, wrapperPath, wrapperEntry                    string
	preflightPath, preflightEntry                            string
	qualification                                            qualifiedInputPaths
	probeURLFile, probeDigestFile                            string
	ipv6ProbeAddress                                         string
	relayPort                                                int
}

type fieldIdentity struct {
	commitSHA, treeSHA, packageSHA, appSHA, testSHA string
	api                                             int
	abi                                             string
	ipv6                                            bool
}

type functionalOutcome struct {
	reconnects uint64
	campaign   rawCampaign
	scanners   []phase17evidence.FieldScannerV3
	boundary   phase17evidence.FieldBoundaryV3
}

type rawEvidence struct {
	Schema      string            `json:"schema"`
	Result      string            `json:"result"`
	Subject     rawSubject        `json:"subject"`
	Environment rawEnvironment    `json:"environment"`
	Checks      map[string]string `json:"checks"`
	Metrics     rawMetrics        `json:"metrics"`
	Privacy     rawPrivacy        `json:"privacy"`
	Limitations []string          `json:"limitations"`
	Campaign    rawCampaign       `json:"campaign"`
}

type rawCampaign struct {
	Mode                   string   `json:"mode"`
	RestartReconnectCycles uint64   `json:"restartReconnectCycles"`
	ProfileRotationCycles  uint64   `json:"profileRotationCycles"`
	Impairments            []string `json:"impairments"`
	SoakDurationMS         uint64   `json:"soakDurationMs"`
	SoakCycles             uint64   `json:"soakCycles"`
}

type rawSubject struct {
	CommitSHA, TreeSHA, PackageSHA, AppAPKSHA, TestAPKSHA string
}

func (value rawSubject) MarshalJSON() ([]byte, error) {
	type wire struct {
		CommitSHA, TreeSHA, PackageSHA, AppAPKSHA, TestAPKSHA string
	}
	return json.Marshal(struct {
		CommitSHA  string `json:"commitSha"`
		TreeSHA    string `json:"treeSha"`
		PackageSHA string `json:"packageSha256"`
		AppAPKSHA  string `json:"appApkSha256"`
		TestAPKSHA string `json:"testApkSha256"`
	}{value.CommitSHA, value.TreeSHA, value.PackageSHA, value.AppAPKSHA, value.TestAPKSHA})
}

type rawEnvironment struct {
	HostClass, OS, Arch, AndroidClass, AndroidABI string
	AndroidAPI                                    int
	IPv4, IPv6                                    bool
}

func (value rawEnvironment) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		HostClass    string `json:"hostClass"`
		OS           string `json:"os"`
		Arch         string `json:"arch"`
		AndroidClass string `json:"androidClass"`
		AndroidAPI   int    `json:"androidApi"`
		AndroidABI   string `json:"androidAbi"`
		IPv4         bool   `json:"ipv4"`
		IPv6         bool   `json:"ipv6"`
	}{value.HostClass, value.OS, value.Arch, value.AndroidClass, value.AndroidAPI, value.AndroidABI, value.IPv4, value.IPv6})
}

type rawMetrics struct {
	DurationMS, PeakRSSBytes, PeakFileDescriptors, Reconnects uint64
}

func (value rawMetrics) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		DurationMS          uint64 `json:"durationMs"`
		PeakRSSBytes        uint64 `json:"peakRssBytes"`
		PeakFileDescriptors uint64 `json:"peakFileDescriptors"`
		Reconnects          uint64 `json:"reconnects"`
	}{value.DurationMS, value.PeakRSSBytes, value.PeakFileDescriptors, value.Reconnects})
}

type rawPrivacy struct {
	PayloadRetained, DestinationRetained, DNSNameRetained, CredentialRetained bool
	KeyRetained, ProfileRetained, RawLogRetained                              bool
}

func (value rawPrivacy) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		PayloadRetained     bool `json:"payloadRetained"`
		DestinationRetained bool `json:"destinationRetained"`
		DNSNameRetained     bool `json:"dnsNameRetained"`
		CredentialRetained  bool `json:"credentialRetained"`
		KeyRetained         bool `json:"keyRetained"`
		ProfileRetained     bool `json:"profileRetained"`
		RawLogRetained      bool `json:"rawLogRetained"`
	}{value.PayloadRetained, value.DestinationRetained, value.DNSNameRetained, value.CredentialRetained, value.KeyRetained, value.ProfileRetained, value.RawLogRetained})
}

type commandRunner struct {
	runFunc        func(context.Context, []byte, string, string, ...string) ([]byte, error)
	remoteGate     connectionGate
	remoteCommands map[string]struct{}
}

type commandExitFailure struct {
	code int
}

func (failure *commandExitFailure) Error() string {
	return fmt.Sprintf("command exited with status %d", failure.code)
}

type connectionGate interface {
	wait(context.Context) error
}

type pacedConnectionGate struct {
	mu       sync.Mutex
	next     time.Time
	interval time.Duration
}

func (gate *pacedConnectionGate) wait(ctx context.Context) error {
	gate.mu.Lock()
	defer gate.mu.Unlock()
	delay := time.Until(gate.next)
	if delay > 0 {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	gate.next = time.Now().Add(gate.interval)
	return nil
}

func main() {
	value := config{}
	flag.StringVar(&value.evidenceRoot, "evidence-root", ".tools/phase17/field", "ignored raw evidence root")
	flag.StringVar(&value.mode, "mode", "Functional", "Functional, Stress, or Soak12h")
	flag.StringVar(&value.policyPath, "policy", "config/phase17/qualification-policy-v1.json", "frozen Phase 17 qualification policy")
	flag.StringVar(&value.qualification.candidatePath, "candidate", "", "locked candidate manifest")
	flag.StringVar(&value.qualification.rcLockedPath, "rc-lock", "", "signed RC_LOCKED receipt")
	flag.StringVar(&value.qualification.attemptPath, "attempt", "", "signed attempt begin receipt")
	flag.StringVar(&value.qualification.environmentPath, "environment", "", "canonical environment context")
	flag.StringVar(&value.qualification.preflightResultPath, "preflight-result", "", "fresh owner-VPS preflight evidence")
	flag.StringVar(&value.privateEnvironmentPath, "private-environment", "", "ignored owner-local private environment input")
	flag.StringVar(&value.environmentSaltPath, "environment-salt", "", "ignored owner-local environment commitment salt")
	flag.StringVar(&value.qualification.ledgerPath, "ledger", "", "append-only qualification ledger")
	flag.StringVar(&value.qualification.trustedPublicKeyPath, "trusted-public-key", "", "pinned qualification public key")
	flag.StringVar(&value.qualification.soakReadyPath, "soak-ready", "", "signed final-soak readiness receipt")
	flag.StringVar(&value.qualification.priorStressPath, "prior-stress-result", "", "exact prior Stress PASS result")
	flag.StringVar(&value.packagePath, "package", "", "verified Linux amd64 package")
	flag.StringVar(&value.packageEntry, "package-entry", "", "exact PQS package entry")
	flag.StringVar(&value.appAPK, "app-apk", "android/app/build/outputs/apk/internal/app-internal.apk", "internal application APK")
	flag.StringVar(&value.appEntry, "app-entry", "", "exact PQS application entry")
	flag.StringVar(&value.testAPK, "test-apk", "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk", "instrumentation APK")
	flag.StringVar(&value.testEntry, "test-entry", "", "exact QHS instrumentation entry")
	flag.StringVar(&value.runnerEntry, "runner-entry", "", "exact QHS phase17field entry")
	flag.StringVar(&value.wrapperPath, "wrapper", "", "active locked campaign wrapper")
	flag.StringVar(&value.wrapperEntry, "wrapper-entry", "", "exact QHS campaign wrapper entry")
	flag.StringVar(&value.preflightPath, "preflight", "", "active locked VPS preflight")
	flag.StringVar(&value.preflightEntry, "preflight-entry", "", "exact QHS VPS preflight entry")
	flag.StringVar(&value.policyEntry, "policy-entry", "", "exact QWS policy entry")
	flag.StringVar(&value.packageVerifierPath, "package-verifier", "", "compiled locked kurdpackage executable")
	flag.StringVar(&value.packageVerifierEntry, "package-verifier-entry", "", "exact QHS kurdpackage entry")
	flag.StringVar(&value.scannerAPath, "privacy-scanner-a", "", "compiled locked Go privacy scanner")
	flag.StringVar(&value.scannerAEntry, "privacy-scanner-a-entry", "", "exact QHS Go privacy scanner entry")
	flag.StringVar(&value.scannerBPath, "privacy-scanner-b", "", "locked Python privacy scanner")
	flag.StringVar(&value.scannerBEntry, "privacy-scanner-b-entry", "", "exact QHS Python privacy scanner entry")
	flag.StringVar(&value.boundaryPath, "boundary-monitor", "", "compiled locked boundary monitor")
	flag.StringVar(&value.boundaryEntry, "boundary-monitor-entry", "", "exact QHS boundary monitor entry")
	flag.Parse()
	runnerPath, err := os.Executable()
	if err != nil {
		fmt.Fprintln(os.Stderr, "PHASE 17 FIELD FAILED: runner identity unavailable")
		os.Exit(2)
	}
	value.runnerPath = runnerPath
	value.qualification.policyPath = value.policyPath
	if err := validateLaunchConfig(value); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 FIELD FAILED: %v\n", err)
		os.Exit(2)
	}
	if err := runWithHostWakeGuard(acquireHostWakeInhibitor, func() error {
		return runField(context.Background(), commandRunner{}, value)
	}); err != nil {
		fmt.Fprintln(os.Stdout, terminalFailureLine(err))
		fmt.Fprintf(os.Stderr, "PHASE 17 FIELD FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 17 OWNED-VPS FIELD MATRIX PASSED")
}

func validateLaunchConfig(value config) error {
	if value.sshAlias != "" || value.avdName != "" || value.deviceSerial != "" || value.relayPort != 0 ||
		value.probeURLFile != "" || value.probeDigestFile != "" || value.ipv6ProbeAddress != "" ||
		value.pythonPath != "" || value.adbPath != "" || value.sshPath != "" || value.scpPath != "" || value.powershellPath != "" {
		return errors.New("inline private environment rejected")
	}
	for _, path := range []string{value.privateEnvironmentPath, value.environmentSaltPath} {
		if strings.TrimSpace(path) == "" || strings.ContainsAny(path, "\r\n\x00") {
			return errors.New("private environment path rejected")
		}
	}
	return validateCommonConfig(value)
}

func terminalFailureLine(err error) string {
	const fallback = "PHASE17_FAILURE FIELD_FAILURE"
	err = primaryFieldFailure(err)
	if err == nil {
		return fallback
	}
	value := err.Error()
	if !terminalFailurePattern.MatchString(value) || !safeCategory([]byte(value)) {
		return fallback
	}
	return "PHASE17_FAILURE " + value
}

func validateConfig(value config) error {
	if !selectorPattern.MatchString(value.sshAlias) {
		return errors.New("SSH alias rejected")
	}
	emulatorSelected := selectorPattern.MatchString(value.avdName) && value.deviceSerial == ""
	physicalSelected := value.avdName == "" && selectorPattern.MatchString(value.deviceSerial)
	if !emulatorSelected && !physicalSelected {
		return errors.New("Android selector rejected")
	}
	if value.relayPort < 1 || value.relayPort > 65535 {
		return errors.New("relay port rejected")
	}
	probeAddress := net.ParseIP(value.ipv6ProbeAddress)
	if probeAddress == nil || probeAddress.To4() != nil || strings.ContainsAny(value.ipv6ProbeAddress, "\r\n\x00") {
		return errors.New("IPv6 probe address rejected")
	}
	for _, required := range []string{value.adbPath, value.sshPath, value.scpPath, value.pythonPath, value.powershellPath} {
		if strings.TrimSpace(required) == "" || strings.ContainsAny(required, "\r\n\x00") {
			return errors.New("private executable path rejected")
		}
	}
	return validateCommonConfig(value)
}

func validateCommonConfig(value config) error {
	if _, found := phase17qualification.CampaignPolicyForMode(value.mode); !found {
		return errors.New("mode rejected")
	}
	for _, required := range []string{
		value.evidenceRoot, value.packagePath, value.packageEntry, value.appAPK, value.appEntry, value.testAPK, value.testEntry,
		value.policyPath, value.policyEntry, value.runnerPath, value.runnerEntry,
		value.wrapperPath, value.wrapperEntry,
		value.preflightPath, value.preflightEntry,
		value.packageVerifierPath, value.packageVerifierEntry, value.qualification.candidatePath, value.qualification.rcLockedPath,
		value.scannerAPath, value.scannerAEntry, value.scannerBPath, value.scannerBEntry,
		value.boundaryPath, value.boundaryEntry,
		value.qualification.attemptPath, value.qualification.environmentPath, value.qualification.ledgerPath,
		value.qualification.preflightResultPath,
		value.qualification.trustedPublicKeyPath,
	} {
		if strings.TrimSpace(required) == "" || strings.ContainsAny(required, "\r\n\x00") {
			return errors.New("required path rejected")
		}
	}
	if value.mode == "Soak12h" {
		if value.qualification.soakReadyPath == "" || value.qualification.priorStressPath == "" {
			return errors.New("final soak prerequisites rejected")
		}
	} else if value.qualification.soakReadyPath != "" || value.qualification.priorStressPath != "" {
		return errors.New("non-final campaign received final-soak prerequisites")
	}
	return nil
}

func safeCategory(raw []byte) bool {
	return !phase17evidence.ContainsSensitiveFieldEvidence(raw)
}

func passingEvidence(identity fieldIdentity, duration, rss, descriptors, reconnects uint64) rawEvidence {
	checks := make(map[string]string, len(requiredChecks))
	for _, name := range requiredChecks {
		checks[name] = "PASS"
	}
	return rawEvidence{
		Schema: rawSchema, Result: "PASS",
		Subject:     rawSubject{identity.commitSHA, identity.treeSHA, identity.packageSHA, identity.appSHA, identity.testSHA},
		Environment: rawEnvironment{"OWNER_CONTROLLED_VPS", "linux", "amd64", "EMULATOR", identity.abi, identity.api, true, identity.ipv6},
		Checks:      checks,
		Metrics:     rawMetrics{duration, rss, descriptors, reconnects},
		Privacy:     rawPrivacy{},
		Limitations: []string{"first owner-controlled provider and emulator evidence only"},
	}
}

func marshalEvidence(value rawEvidence) ([]byte, error) {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(encoded, '\n'), nil
}

func runField(parent context.Context, runner commandRunner, value config) (resultErr error) {
	started := time.Now()
	value, environmentSalt, probeURL, probeDigest, err := loadPrivateRuntime(value)
	if err != nil {
		return errors.New("private environment unavailable")
	}
	defer clear(environmentSalt)
	defer clear(probeURL)
	defer clear(probeDigest)
	if err := validateConfig(value); err != nil {
		return errors.New("private environment rejected")
	}
	runner = prepareProductionCommandRunner(runner, value)
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	qualified, err := loadQualifiedRun(value.mode, value.qualification, qualifiedArtifactPaths{
		packagePath: value.packagePath, packageEntry: value.packageEntry,
		appPath: value.appAPK, appEntry: value.appEntry,
		testPath: value.testAPK, testEntry: value.testEntry,
		runnerPath: value.runnerPath, runnerEntry: value.runnerEntry,
		wrapperPath: value.wrapperPath, wrapperEntry: value.wrapperEntry,
		preflightPath: value.preflightPath, preflightEntry: value.preflightEntry,
		packageVerifierPath: value.packageVerifierPath, packageVerifierEntry: value.packageVerifierEntry,
		scannerAPath: value.scannerAPath, scannerAEntry: value.scannerAEntry,
		scannerBPath: value.scannerBPath, scannerBEntry: value.scannerBEntry,
		boundaryPath: value.boundaryPath, boundaryEntry: value.boundaryEntry,
		pythonPath: value.pythonPath, adbPath: value.adbPath, sshPath: value.sshPath, scpPath: value.scpPath,
		powershellPath: value.powershellPath,
		policyPath:     value.policyPath, policyEntry: value.policyEntry,
	})
	if err != nil {
		return errors.New("qualification identity rejected")
	}
	tracker := &resourceTracker{}
	api := qualified.environment.AndroidAPI
	abi := qualified.environment.AndroidABI
	ipv6Authorized := false
	outcome := functionalOutcome{
		campaign: rawCampaign{Mode: value.mode, Impairments: []string{}},
	}
	defer func() {
		durationMS := terminalDurationMilliseconds(time.Since(started))
		terminal, err := buildTerminalEvidenceV3(qualified, api, abi, ipv6Authorized, durationMS, *tracker, outcome, resultErr)
		if err != nil {
			resultErr = errors.Join(resultErr, errors.New("terminal field evidence construction failed"))
			return
		}
		encoded, err := phase17evidence.MarshalOwnedVPSRawV3(terminal)
		if err != nil || !safeCategory(encoded) {
			resultErr = errors.Join(resultErr, errors.New("terminal field evidence privacy validation failed"))
			return
		}
		runRoot := filepath.Join(value.evidenceRoot, time.Now().UTC().Format("20060102T150405Z")+"-"+qualified.attempt.AttemptID)
		if err := os.MkdirAll(runRoot, 0o700); err != nil {
			resultErr = errors.Join(resultErr, errors.New("terminal field evidence directory failed"))
			return
		}
		if err := writeAtomic(filepath.Join(runRoot, "field-result.json"), encoded, 0o600); err != nil {
			resultErr = errors.Join(resultErr, errors.New("terminal field evidence write failed"))
		}
	}()
	if err := verifyPrivateEnvironmentCommitment(parent, qualified, value, environmentSalt, probeURL, probeDigest); err != nil {
		return err
	}
	if err := verifyOwnerVPSClock(parent, runner, value, root, time.Now); err != nil {
		return err
	}
	commit, tree, err := readCleanSourceIdentity(parent, runner, root)
	if err != nil {
		return err
	}
	if commit != qualified.candidate.CommitSHA || tree != qualified.candidate.TreeSHA {
		return errors.New("source identity differs from locked candidate")
	}
	if _, err := runBytes(parent, runner, nil, root, 2*time.Minute, value.packageVerifierPath, "verify", "-archive", value.packagePath); err != nil {
		return errors.New("package verification failed")
	}
	remotePackage, err := stageAndVerifyPackage(parent, runner, value, root)
	if err != nil {
		return err
	}
	defer func() {
		joinFieldCleanup(&resultErr, removeRemoteStagedPackage(context.Background(), runner, value, root, remotePackage))
	}()
	serial, observedAPI, observedABI, err := selectDevice(parent, runner, value, qualified.environment.AndroidClass)
	if err != nil {
		return err
	}
	api = observedAPI
	abi = observedABI
	if err := prepareAndroidPackages(parent, runner, value, root, serial); err != nil {
		return err
	}
	ipv6Authorized, err = prepareIPv6Capability(parent, runner, value, root)
	if err != nil {
		return err
	}
	if !ipv6Authorized {
		return errors.New("IPv6 capability unavailable")
	}
	if err := prepareRemoteCampaignAuthority(parent, runner, value, root); err != nil {
		return err
	}
	outcome, err = runFunctional(parent, runner, value, qualified, root, serial, remotePackage, probeURL, probeDigest, ipv6Authorized, tracker)
	if err != nil {
		joinFieldCleanup(&err, safeStop(parent, runner, value, root))
		return err
	}
	last := tracker.samples[len(tracker.samples)-1]
	if !last.ipv6 {
		return errors.New("authorized IPv6 route unavailable after field run")
	}
	finalCommit, finalTree, err := readCleanSourceIdentity(parent, runner, root)
	if err != nil || finalCommit != commit || finalTree != tree {
		return errors.New("source identity changed during field run")
	}
	identity := fieldIdentity{strings.TrimSpace(commit), strings.TrimSpace(tree), qualified.packageDigest, qualified.appDigest, qualified.testDigest, api, abi, ipv6Authorized}
	if !hex64Pattern.MatchString(identity.packageSHA) || !hex64Pattern.MatchString(identity.appSHA) || !hex64Pattern.MatchString(identity.testSHA) {
		return errors.New("artifact digest rejected")
	}
	return nil
}

func prepareProductionCommandRunner(runner commandRunner, value config) commandRunner {
	if runner.runFunc != nil {
		return runner
	}
	runner.remoteGate = &pacedConnectionGate{interval: 7 * time.Second}
	runner.remoteCommands = map[string]struct{}{value.sshPath: {}, value.scpPath: {}}
	return runner
}

func terminalDurationMilliseconds(elapsed time.Duration) uint64 {
	milliseconds := elapsed.Milliseconds()
	if milliseconds < 1 {
		return 1
	}
	return uint64(milliseconds)
}

func prepareAndroidPackages(ctx context.Context, runner commandRunner, value config, root, serial string) error {
	for _, apk := range []string{value.appAPK, value.testAPK} {
		if _, err := runBytes(ctx, runner, nil, root, 2*time.Minute, value.adbPath, "-s", serial, "install", "-r", "-t", apk); err != nil {
			return errors.New("APK installation failed")
		}
	}
	permissionDump, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.adbPath,
		"-s", serial, "shell", "dumpsys", "package", testPackage)
	permissionAvailable := err == nil && packageRequestsPermission(permissionDump, probeNetworkStatePermission)
	clear(permissionDump)
	if !permissionAvailable {
		return errors.New("Android boundary probe permission unavailable")
	}
	for _, packageName := range []string{appPackage, testPackage} {
		output, err := runBytes(ctx, runner, nil, root, androidPackageCompileTimeout, value.adbPath,
			"-s", serial, "shell", "cmd", "package", "compile", "-m", "speed", "-f", packageName)
		compiled := err == nil && bytes.Equal(bytes.TrimSpace(output), []byte("Success"))
		clear(output)
		if !compiled {
			return errors.New("Android package compilation failed")
		}
	}
	if _, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.adbPath,
		"-s", serial, "shell", "appops", "set", appPackage, "ACTIVATE_VPN", "allow"); err != nil {
		return errors.New("Android VPN permission preparation failed")
	}
	return nil
}

func packageRequestsPermission(raw []byte, permission string) bool {
	if strings.TrimSpace(permission) == "" || strings.ContainsAny(permission, "\r\n\x00") {
		return false
	}
	inRequestedPermissions := false
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "requested permissions:" {
			inRequestedPermissions = true
			continue
		}
		if !inRequestedPermissions {
			continue
		}
		if strings.HasSuffix(trimmed, ":") {
			return false
		}
		if trimmed == permission {
			return true
		}
	}
	return false
}

func readCleanSourceIdentity(ctx context.Context, runner commandRunner, root string) (string, string, error) {
	status, err := runText(ctx, runner, nil, root, "git", "status", "--porcelain=v1", "--untracked-files=all")
	if err != nil {
		return "", "", errors.New("source state unavailable")
	}
	if status != "" {
		return "", "", errors.New("source state is not clean")
	}
	commit, err := runText(ctx, runner, nil, root, "git", "rev-parse", "HEAD")
	if err != nil || !hex40Pattern.MatchString(commit) {
		return "", "", errors.New("commit identity rejected")
	}
	tree, err := runText(ctx, runner, nil, root, "git", "rev-parse", "HEAD^{tree}")
	if err != nil || !hex40Pattern.MatchString(tree) {
		return "", "", errors.New("tree identity rejected")
	}
	return commit, tree, nil
}

func runFunctional(ctx context.Context, runner commandRunner, value config, qualified qualifiedRun, root, serial, remotePackage string, probeURL, probeDigest []byte, ipv6Authorized bool, tracker *resourceTracker) (outcome functionalOutcome, resultErr error) {
	campaignStarted := time.Now()
	campaignPolicy := qualified.campaign
	outcome = functionalOutcome{
		campaign: rawCampaign{Mode: value.mode, Impairments: []string{}},
	}
	profileID, err := issueAndActivateProfile(ctx, runner, value, root, serial)
	if err != nil {
		return outcome, err
	}
	defer func() {
		joinFieldCleanup(&resultErr, removeRemoteProfile(context.Background(), runner, value, root, profileID))
	}()
	if err := verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized); err != nil {
		return outcome, err
	}
	if err := observeRemoteMetrics(ctx, runner, value, root, tracker); err != nil {
		return outcome, err
	}
	if err := remoteService(ctx, runner, value, root, "sudo -n systemctl stop unbound.service"); err != nil {
		return outcome, err
	}
	if err := assertRemoteDNSDegraded(ctx, runner, value, root); err != nil {
		_ = remoteService(ctx, runner, value, root, "sudo -n systemctl start unbound.service")
		return outcome, err
	}
	if err := runFieldAction(ctx, runner, value, root, serial, "dns-probe", map[string]string{
		"phase17DnsFamily": "4", "phase17ExpectDnsAvailable": "false",
	}, "DNS_IPV4_FAIL_CLOSED"); err != nil {
		_ = remoteService(ctx, runner, value, root, "sudo -n systemctl start unbound.service")
		return outcome, err
	}
	if err := remoteService(ctx, runner, value, root, "sudo -n systemctl start unbound.service"); err != nil {
		return outcome, err
	}
	if err := exerciseRemoteRecovery(ctx, runner, value, root, profileID, remotePackage); err != nil {
		return outcome, err
	}
	if value.mode == "Stress" {
		stressReconnects, err := runOwnedVPSStressCampaign(
			ctx, runner, value, campaignPolicy, root, serial, &profileID, probeURL, probeDigest, ipv6Authorized, tracker,
		)
		if err != nil {
			return outcome, err
		}
		outcome.reconnects += stressReconnects
		outcome.campaign.RestartReconnectCycles = campaignPolicy.RestartReconnectCycles
		outcome.campaign.ProfileRotationCycles = campaignPolicy.ProfileRotationCycles
		outcome.campaign.Impairments = append([]string{}, campaignPolicy.Impairments...)
	}
	if campaignPolicy.MinimumDurationMS > 0 {
		soakResult, err := runOwnedVPSSoakCampaign(ctx, runner, value, campaignPolicy, realCampaignClock{}, root, serial, probeURL, probeDigest, ipv6Authorized, tracker)
		if err != nil {
			return outcome, err
		}
		outcome.reconnects += soakResult.reconnects
		outcome.campaign.SoakDurationMS = soakResult.durationMS
		outcome.campaign.SoakCycles = soakResult.cycles
	}
	if err := observeRemoteMetrics(ctx, runner, value, root, tracker); err != nil {
		return outcome, err
	}
	boundary, err := runBoundaryMonitor(ctx, runner, value, qualified, root, serial, probeURL, ipv6Authorized)
	outcome.boundary = boundary
	if err != nil {
		return outcome, err
	}
	if err := revokeRemoteProfile(ctx, runner, value, root, profileID); err != nil {
		return outcome, err
	}
	profileID = ""
	scanners, err := assertQualifiedAndroidPrivacy(ctx, runner, value, qualified, root, serial, campaignStarted, probeURL)
	outcome.scanners = scanners
	if err != nil {
		return outcome, err
	}
	return outcome, nil
}

func issueAndActivateProfile(ctx context.Context, runner commandRunner, value config, root, serial string) (string, error) {
	if err := runFieldAction(ctx, runner, value, root, serial, "export-recipient", nil, "RECIPIENT_READY"); err != nil {
		return "", err
	}
	request, err := readAppPrivate(ctx, runner, value, root, serial, recipientFile, 512)
	if err != nil {
		return "", errors.New("recipient export failed")
	}
	defer clear(request)
	profileID, artifact, err := issueProfile(ctx, runner, value, root, request)
	if err != nil {
		return "", err
	}
	defer clear(artifact)
	if err := writeAppPrivate(ctx, runner, value, root, serial, profileFile, artifact); err != nil {
		_ = removeRemoteProfile(context.Background(), runner, value, root, profileID)
		return "", err
	}
	if err := runFieldAction(ctx, runner, value, root, serial, "import-profile", nil, "PROFILE_ACTIVE"); err != nil {
		_ = removeRemoteProfile(context.Background(), runner, value, root, profileID)
		return "", err
	}
	return profileID, nil
}

func verifyFieldTraffic(ctx context.Context, runner commandRunner, value config, root, serial string, probeURL, probeDigest []byte, ipv6Authorized bool) error {
	if err := runFieldAction(ctx, runner, value, root, serial, "traffic", map[string]string{
		"phase17ProbeUrl":               string(probeURL),
		"phase17ExpectedResponseSha256": string(probeDigest),
		"phase17VerifyIPv6":             strconv.FormatBool(ipv6Authorized),
	}, "TRAFFIC_VERIFIED"); err != nil {
		return err
	}
	return nil
}

func prepareIPv6Capability(ctx context.Context, runner commandRunner, value config, root string) (bool, error) {
	if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
		return false, err
	}
	authorized, err := authorizeIPv6Capability(ctx, runner, value, root)
	if err != nil || !authorized {
		return authorized, err
	}
	if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
		return false, err
	}
	return true, nil
}

func prepareRemoteCampaignAuthority(ctx context.Context, runner commandRunner, value config, root string) error {
	raw, err := ssh(ctx, runner, value, root, 2*time.Minute, "sudo -n sh -c "+shellQuote(remoteCampaignAuthorityScript()))
	if err != nil || strings.TrimSpace(string(raw)) != "ISSUER_ROLLOVER_PASS" {
		return errors.New("campaign authority rollover failed")
	}
	if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
		return errors.New("campaign authority health failed")
	}
	return nil
}

func remoteCampaignAuthorityScript() string {
	return fmt.Sprintf(`set -eu
pass=%q
recovery=%q
[ -f "$pass" ] && [ ! -L "$pass" ] && [ -f "$recovery" ] && [ ! -L "$recovery" ]
tmp=$(mktemp -d /var/tmp/phase17-authority.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chown kurd-node:kurd-node "$tmp"
install -o kurd-node -g kurd-node -m 0600 "$recovery" "$tmp/recovery"
set +e
runuser -u kurd-node -- /usr/local/bin/kurdctl keys rotate issuer --data-dir %q --recovery-file "$tmp/recovery" --confirm issuer --control-socket %q <"$pass" >/dev/null 2>"$tmp/rotate.err"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  printf ISSUER_ROLLOVER_PASS
  exit 0
fi
if [ "$status" -ne 7 ] || ! grep -Fqx 'kurdctl: state committed; runtime notification pending; run kurdctl node reload' "$tmp/rotate.err"; then
  exit "$status"
fi
attempt=0
while [ "$attempt" -lt 3 ]; do
  if runuser -u kurd-node -- /usr/local/bin/kurdctl node reload --data-dir %q --control-socket %q >/dev/null 2>&1; then
    printf ISSUER_ROLLOVER_PASS
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done
systemctl restart kurd-node.socket kurd-node.service >/dev/null
systemctl is-active --quiet kurd-node.socket
systemctl is-active --quiet kurd-node.service
runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir %q >/dev/null
printf ISSUER_ROLLOVER_PASS
`, remotePassFile, remoteRecovery, remoteDataDir, remoteControl, remoteDataDir, remoteControl, remoteDataDir)
}

func dnsProbeFamilies(ipv6Authorized bool) []string {
	if ipv6Authorized {
		return []string{"4", "6"}
	}
	return []string{"4"}
}

func authorizeIPv6Capability(ctx context.Context, runner commandRunner, value config, root string) (bool, error) {
	raw, err := sshScript(ctx, runner, value, root, 45*time.Second, remoteIPv6CapabilityScript(value.ipv6ProbeAddress))
	if err != nil {
		return false, errors.New("IPv6 capability preflight failed")
	}
	switch strings.TrimSpace(string(raw)) {
	case "IPV6_AUTHORIZED":
		return true, nil
	case "IPV6_UNAVAILABLE":
		return false, nil
	default:
		return false, errors.New("IPv6 capability result rejected")
	}
}

func remoteIPv6CapabilityScript(probeAddress string) string {
	encodedProbe := base64.RawStdEncoding.EncodeToString([]byte(probeAddress))
	return fmt.Sprintf(`set -eu
probe=$(printf '%%s' %q | base64 -d)
global=false; ip -o -6 addr show scope global | grep -qv ' tentative' && global=true
default=false; ip -o -6 route show default | grep -q . && default=true
forward=false; [ "$(sysctl -n net.ipv6.conf.all.forwarding 2>/dev/null || true)" = 1 ] && forward=true
nft6=false
rules=$(nft list table inet kurd_node 2>/dev/null || true)
printf '%%s' "$rules" | grep -F 'ip6 saddr fd4b:7572:6400::/64' >/dev/null && printf '%%s' "$rules" | grep -F 'masquerade' >/dev/null && nft6=true
external=false
if command -v ping >/dev/null 2>&1 && ping -6 -n -c 1 -W 5 "$probe" >/dev/null 2>&1; then external=true; fi
if [ "$global:$default:$forward:$nft6:$external" != true:true:true:true:true ]; then printf IPV6_UNAVAILABLE; exit 0; fi
pass=%q
recovery=%q
[ -f "$pass" ] && [ ! -L "$pass" ] && [ -f "$recovery" ] && [ ! -L "$recovery" ]
tmp=$(mktemp -d /var/tmp/phase17-ipv6.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chown kurd-node:kurd-node "$tmp"
install -o kurd-node -g kurd-node -m 0600 "$recovery" "$tmp/recovery"
runuser -u kurd-node -- /usr/local/bin/kurdctl network ipv6 enable --data-dir %q --recovery-file "$tmp/recovery" --confirm enable-ipv6 <"$pass" >/dev/null
printf IPV6_AUTHORIZED
`, encodedProbe, remotePassFile, remoteRecovery, remoteDataDir)
}

func selectDevice(ctx context.Context, runner commandRunner, value config, androidClass string) (string, int, string, error) {
	raw, err := runBytes(ctx, runner, nil, "", 30*time.Second, value.adbPath, "devices")
	if err != nil {
		return "", 0, "", fmt.Errorf("%w: ADB device discovery failed", errAndroidEnvironmentUnavailable)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "device" {
			continue
		}
		serial := fields[0]
		switch androidClass {
		case "EMULATOR":
			if value.deviceSerial != "" || value.avdName == "" {
				return "", 0, "", errors.New("Android emulator selector rejected")
			}
			name, nameErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "emu", "avd", "name")
			if nameErr != nil || strings.TrimSpace(strings.Split(name, "\n")[0]) != value.avdName {
				continue
			}
		case "PHYSICAL":
			if value.avdName != "" || serial != value.deviceSerial {
				continue
			}
			qemu, qemuErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "shell", "getprop", "ro.kernel.qemu")
			if qemuErr != nil {
				return "", 0, "", fmt.Errorf("%w: Android class query failed", errAndroidEnvironmentUnavailable)
			}
			if qemu != "" && qemu != "0" {
				return "", 0, "", errors.New("Android physical-device class rejected")
			}
		default:
			return "", 0, "", errors.New("Android device class rejected")
		}
		apiRaw, apiErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "shell", "getprop", "ro.build.version.sdk")
		abi, abiErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "shell", "getprop", "ro.product.cpu.abi")
		api, parseErr := strconv.Atoi(strings.TrimSpace(apiRaw))
		if apiErr != nil || abiErr != nil {
			return "", 0, "", fmt.Errorf("%w: Android identity query failed", errAndroidEnvironmentUnavailable)
		}
		if parseErr != nil || api != 26 && api != 34 && api != 36 {
			return "", 0, "", errors.New("Android identity rejected")
		}
		abi = strings.TrimSpace(abi)
		if abi != "x86_64" && abi != "arm64-v8a" {
			return "", 0, "", errors.New("Android ABI rejected")
		}
		return serial, api, abi, nil
	}
	return "", 0, "", fmt.Errorf("%w: requested Android device is not active", errAndroidEnvironmentUnavailable)
}

func runFieldAction(ctx context.Context, runner commandRunner, value config, root, serial, action string, extras map[string]string, expected string) error {
	for launchAttempt := 0; launchAttempt < fieldActionLaunchAttempts; launchAttempt++ {
		attemptID, err := newFieldAttemptID()
		if err != nil {
			return fmt.Errorf("Android field action %s attempt identity unavailable", action)
		}
		resetCtx, cancelReset := context.WithTimeout(ctx, fieldEvidenceResetTimeout)
		err = retryFieldEvidenceReset(resetCtx, fieldEvidenceResetAttempts, fieldEvidenceResetDelay, func(attemptCtx context.Context) error {
			raw, resetErr := runBytes(attemptCtx, runner, nil, root, fieldEvidenceAttemptTimeout, value.adbPath,
				"-s", serial, "shell", "run-as", appPackage, "rm", "-f", fieldResultFile, fieldAttemptFile)
			clear(raw)
			return resetErr
		})
		cancelReset()
		if err != nil {
			return fmt.Errorf("Android field action %s evidence reset failed", action)
		}
		if err := writePendingFieldAttempt(ctx, runner, value, root, serial, attemptID); err != nil {
			return fmt.Errorf("Android field action %s attempt correlation failed", action)
		}
		arguments := []string{"-s", serial, "shell", "am", "instrument", "-w", "-r", "-e", "phase17FieldAction", action}
		for key, item := range extras {
			arguments = append(arguments, "-e", key, item)
		}
		arguments = append(arguments, "-e", "phase17AttemptId", attemptID, "-e", "class", fieldTest, testRunner)
		instrumentation, instrumentationErr := runBytes(ctx, runner, nil, root, 3*time.Minute, value.adbPath, arguments...)
		category := instrumentationFailureCategory(instrumentation)
		clear(instrumentation)
		if category != "" {
			return &fieldActionFailure{action: action, category: category}
		}
		if instrumentationErr != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			state, stateErr := runText(ctx, runner, nil, root, value.adbPath,
				"-s", serial, "shell", "run-as", appPackage, "cat", fieldAttemptFile)
			if stateErr != nil || !safeCategory([]byte(state)) {
				return &fieldActionFailure{action: action, category: "INSTRUMENTATION_ATTEMPT_STATE_UNAVAILABLE"}
			}
			switch strings.TrimSpace(state) {
			case "STARTED:" + attemptID:
				return &fieldActionFailure{action: action, category: "INSTRUMENTATION_STARTED_WITHOUT_TERMINAL_RESULT"}
			case "PENDING:" + attemptID:
				if launchAttempt+1 == fieldActionLaunchAttempts {
					return &fieldActionFailure{action: action, category: "INSTRUMENTATION_LAUNCH_FAILED"}
				}
				if err := synchronizeFieldInstrumentationRunner(ctx, runner, value, root, serial); err != nil {
					return &fieldActionFailure{action: action, category: "INSTRUMENTATION_RECOVERY_FAILED"}
				}
				continue
			default:
				return &fieldActionFailure{action: action, category: "INSTRUMENTATION_ATTEMPT_STATE_REJECTED"}
			}
		}
		result, err := runText(ctx, runner, nil, root, value.adbPath, "-s", serial, "shell", "run-as", appPackage, "cat", fieldResultFile)
		if err != nil || strings.TrimSpace(result) != expected || !safeCategory([]byte(result)) {
			return fmt.Errorf("%w: Android field action %s returned invalid evidence", errFieldEvidenceInvalid, action)
		}
		return nil
	}
	return &fieldActionFailure{action: action, category: "INSTRUMENTATION_LAUNCH_FAILED"}
}

func newFieldAttemptID() (string, error) {
	raw := make([]byte, 16)
	if _, err := rand.Read(raw); err != nil {
		clear(raw)
		return "", err
	}
	encoded := hex.EncodeToString(raw)
	clear(raw)
	return encoded, nil
}

func writePendingFieldAttempt(ctx context.Context, runner commandRunner, value config, root, serial, attemptID string) error {
	if !fieldAttemptIDPattern.MatchString(attemptID) {
		return errors.New("field attempt identity rejected")
	}
	script := fmt.Sprintf("umask 077; mkdir -p %s; printf 'PENDING:%s\\n' > %s", fieldDirectory, attemptID, fieldAttemptFile)
	raw, err := runBytes(ctx, runner, nil, root, fieldEvidenceAttemptTimeout, value.adbPath,
		"-s", serial, "shell", "run-as", appPackage, "sh", "-c", shellQuote(script))
	clear(raw)
	return err
}

func synchronizeFieldInstrumentationRunner(ctx context.Context, runner commandRunner, value config, root, serial string) error {
	for _, arguments := range [][]string{
		{"-s", serial, "wait-for-device"},
		{"-s", serial, "shell", "am", "force-stop", appPackage},
		{"-s", serial, "shell", "am", "force-stop", testPackage},
	} {
		raw, err := runBytes(ctx, runner, nil, root, fieldEvidenceAttemptTimeout, value.adbPath, arguments...)
		clear(raw)
		if err != nil {
			return err
		}
	}
	return nil
}

func retryFieldEvidenceReset(ctx context.Context, attempts int, delay time.Duration, reset func(context.Context) error) error {
	if attempts < 1 || delay < 0 || reset == nil {
		return errors.New("field evidence reset policy rejected")
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := reset(ctx); err == nil {
			return nil
		} else {
			last = err
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		if attempt+1 == attempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

func verifyImpairedFieldTraffic(ctx context.Context, verify func(context.Context) error) error {
	for attempt := 0; attempt < impairmentVerificationTries; attempt++ {
		err := verify(ctx)
		if err == nil {
			return nil
		}
		var failure *fieldActionFailure
		if !errors.As(err, &failure) ||
			failure.action != "traffic" ||
			(failure.category != "DATA_PLANE_PROBE_FAILED" &&
				failure.category != "DATA_PLANE_TIMEOUT" &&
				failure.category != "DNS_UNAVAILABLE") ||
			attempt+1 == impairmentVerificationTries {
			return err
		}
		timer := time.NewTimer(impairmentRetryDelay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
	return errors.New("impaired traffic verification exhausted")
}

func instrumentationFailureCategory(raw []byte) string {
	allowed := map[string]bool{
		"ACTIVE_PROFILE_UNAVAILABLE": true, "DATA_PLANE_PROBE_FAILED": true, "DATA_PLANE_TIMEOUT": true,
		"DNS_FAMILY_REJECTED": true, "DNS_EXPECTATION_REJECTED": true, "DNS_UNAVAILABLE": true,
		"LIVE_CONNECT_FAILED": true, "LIVE_CONNECT_TIMEOUT": true, "LIVE_RUNTIME_UNSTABLE": true,
		"LIVE_SESSION_EVIDENCE_MISSING": true, "LIVE_STOP_TIMEOUT": true,
		"PROFILE_ADMISSION_FAILED": true, "PROFILE_PREVIEW_FAILED": true,
		"RECIPIENT_CREATE_FAILED": true, "RECIPIENT_REQUEST_UNAVAILABLE": true,
		"RUNTIME_AUTHORITY_FAILED": true, "RUNTIME_AUTHORITY_UNAVAILABLE": true,
		"SEALED_PROFILE_UNAVAILABLE": true, "VPN_CONSENT_REQUIRED": true,
		"VPN_NETWORK_NOT_READY": true, "VPN_NETWORK_TEARDOWN_TIMEOUT": true,
		"BOUNDARY_LEAK": true,
	}
	for _, match := range instrumentCategoryV1.FindAll(raw, -1) {
		value := string(match)
		head, _, _ := strings.Cut(value, ":")
		if allowed[head] && len(value) <= 256 && safeCategory(match) {
			return value
		}
	}
	lower := bytes.ToLower(raw)
	if bytes.Contains(raw, []byte("java.net.UnknownHostException")) {
		return "DATA_PLANE_DNS_RESOLUTION_FAILED"
	}
	if bytes.Contains(raw, []byte("java.net.SocketTimeoutException")) {
		switch {
		case bytes.Contains(lower, []byte("connect timed out")):
			return "DATA_PLANE_CONNECT_TIMEOUT"
		case bytes.Contains(lower, []byte("read timed out")):
			return "DATA_PLANE_READ_TIMEOUT"
		default:
			return "DATA_PLANE_TIMEOUT"
		}
	}
	if bytes.Contains(raw, []byte("javax.net.ssl.SSLHandshakeException")) {
		return "DATA_PLANE_TLS_HANDSHAKE_FAILED"
	}
	if bytes.Contains(raw, []byte("java.net.ConnectException")) {
		return "DATA_PLANE_CONNECT_FAILED"
	}
	if bytes.Contains(lower, []byte("shortmsg=process crashed")) {
		return "INSTRUMENTATION_PROCESS_CRASH"
	}
	if bytes.Contains(lower, []byte("failures!!!")) || bytes.Contains(lower, []byte("instrumentation_failed")) {
		return "INSTRUMENTATION_FAILED"
	}
	return ""
}

func readAppPrivate(ctx context.Context, runner commandRunner, value config, root, serial, path string, maximum int) ([]byte, error) {
	raw, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.adbPath, "-s", serial, "exec-out", "run-as", appPackage, "base64", path)
	if err != nil {
		return nil, err
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(raw)))
	clear(raw)
	if err != nil || len(decoded) == 0 || len(decoded) > maximum {
		clear(decoded)
		return nil, errors.New("app-private file rejected")
	}
	return decoded, nil
}

func writeAppPrivate(ctx context.Context, runner commandRunner, value config, root, serial, path string, data []byte) error {
	temporary, err := os.CreateTemp("", "phase17-field-*.bin")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil || temporary.Sync() != nil || temporary.Close() != nil {
		return errors.New("temporary field file write failed")
	}
	remote := "/data/local/tmp/phase17-field-" + strconv.FormatInt(time.Now().UnixNano(), 16)
	if _, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.adbPath, "-s", serial, "push", name, remote); err != nil {
		return errors.New("field file push failed")
	}
	defer func() {
		_, _ = runBytes(context.Background(), runner, nil, root, 10*time.Second, value.adbPath, "-s", serial, "shell", "rm", "-f", remote)
	}()
	if _, err := runBytes(ctx, runner, nil, root, 10*time.Second, value.adbPath, "-s", serial, "shell", "chmod", "0644", remote); err != nil {
		return errors.New("field file staging permissions failed")
	}
	_, err = runBytes(ctx, runner, nil, root, 30*time.Second, value.adbPath, "-s", serial, "shell", "run-as", appPackage, "cp", remote, path)
	return err
}

func issueProfile(ctx context.Context, runner commandRunner, value config, root string, request []byte) (string, []byte, error) {
	local, err := os.CreateTemp("", "phase17-recipient-*.bin")
	if err != nil {
		return "", nil, err
	}
	localName := local.Name()
	defer os.Remove(localName)
	if err := local.Chmod(0o600); err != nil {
		local.Close()
		return "", nil, err
	}
	if _, err := local.Write(request); err != nil || local.Sync() != nil || local.Close() != nil {
		return "", nil, errors.New("recipient request staging failed")
	}
	token := strconv.FormatInt(time.Now().UnixNano(), 16)
	profileName := "p17-" + token
	remoteRequest := "/tmp/phase17-recipient-" + token
	remoteOutput := remoteDataDir + "/.phase17-profile-" + token
	remoteResponse := remoteRequest + ".response"
	remoteError := remoteRequest + ".error"
	remoteArtifact := remoteRequest + ".profile"
	if _, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.scpPath, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", localName, value.sshAlias+":"+remoteRequest); err != nil {
		return "", nil, errors.New("recipient request transfer failed")
	}
	defer func() {
		_ = remoteService(context.Background(), runner, value, root, "sudo -n sh -c 'rm -rf "+remoteRequest+" "+remoteResponse+" "+remoteError+" "+remoteArtifact+" "+remoteOutput+"'")
	}()
	script := fmt.Sprintf(`set -eu
req=%q
out=%q
response=%q
error_output=%q
artifact=%q
umask 077
sudo -n chown kurd-node:kurd-node "$req" || { printf PROFILE_REQUEST_OWNER_FAILED; exit 2; }
sudo -n chmod 0600 "$req" || { printf PROFILE_REQUEST_MODE_FAILED; exit 2; }
status=0
sudo -n -u kurd-node /usr/local/bin/kurdctl profile create --data-dir %q --name %s --valid-for 24h --recipient-request "$req" --recipient-registry-dir %q --output-dir "$out" --control-socket %q >"$response" 2>"$error_output" || status=$?
if [ -s "$response" ] && sudo -n test -s "$out/profile.kurd-profile"; then
  sudo -n install -o "$(id -un)" -g "$(id -gn)" -m 0600 "$out/profile.kurd-profile" "$artifact" || { printf PROFILE_ARTIFACT_STAGE_FAILED; exit 6; }
  if [ "$status" -eq 7 ]; then
    sudo -n -u kurd-node /usr/local/bin/kurdctl node reload --data-dir %q --control-socket %q >/dev/null 2>>"$error_output" || { printf PROFILE_RUNTIME_RELOAD_FAILED; exit 7; }
  elif [ "$status" -ne 0 ]; then
    cat "$error_output"
    exit "$status"
  fi
  printf PHASE17_ISSUE_READY
  exit 0
fi
if [ "$status" -eq 7 ] && [ ! -s "$response" ]; then
  printf PROFILE_COMMITTED_RESPONSE_MISSING
  exit 7
fi
if [ "$status" -eq 7 ] && ! sudo -n test -s "$out/profile.kurd-profile"; then
  printf PROFILE_COMMITTED_ARTIFACT_MISSING
  exit 7
fi
cat "$error_output"
[ -s "$error_output" ] || printf PROFILE_COMMAND_FAILED_%%s "$status"
[ "$status" -ne 0 ] || status=6
exit "$status"
`, remoteRequest, remoteOutput, remoteResponse, remoteError, remoteArtifact, remoteDataDir, shellQuote(profileName), remoteRegistry, remoteControl, remoteDataDir, remoteControl)
	attemptIssuance := func() (bool, []byte, error) {
		raw, commandErr := ssh(ctx, runner, value, root, 2*time.Minute, script)
		ready := commandErr == nil && strings.TrimSpace(string(raw)) == "PHASE17_ISSUE_READY"
		failure := append([]byte(nil), raw...)
		clear(raw)
		for attempt := 0; !ready && attempt < 4; attempt++ {
			if attempt > 0 {
				timer := time.NewTimer(250 * time.Millisecond)
				select {
				case <-ctx.Done():
					timer.Stop()
					clear(failure)
					return false, nil, ctx.Err()
				case <-timer.C:
				}
			}
			check, checkErr := ssh(ctx, runner, value, root, 15*time.Second,
				fmt.Sprintf(`set -eu; test -s %q; test -s %q; printf PHASE17_ISSUE_READY`, remoteResponse, remoteArtifact))
			ready = checkErr == nil && strings.TrimSpace(string(check)) == "PHASE17_ISSUE_READY"
			clear(check)
		}
		return ready, failure, commandErr
	}
	ready, initialFailure, issuanceErr := attemptIssuance()
	if !ready {
		if len(initialFailure) == 0 {
			failure, _ := ssh(ctx, runner, value, root, 10*time.Second, fmt.Sprintf(`cat %q`, remoteError))
			initialFailure = failure
		}
		category := categorizeProfileIssuanceFailure(initialFailure, issuanceErr)
		clear(initialFailure)
		if !errors.Is(category, errProfileIssuanceTransport) {
			return "", nil, category
		}
		committed, reconcileErr := profileNameCommitted(ctx, runner, value, root, profileName)
		if reconcileErr != nil {
			return "", nil, errors.New("profile issuance reconciliation unavailable")
		}
		if committed {
			return "", nil, errors.New("profile issuance committed without recoverable artifact")
		}
		if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
			return "", nil, errors.New("profile issuance transport failed after node health check")
		}
		ready, initialFailure, issuanceErr = attemptIssuance()
		if !ready {
			if len(initialFailure) == 0 {
				failure, _ := ssh(ctx, runner, value, root, 10*time.Second, fmt.Sprintf(`cat %q`, remoteError))
				initialFailure = failure
			}
			category = categorizeProfileIssuanceFailure(initialFailure, issuanceErr)
			clear(initialFailure)
			return "", nil, category
		}
	}
	clear(initialFailure)
	responseBytes, err := ssh(ctx, runner, value, root, 10*time.Second, fmt.Sprintf(`cat %q`, remoteResponse))
	if err != nil {
		clear(responseBytes)
		return "", nil, errors.New("profile issuance response unavailable")
	}
	defer clear(responseBytes)
	var response struct {
		Schema    string `json:"schema"`
		ProfileID string `json:"profileId"`
	}
	if json.Unmarshal(responseBytes, &response) != nil || response.Schema != "kurdctl-profile-create-v2" || !selectorPattern.MatchString(response.ProfileID) {
		return "", nil, errors.New("profile issuance response rejected")
	}
	localArtifact, err := os.CreateTemp("", "phase17-profile-*.bin")
	if err != nil {
		return "", nil, err
	}
	artifactName := localArtifact.Name()
	localArtifact.Close()
	defer os.Remove(artifactName)
	if _, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.scpPath, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", value.sshAlias+":"+remoteArtifact, artifactName); err != nil {
		return "", nil, errors.New("sealed profile transfer failed")
	}
	artifact, err := os.ReadFile(artifactName)
	if err != nil || len(artifact) == 0 || len(artifact) > 1_500_000 {
		clear(artifact)
		return "", nil, errors.New("sealed profile artifact rejected")
	}
	return response.ProfileID, artifact, nil
}

func profileNameCommitted(ctx context.Context, runner commandRunner, value config, root, name string) (bool, error) {
	if !selectorPattern.MatchString(name) {
		return false, errors.New("profile reconciliation name rejected")
	}
	raw, err := ssh(ctx, runner, value, root, 30*time.Second,
		fmt.Sprintf(`sudo -n -u kurd-node /usr/local/bin/kurdctl profile list --data-dir %q`, remoteDataDir))
	if err != nil {
		clear(raw)
		return false, errors.New("profile reconciliation query failed")
	}
	defer clear(raw)
	var listing struct {
		Schema   string `json:"schema"`
		Profiles []struct {
			Name string `json:"Name"`
		} `json:"profiles"`
	}
	if json.Unmarshal(raw, &listing) != nil || listing.Schema != "kurdctl-profile-list-v1" || listing.Profiles == nil {
		return false, errors.New("profile reconciliation response rejected")
	}
	matches := 0
	for _, profile := range listing.Profiles {
		if profile.Name == name {
			matches++
		}
	}
	if matches > 1 {
		return false, errors.New("profile reconciliation response ambiguous")
	}
	return matches == 1, nil
}

func categorizeProfileIssuanceFailure(raw []byte, transportErr error) error {
	value := strings.ToLower(string(raw))
	for marker, category := range map[string]string{
		"recipient registry rejected":        "profile issuance rejected: recipient registry unavailable",
		"request rejected":                   "profile issuance rejected: recipient request unavailable",
		"recipient authority rejected":       "profile issuance rejected: recipient authority unavailable",
		"capacity exhausted":                 "profile issuance rejected: node capacity unavailable",
		"tls validity rejected":              "profile issuance rejected: relay TLS unavailable",
		"unsupported filesystem":             "profile issuance rejected: private output filesystem unavailable",
		"profile_runtime_reload_failed":      "profile issuance committed: relay runtime reload failed",
		"profile_committed_response_missing": "profile issuance committed: response evidence unavailable",
		"profile_committed_artifact_missing": "profile issuance committed: artifact evidence unavailable",
		"profile_request_owner_failed":       "profile issuance rejected: request ownership unavailable",
		"profile_request_mode_failed":        "profile issuance rejected: request protection unavailable",
		"profile_artifact_stage_failed":      "profile issuance committed: artifact staging unavailable",
		"profile_command_failed_":            "profile issuance failed: command produced no category",
	} {
		if strings.Contains(value, marker) {
			return errors.New(category)
		}
	}
	if errors.Is(transportErr, context.DeadlineExceeded) {
		return errors.New("profile issuance transport timed out")
	}
	if errors.Is(transportErr, context.Canceled) {
		return errors.New("profile issuance cancelled")
	}
	if transportErr != nil {
		return errProfileIssuanceTransport
	}
	return errors.New("profile issuance failed")
}

const (
	remoteHealthAttempts          = 10
	remoteDeploymentStateAttempts = 5
)

func assertRemoteHealth(ctx context.Context, runner commandRunner, value config, root string) error {
	script := fmt.Sprintf(`set -eu
sudo -n systemctl start kurd-node-network.service kurd-node.socket >/dev/null 2>&1 || { printf NETWORK_START_FAILED; exit 8; }
sudo -n systemctl start kurd-node.service >/dev/null 2>&1 || { printf RELAY_START_FAILED; exit 8; }
systemctl is-active --quiet kurd-node.socket || { printf SOCKET_INACTIVE; exit 8; }
systemctl is-active --quiet kurd-node.service || { printf RELAY_INACTIVE; exit 8; }
systemctl is-active --quiet unbound.service || { printf DNS_INACTIVE; exit 8; }
test -e /sys/class/net/kurd0/tun_flags || { printf TUN_UNAVAILABLE; exit 8; }
ss -H -ltn 'sport = :%d' | grep -q . || { printf LISTENER_UNAVAILABLE; exit 8; }
sudo -n -u kurd-node /usr/local/bin/kurdctl doctor --data-dir %s >/dev/null 2>&1 || { printf DOCTOR_FAILED; exit 8; }
printf SERVICE_HEALTH_PASS
`, value.relayPort, remoteDataDir)
	return retryRemoteHealth(ctx, remoteHealthAttempts, 2*time.Second, func() error {
		raw, err := ssh(ctx, runner, value, root, 30*time.Second, script)
		if err != nil || strings.TrimSpace(string(raw)) != "SERVICE_HEALTH_PASS" {
			return remoteHealthError(raw)
		}
		return nil
	})
}

func remoteHealthError(raw []byte) error {
	category := strings.TrimSpace(string(raw))
	switch category {
	case "NETWORK_START_FAILED", "RELAY_START_FAILED", "SOCKET_INACTIVE", "RELAY_INACTIVE", "DNS_INACTIVE", "TUN_UNAVAILABLE", "LISTENER_UNAVAILABLE", "DOCTOR_FAILED":
		return fmt.Errorf("remote service health failed: %s", category)
	default:
		return errors.New("remote service health failed")
	}
}

func retryRemoteHealth(ctx context.Context, attempts int, delay time.Duration, check func() error) error {
	if attempts < 1 || check == nil {
		return errors.New("remote service health retry rejected")
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := check(); err == nil {
			return nil
		} else {
			last = err
		}
		if attempt+1 == attempts {
			break
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return errors.New("remote service health cancelled")
		case <-timer.C:
		}
	}
	return last
}

func assertRemoteDNSDegraded(ctx context.Context, runner commandRunner, value config, root string) error {
	raw, err := ssh(ctx, runner, value, root, 30*time.Second, remoteDNSDegradedScript(value.relayPort))
	if err != nil || strings.TrimSpace(string(raw)) != "DNS_DEGRADED_PASS" {
		return errors.New("remote DNS degraded state rejected")
	}
	return nil
}

func remoteDNSDegradedScript(relayPort int) string {
	return fmt.Sprintf(`set -eu
systemctl is-active --quiet kurd-node.service
systemctl is-active --quiet kurd-node.socket
systemctl is-active --quiet kurd-node-network.service
! systemctl is-active --quiet unbound.service
ss -H -ltn 'sport = :%d' | grep -q .
printf DNS_DEGRADED_PASS
`, relayPort)
}

func exerciseRemoteRecovery(ctx context.Context, runner commandRunner, value config, root, profileID, remotePackage string) error {
	if err := remoteService(ctx, runner, value, root, "sudo -n systemctl restart kurd-node.service; sudo -n systemctl is-active --quiet kurd-node.service"); err != nil {
		return errors.New("service restart failed")
	}
	if err := remoteService(ctx, runner, value, root, "sudo -n -u kurd-node /usr/local/bin/kurdctl node drain --data-dir "+remoteDataDir+" >/dev/null; sudo -n -u kurd-node /usr/local/bin/kurdctl node resume --data-dir "+remoteDataDir+" >/dev/null"); err != nil {
		return errors.New("drain and resume failed")
	}
	raw, err := ssh(ctx, runner, value, root, 2*time.Minute, "sudo -n sh -c "+shellQuote(remoteRecoveryScript()))
	if err != nil || strings.TrimSpace(string(raw)) != "RECOVERY_BACKUP_PASS" {
		return errors.New("backup or restore recovery failed")
	}
	if err := withRemoteDeploymentDisabled(ctx, runner, value, root, func() error {
		return remoteService(ctx, runner, value, root, "sudo -n systemctl start kurd-node.socket kurd-node.service >/dev/null; sudo -n systemctl is-active --quiet kurd-node.socket; sudo -n systemctl is-active --quiet kurd-node.service")
	}); err != nil {
		return errors.New("emergency disable recovery failed")
	}
	if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
		return err
	}
	rollback := remoteRollbackRestoreScript(remotePackage, value.relayPort)
	raw, err = ssh(ctx, runner, value, root, 3*time.Minute, rollback)
	if err != nil || strings.TrimSpace(string(raw)) != "ROLLBACK_RESTORE_PASS" {
		category := strings.TrimSpace(string(raw))
		if category != "" && len(category) <= 128 && safeCategory([]byte(category)) {
			return fmt.Errorf("upgrade and rollback recovery failed: %s", category)
		}
		return errors.New("upgrade and rollback recovery failed")
	}
	if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
		return err
	}
	_ = profileID
	return nil
}

func remoteRollbackRestoreScript(remotePackage string, relayPort int) string {
	return fmt.Sprintf(`set -eu
sudo -n test -x /var/lib/kurd-node/install/previous/bin/kurd-node || { printf PREVIOUS_PACKAGE_MISSING; exit 8; }
sudo -n /usr/local/lib/kurd-node/rollback.sh --apply --confirm rollback >/dev/null 2>&1 || { printf ROLLBACK_APPLY_FAILED; exit 8; }
sudo -n systemctl stop kurd-node.socket kurd-node.service kurd-node-network.service >/dev/null 2>&1 || { printf RESTORED_LISTENER_STOP_FAILED; exit 8; }
sudo -n sh -c 'cd "$1" && ./install.sh --upgrade --port "$2"' sh %q %d >/dev/null 2>&1 || { printf PACKAGE_REINSTALL_FAILED; exit 8; }
sudo -n systemctl daemon-reload >/dev/null 2>&1 || { printf DAEMON_RELOAD_FAILED; exit 8; }
sudo -n networkctl reload >/dev/null 2>&1 || { printf NETWORK_RELOAD_FAILED; exit 8; }
sudo -n systemctl enable --now kurd-node-network.service kurd-node.socket >/dev/null 2>&1 || { printf NETWORK_OR_SOCKET_START_FAILED; exit 8; }
sudo -n systemctl start kurd-node.service >/dev/null 2>&1 || { printf RELAY_START_FAILED; exit 8; }
sudo -n systemctl is-active --quiet kurd-node.service || { printf RELAY_INACTIVE; exit 8; }
sudo -n -u kurd-node /usr/local/bin/kurdctl doctor --data-dir %q >/dev/null 2>&1 || { printf DOCTOR_FAILED; exit 8; }
printf ROLLBACK_RESTORE_PASS
`, remotePackage, relayPort, remoteDataDir)
}

func remoteRecoveryScript() string {
	return `set -eu
pass=/root/.kurd-node-field/current-passphrase
recovery=/root/.kurd-node-field/current.kurd-recovery
[ -f "$pass" ] && [ ! -L "$pass" ] && [ -f "$recovery" ] && [ ! -L "$recovery" ]
tmp=$(mktemp -d /var/tmp/phase17-recovery.XXXXXX)
chown kurd-node:kurd-node "$tmp"
work="$tmp/work"
backup="$work/state.kurd-backup"
restored="$work/restored"
cleanup() {
  rm -rf "$tmp"
}
trap cleanup EXIT HUP INT TERM
install -d -o kurd-node -g kurd-node -m 0700 "$work"
install -o kurd-node -g kurd-node -m 0600 "$recovery" "$work/recovery"
runuser -u kurd-node -- /usr/local/bin/kurdctl backup create --data-dir /var/lib/kurd-node --recipient-registry-dir /var/lib/kurd-node/recipient-registry --file "$backup" <"$pass" >/dev/null
runuser -u kurd-node -- /usr/local/bin/kurdctl backup verify --file "$backup" <"$pass" >/dev/null
[ ! -e "$restored" ]
preview=$(runuser -u kurd-node -- /usr/local/bin/kurdctl restore preview --file "$backup" --data-dir "$restored" <"$pass")
digest=$(printf '%s\n' "$preview" | sed -n 's/.*"Digest":"\([0-9a-f]\{64\}\)".*/\1/p')
[ "${#digest}" -eq 64 ]
runuser -u kurd-node -- /usr/local/bin/kurdctl restore apply --file "$backup" --data-dir "$restored" --recipient-registry-dir "$restored/recipient-registry" --expected-digest "$digest" <"$pass" >/dev/null
runuser -u kurd-node -- /usr/local/bin/kurdctl recovery confirm --data-dir "$restored" --recovery-file "$work/recovery" <"$pass" >/dev/null
runuser -u kurd-node -- /usr/local/bin/kurdctl doctor --data-dir "$restored" >/dev/null
printf RECOVERY_BACKUP_PASS
`
}

func setRemoteDeployment(ctx context.Context, runner commandRunner, value config, root string, disabled bool) error {
	raw, err := ssh(ctx, runner, value, root, 30*time.Second, "sudo -n sh -c "+shellQuote(remoteDeploymentMutationScript(disabled)))
	category := strings.TrimSpace(string(raw))
	if err != nil {
		if category != "DEPLOYMENT_COMMITTED_PENDING" {
			return errors.New("deployment mutation failed")
		}
		raw, err = ssh(ctx, runner, value, root, 30*time.Second, "sudo -n sh -c "+shellQuote(remoteDeploymentReconcileScript(disabled)))
		if err != nil || strings.TrimSpace(string(raw)) != "DEPLOYMENT_RECONCILE_PASS" {
			return errors.New("deployment runtime reconciliation failed")
		}
	} else if category != "DEPLOYMENT_MUTATION_PASS" {
		return errors.New("deployment mutation response rejected")
	}
	if err := waitRemoteDeploymentState(ctx, runner, value, root, disabled); err != nil {
		return errors.New("deployment durable state mismatch")
	}
	return nil
}

func waitRemoteDeploymentState(ctx context.Context, runner commandRunner, value config, root string, disabled bool) error {
	var last error
	for attempt := 0; attempt < remoteDeploymentStateAttempts; attempt++ {
		observed, err := remoteDeploymentDisabled(ctx, runner, value, root)
		if err == nil && observed == disabled {
			return nil
		}
		last = err
		if last == nil {
			last = errors.New("deployment state has not converged")
		}
		if attempt+1 == remoteDeploymentStateAttempts {
			break
		}
		timer := time.NewTimer(time.Second)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return errors.New("deployment state convergence cancelled")
		case <-timer.C:
		}
	}
	return last
}

func withRemoteDeploymentDisabled(ctx context.Context, runner commandRunner, value config, root string, during func() error) (resultErr error) {
	if during == nil {
		return errors.New("deployment disabled-state check unavailable")
	}
	cleanupArmed := true
	defer func() {
		if !cleanupArmed {
			return
		}
		if err := restoreRemoteDeploymentEnabled(context.Background(), runner, value, root); err != nil {
			cleanupErr := errors.New("deployment fail-safe enable failed")
			if resultErr == nil {
				resultErr = cleanupErr
			} else {
				resultErr = errors.Join(resultErr, cleanupErr)
			}
		}
	}()
	if err := setRemoteDeployment(ctx, runner, value, root, true); err != nil {
		return err
	}
	if err := during(); err != nil {
		return err
	}
	if err := setRemoteDeployment(ctx, runner, value, root, false); err != nil {
		return err
	}
	cleanupArmed = false
	return nil
}

func restoreRemoteDeploymentEnabled(ctx context.Context, runner commandRunner, value config, root string) error {
	disabled, err := remoteDeploymentDisabled(ctx, runner, value, root)
	if err == nil && !disabled {
		return nil
	}
	return setRemoteDeployment(ctx, runner, value, root, false)
}

func remoteDeploymentDisabled(ctx context.Context, runner commandRunner, value config, root string) (bool, error) {
	raw, err := ssh(ctx, runner, value, root, 30*time.Second, "sudo -n sh -c "+shellQuote(remoteDeploymentStateScript()))
	if err != nil {
		return false, errors.New("deployment state unavailable")
	}
	switch strings.TrimSpace(string(raw)) {
	case "DEPLOYMENT_DISABLED":
		return true, nil
	case "DEPLOYMENT_ENABLED":
		return false, nil
	default:
		return false, errors.New("deployment state response rejected")
	}
}

func remoteDeploymentMutationScript(disabled bool) string {
	action := "enable"
	if disabled {
		action = "disable"
	}
	return fmt.Sprintf(`set -eu
pass=%q
recovery=%q
tmp=$(mktemp -d /var/tmp/phase17-deployment.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chown kurd-node:kurd-node "$tmp"
install -o kurd-node -g kurd-node -m 0600 "$recovery" "$tmp/recovery"
set +e
runuser -u kurd-node -- /usr/local/bin/kurdctl deployment %s --data-dir %q --recovery-file "$tmp/recovery" --confirm %s --control-socket %q <"$pass" >/dev/null 2>"$tmp/mutation.err"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  printf DEPLOYMENT_MUTATION_PASS
  exit 0
fi
if [ "$status" -eq 7 ] && grep -Fqx 'kurdctl: state committed; runtime notification pending; run kurdctl node reload' "$tmp/mutation.err"; then
  printf DEPLOYMENT_COMMITTED_PENDING
  exit 7
fi
exit "$status"
`, remotePassFile, remoteRecovery, action, remoteDataDir, action, remoteControl)
}

func remoteDeploymentStateScript() string {
	return fmt.Sprintf(`set -eu
summary=$(runuser -u kurd-node -- /usr/local/bin/kurdctl deployment status --data-dir %q)
if printf '%%s\n' "$summary" | grep -Fq '"disabled":true'; then
  printf DEPLOYMENT_DISABLED
elif printf '%%s\n' "$summary" | grep -Fq '"disabled":false'; then
  printf DEPLOYMENT_ENABLED
else
  exit 8
fi
`, remoteDataDir)
}

func remoteDeploymentReconcileScript(disabled bool) string {
	expected := "false"
	if disabled {
		expected = "true"
	}
	return fmt.Sprintf(`set -eu
summary=$(runuser -u kurd-node -- /usr/local/bin/kurdctl deployment status --data-dir %q)
printf '%%s\n' "$summary" | grep -Fq '"disabled":%s'
attempt=0
while [ "$attempt" -lt 3 ]; do
  if runuser -u kurd-node -- /usr/local/bin/kurdctl node reload --control-socket %q >/dev/null 2>&1; then
    printf DEPLOYMENT_RECONCILE_PASS
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done
systemctl restart kurd-node.socket kurd-node.service >/dev/null
systemctl is-active --quiet kurd-node.socket
systemctl is-active --quiet kurd-node.service
summary=$(runuser -u kurd-node -- /usr/local/bin/kurdctl deployment status --data-dir %q)
printf '%%s\n' "$summary" | grep -Fq '"disabled":%s'
printf DEPLOYMENT_RECONCILE_PASS
`, remoteDataDir, expected, remoteControl, remoteDataDir, expected)
}

func revokeRemoteProfile(ctx context.Context, runner commandRunner, value config, root, profileID string) error {
	return revokeRemoteProfileWithDelay(ctx, runner, value, root, profileID, time.Second)
}

func revokeRemoteProfileWithDelay(
	ctx context.Context,
	runner commandRunner,
	value config,
	root, profileID string,
	delay time.Duration,
) error {
	return retryFieldCleanup(ctx, 3, delay, func(attemptContext context.Context) error {
		raw, err := ssh(attemptContext, runner, value, root, 45*time.Second, "sudo -n sh -c "+shellQuote(remoteRevocationScript(profileID)))
		category := strings.TrimSpace(string(raw))
		if err == nil && category == "REVOKE_PASS" {
			return nil
		}

		// A failed mutation can still have committed before runtime notification,
		// even when transport loss prevents the exact pending marker reaching us.
		// Reconcile authoritative state before deciding whether a retry is safe.
		raw, reconcileErr := ssh(attemptContext, runner, value, root, 30*time.Second, "sudo -n sh -c "+shellQuote(remoteRevocationReconcileScript(profileID)))
		if reconcileErr == nil && strings.TrimSpace(string(raw)) == "REVOKE_PASS" {
			return nil
		}
		if category == "REVOKE_COMMITTED_PENDING" {
			return errors.New("profile revocation reconciliation failed")
		}
		return errors.New("profile revocation failed")
	})
}

func remoteRevocationScript(profileID string) string {
	return fmt.Sprintf(`set -eu
pass=%q
recovery=%q
profile_id=%s
state_lock=%q/.state.lock
[ -f "$pass" ] && [ ! -L "$pass" ] && [ -f "$recovery" ] && [ ! -L "$recovery" ]
tmp=$(mktemp -d /var/tmp/phase17-revoke.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chown kurd-node:kurd-node "$tmp"
install -o kurd-node -g kurd-node -m 0600 "$recovery" "$tmp/recovery"
ready=0
attempt=0
while [ -d "$state_lock" ] || [ "$ready" -lt 2 ]; do
  if [ ! -d "$state_lock" ]; then
    ready=$((ready + 1))
  else
    ready=0
  fi
  attempt=$((attempt + 1))
  if [ "$attempt" -ge 120 ]; then
    printf REVOKE_BUSY
    exit 5
  fi
  sleep 0.25
done
set +e
runuser -u kurd-node -- /usr/local/bin/kurdctl profile revoke --data-dir %q --profile-id "$profile_id" --recovery-file "$tmp/recovery" --confirm-profile "$profile_id" --control-socket %q <"$pass" >/dev/null 2>"$tmp/revoke.err"
status=$?
set -e
if [ "$status" -eq 0 ]; then
  printf REVOKE_PASS
  exit 0
fi
if [ "$status" -eq 7 ] && grep -Fqx 'kurdctl: state committed; runtime notification pending; run kurdctl node reload' "$tmp/revoke.err"; then
  printf REVOKE_COMMITTED_PENDING
  exit 7
fi
if [ "$status" -eq 5 ] && grep -Fqx 'kurdctl: busy' "$tmp/revoke.err"; then
  printf REVOKE_BUSY
  exit 5
fi
exit "$status"
`, remotePassFile, remoteRecovery, shellQuote(profileID), remoteDataDir, remoteDataDir, remoteControl)
}

func remoteRevocationReconcileScript(profileID string) string {
	return fmt.Sprintf(`set -eu
profile_id=%s
summary=$(runuser -u kurd-node -- /usr/local/bin/kurdctl profile show --data-dir %q --profile-id "$profile_id" --redacted)
printf '%%s\n' "$summary" | grep -Fq '"revoked":true'
printf '%%s\n' "$summary" | grep -Fq '"connectable":false'
attempt=0
while [ "$attempt" -lt 3 ]; do
  if runuser -u kurd-node -- /usr/local/bin/kurdctl node reload --control-socket %q >/dev/null 2>&1; then
    printf REVOKE_PASS
    exit 0
  fi
  attempt=$((attempt + 1))
  sleep 1
done
systemctl restart kurd-node.socket kurd-node.service >/dev/null
systemctl is-active --quiet kurd-node.socket
systemctl is-active --quiet kurd-node.service
printf REVOKE_PASS
`, shellQuote(profileID), remoteDataDir, remoteControl)
}

func removeRemoteProfile(ctx context.Context, runner commandRunner, value config, root, profileID string) error {
	if profileID == "" {
		return nil
	}
	return retryFieldCleanup(ctx, 3, time.Second, func(attemptContext context.Context) error {
		return revokeRemoteProfile(attemptContext, runner, value, root, profileID)
	})
}

func assertQualifiedAndroidPrivacy(
	ctx context.Context,
	runner commandRunner,
	value config,
	qualified qualifiedRun,
	root, serial string,
	campaignStarted time.Time,
	forbiddenProbeURL []byte,
) ([]phase17evidence.FieldScannerV3, error) {
	raw, err := captureAndroidPrivacyLog(ctx, runner, value, root, serial)
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	journal, err := ssh(ctx, runner, value, root, 2*time.Minute, remotePrivacyJournalCommand(campaignStarted))
	if err != nil {
		return nil, errors.New("remote privacy journal scan unavailable")
	}
	defer clear(journal)
	stream, records, err := marshalPrivacyObservationStream([]privacyObservation{
		{source: "ANDROID_LOGCAT", data: raw},
		{source: "REMOTE_JOURNAL", data: journal},
	})
	if err != nil {
		return nil, err
	}
	defer clear(stream)
	receipts, scannerErr := runPrivacyScanners(ctx, runner, value, qualified, root, stream, records)
	if scannerErr != nil {
		return receipts, scannerErr
	}
	if err := validateAndroidPrivacyLog(raw, forbiddenProbeURL, value.ipv6ProbeAddress); err != nil {
		return receipts, err
	}
	return receipts, nil
}

func assertAndroidPrivacy(
	ctx context.Context,
	runner commandRunner,
	value config,
	root, serial string,
	forbiddenProbeURL []byte,
) error {
	raw, err := captureAndroidPrivacyLog(ctx, runner, value, root, serial)
	if err != nil {
		return err
	}
	defer clear(raw)
	return validateAndroidPrivacyLog(raw, forbiddenProbeURL, value.ipv6ProbeAddress)
}

func captureAndroidPrivacyLog(
	ctx context.Context,
	runner commandRunner,
	value config,
	root, serial string,
) ([]byte, error) {
	packageIdentity, err := runText(ctx, runner, nil, root, value.adbPath, "-s", serial, "shell", "cmd", "package", "list", "packages", "-U", appPackage)
	if err != nil {
		return nil, errors.New("Android package identity unavailable for privacy scan")
	}
	uid, err := parsePackageUID(packageIdentity, appPackage)
	if err != nil {
		return nil, errors.New("Android package identity rejected")
	}
	arguments := []string{"-s", serial, "logcat", "-d", "-v", "brief", "--uid=" + uid}
	raw, err := runBytesWithLimit(ctx, runner, nil, root, 2*time.Minute, maxAndroidPrivacyLogBytes, value.adbPath, arguments...)
	if err != nil {
		return nil, errors.New("Android privacy log scan unavailable")
	}
	return raw, nil
}

func validateAndroidPrivacyLog(raw, forbiddenProbeURL []byte, ipv6ProbeAddress string) error {
	if !safeAndroidPrivacyLog(raw) {
		return errors.New("Android privacy log scan found sensitive material")
	}
	if containsForbiddenProbeLogValue(raw, forbiddenProbeURL, ipv6ProbeAddress) {
		return errors.New("Android privacy log scan found a private probe endpoint")
	}
	lower := bytes.ToLower(raw)
	for _, marker := range [][]byte{[]byte("fatal exception"), []byte("anr in " + appPackage)} {
		if bytes.Contains(lower, marker) {
			return errors.New("Android crash or ANR detected")
		}
	}
	return nil
}

func remotePrivacyJournalCommand(started time.Time) string {
	return fmt.Sprintf("sudo -n journalctl --no-pager -o cat -u kurd-node.service --since @%d", started.UTC().Unix())
}

func safeAndroidPrivacyLog(raw []byte) bool {
	normalized := frameTrackerCUJLineV1.ReplaceAllFunc(raw, func(line []byte) []byte {
		return frameTrackerCUJIndexV1.ReplaceAll(line, []byte("-ui-index-@"))
	})
	defer clear(normalized)
	return safeCategory(normalized)
}

func containsForbiddenProbeLogValue(raw, probeURL []byte, ipv6ProbeAddress string) bool {
	lower := bytes.ToLower(raw)
	for _, forbidden := range [][]byte{probeURL, []byte(ipv6ProbeAddress)} {
		trimmed := bytes.TrimSpace(forbidden)
		if len(trimmed) != 0 && bytes.Contains(lower, bytes.ToLower(trimmed)) {
			return true
		}
	}
	parsed, err := url.Parse(string(probeURL))
	if err == nil {
		host := strings.TrimSpace(parsed.Hostname())
		if host != "" && bytes.Contains(lower, []byte(strings.ToLower(host))) {
			return true
		}
	}
	return false
}

func parsePackageUID(raw, packageName string) (string, error) {
	prefix := "package:" + packageName + " uid:"
	var uid string
	for _, rawLine := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(rawLine)
		if line == "" || !strings.HasPrefix(line, prefix) {
			continue
		}
		candidate := strings.TrimPrefix(line, prefix)
		if uid != "" {
			return "", errors.New("package identity is ambiguous")
		}
		uid = candidate
	}
	if uid == "" || strings.ContainsAny(uid, " \t") {
		return "", errors.New("package identity contains an invalid uid")
	}
	value, err := strconv.ParseUint(uid, 10, 31)
	if err != nil || value == 0 {
		return "", errors.New("package identity contains an invalid uid")
	}
	return strconv.FormatUint(value, 10), nil
}

func runOwnedVPSStressCampaign(
	ctx context.Context,
	runner commandRunner,
	value config,
	campaignPolicy phase17qualification.CampaignPolicy,
	root, serial string,
	profileID *string,
	probeURL, probeDigest []byte,
	ipv6Authorized bool,
	tracker *resourceTracker,
) (uint64, error) {
	var reconnects uint64
	actions := stressActions{
		restartReconnect: func(ctx context.Context, _ int) error {
			if err := remoteService(ctx, runner, value, root, "sudo -n systemctl restart kurd-node.service"); err != nil {
				return errors.New("relay restart failed")
			}
			if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
				return err
			}
			if err := verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized); err != nil {
				return err
			}
			reconnects++
			return nil
		},
		rotateReissue: func(ctx context.Context, _ int) error {
			if *profileID == "" {
				return errors.New("active profile unavailable")
			}
			if err := revokeRemoteProfile(ctx, runner, value, root, *profileID); err != nil {
				return err
			}
			*profileID = ""
			nextProfile, err := issueAndActivateProfile(ctx, runner, value, root, serial)
			if err != nil {
				return err
			}
			*profileID = nextProfile
			if err := verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized); err != nil {
				return err
			}
			reconnects++
			return nil
		},
		impair: func(ctx context.Context, name string) error {
			var selected *impairmentScenario
			for index := range frozenImpairmentMatrix {
				if frozenImpairmentMatrix[index].name == name {
					selected = &frozenImpairmentMatrix[index]
					break
				}
			}
			if selected == nil {
				return errors.New("unknown impairment scenario")
			}
			if selected.carrierReset {
				if err := remoteService(ctx, runner, value, root, "sudo -n systemctl restart kurd-node.service"); err != nil {
					return errors.New("carrier reset failed")
				}
				if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
					return err
				}
				reconnects++
				return verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized)
			}
			return exerciseRemoteImpairment(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized, *selected)
		},
		sample: func(ctx context.Context) error {
			return observeRemoteMetrics(ctx, runner, value, root, tracker)
		},
		progress: func(category string, completed, total int) {
			fmt.Printf("PHASE17_PROGRESS %s %d/%d\n", category, completed, total)
		},
	}
	if err := executeStressCampaign(ctx, campaignPolicy, actions); err != nil {
		return reconnects, err
	}
	return reconnects, nil
}

func exerciseRemoteImpairment(
	ctx context.Context,
	runner commandRunner,
	value config,
	root, serial string,
	probeURL, probeDigest []byte,
	ipv6Authorized bool,
	scenario impairmentScenario,
) (result error) {
	if scenario.carrierReset || scenario.netem == "" {
		return errors.New("network impairment scenario rejected")
	}
	if err := remoteService(ctx, runner, value, root, remoteImpairmentApplyScript(scenario)); err != nil {
		return errors.New("network impairment apply failed")
	}
	defer func() {
		cleanupErr := remoteService(context.Background(), runner, value, root, remoteImpairmentCleanupScript())
		if result == nil && cleanupErr != nil {
			result = errors.New("network impairment cleanup failed")
		}
	}()
	return verifyImpairedFieldTraffic(ctx, func(attemptCtx context.Context) error {
		return verifyFieldTraffic(attemptCtx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized)
	})
}

func remoteImpairmentApplyScript(scenario impairmentScenario) string {
	return "sudo -n tc qdisc replace dev kurd0 root netem " + scenario.netem
}

func remoteImpairmentCleanupScript() string {
	return "sudo -n sh -c 'tc qdisc del dev kurd0 root 2>/dev/null || true'"
}

func runOwnedVPSSoakCampaign(
	ctx context.Context,
	runner commandRunner,
	value config,
	campaignPolicy phase17qualification.CampaignPolicy,
	clock campaignClock,
	root, serial string,
	probeURL, probeDigest []byte,
	ipv6Authorized bool,
	tracker *resourceTracker,
) (soakCampaignResult, error) {
	return executeSoakCampaign(ctx, campaignPolicy, clock, soakActions{
		cycle: func(ctx context.Context, cycle uint64) (uint64, error) {
			if err := verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized); err != nil {
				return 0, err
			}
			var reconnects uint64
			if cycle%10 == 9 {
				if err := remoteService(ctx, runner, value, root, "sudo -n systemctl restart kurd-node.service"); err != nil {
					return reconnects, errors.New("soak restart failed")
				}
				if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
					return reconnects, err
				}
				reconnects++
			}
			if cycle%12 == 11 {
				if err := exerciseRemoteImpairment(
					ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized, frozenImpairmentMatrix[3],
				); err != nil {
					return reconnects, fmt.Errorf("soak bounded interruption failed: %w", err)
				}
			}
			if err := observeRemoteMetrics(ctx, runner, value, root, tracker); err != nil {
				return reconnects, fmt.Errorf("soak resource sample failed: %w", err)
			}
			return reconnects, nil
		},
		progress: func(completed, _ uint64, elapsed time.Duration) {
			fmt.Printf("PHASE17_PROGRESS soak %d elapsed_minutes=%d\n", completed, uint64(elapsed.Minutes()))
		},
	})
}

func remoteMetrics(ctx context.Context, runner commandRunner, value config, root string) (resourceSample, error) {
	raw, err := ssh(ctx, runner, value, root, 30*time.Second, remoteMetricsCommand())
	if err != nil {
		return resourceSample{}, errors.New("remote resource metrics failed")
	}
	var valueOut struct {
		RSS      uint64 `json:"rss"`
		FDs      uint64 `json:"fds"`
		Swap     uint64 `json:"swap"`
		OOMKills uint64 `json:"oomKills"`
		Threads  uint64 `json:"threads"`
		IPv6     bool   `json:"ipv6"`
	}
	if json.Unmarshal(raw, &valueOut) != nil {
		return resourceSample{}, errors.New("remote resource metrics rejected")
	}
	return resourceSample{valueOut.RSS, valueOut.FDs, valueOut.Swap, valueOut.OOMKills, valueOut.Threads, valueOut.IPv6}, nil
}

func observeRemoteMetrics(ctx context.Context, runner commandRunner, value config, root string, tracker *resourceTracker) error {
	sample, err := remoteMetrics(ctx, runner, value, root)
	if err != nil {
		return err
	}
	return tracker.observe(sample)
}

func remoteMetricsCommand() string {
	return "sudo -n sh -c " + shellQuote(remoteMetricsScript())
}

func remoteMetricsScript() string {
	return `set -eu
pid=$(systemctl show -p MainPID --value kurd-node.service)
[ "$pid" -gt 0 ]
rss=$(awk '/^VmRSS:/ {print $2*1024; exit}' /proc/$pid/status)
swap=$(awk '/^VmSwap:/ {print $2*1024; exit}' /proc/$pid/status)
threads=$(awk '/^Threads:/ {print $2; exit}' /proc/$pid/status)
fds=$(find /proc/$pid/fd -mindepth 1 -maxdepth 1 | wc -l)
cg=$(systemctl show -p ControlGroup --value kurd-node.service)
oom_kills=0
if [ -n "$cg" ] && [ -f "/sys/fs/cgroup$cg/memory.events" ]; then
  oom_kills=$(awk '$1=="oom_kill" {print $2; exit}' "/sys/fs/cgroup$cg/memory.events")
fi
ipv6=false; ip -o -6 route show default | grep -q . && ipv6=true
printf '{"rss":%s,"fds":%s,"swap":%s,"oomKills":%s,"threads":%s,"ipv6":%s}' "$rss" "$fds" "$swap" "$oom_kills" "$threads" "$ipv6"
`
}

func safeStop(ctx context.Context, runner commandRunner, value config, root string) error {
	return retryFieldCleanup(ctx, 3, time.Second, func(attemptContext context.Context) error {
		return remoteService(attemptContext, runner, value, root, "sudo -n systemctl stop kurd-node.socket kurd-node.service")
	})
}

func removeRemoteStagedPackage(ctx context.Context, runner commandRunner, value config, root, remotePackage string) error {
	return removeRemotePackageArtifacts(ctx, runner, value, root, remotePackage, "")
}

func removeRemotePackageArtifacts(
	ctx context.Context,
	runner commandRunner,
	value config,
	root, remotePackage, remoteArchive string,
) error {
	if !remotePackagePattern.MatchString(remotePackage) {
		return errors.New("remote package cleanup path rejected")
	}
	cleanup := "rm -rf " + remotePackage
	verify := "test ! -e " + remotePackage
	if remoteArchive != "" {
		if !remoteArchivePattern.MatchString(remoteArchive) {
			return errors.New("remote package cleanup path rejected")
		}
		cleanup += "; rm -f " + remoteArchive
		verify += "; test ! -e " + remoteArchive
	}
	command := "sudo -n sh -c " + shellQuote(cleanup+"; "+verify)
	return retryFieldCleanup(ctx, 3, time.Second, func(attemptContext context.Context) error {
		return remoteService(attemptContext, runner, value, root, command)
	})
}

func retryFieldCleanup(
	ctx context.Context,
	attempts int,
	delay time.Duration,
	action func(context.Context) error,
) error {
	if ctx == nil || attempts < 1 || delay < 0 || action == nil {
		return errors.New("field cleanup retry rejected")
	}
	var last error
	for attempt := 0; attempt < attempts; attempt++ {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := action(ctx); err == nil {
			return nil
		} else {
			last = err
		}
		if attempt+1 == attempts || delay == 0 {
			continue
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
	return last
}

func remoteService(ctx context.Context, runner commandRunner, value config, root, command string) error {
	_, err := ssh(ctx, runner, value, root, 2*time.Minute, command)
	return err
}

func ssh(ctx context.Context, runner commandRunner, value config, root string, timeout time.Duration, command string) ([]byte, error) {
	raw, err := runBytes(ctx, runner, nil, root, timeout, value.sshPath,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20", "--", value.sshAlias, command)
	return classifySSHFailure(raw, err)
}

func sshScript(ctx context.Context, runner commandRunner, value config, root string, timeout time.Duration, script string) ([]byte, error) {
	raw, err := runBytes(ctx, runner, []byte(script), root, timeout, value.sshPath,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20", "--", value.sshAlias, "sudo -n sh -s")
	return classifySSHFailure(raw, err)
}

func classifySSHFailure(raw []byte, err error) ([]byte, error) {
	var exitFailure *commandExitFailure
	if errors.As(err, &exitFailure) && exitFailure.code == 255 {
		return raw, fmt.Errorf("%w: secure shell transport failed", errVPSEnvironmentUnavailable)
	}
	return raw, err
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'" }

func (runner commandRunner) run(ctx context.Context, stdin []byte, directory, name string, arguments ...string) ([]byte, error) {
	return runner.runWithLimit(ctx, stdin, directory, maxOutputBytes, name, arguments...)
}

func (runner commandRunner) runWithLimit(ctx context.Context, stdin []byte, directory string, maximum int, name string, arguments ...string) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("command output bound rejected")
	}
	if _, remote := runner.remoteCommands[name]; remote && runner.remoteGate != nil {
		if err := runner.remoteGate.wait(ctx); err != nil {
			return nil, err
		}
	}
	if runner.runFunc != nil {
		raw, err := runner.runFunc(ctx, stdin, directory, name, arguments...)
		if len(raw) > maximum {
			clear(raw)
			return nil, errors.New("command output exceeded bound")
		}
		return raw, err
	}
	command := exec.CommandContext(ctx, name, arguments...)
	command.Dir = directory
	if stdin != nil {
		command.Stdin = bytes.NewReader(stdin)
	}
	output := boundedBuffer{maximum: maximum}
	command.Stdout = &output
	command.Stderr = &output
	err := command.Run()
	if output.overflow {
		return nil, errors.New("command output exceeded bound")
	}
	if err != nil {
		var exitFailure *exec.ExitError
		if errors.As(err, &exitFailure) {
			return output.data, &commandExitFailure{code: exitFailure.ExitCode()}
		}
		return output.data, errors.New("command launch failed")
	}
	return output.data, nil
}

type boundedBuffer struct {
	data     []byte
	overflow bool
	maximum  int
}

func (buffer *boundedBuffer) Write(data []byte) (int, error) {
	if len(buffer.data)+len(data) > buffer.maximum {
		buffer.overflow = true
		remaining := buffer.maximum - len(buffer.data)
		if remaining > 0 {
			buffer.data = append(buffer.data, data[:remaining]...)
		}
		return len(data), nil
	}
	buffer.data = append(buffer.data, data...)
	return len(data), nil
}

func runBytes(parent context.Context, runner commandRunner, stdin []byte, directory string, timeout time.Duration, name string, arguments ...string) ([]byte, error) {
	return runBytesWithLimit(parent, runner, stdin, directory, timeout, maxOutputBytes, name, arguments...)
}

func runBytesWithLimit(parent context.Context, runner commandRunner, stdin []byte, directory string, timeout time.Duration, maximum int, name string, arguments ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	raw, err := runner.runWithLimit(ctx, stdin, directory, maximum, name, arguments...)
	if err != nil && ctx.Err() != nil {
		return raw, ctx.Err()
	}
	return raw, err
}

func runText(ctx context.Context, runner commandRunner, stdin []byte, directory, name string, arguments ...string) (string, error) {
	raw, err := runBytes(ctx, runner, stdin, directory, 30*time.Second, name, arguments...)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(raw)), nil
}

func fileSHA256(path string) string {
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, file); err != nil {
		return ""
	}
	return hex.EncodeToString(digest.Sum(nil))
}

func readTrimmedSecret(path string, maximum int) ([]byte, error) {
	if maximum < 1 {
		return nil, errors.New("secret input rejected")
	}
	raw, err := readQualifiedRegular(path, int64(maximum+2))
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	data := append([]byte(nil), bytes.TrimSpace(raw)...)
	if len(data) == 0 || len(data) > maximum || bytes.ContainsAny(data, "\r\n\x00") {
		clear(data)
		return nil, errors.New("secret input rejected")
	}
	return data, nil
}

func stageAndVerifyPackage(ctx context.Context, runner commandRunner, value config, root string) (string, error) {
	manifestDigest, err := packageManifestDigest(value.packagePath)
	if err != nil {
		return "", errors.New("package manifest unavailable")
	}
	token := strconv.FormatInt(time.Now().UnixNano(), 16)
	remoteArchive := "/tmp/phase17-package-" + token + ".tar.gz"
	remoteRoot := "/var/tmp/phase17-package-" + token
	cleanupFailure := func(primary error) error {
		joinFieldCleanup(&primary, removeRemotePackageArtifacts(context.Background(), runner, value, root, remoteRoot, remoteArchive))
		return primary
	}
	if _, err := runBytes(ctx, runner, nil, root, 2*time.Minute, value.scpPath, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", value.packagePath, value.sshAlias+":"+remoteArchive); err != nil {
		return "", cleanupFailure(errors.New("package transfer failed"))
	}
	script := fmt.Sprintf(`set -eu
archive=%q
root=%q
log=$(mktemp /var/tmp/phase17-package-log.XXXXXX)
trap 'rm -f "$log"' EXIT HUP INT TERM
sudo -n install -d -o root -g root -m 0700 "$root"
sudo -n tar -xzf "$archive" -C "$root" --strip-components=1 --no-same-owner
sudo -n rm -f "$archive"
cd "$root"
sudo -n sha256sum -c SHA256SUMS >/dev/null
observed=$(sha256sum /usr/local/share/doc/kurd-node/manifest.json | cut -d' ' -f1)
if [ "$observed" != %q ]; then
  pass=%q
  [ -f "$pass" ] && [ ! -L "$pass" ]
  if ! sudo -n env KURD_BACKUP_PASSPHRASE_FILE="$pass" "$root/upgrade.sh" --apply --port %d >"$log" 2>&1; then
    printf PACKAGE_UPGRADE_FAILED
    exit 2
  fi
  observed=$(sha256sum /usr/local/share/doc/kurd-node/manifest.json | cut -d' ' -f1)
fi
[ "$observed" = %q ]
if ! sudo -n ./preflight.sh --runtime --port %d --allow-systemd-socket >"$log" 2>&1; then
  printf PACKAGE_PREFLIGHT_FAILED
  exit 2
fi
rm -f "$log"
trap - EXIT HUP INT TERM
printf PACKAGE_MATCH_PASS
`, remoteArchive, remoteRoot, manifestDigest, remotePassFile, value.relayPort, manifestDigest, value.relayPort)
	raw, err := ssh(ctx, runner, value, root, 2*time.Minute, "sudo -n sh -c "+shellQuote(script))
	if err != nil || strings.TrimSpace(string(raw)) != "PACKAGE_MATCH_PASS" {
		category := strings.TrimSpace(string(raw))
		if category != "" && len(category) <= 256 && safeCategory([]byte(category)) {
			return "", cleanupFailure(fmt.Errorf("installed package identity rejected: %s", category))
		}
		return "", cleanupFailure(errors.New("installed package identity rejected"))
	}
	return remoteRoot, nil
}

func packageManifestDigest(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	zipper, err := gzip.NewReader(file)
	if err != nil {
		return "", err
	}
	defer zipper.Close()
	reader := tar.NewReader(zipper)
	for {
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return "", err
		}
		if filepath.Base(header.Name) != "manifest.json" || header.Size <= 0 || header.Size > 1<<20 {
			continue
		}
		raw, err := io.ReadAll(io.LimitReader(reader, 1<<20))
		if err != nil || int64(len(raw)) != header.Size {
			return "", errors.New("package manifest truncated")
		}
		digest := sha256.Sum256(raw)
		clear(raw)
		return hex.EncodeToString(digest[:]), nil
	}
	return "", errors.New("package manifest missing")
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	return writeExclusiveAtomic(path, data, mode, syncFieldEvidenceDirectory)
}

type atomicEvidenceOps struct {
	createTemp func(string, string) (*os.File, error)
	chmod      func(*os.File, os.FileMode) error
	write      func(*os.File, []byte) (int, error)
	sync       func(*os.File) error
	close      func(*os.File) error
	link       func(string, string) error
	remove     func(string) error
}

func systemAtomicEvidenceOps() atomicEvidenceOps {
	return atomicEvidenceOps{
		createTemp: os.CreateTemp,
		chmod:      func(file *os.File, mode os.FileMode) error { return file.Chmod(mode) },
		write:      func(file *os.File, data []byte) (int, error) { return file.Write(data) },
		sync:       func(file *os.File) error { return file.Sync() },
		close:      func(file *os.File) error { return file.Close() },
		link:       os.Link,
		remove:     os.Remove,
	}
}

func writeExclusiveAtomic(path string, data []byte, mode os.FileMode, syncDirectory func(string) error) error {
	return writeExclusiveAtomicWithOps(path, data, mode, syncDirectory, systemAtomicEvidenceOps())
}

func writeExclusiveAtomicWithOps(
	path string,
	data []byte,
	mode os.FileMode,
	syncDirectory func(string) error,
	operations atomicEvidenceOps,
) error {
	if path == "" || len(data) == 0 || syncDirectory == nil {
		return errors.New("atomic evidence output rejected")
	}
	if operations.createTemp == nil || operations.chmod == nil || operations.write == nil || operations.sync == nil ||
		operations.close == nil || operations.link == nil || operations.remove == nil {
		return errors.New("atomic evidence operations rejected")
	}
	directory := filepath.Dir(path)
	absDirectory, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	if err := phase17qualification.ValidateNoLinkedPath(absDirectory); err != nil {
		return errors.New("atomic evidence directory rejected")
	}
	file, err := operations.createTemp(directory, ".phase17-field-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	closed := false
	defer func() {
		if !closed {
			_ = operations.close(file)
		}
		_ = operations.remove(name)
	}()
	if err := operations.chmod(file, mode); err != nil {
		return err
	}
	written, err := operations.write(file, data)
	if err != nil {
		return err
	}
	if written != len(data) {
		return io.ErrShortWrite
	}
	if err := operations.sync(file); err != nil {
		return err
	}
	if err := operations.close(file); err != nil {
		return err
	}
	closed = true
	if err := operations.link(name, path); err != nil {
		return err
	}
	if err := operations.remove(name); err != nil {
		return err
	}
	return syncDirectory(directory)
}

func syncFieldEvidenceDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
}

func sameFieldPath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
