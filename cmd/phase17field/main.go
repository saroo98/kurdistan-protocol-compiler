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
)

const (
	rawSchema                   = "kurdistan-phase17-owned-vps-raw-v2"
	maxOutputBytes              = 2 << 20
	maxAndroidPrivacyLogBytes   = 16 << 20
	appPackage                  = "org.kurdistanvpn.app.internal"
	testPackage                 = "org.kurdistanvpn.app.internal.test"
	testRunner                  = "org.kurdistanvpn.app.internal.test/androidx.test.runner.AndroidJUnitRunner"
	fieldTest                   = "org.kurdistanvpn.app.Phase17FieldActionDeviceTest#runRequestedFieldAction"
	remoteDataDir               = "/var/lib/kurd-node"
	remoteRegistry              = "/var/lib/kurd-node/recipient-registry"
	remoteControl               = "/run/kurd-node/control.sock"
	remotePassFile              = "/root/.kurd-node-field/current-passphrase"
	remoteRecovery              = "/root/.kurd-node-field/current.kurd-recovery"
	fieldDirectory              = "files/phase17-field"
	recipientFile               = fieldDirectory + "/recipient-request.bin"
	profileFile                 = fieldDirectory + "/sealed-profile.bin"
	fieldResultFile             = fieldDirectory + "/result.txt"
	frozenRestartCycles         = 100
	frozenProfileRotationCycles = 100
	maximumRelayRSSBytes        = 384 << 20
	maximumRelayFileDescriptors = 1024
	maximumRelaySwapBytes       = 64 << 20
)

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
	instrumentCategoryV1   = regexp.MustCompile(`[A-Z][A-Z0-9_]{2,63}(?::[A-Z0-9_-]{1,64}){0,4}`)
	frozenImpairmentMatrix = []impairmentScenario{
		{name: "bandwidth", netem: "rate 5mbit"},
		{name: "latency", netem: "delay 150ms 25ms distribution normal"},
		{name: "loss", netem: "loss 1%"},
		{name: "combined", netem: "delay 100ms 20ms distribution normal loss 1% rate 5mbit"},
		{name: "carrier-reset", carrierReset: true},
	}
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

func executeStressCampaign(ctx context.Context, actions stressActions) error {
	for cycle := 0; cycle < frozenRestartCycles; cycle++ {
		if err := actions.restartReconnect(ctx, cycle); err != nil {
			return fmt.Errorf("restart/reconnect cycle %d failed: %w", cycle, err)
		}
		if err := actions.sample(ctx); err != nil {
			return fmt.Errorf("restart/reconnect resource sample %d failed: %w", cycle, err)
		}
		if actions.progress != nil {
			actions.progress("restart-reconnect", cycle+1, frozenRestartCycles)
		}
	}
	for cycle := 0; cycle < frozenProfileRotationCycles; cycle++ {
		if err := actions.rotateReissue(ctx, cycle); err != nil {
			return fmt.Errorf("profile revoke/reissue cycle %d failed: %w", cycle, err)
		}
		if err := actions.sample(ctx); err != nil {
			return fmt.Errorf("profile revoke/reissue resource sample %d failed: %w", cycle, err)
		}
		if actions.progress != nil {
			actions.progress("profile-rotation", cycle+1, frozenProfileRotationCycles)
		}
	}
	for index, scenario := range frozenImpairmentMatrix {
		if err := actions.impair(ctx, scenario.name); err != nil {
			return fmt.Errorf("impairment %s failed: %w", scenario.name, err)
		}
		if err := actions.sample(ctx); err != nil {
			return fmt.Errorf("impairment %s resource sample failed: %w", scenario.name, err)
		}
		if actions.progress != nil {
			actions.progress("impairment", index+1, len(frozenImpairmentMatrix))
		}
	}
	return nil
}

type config struct {
	sshAlias, avdName, evidenceRoot, mode                   string
	packagePath, appAPK, testAPK, adbPath, sshPath, scpPath string
	probeURLFile, probeDigestFile                           string
	ipv6ProbeAddress                                        string
	relayPort                                               int
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
	flag.StringVar(&value.sshAlias, "ssh-alias", "", "strict SSH config alias")
	flag.StringVar(&value.avdName, "avd-name", "", "exact running Android virtual device name")
	flag.StringVar(&value.evidenceRoot, "evidence-root", ".tools/phase17/field", "ignored raw evidence root")
	flag.StringVar(&value.mode, "mode", "Functional", "Functional, Stress, or Soak12h")
	flag.IntVar(&value.relayPort, "relay-port", 8443, "signed Kurd relay port")
	flag.StringVar(&value.packagePath, "package", "", "verified Linux amd64 package")
	flag.StringVar(&value.appAPK, "app-apk", "android/app/build/outputs/apk/internal/app-internal.apk", "internal application APK")
	flag.StringVar(&value.testAPK, "test-apk", "android/app/build/outputs/apk/androidTest/internal/app-internal-androidTest.apk", "instrumentation APK")
	flag.StringVar(&value.adbPath, "adb", "adb", "adb executable")
	flag.StringVar(&value.sshPath, "ssh", "ssh", "ssh executable")
	flag.StringVar(&value.scpPath, "scp", "scp", "scp executable")
	flag.StringVar(&value.probeURLFile, "probe-url-file", ".tools/phase17/field/runtime-stage/probe-url.txt", "ignored probe URL file")
	flag.StringVar(&value.probeDigestFile, "probe-digest-file", ".tools/phase17/field/runtime-stage/probe-digest.txt", "ignored expected response digest file")
	flag.StringVar(&value.ipv6ProbeAddress, "ipv6-probe-address", "2606:4700:4700::1111", "public IPv6 literal used only for owner-VPS reachability preflight")
	flag.Parse()
	if err := validateConfig(value); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 FIELD FAILED: %v\n", err)
		os.Exit(2)
	}
	if err := runField(context.Background(), commandRunner{}, value); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 FIELD FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 17 OWNED-VPS FIELD MATRIX PASSED")
}

func validateConfig(value config) error {
	if !selectorPattern.MatchString(value.sshAlias) || !selectorPattern.MatchString(value.avdName) {
		return errors.New("SSH alias or AVD selector rejected")
	}
	if value.mode != "Functional" && value.mode != "Stress" && value.mode != "Soak12h" {
		return errors.New("mode rejected")
	}
	if value.relayPort < 1 || value.relayPort > 65535 {
		return errors.New("relay port rejected")
	}
	probeAddress := net.ParseIP(value.ipv6ProbeAddress)
	if probeAddress == nil || probeAddress.To4() != nil || strings.ContainsAny(value.ipv6ProbeAddress, "\r\n\x00") {
		return errors.New("IPv6 probe address rejected")
	}
	for _, required := range []string{value.evidenceRoot, value.packagePath, value.appAPK, value.testAPK, value.adbPath, value.sshPath, value.scpPath} {
		if strings.TrimSpace(required) == "" || strings.ContainsAny(required, "\r\n\x00") {
			return errors.New("required path rejected")
		}
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

func runField(parent context.Context, runner commandRunner, value config) error {
	started := time.Now()
	if runner.runFunc == nil {
		runner.remoteGate = &pacedConnectionGate{interval: 7 * time.Second}
		runner.remoteCommands = map[string]struct{}{value.sshPath: {}, value.scpPath: {}}
	}
	for _, path := range []string{value.packagePath, value.appAPK, value.testAPK, value.probeURLFile, value.probeDigestFile} {
		if info, err := os.Stat(path); err != nil || info.IsDir() || info.Size() == 0 {
			return fmt.Errorf("required field input unavailable")
		}
	}
	root, err := os.Getwd()
	if err != nil {
		return err
	}
	commit, tree, err := readCleanSourceIdentity(parent, runner, root)
	if err != nil {
		return err
	}
	if _, err := runBytes(parent, runner, nil, root, 2*time.Minute, "go", "run", "./cmd/kurdpackage", "verify", "-archive", value.packagePath); err != nil {
		return errors.New("package verification failed")
	}
	remotePackage, err := stageAndVerifyPackage(parent, runner, value, root)
	if err != nil {
		return err
	}
	defer func() { _ = remoteService(context.Background(), runner, value, root, "sudo -n rm -rf "+remotePackage) }()
	serial, api, abi, err := selectDevice(parent, runner, value)
	if err != nil {
		return err
	}
	if err := prepareAndroidPackages(parent, runner, value, root, serial); err != nil {
		return err
	}
	ipv6Authorized, err := prepareIPv6Capability(parent, runner, value, root)
	if err != nil {
		return err
	}
	if !ipv6Authorized {
		return errors.New("IPv6 capability unavailable")
	}
	if err := prepareRemoteCampaignAuthority(parent, runner, value, root); err != nil {
		return err
	}
	tracker := &resourceTracker{}
	outcome, err := runFunctional(parent, runner, value, root, serial, remotePackage, ipv6Authorized, tracker)
	if err != nil {
		_ = safeStop(parent, runner, value, root)
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
	identity := fieldIdentity{strings.TrimSpace(commit), strings.TrimSpace(tree), fileSHA256(value.packagePath), fileSHA256(value.appAPK), fileSHA256(value.testAPK), api, abi, ipv6Authorized}
	if !hex64Pattern.MatchString(identity.packageSHA) || !hex64Pattern.MatchString(identity.appSHA) || !hex64Pattern.MatchString(identity.testSHA) {
		return errors.New("artifact digest rejected")
	}
	evidence := passingEvidence(identity, uint64(time.Since(started).Milliseconds()), tracker.peakRSS, tracker.peakFDs, outcome.reconnects)
	evidence.Campaign = outcome.campaign
	encoded, err := marshalEvidence(evidence)
	if err != nil || !safeCategory(encoded) {
		return errors.New("field evidence privacy validation failed")
	}
	runRoot := filepath.Join(value.evidenceRoot, time.Now().UTC().Format("20060102T150405Z")+"-"+strconv.FormatInt(time.Now().UnixNano()&0xfffffff, 16))
	if err := os.MkdirAll(runRoot, 0o700); err != nil {
		return err
	}
	if err := writeAtomic(filepath.Join(runRoot, "field-result.json"), encoded, 0o600); err != nil {
		return err
	}
	return nil
}

func prepareAndroidPackages(ctx context.Context, runner commandRunner, value config, root, serial string) error {
	for _, apk := range []string{value.appAPK, value.testAPK} {
		if _, err := runBytes(ctx, runner, nil, root, 2*time.Minute, value.adbPath, "-s", serial, "install", "-r", "-t", apk); err != nil {
			return errors.New("APK installation failed")
		}
	}
	for _, packageName := range []string{appPackage, testPackage} {
		output, err := runText(ctx, runner, nil, root, value.adbPath,
			"-s", serial, "shell", "cmd", "package", "compile", "-m", "speed", "-f", packageName)
		if err != nil || output != "Success" {
			return errors.New("Android package compilation failed")
		}
	}
	if _, err := runBytes(ctx, runner, nil, root, 30*time.Second, value.adbPath,
		"-s", serial, "shell", "appops", "set", appPackage, "ACTIVATE_VPN", "allow"); err != nil {
		return errors.New("Android VPN permission preparation failed")
	}
	return nil
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

func runFunctional(ctx context.Context, runner commandRunner, value config, root, serial, remotePackage string, ipv6Authorized bool, tracker *resourceTracker) (functionalOutcome, error) {
	outcome := functionalOutcome{campaign: rawCampaign{Mode: value.mode, Impairments: []string{}}}
	profileID, err := issueAndActivateProfile(ctx, runner, value, root, serial)
	if err != nil {
		return outcome, err
	}
	defer func() { _ = removeRemoteProfile(context.Background(), runner, value, root, profileID) }()
	probeURL, err := readTrimmedSecret(value.probeURLFile, 2048)
	if err != nil {
		return outcome, errors.New("probe URL unavailable")
	}
	defer clear(probeURL)
	probeDigest, err := readTrimmedSecret(value.probeDigestFile, 64)
	if err != nil || !hex64Pattern.Match(probeDigest) {
		return outcome, errors.New("probe digest unavailable")
	}
	defer clear(probeDigest)
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
	if value.mode == "Stress" || value.mode == "Soak12h" {
		stressReconnects, err := runOwnedVPSStressCampaign(
			ctx, runner, value, root, serial, &profileID, probeURL, probeDigest, ipv6Authorized, tracker,
		)
		if err != nil {
			return outcome, err
		}
		outcome.reconnects += stressReconnects
		outcome.campaign.RestartReconnectCycles = frozenRestartCycles
		outcome.campaign.ProfileRotationCycles = frozenProfileRotationCycles
		for _, scenario := range frozenImpairmentMatrix {
			outcome.campaign.Impairments = append(outcome.campaign.Impairments, scenario.name)
		}
	}
	if value.mode == "Soak12h" {
		soakReconnects, soakDurationMS, soakCycles, err := soak(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized, tracker)
		if err != nil {
			return outcome, err
		}
		outcome.reconnects += soakReconnects
		outcome.campaign.SoakDurationMS = soakDurationMS
		outcome.campaign.SoakCycles = soakCycles
	}
	if err := observeRemoteMetrics(ctx, runner, value, root, tracker); err != nil {
		return outcome, err
	}
	if err := revokeRemoteProfile(ctx, runner, value, root, profileID); err != nil {
		return outcome, err
	}
	profileID = ""
	if err := assertAndroidPrivacy(ctx, runner, value, root, serial, probeURL); err != nil {
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

func selectDevice(ctx context.Context, runner commandRunner, value config) (string, int, string, error) {
	raw, err := runBytes(ctx, runner, nil, "", 30*time.Second, value.adbPath, "devices")
	if err != nil {
		return "", 0, "", errors.New("ADB device discovery failed")
	}
	for _, line := range strings.Split(string(raw), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "device" {
			continue
		}
		serial := fields[0]
		name, nameErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "emu", "avd", "name")
		if nameErr != nil || strings.TrimSpace(strings.Split(name, "\n")[0]) != value.avdName {
			continue
		}
		apiRaw, apiErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "shell", "getprop", "ro.build.version.sdk")
		abi, abiErr := runText(ctx, runner, nil, "", value.adbPath, "-s", serial, "shell", "getprop", "ro.product.cpu.abi")
		api, parseErr := strconv.Atoi(strings.TrimSpace(apiRaw))
		if apiErr != nil || abiErr != nil || parseErr != nil || api != 26 && api != 34 && api != 36 {
			return "", 0, "", errors.New("Android identity rejected")
		}
		abi = strings.TrimSpace(abi)
		if abi != "x86_64" && abi != "arm64-v8a" {
			return "", 0, "", errors.New("Android ABI rejected")
		}
		return serial, api, abi, nil
	}
	return "", 0, "", errors.New("requested AVD is not the active authorized emulator")
}

func runFieldAction(ctx context.Context, runner commandRunner, value config, root, serial, action string, extras map[string]string, expected string) error {
	if _, err := runBytes(ctx, runner, nil, root, 10*time.Second, value.adbPath,
		"-s", serial, "shell", "run-as", appPackage, "rm", "-f", fieldResultFile); err != nil {
		return fmt.Errorf("Android field action %s evidence reset failed", action)
	}
	arguments := []string{"-s", serial, "shell", "am", "instrument", "-w", "-r", "-e", "phase17FieldAction", action}
	for key, item := range extras {
		arguments = append(arguments, "-e", key, item)
	}
	arguments = append(arguments, "-e", "class", fieldTest, testRunner)
	instrumentation, err := runBytes(ctx, runner, nil, root, 3*time.Minute, value.adbPath, arguments...)
	category := instrumentationFailureCategory(instrumentation)
	clear(instrumentation)
	if category != "" {
		return fmt.Errorf("Android field action %s failed: %s", action, category)
	}
	if err != nil {
		return fmt.Errorf("Android field action %s failed", action)
	}
	result, err := runText(ctx, runner, nil, root, value.adbPath, "-s", serial, "shell", "run-as", appPackage, "cat", fieldResultFile)
	if err != nil || strings.TrimSpace(result) != expected || !safeCategory([]byte(result)) {
		return fmt.Errorf("Android field action %s returned invalid evidence", action)
	}
	return nil
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
sudo -n -u kurd-node /usr/local/bin/kurdctl profile create --data-dir %q --name phase17-field --valid-for 24h --recipient-request "$req" --recipient-registry-dir %q --output-dir "$out" --control-socket %q >"$response" 2>"$error_output" || status=$?
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
`, remoteRequest, remoteOutput, remoteResponse, remoteError, remoteArtifact, remoteDataDir, remoteRegistry, remoteControl, remoteDataDir, remoteControl)
	raw, err := ssh(ctx, runner, value, root, 2*time.Minute, script)
	ready := err == nil && strings.TrimSpace(string(raw)) == "PHASE17_ISSUE_READY"
	initialFailure := append([]byte(nil), raw...)
	clear(raw)
	for attempt := 0; !ready && attempt < 4; attempt++ {
		if attempt > 0 {
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				clear(initialFailure)
				return "", nil, errors.New("profile issuance recovery cancelled")
			case <-timer.C:
			}
		}
		check, checkErr := ssh(ctx, runner, value, root, 15*time.Second,
			fmt.Sprintf(`set -eu; test -s %q; test -s %q; printf PHASE17_ISSUE_READY`, remoteResponse, remoteArtifact))
		ready = checkErr == nil && strings.TrimSpace(string(check)) == "PHASE17_ISSUE_READY"
		clear(check)
	}
	if !ready {
		if len(initialFailure) == 0 {
			failure, _ := ssh(ctx, runner, value, root, 10*time.Second, fmt.Sprintf(`cat %q`, remoteError))
			initialFailure = failure
		}
		category := categorizeProfileIssuanceFailure(initialFailure)
		clear(initialFailure)
		return "", nil, category
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

func categorizeProfileIssuanceFailure(raw []byte) error {
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
	return errors.New("profile issuance failed")
}

const remoteHealthAttempts = 10

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
	observed, err := remoteDeploymentDisabled(ctx, runner, value, root)
	if err != nil || observed != disabled {
		return errors.New("deployment durable state mismatch")
	}
	return nil
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
	raw, err := ssh(ctx, runner, value, root, 30*time.Second, "sudo -n sh -c "+shellQuote(remoteRevocationScript(profileID)))
	category := strings.TrimSpace(string(raw))
	if err == nil && category == "REVOKE_PASS" {
		return nil
	}
	if err == nil || category != "REVOKE_COMMITTED_PENDING" {
		return errors.New("profile revocation failed")
	}
	raw, err = ssh(ctx, runner, value, root, 30*time.Second, "sudo -n sh -c "+shellQuote(remoteRevocationReconcileScript(profileID)))
	if err != nil || strings.TrimSpace(string(raw)) != "REVOKE_PASS" {
		return errors.New("profile revocation reconciliation failed")
	}
	return nil
}

func remoteRevocationScript(profileID string) string {
	return fmt.Sprintf(`set -eu
pass=%q
recovery=%q
profile_id=%s
[ -f "$pass" ] && [ ! -L "$pass" ] && [ -f "$recovery" ] && [ ! -L "$recovery" ]
tmp=$(mktemp -d /var/tmp/phase17-revoke.XXXXXX)
trap 'rm -rf "$tmp"' EXIT HUP INT TERM
chown kurd-node:kurd-node "$tmp"
install -o kurd-node -g kurd-node -m 0600 "$recovery" "$tmp/recovery"
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
exit "$status"
`, remotePassFile, remoteRecovery, shellQuote(profileID), remoteDataDir, remoteControl)
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
	return revokeRemoteProfile(ctx, runner, value, root, profileID)
}

func assertAndroidPrivacy(ctx context.Context, runner commandRunner, value config, root, serial string, forbiddenProbeURL []byte) error {
	packageIdentity, err := runText(ctx, runner, nil, root, value.adbPath, "-s", serial, "shell", "cmd", "package", "list", "packages", "-U", appPackage)
	if err != nil {
		return errors.New("Android package identity unavailable for privacy scan")
	}
	uid, err := parsePackageUID(packageIdentity, appPackage)
	if err != nil {
		return errors.New("Android package identity rejected")
	}
	arguments := []string{"-s", serial, "logcat", "-d", "-v", "brief", "--uid=" + uid}
	raw, err := runBytesWithLimit(ctx, runner, nil, root, 2*time.Minute, maxAndroidPrivacyLogBytes, value.adbPath, arguments...)
	if err != nil {
		return errors.New("Android privacy log scan unavailable")
	}
	defer clear(raw)
	if !safeCategory(raw) {
		return errors.New("Android privacy log scan found sensitive material")
	}
	if containsForbiddenProbeLogValue(raw, forbiddenProbeURL, value.ipv6ProbeAddress) {
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
	if err := executeStressCampaign(ctx, actions); err != nil {
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
	return verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized)
}

func remoteImpairmentApplyScript(scenario impairmentScenario) string {
	return "sudo -n tc qdisc replace dev kurd0 root netem " + scenario.netem
}

func remoteImpairmentCleanupScript() string {
	return "sudo -n sh -c 'tc qdisc del dev kurd0 root 2>/dev/null || true'"
}

func soak(ctx context.Context, runner commandRunner, value config, root, serial string, probeURL, probeDigest []byte, ipv6Authorized bool, tracker *resourceTracker) (uint64, uint64, uint64, error) {
	started := time.Now()
	deadline := started.Add(12 * time.Hour)
	var reconnects uint64
	var cycles uint64
	for cycle := 0; time.Now().Before(deadline); cycle++ {
		if err := verifyFieldTraffic(ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized); err != nil {
			return reconnects, 0, cycles, fmt.Errorf("soak cycle %d failed", cycle)
		}
		cycles++
		if cycle%10 == 9 {
			if err := remoteService(ctx, runner, value, root, "sudo -n systemctl restart kurd-node.service"); err != nil {
				return reconnects, 0, cycles, errors.New("soak restart failed")
			}
			if err := assertRemoteHealth(ctx, runner, value, root); err != nil {
				return reconnects, 0, cycles, err
			}
			reconnects++
		}
		if cycle%12 == 11 {
			if err := exerciseRemoteImpairment(
				ctx, runner, value, root, serial, probeURL, probeDigest, ipv6Authorized, frozenImpairmentMatrix[3],
			); err != nil {
				return reconnects, 0, cycles, fmt.Errorf("soak bounded interruption failed: %w", err)
			}
		}
		if err := observeRemoteMetrics(ctx, runner, value, root, tracker); err != nil {
			return reconnects, 0, cycles, fmt.Errorf("soak resource sample %d failed: %w", cycle, err)
		}
		fmt.Printf("PHASE17_PROGRESS soak %d elapsed_minutes=%d\n", cycles, uint64(time.Since(started).Minutes()))
		select {
		case <-ctx.Done():
			return reconnects, 0, cycles, ctx.Err()
		case <-time.After(5 * time.Minute):
		}
	}
	return reconnects, uint64(time.Since(started).Milliseconds()), cycles, nil
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
	return remoteService(ctx, runner, value, root, "sudo -n systemctl stop kurd-node.socket kurd-node.service")
}

func remoteService(ctx context.Context, runner commandRunner, value config, root, command string) error {
	_, err := ssh(ctx, runner, value, root, 2*time.Minute, command)
	return err
}

func ssh(ctx context.Context, runner commandRunner, value config, root string, timeout time.Duration, command string) ([]byte, error) {
	return runBytes(ctx, runner, nil, root, timeout, value.sshPath,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20", "--", value.sshAlias, command)
}

func sshScript(ctx context.Context, runner commandRunner, value config, root string, timeout time.Duration, script string) ([]byte, error) {
	return runBytes(ctx, runner, []byte(script), root, timeout, value.sshPath,
		"-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "-o", "ConnectTimeout=20", "--", value.sshAlias, "sudo -n sh -s")
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
		return output.data, fmt.Errorf("command failed")
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
	return runner.runWithLimit(ctx, stdin, directory, maximum, name, arguments...)
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
	raw, err := os.ReadFile(path)
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
	if _, err := runBytes(ctx, runner, nil, root, 2*time.Minute, value.scpPath, "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=yes", "--", value.packagePath, value.sshAlias+":"+remoteArchive); err != nil {
		return "", errors.New("package transfer failed")
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
		_ = remoteService(context.Background(), runner, value, root, "sudo -n rm -rf "+remoteArchive+" "+remoteRoot)
		category := strings.TrimSpace(string(raw))
		if category != "" && len(category) <= 256 && safeCategory([]byte(category)) {
			return "", fmt.Errorf("installed package identity rejected: %s", category)
		}
		return "", errors.New("installed package identity rejected")
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
	directory := filepath.Dir(path)
	file, err := os.CreateTemp(directory, ".phase17-field-*.tmp")
	if err != nil {
		return err
	}
	name := file.Name()
	failed := true
	defer func() {
		_ = file.Close()
		if failed {
			_ = os.Remove(name)
		}
	}()
	if err := file.Chmod(mode); err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil || file.Sync() != nil || file.Close() != nil {
		return errors.New("atomic evidence write failed")
	}
	if err := os.Rename(name, path); err != nil {
		return err
	}
	failed = false
	return nil
}

func clear(value []byte) {
	for index := range value {
		value[index] = 0
	}
	runtime.KeepAlive(value)
}
