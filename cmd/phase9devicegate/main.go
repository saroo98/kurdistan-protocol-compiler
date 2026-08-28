// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase9devicegate executes a labelled Android device suite and rejects
// false passes where instrumentation reports success while the app process
// crashes. It is intentionally separate from the host-only Android gate.
package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	defaultAppPackage  = "org.kurdistanvpn.app.debug"
	defaultTestPackage = "org.kurdistanvpn.app.debug.test"
	defaultRunner      = "androidx.test.runner.AndroidJUnitRunner"
	maxCommandEvidence = 2 << 20
	maxLogcatInput     = 4 << 20
	maxDiagnosticBytes = 16 << 10
	deviceGateTimeout  = 35 * time.Minute
)

var deviceEvidenceProperties = []struct {
	file string
	key  string
}{
	{"02-sdk-level.txt", "ro.build.version.sdk"},
	{"02-primary-abi.txt", "ro.product.cpu.abi"},
	{"02-supported-abis.txt", "ro.product.cpu.abilist"},
	{"02-security-patch.txt", "ro.build.version.security_patch"},
}

type options struct {
	adbPath               string
	serial                string
	appAPK                string
	testAPK               string
	appPackage            string
	testPackage           string
	runner                string
	minimumTests          int
	expectedAPI           int
	expectedABI           string
	expectedTestsFile     string
	evidenceDir           string
	conflictingAppPackage string
	label                 string
}

type expectedTest struct {
	name   string
	minSDK int
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "diagnose-junit" {
		os.Exit(runJUnitDiagnostics(os.Args[2:]))
	}
	var value options
	flag.StringVar(&value.adbPath, "adb", "", "adb executable; defaults to the configured Android SDK or PATH")
	flag.StringVar(&value.serial, "serial", "", "connected Android device serial; required when multiple devices are connected")
	flag.StringVar(&value.appAPK, "app-apk", "", "debug application APK")
	flag.StringVar(&value.testAPK, "test-apk", "", "debug instrumentation APK")
	flag.StringVar(&value.appPackage, "app-package", defaultAppPackage, "application package under test")
	flag.StringVar(&value.testPackage, "test-package", defaultTestPackage, "instrumentation package")
	flag.StringVar(&value.runner, "runner", defaultRunner, "instrumentation runner")
	flag.IntVar(&value.minimumTests, "minimum-tests", 1, "minimum number of completed instrumentation tests")
	flag.IntVar(&value.expectedAPI, "expected-api", 0, "exact Android API level expected for this lane; pair with expected-abi")
	flag.StringVar(&value.expectedABI, "expected-abi", "", "exact primary Android ABI expected for this lane; pair with expected-api")
	flag.StringVar(&value.expectedTestsFile, "expected-tests", "", "optional newline-delimited exact class#method manifest")
	flag.StringVar(&value.label, "label", "PHASE 9", "bounded uppercase evidence label")
	flag.StringVar(
		&value.conflictingAppPackage,
		"conflicting-app-package",
		"",
		"optional sibling application package to force-stop before the device suite",
	)
	flag.StringVar(
		&value.evidenceDir,
		"evidence-dir",
		filepath.FromSlash(".tools/phase9/device-gate/latest"),
		"directory for raw device evidence",
	)
	flag.Parse()
	if !validLabel(value.label) {
		fmt.Fprintln(os.Stderr, "ANDROID DEVICE GATE FAILED: invalid label")
		os.Exit(2)
	}
	if err := run(value); err != nil {
		fmt.Fprintf(os.Stderr, "%s DEVICE GATE FAILED: %v\n", value.label, err)
		os.Exit(1)
	}
	fmt.Printf("%s DEVICE GATE PASSED\n", value.label)
}

func validLabel(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, character := range value {
		if (character < 'A' || character > 'Z') &&
			(character < '0' || character > '9') &&
			character != ' ' && character != '-' {
			return false
		}
	}
	return true
}

func verifyExpectedDeviceIdentity(expectedAPI int, expectedABI string, actualAPI int, actualABI string) error {
	if expectedAPI < 0 {
		return errors.New("expected-api must be positive when supplied")
	}
	if (expectedAPI == 0) != (expectedABI == "") {
		return errors.New("expected-api and expected-abi must be supplied together")
	}
	if expectedABI != "" {
		allowed := map[string]bool{"arm64-v8a": true, "armeabi-v7a": true, "x86": true, "x86_64": true}
		if !allowed[expectedABI] {
			return fmt.Errorf("expected-abi %q is unsupported", expectedABI)
		}
	}
	if expectedAPI > 0 && actualAPI != expectedAPI {
		return fmt.Errorf("device API = %d, expected exactly %d", actualAPI, expectedAPI)
	}
	if expectedABI != "" && actualABI != expectedABI {
		return fmt.Errorf("device primary ABI = %q, expected exactly %q", actualABI, expectedABI)
	}
	return nil
}

func run(value options) error {
	if value.appAPK == "" || value.testAPK == "" {
		return errors.New("app-apk and test-apk are required")
	}
	if value.minimumTests < 1 {
		return errors.New("minimum-tests must be at least one")
	}
	expectedTestManifest, err := readExpectedTests(value.expectedTestsFile)
	if err != nil {
		return err
	}
	adb, err := locateADB(value.adbPath)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(value.evidenceDir, 0o755); err != nil {
		return fmt.Errorf("create evidence directory: %w", err)
	}
	if err := clearKnownEvidenceFiles(value.evidenceDir); err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(context.Background(), deviceGateTimeout)
	defer cancel()
	timeline := &diagnosticTimeline{Started: time.Now()}
	client := adbClient{path: adb, serial: value.serial, evidenceDir: value.evidenceDir, timeline: timeline}
	defer func() {
		if err := writeDiagnosticJSON(filepath.Join(value.evidenceDir, "01-command-timings.txt"), timeline); err != nil {
			fmt.Fprintln(os.Stderr, "command timing diagnostics INCOMPLETE")
		}
	}()
	if _, err := client.capture(ctx, "01-device-state.txt", "get-state"); err != nil {
		return fmt.Errorf("device state: %w", err)
	}
	sdkLevel := 0
	primaryABI := ""
	for _, property := range deviceEvidenceProperties {
		output, err := client.capture(ctx, property.file, "shell", "getprop", property.key)
		if err != nil {
			return fmt.Errorf("device compatibility property %s: %w", property.key, err)
		}
		if property.key == "ro.build.version.sdk" {
			sdkLevel, err = strconv.Atoi(strings.TrimSpace(output))
			if err != nil || sdkLevel < 1 {
				return fmt.Errorf("invalid device SDK level %q", strings.TrimSpace(output))
			}
		}
		if property.key == "ro.product.cpu.abi" {
			primaryABI = strings.TrimSpace(output)
			if primaryABI == "" {
				return errors.New("device primary ABI is empty")
			}
		}
	}
	if err := verifyExpectedDeviceIdentity(value.expectedAPI, value.expectedABI, sdkLevel, primaryABI); err != nil {
		return err
	}
	if err := waitForAndroidFramework(ctx, client, "02a"); err != nil {
		return err
	}
	expectedTests := expectedTestsForSDK(expectedTestManifest, sdkLevel)
	minimumTests := value.minimumTests
	if len(expectedTests) > 0 && minimumTests > len(expectedTests) {
		minimumTests = len(expectedTests)
	}
	if err := removeInstalledPackage(ctx, client, "test", value.testPackage); err != nil {
		return err
	}
	if err := removeInstalledPackage(ctx, client, "app", value.appPackage); err != nil {
		return err
	}
	if err := installPackage(ctx, client, "03-install-app.txt", value.appAPK); err != nil {
		return fmt.Errorf("install application: %w", err)
	}
	if err := installPackage(ctx, client, "04-install-test.txt", value.testAPK); err != nil {
		return fmt.Errorf("install instrumentation: %w", err)
	}
	if err := captureInstalledIdentity(ctx, client, value); err != nil {
		return err
	}
	recoveredPackageService, err := prepareInstrumentationRuntime(ctx, client, value.appPackage, value.testPackage)
	if err != nil {
		return err
	}
	if recoveredPackageService {
		if err := restoreInstalledPackages(ctx, client, value, "04r"); err != nil {
			return err
		}
	}
	if err := waitForAndroidFramework(ctx, client, "04i"); err != nil {
		return err
	}
	if value.conflictingAppPackage != "" {
		if _, err := client.capture(
			ctx,
			"04-conflicting-app-force-stop.txt",
			"shell",
			"am",
			"force-stop",
			value.conflictingAppPackage,
		); err != nil {
			return fmt.Errorf("force-stop conflicting application: %w", err)
		}
	}
	if err := configureInstalledPackages(ctx, client, value); err != nil {
		return err
	}
	if err := prepareLogcatBaseline(ctx, client, "05-clear-logcat.txt", value.appPackage); err != nil {
		return fmt.Errorf("clear logcat: %w", err)
	}
	_, _ = client.capture(ctx, "06-force-stop.txt", "shell", "am", "force-stop", value.appPackage)
	if _, err := client.capture(
		ctx,
		"07-home-before-launch.txt",
		"shell",
		"am",
		"start",
		"-W",
		"-a",
		"android.intent.action.MAIN",
		"-c",
		"android.intent.category.HOME",
	); err != nil {
		return fmt.Errorf("return device to Home before launch: %w", err)
	}
	time.Sleep(300 * time.Millisecond)
	if err := launchSmokeWithDiagnostics(ctx, client, value); err != nil {
		return err
	}
	_, _ = client.capture(ctx, "11-pre-test-force-stop.txt", "shell", "am", "force-stop", value.appPackage)
	if err := waitForAndroidFramework(ctx, client, "11a"); err != nil {
		return err
	}
	if err := prepareLogcatBaseline(ctx, client, "12-pre-test-clear-logcat.txt", value.appPackage); err != nil {
		return fmt.Errorf("clear pre-test logcat: %w", err)
	}
	instrumentation, instrumentationErr := client.captureInstrumentation(
		ctx,
		"13-instrumentation-summary.txt",
		"shell",
		"am",
		"instrument",
		"-w",
		"-r",
		value.testPackage+"/"+value.runner,
	)
	logcat, logcatErr := client.captureDiagnostic(ctx, "14-device-diagnostics.txt", value.appPackage, diagnosticLogcatArgs("all")...)
	crashLog, crashLogErr := client.captureDiagnostic(ctx, "15-crash-diagnostics.txt", value.appPackage, diagnosticLogcatArgs("crash")...)
	if logcatErr != nil {
		return fmt.Errorf("capture logcat: %w", logcatErr)
	}
	if crashLogErr != nil {
		return fmt.Errorf("capture crash log: %w", crashLogErr)
	}
	if err := evaluateInstrumentation(
		instrumentation,
		logcat+"\n"+crashLog,
		value.appPackage,
		minimumTests,
	); err != nil {
		if instrumentationErr != nil {
			return fmt.Errorf("%w; adb instrumentation error: %v", err, instrumentationErr)
		}
		return err
	}
	if len(expectedTests) > 0 {
		if err := verifyExpectedTests(instrumentation, expectedTests); err != nil {
			return err
		}
	}
	if instrumentationErr != nil {
		return fmt.Errorf("instrumentation command: %w", instrumentationErr)
	}
	summary := fmt.Sprintf(
		"device_gate=passed\nlabel=%s\napplication=%s\nsdk_level=%d\nprimary_abi=%s\nexpected_sdk_level=%d\nexpected_primary_abi=%s\nminimum_tests=%d\ncompleted_tests=%d\nexpected_tests=%d\n",
		value.label,
		value.appPackage,
		sdkLevel,
		primaryABI,
		value.expectedAPI,
		value.expectedABI,
		minimumTests,
		completedTestCount(instrumentation),
		len(expectedTests),
	)
	if err := os.WriteFile(filepath.Join(value.evidenceDir, "16-summary.txt"), []byte(summary), 0o644); err != nil {
		return fmt.Errorf("write summary: %w", err)
	}
	return nil
}

func launchSmokeWithDiagnostics(ctx context.Context, client adbClient, value options) error {
	observation := beginLaunchObservation(ctx, client, value)
	component := value.appPackage + "/org.kurdistanvpn.app.MainActivity"
	// NEW_TASK | CLEAR_TASK prevents a stale system picker, opened on behalf of
	// the app, from being restored as the top activity during the smoke launch.
	launchOutput, err := observation.captureLaunch(
		ctx,
		"08-launch.txt",
		"shell",
		"am",
		"start",
		"-W",
		"-f",
		"0x10008000",
		"-n",
		component,
	)
	if err != nil {
		return retainLaunchFailure(fmt.Errorf("launch smoke test: %w", err), func() error { return observation.finish(context.Background(), true) })
	}
	// The observational query runs inside, not in addition to, the original
	// two-second survival interval. The acceptance query below is unchanged.
	survivalAt := time.Now().Add(2 * time.Second)
	observation.processSnapshot(ctx, "immediately-after-launch", time.Second)
	if remaining := time.Until(survivalAt); remaining > 0 {
		time.Sleep(remaining)
	}
	pidOutput, pidErr := client.captureProcessState(ctx, "09-launch-process.txt", value.appPackage)
	observation.processSnapshot(ctx, "after-survival-interval", time.Second)
	if err := validateLaunchSmoke(launchOutput, pidOutput, value.appPackage, pidErr); err != nil {
		_, _ = client.captureDiagnostic(ctx, "10-launch-failure-diagnostics.txt", value.appPackage, diagnosticLogcatArgs("all")...)
		return retainLaunchFailure(err, func() error { return observation.finish(context.Background(), true) })
	}
	// A PID and a successful am response are necessary, not sufficient. Required
	// observations are collected inside the original gate deadline and consumed
	// before the startup gate can pass. The failure-only grace never admits work.
	if err := observation.finish(ctx, false); err != nil {
		return fmt.Errorf("launch observations NOT_AVAILABLE: %w", err)
	}
	return ctx.Err()
}

func (client adbClient) captureProcessState(ctx context.Context, name, appPackage string) (string, error) {
	output, err := client.captureOutput(ctx, "shell", "pidof", appPackage)
	alive := err == nil && strings.TrimSpace(output) != ""
	summary := fmt.Sprintf("schema=kurdistan-process-state-v1\napplication=%s\nalive=%t\n", appPackage, alive)
	if writeErr := os.WriteFile(filepath.Join(client.evidenceDir, name), []byte(summary), 0o644); writeErr != nil {
		return output, fmt.Errorf("write %s: %w", name, writeErr)
	}
	return output, err
}

func (client adbClient) captureInstrumentation(ctx context.Context, name string, args ...string) (string, error) {
	output, err := client.captureOutput(ctx, args...)
	summary := summarizeInstrumentation(output)
	if len(summary) > maxDiagnosticBytes {
		return output, errors.New("instrumentation summary exceeded its byte limit")
	}
	if writeErr := os.WriteFile(filepath.Join(client.evidenceDir, name), []byte(summary), 0o644); writeErr != nil {
		return output, fmt.Errorf("write %s: %w", name, writeErr)
	}
	return output, err
}

func diagnosticLogcatArgs(buffer string) []string {
	// Query a bounded recent window at the source. A complete API 36 device
	// suite can legitimately produce more than the diagnostic input ceiling;
	// asking logcat for its entire buffer would turn ordinary framework noise
	// into a false gate failure before the redacted summary is evaluated.
	// Instrumentation output independently preserves per-test completion and
	// crash markers, while this tail retains the most recent app-attributed
	// Java, native, and ANR evidence.
	return []string{"logcat", "-b", buffer, "-t", "4096", "-v", "brief", "*:W"}
}

func summarizeInstrumentation(input string) string {
	tests := completedTestCount(input)
	lower := strings.ToLower(input)
	failure := false
	for _, marker := range []string{"instrumentation_failed", "process crashed", "failures!!!", "shortmsg=process crashed"} {
		failure = failure || strings.Contains(lower, marker)
	}
	summary := fmt.Sprintf("schema=kurdistan-instrumentation-summary-v1\ncompleted_tests=%d\njunit_success=%t\nfailure_marker=%t\n", tests, strings.Contains(input, "OK ("), failure)
	started, completed := instrumentationProgress(input)
	if started != "" {
		summary += "last_started_test=" + started + "\n"
	}
	if completed != "" {
		summary += "last_completed_test=" + completed + "\n"
	}
	for _, test := range failedInstrumentationTests(input, 64) {
		summary += "failed_test=" + test + "\n"
	}
	if failure {
		category, exception := instrumentationFailureDetails(input)
		summary += "failure_category=" + category + "\n"
		if exception != "" {
			summary += "failure_exception=" + exception + "\n"
		}
	}
	return summary
}

func instrumentationFailureDetails(input string) (string, string) {
	lower := strings.ToLower(input)
	category := "test_failure"
	switch {
	case strings.Contains(lower, "accessibilityviewcheckexception"),
		strings.Contains(lower, "accessibility check"):
		category = "accessibility_assertion"
	case strings.Contains(lower, "composenotidleexception"),
		strings.Contains(lower, "idlingresourcetimeoutexception"),
		strings.Contains(lower, "appnotidleexception"),
		strings.Contains(lower, "timeoutexception"):
		category = "test_timeout"
	case strings.Contains(lower, "assertionerror"),
		strings.Contains(lower, "assertionfailederror"):
		category = "assertion"
	case strings.Contains(lower, "process crashed"),
		strings.Contains(lower, "instrumentation_failed"),
		strings.Contains(lower, "shortmsg=process crashed"):
		category = "process_failure"
	}

	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if !strings.HasPrefix(line, "INSTRUMENTATION_STATUS: stack=") {
			continue
		}
		stack := strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: stack="))
		fields := strings.Fields(stack)
		if len(fields) == 0 {
			break
		}
		candidate := strings.TrimSuffix(fields[0], ":")
		if safeExceptionIdentity(candidate) {
			return category, candidate
		}
		break
	}
	return category, ""
}

func safeExceptionIdentity(value string) bool {
	if len(value) == 0 || len(value) > 160 ||
		(!strings.HasSuffix(value, "Error") && !strings.HasSuffix(value, "Exception")) {
		return false
	}
	for _, char := range value {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '.' || char == '$' {
			continue
		}
		return false
	}
	return true
}

func instrumentationProgress(input string) (string, string) {
	var className, testName, lastStarted, lastCompleted string
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: class="):
			className = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: class="))
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: test="):
			testName = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: test="))
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS_CODE:"):
			code, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS_CODE:")))
			identity := className + "#" + testName
			if err == nil && safeTestIdentity(identity) {
				if code == 1 {
					lastStarted = identity
				}
				if code == 0 {
					lastCompleted = identity
				}
			}
			className, testName = "", ""
		}
	}
	return lastStarted, lastCompleted
}

type instrumentationPreparationCommand struct {
	evidence string
	args     []string
}

func instrumentationPreparationCommands(appPackage, testPackage string) []instrumentationPreparationCommand {
	return []instrumentationPreparationCommand{
		{evidence: "04d-disable-window-animations.txt", args: []string{"shell", "settings", "put", "global", "window_animation_scale", "0"}},
		{evidence: "04e-disable-transition-animations.txt", args: []string{"shell", "settings", "put", "global", "transition_animation_scale", "0"}},
		{evidence: "04f-disable-animator-duration.txt", args: []string{"shell", "settings", "put", "global", "animator_duration_scale", "0"}},
		{evidence: "04g-compile-application.txt", args: []string{"shell", "cmd", "package", "compile", "-m", "speed", "-f", appPackage}},
		{evidence: "04h-compile-instrumentation.txt", args: []string{"shell", "cmd", "package", "compile", "-m", "speed", "-f", testPackage}},
	}
}

func prepareInstrumentationRuntime(ctx context.Context, client adbClient, appPackage, testPackage string) (bool, error) {
	return prepareInstrumentationRuntimeWith(
		ctx,
		instrumentationPreparationCommands(appPackage, testPackage),
		client.capture,
		func(prefix string) error { return waitForAndroidFramework(ctx, client, prefix) },
	)
}

func prepareInstrumentationRuntimeWith(
	ctx context.Context,
	commands []instrumentationPreparationCommand,
	capture func(context.Context, string, ...string) (string, error),
	waitForFramework func(string) error,
) (bool, error) {
	recoveredPackageService := false
	for _, command := range commands {
		output, err := capture(ctx, command.evidence, command.args...)
		if err != nil && transientPackageServiceFailure(output) {
			recoveredPackageService = true
			stem := strings.TrimSuffix(command.evidence, filepath.Ext(command.evidence))
			if waitErr := waitForFramework(stem + "-retry"); waitErr != nil {
				return false, fmt.Errorf("prepare instrumentation runtime package service recovery (%s): %w", command.evidence, waitErr)
			}
			_, err = capture(ctx, stem+"-retry.txt", command.args...)
		}
		if err != nil {
			return false, fmt.Errorf("prepare instrumentation runtime (%s): %w", command.evidence, err)
		}
	}
	return recoveredPackageService, nil
}

func restoreInstalledPackages(ctx context.Context, client adbClient, value options, prefix string) error {
	if err := waitForAndroidFramework(ctx, client, prefix); err != nil {
		return err
	}
	if err := installPackage(ctx, client, prefix+"-install-app.txt", value.appAPK); err != nil {
		return fmt.Errorf("restore application after package service recovery: %w", err)
	}
	if err := installPackage(ctx, client, prefix+"-install-test.txt", value.testAPK); err != nil {
		return fmt.Errorf("restore instrumentation after package service recovery: %w", err)
	}
	if err := captureInstalledIdentity(ctx, client, value); err != nil {
		return fmt.Errorf("verify restored package identity: %w", err)
	}
	return nil
}

func packageConfigurationCommands(appPackage string, api int) []instrumentationPreparationCommand {
	commands := []instrumentationPreparationCommand{
		{evidence: "04-clear-app-data.txt", args: []string{"shell", "pm", "clear", appPackage}},
		{evidence: "04a-authorize-test-vpn.txt", args: []string{"shell", "appops", "set", appPackage, "ACTIVATE_VPN", "allow"}},
	}
	if api >= 33 {
		commands = append(commands, instrumentationPreparationCommand{
			evidence: "04b-grant-notification-permission.txt",
			args:     []string{"shell", "pm", "grant", appPackage, "android.permission.POST_NOTIFICATIONS"},
		})
	}
	return commands
}

func configureInstalledPackages(ctx context.Context, client adbClient, value options) error {
	if value.expectedAPI < 33 {
		if err := os.WriteFile(
			filepath.Join(value.evidenceDir, "04b-grant-notification-permission.txt"),
			[]byte("not_applicable=api_below_33\n"),
			0o644,
		); err != nil {
			return fmt.Errorf("record notification permission applicability: %w", err)
		}
	}
	return configureInstalledPackagesWith(
		ctx,
		packageConfigurationCommands(value.appPackage, value.expectedAPI),
		func(ctx context.Context, name string, args ...string) (string, error) {
			return client.capture(ctx, name, args...)
		},
		func(prefix string) error {
			return restoreInstalledPackages(ctx, client, value, prefix)
		},
	)
}

func configureInstalledPackagesWith(
	ctx context.Context,
	commands []instrumentationPreparationCommand,
	capture func(context.Context, string, ...string) (string, error),
	recoverPackages func(string) error,
) error {
	for attempt := 1; attempt <= 2; attempt++ {
		replay := false
		for _, command := range commands {
			evidence := command.evidence
			if attempt > 1 {
				stem := strings.TrimSuffix(command.evidence, filepath.Ext(command.evidence))
				evidence = stem + "-retry.txt"
			}
			output, err := capture(ctx, evidence, command.args...)
			if err == nil {
				continue
			}
			if attempt == 1 && transientPackageServiceFailure(output) {
				stem := strings.TrimSuffix(command.evidence, filepath.Ext(command.evidence))
				if recoverErr := recoverPackages(stem + "-recovery"); recoverErr != nil {
					return fmt.Errorf("configure installed packages recovery (%s): %w", command.evidence, recoverErr)
				}
				replay = true
				break
			}
			return fmt.Errorf("configure installed packages (%s): %w", command.evidence, err)
		}
		if !replay {
			return nil
		}
	}
	return errors.New("configure installed packages exhausted recovery budget")
}

func failedInstrumentationTests(input string, limit int) []string {
	if limit < 1 {
		return nil
	}
	var className, testName string
	failed := make([]string, 0)
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: class="):
			className = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: class="))
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: test="):
			testName = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: test="))
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS_CODE:"):
			code, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS_CODE:")))
			if err == nil && code < 0 {
				identity := className + "#" + testName
				if safeTestIdentity(identity) {
					failed = append(failed, identity)
					if len(failed) == limit {
						return failed
					}
				}
			}
			className, testName = "", ""
		}
	}
	return failed
}

func safeTestIdentity(value string) bool {
	if value == "#" || len(value) > 256 || strings.Count(value, "#") != 1 {
		return false
	}
	for _, character := range value {
		if (character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			character == '.' || character == '_' || character == '$' || character == '#' {
			continue
		}
		return false
	}
	return true
}

func waitForAndroidFramework(parent context.Context, client adbClient, evidencePrefix string) error {
	ctx, cancel := context.WithTimeout(parent, 2*time.Minute)
	defer cancel()

	const requiredConsecutiveChecks = 3
	consecutive := 0
	for attempt := 1; ; attempt++ {
		activityName := fmt.Sprintf("%s-framework-activity-%03d.txt", evidencePrefix, attempt)
		packageName := fmt.Sprintf("%s-framework-package-%03d.txt", evidencePrefix, attempt)
		activityOutput, activityErr := client.capture(ctx, activityName, "shell", "service", "check", "activity")
		packageOutput, packageErr := client.capture(ctx, packageName, "shell", "service", "check", "package")
		if frameworkServicesReady(activityOutput, activityErr, packageOutput, packageErr) {
			consecutive++
			if consecutive == requiredConsecutiveChecks {
				return nil
			}
		} else {
			consecutive = 0
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("Android activity and package services did not remain healthy: %w", ctx.Err())
		case <-time.After(time.Second):
		}
	}
}

func frameworkServicesReady(activityOutput string, activityErr error, packageOutput string, packageErr error) bool {
	if activityErr != nil || packageErr != nil {
		return false
	}
	activity := strings.ToLower(strings.TrimSpace(activityOutput))
	packages := strings.ToLower(strings.TrimSpace(packageOutput))
	return activity == "service activity: found" && packages == "service package: found"
}

func installPackage(ctx context.Context, client adbClient, evidenceName, apkPath string) error {
	output, err := client.capture(ctx, evidenceName, "install", "-r", apkPath)
	if err == nil {
		return nil
	}
	if !transientPackageServiceFailure(output) {
		return err
	}
	stem := strings.TrimSuffix(evidenceName, filepath.Ext(evidenceName))
	if waitErr := waitForAndroidFramework(ctx, client, stem+"-retry"); waitErr != nil {
		return fmt.Errorf("package service recovery: %w", waitErr)
	}
	_, retryErr := client.capture(ctx, stem+"-retry.txt", "install", "-r", apkPath)
	return retryErr
}

func transientPackageServiceFailure(output string) bool {
	normalized := strings.ToLower(output)
	return strings.Contains(normalized, "failure calling service package") &&
		strings.Contains(normalized, "broken pipe")
}

func removeInstalledPackage(ctx context.Context, client adbClient, label, packageName string) error {
	output, err := client.capture(
		ctx,
		"03-query-"+label+"-package.txt",
		"shell",
		"pm",
		"list",
		"packages",
		"--user",
		"0",
		packageName,
	)
	if err != nil {
		return fmt.Errorf("query installed %s package: %w", label, err)
	}
	if !packageListContainsExact(output, packageName) {
		return nil
	}
	if _, err := client.capture(
		ctx,
		"03-uninstall-"+label+"-package.txt",
		"uninstall",
		packageName,
	); err != nil {
		return fmt.Errorf("remove installed %s package: %w", label, err)
	}
	return nil
}

func packageListContainsExact(output, packageName string) bool {
	want := "package:" + strings.TrimSpace(packageName)
	if want == "package:" {
		return false
	}
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == want {
			return true
		}
	}
	return false
}

func clearKnownEvidenceFiles(directory string) error {
	for index := 1; index <= 16; index++ {
		matches, err := filepath.Glob(filepath.Join(directory, fmt.Sprintf("%02d-*.txt", index)))
		if err != nil {
			return fmt.Errorf("enumerate stale device evidence: %w", err)
		}
		for _, path := range matches {
			if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("remove stale device evidence %s: %w", filepath.Base(path), err)
			}
		}
	}
	return nil
}

func validateLaunchSmoke(launchOutput, pidOutput, appPackage string, pidErr error) error {
	if pidErr != nil || strings.TrimSpace(pidOutput) == "" {
		return errors.New("application process did not survive launch")
	}
	pid, err := strconv.ParseInt(strings.TrimSpace(pidOutput), 10, 32)
	if err != nil || pid < 1 {
		return errors.New("launch process identity NOT_AVAILABLE")
	}
	lines, complete := sanitizeLaunchOutput(launchOutput, appPackage)
	return validateTerminalLaunch(lines, complete, appPackage)
}

func validateTerminalLaunch(lines []string, complete bool, appPackage string) error {
	if !complete || len(lines) < 5 || lines[len(lines)-1] != "Complete" {
		return errors.New("terminal launch evidence NOT_AVAILABLE")
	}
	seen := map[string]bool{}
	for _, line := range lines {
		key, _, _ := strings.Cut(line, ":")
		if seen[key] {
			return errors.New("ambiguous launch evidence NOT_AVAILABLE")
		}
		seen[key] = true
		switch key {
		case "Starting":
			if line != "Starting: "+appPackage+"/org.kurdistanvpn.app.MainActivity" {
				return errLaunchIncomplete
			}
		case "LaunchState":
			if line != "LaunchState: COLD" && line != "LaunchState: WARM" && line != "LaunchState: HOT" {
				return errLaunchIncomplete
			}
		case "ThisTime", "TotalTime", "WaitTime":
			value := strings.TrimPrefix(line, key+": ")
			if _, err := strconv.ParseUint(value, 10, 31); err != nil {
				return errLaunchIncomplete
			}
		case "Complete":
		case "Status":
			if line != "Status: ok" {
				return errors.New("launch did not succeed")
			}
		case "Activity":
			if line != "Activity: "+appPackage+"/org.kurdistanvpn.app.MainActivity" {
				return errors.New("launch resolved to another activity")
			}
		default:
			return errors.New("unknown launch evidence NOT_AVAILABLE")
		}
	}
	for _, key := range []string{"Status", "Activity", "TotalTime", "WaitTime", "Complete"} {
		if !seen[key] {
			return errors.New("incomplete launch evidence NOT_AVAILABLE")
		}
	}
	return nil
}

func logcatClearArgs() []string {
	// Android 8 can reject the adb host-side `logcat -c` service command even
	// though the device shell command is supported. Clearing through the shell
	// works across the supported API 26-36 matrix and still fails closed when
	// the device or logcat process is unavailable.
	return []string{"shell", "logcat", "-b", "all", "-c"}
}

func prepareLogcatBaseline(ctx context.Context, client adbClient, evidenceName, appPackage string) error {
	if _, err := client.capture(ctx, evidenceName, logcatClearArgs()...); err == nil {
		return nil
	}
	// API 26 can transiently fail the first clear immediately after package
	// installation while logd reopens its buffers. Retry once and preserve both
	// command results before attempting the bounded clean-baseline fallback.
	time.Sleep(250 * time.Millisecond)
	stem := strings.TrimSuffix(evidenceName, filepath.Ext(evidenceName))
	retryName := stem + "-retry.txt"
	if _, err := client.capture(ctx, retryName, logcatClearArgs()...); err == nil {
		return nil
	}

	// Some API 26 images deny log-buffer clearing to the shell user. Android's
	// own logcat documentation notes that options can be root-only and vary by
	// OS version. In that case, fail closed unless bounded, redacted snapshots
	// prove that the pre-run buffers contain no crash attributed to this app.
	// This preserves crash detection without requiring elevated emulator access.
	mainSummary, mainErr := client.captureDiagnostic(
		ctx,
		stem+"-baseline-main.txt",
		appPackage,
		diagnosticLogcatArgs("all")...,
	)
	crashSummary, crashErr := client.captureDiagnostic(
		ctx,
		stem+"-baseline-crash.txt",
		appPackage,
		diagnosticLogcatArgs("crash")...,
	)
	if mainErr != nil || crashErr != nil {
		return fmt.Errorf("log buffers cannot be cleared or safely baselined: main=%v crash=%v", mainErr, crashErr)
	}
	if !diagnosticBaselineIsClean(mainSummary, crashSummary) {
		return errors.New("log buffers cannot be cleared and contain a pre-existing app crash")
	}
	status := "schema=kurdistan-logcat-baseline-v1\nclear_supported=false\napp_crash=false\n"
	if err := os.WriteFile(filepath.Join(client.evidenceDir, stem+"-baseline-status.txt"), []byte(status), 0o644); err != nil {
		return fmt.Errorf("write logcat baseline status: %w", err)
	}
	return nil
}

func diagnosticBaselineIsClean(summaries ...string) bool {
	return !diagnosticSummaryReportsCrash(strings.Join(summaries, "\n"))
}

type adbClient struct {
	path        string
	serial      string
	evidenceDir string
	timeline    *diagnosticTimeline
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	exceeded bool
}

func (buffer *boundedBuffer) Write(input []byte) (int, error) {
	remaining := buffer.limit - buffer.buffer.Len()
	if remaining > 0 {
		write := len(input)
		if write > remaining {
			write = remaining
		}
		_, _ = buffer.buffer.Write(input[:write])
	}
	if len(input) > remaining {
		buffer.exceeded = true
	}
	return len(input), nil
}

func (buffer *boundedBuffer) String() string { return buffer.buffer.String() }
func (buffer *boundedBuffer) Bytes() []byte  { return buffer.buffer.Bytes() }

func (client adbClient) capture(ctx context.Context, name string, args ...string) (output string, resultErr error) {
	started := time.Now()
	defer func() { client.timeline.record(name, started, resultErr) }()
	commandArgs := make([]string, 0, len(args)+2)
	if client.serial != "" {
		commandArgs = append(commandArgs, "-s", client.serial)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, client.path, commandArgs...)
	combined := boundedBuffer{limit: maxCommandEvidence}
	command.Stdout = &combined
	command.Stderr = &combined
	err := command.Run()
	if writeErr := os.WriteFile(filepath.Join(client.evidenceDir, name), combined.Bytes(), 0o644); writeErr != nil {
		return combined.String(), fmt.Errorf("write %s: %w", name, writeErr)
	}
	if combined.exceeded {
		return combined.String(), fmt.Errorf("adb evidence exceeded %d bytes", maxCommandEvidence)
	}
	return combined.String(), err
}

func (client adbClient) captureDiagnostic(ctx context.Context, name, appPackage string, args ...string) (output string, resultErr error) {
	started := time.Now()
	defer func() { client.timeline.record(name, started, resultErr) }()
	commandArgs := make([]string, 0, len(args)+2)
	if client.serial != "" {
		commandArgs = append(commandArgs, "-s", client.serial)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, client.path, commandArgs...)
	combined := boundedBuffer{limit: maxLogcatInput}
	command.Stdout = &combined
	command.Stderr = &combined
	commandErr := command.Run()
	summary := summarizeDiagnostics(combined.String(), appPackage, combined.exceeded)
	if len(summary) > maxDiagnosticBytes {
		return summary[:maxDiagnosticBytes], errors.New("sanitized diagnostic summary exceeded its byte limit")
	}
	if err := os.WriteFile(filepath.Join(client.evidenceDir, name), []byte(summary), 0o644); err != nil {
		return summary, fmt.Errorf("write %s: %w", name, err)
	}
	if combined.exceeded {
		return summary, fmt.Errorf("diagnostic input exceeded %d bytes", maxLogcatInput)
	}
	return summary, commandErr
}

func summarizeDiagnostics(input, appPackage string, truncated bool) string {
	lower := strings.ToLower(strings.ReplaceAll(input, "\r\n", "\n"))
	packageName := strings.ToLower(strings.TrimSpace(appPackage))
	appCrash := containsAppCrash(lower, packageName)
	anr := false
	javaCrash := false
	nativeCrash := false
	for _, line := range strings.Split(lower, "\n") {
		line = strings.TrimSpace(line)
		if packageIdentityAt(line, "anr in ", packageName) {
			anr = true
		}
		if strings.Contains(line, "fatal exception") && strings.Contains(lower, "process: "+packageName) {
			javaCrash = true
		}
		if strings.Contains(line, "fatal signal") && (strings.Contains(lower, "cmdline: "+packageName) || strings.Contains(lower, ">>> "+packageName)) {
			nativeCrash = true
		}
	}
	instrumentationFailure := false
	for _, marker := range []string{"instrumentation_failed", "process crashed", "failures!!!", "shortmsg=process crashed"} {
		instrumentationFailure = instrumentationFailure || strings.Contains(lower, marker)
	}
	summary := fmt.Sprintf(
		"schema=kurdistan-device-diagnostic-summary-v1\napp_package=%s\ninput_truncated=%t\napp_crash=%t\njava_crash=%t\nnative_crash=%t\nanr=%t\ninstrumentation_failure=%t\n",
		appPackage, truncated, appCrash, javaCrash, nativeCrash, anr, instrumentationFailure,
	)
	if appCrash {
		// The legacy summary remains payload/stack-free. Detailed launch stacks
		// are retained only by the separately window-bound diagnostic observer.
		for _, detail := range attributedJavaDetails(input, appPackage) {
			summary += "exception_class=" + detail.Class + "\nexception_message=" + detail.Message + "\n"
		}
	}
	return summary
}

func captureInstalledIdentity(ctx context.Context, client adbClient, value options) error {
	appPaths, appErr := client.captureOutput(ctx, "shell", "pm", "path", value.appPackage)
	testPaths, testErr := client.captureOutput(ctx, "shell", "pm", "path", value.testPackage)
	runners, runnerErr := client.captureOutput(ctx, "shell", "pm", "list", "instrumentation")
	if appErr != nil || testErr != nil || runnerErr != nil {
		return errors.New("query installed package identity")
	}
	appSplits := installedPathCount(appPaths)
	testSplits := installedPathCount(testPaths)
	expectedRunner := "instrumentation:" + value.testPackage + "/" + value.runner + " (target=" + value.appPackage + ")"
	if appSplits < 1 || testSplits < 1 || !containsExactLine(runners, expectedRunner) {
		return errors.New("installed application or instrumentation identity is incomplete")
	}
	appDigest, err := fileSHA256(value.appAPK)
	if err != nil {
		return fmt.Errorf("digest application APK: %w", err)
	}
	testDigest, err := fileSHA256(value.testAPK)
	if err != nil {
		return fmt.Errorf("digest instrumentation APK: %w", err)
	}
	summary := fmt.Sprintf("schema=kurdistan-installed-package-identity-v1\napplication=%s\napplication_splits=%d\napplication_apk_sha256=%s\ninstrumentation=%s\ninstrumentation_splits=%d\ninstrumentation_apk_sha256=%s\nrunner=%s\n", value.appPackage, appSplits, appDigest, value.testPackage, testSplits, testDigest, value.runner)
	if err := os.WriteFile(filepath.Join(value.evidenceDir, "04c-installed-package-identity.txt"), []byte(summary), 0o644); err != nil {
		return fmt.Errorf("write installed package identity: %w", err)
	}
	return nil
}

func (client adbClient) captureOutput(ctx context.Context, args ...string) (output string, resultErr error) {
	started := time.Now()
	defer func() { client.timeline.record("identity-query", started, resultErr) }()
	commandArgs := make([]string, 0, len(args)+2)
	if client.serial != "" {
		commandArgs = append(commandArgs, "-s", client.serial)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, client.path, commandArgs...)
	combined := boundedBuffer{limit: maxCommandEvidence}
	command.Stdout, command.Stderr = &combined, &combined
	err := command.Run()
	if combined.exceeded {
		return combined.String(), fmt.Errorf("adb identity output exceeded %d bytes", maxCommandEvidence)
	}
	return combined.String(), err
}

func installedPathCount(output string) int {
	count := 0
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "package:") {
			count++
		}
	}
	return count
}

func containsExactLine(output, wanted string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == wanted {
			return true
		}
	}
	return false
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", hash.Sum(nil)), nil
}

func locateADB(explicit string) (string, error) {
	if explicit != "" {
		return explicit, nil
	}
	executable := "adb"
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	for _, variable := range []string{"ANDROID_HOME", "ANDROID_SDK_ROOT"} {
		if root := os.Getenv(variable); root != "" {
			candidate := filepath.Join(root, "platform-tools", executable)
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				return candidate, nil
			}
		}
	}
	path, err := exec.LookPath(executable)
	if err != nil {
		return "", errors.New("adb was not found; set ANDROID_HOME, ANDROID_SDK_ROOT, PATH, or -adb")
	}
	return path, nil
}

func readExpectedTests(path string) ([]expectedTest, error) {
	if path == "" {
		return nil, nil
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read expected tests: %w", err)
	}
	seen := map[string]bool{}
	var tests []expectedTest
	for _, line := range strings.Split(strings.ReplaceAll(string(encoded), "\r\n", "\n"), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		minimumSDK := 0
		testName := line
		if strings.HasPrefix(line, "minSdk=") {
			fields := strings.Fields(line)
			if len(fields) != 2 {
				return nil, fmt.Errorf("invalid expected test %q", line)
			}
			minimumSDK, err = strconv.Atoi(strings.TrimPrefix(fields[0], "minSdk="))
			if err != nil || minimumSDK < 1 {
				return nil, fmt.Errorf("invalid expected test SDK guard %q", fields[0])
			}
			testName = fields[1]
		}
		parts := strings.Split(testName, "#")
		if len(parts) != 2 || parts[0] == "" || parts[1] == "" || seen[testName] {
			return nil, fmt.Errorf("invalid expected test %q", line)
		}
		seen[testName] = true
		tests = append(tests, expectedTest{name: testName, minSDK: minimumSDK})
	}
	if len(tests) == 0 {
		return nil, errors.New("expected test manifest is empty")
	}
	sort.Slice(tests, func(left, right int) bool { return tests[left].name < tests[right].name })
	return tests, nil
}

func expectedTestsForSDK(manifest []expectedTest, sdkLevel int) []string {
	tests := make([]string, 0, len(manifest))
	for _, test := range manifest {
		if test.minSDK == 0 || sdkLevel >= test.minSDK {
			tests = append(tests, test.name)
		}
	}
	sort.Strings(tests)
	return tests
}

func verifyExpectedTests(output string, expected []string) error {
	actualSet := map[string]bool{}
	var className, testName string
	for _, raw := range strings.Split(strings.ReplaceAll(output, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		switch {
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: class="):
			className = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: class="))
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: test="):
			testName = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: test="))
		case line == "INSTRUMENTATION_STATUS_CODE: 0" && className != "" && testName != "":
			actualSet[className+"#"+testName] = true
			className, testName = "", ""
		}
	}
	actual := make([]string, 0, len(actualSet))
	for test := range actualSet {
		actual = append(actual, test)
	}
	sort.Strings(actual)
	want := append([]string(nil), expected...)
	sort.Strings(want)
	if strings.Join(actual, "\n") != strings.Join(want, "\n") {
		return fmt.Errorf("executed test manifest differs: got %v want %v", actual, want)
	}
	return nil
}

func evaluateInstrumentation(output, logcat, appPackage string, minimumTests int) error {
	lowerOutput := strings.ToLower(output)
	for _, marker := range []string{
		"process crashed",
		"instrumentation_failed",
		"failures!!!",
		"shortmsg=process crashed",
	} {
		if strings.Contains(lowerOutput, marker) {
			return fmt.Errorf("instrumentation reported %q", marker)
		}
	}
	completed := completedTestCount(output)
	if completed < minimumTests {
		return fmt.Errorf("completed %d tests, require at least %d", completed, minimumTests)
	}
	if !strings.Contains(output, "OK (") {
		return errors.New("instrumentation did not report a successful JUnit completion")
	}
	if diagnosticSummaryReportsCrash(logcat) || containsAppCrash(logcat, appPackage) {
		return errors.New("device log records an application crash during the test interval")
	}
	return nil
}

func completedTestCount(output string) int {
	count := 0
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "INSTRUMENTATION_STATUS_CODE:") {
			value := strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS_CODE:"))
			code, err := strconv.Atoi(value)
			if err == nil && code == 0 {
				count++
			}
		}
	}
	return count
}

func containsAppCrash(logcat, appPackage string) bool {
	packageName := strings.ToLower(strings.TrimSpace(appPackage))
	if packageName == "" {
		return false
	}
	lines := strings.Split(strings.ToLower(strings.ReplaceAll(logcat, "\r\n", "\n")), "\n")
	javaCrashLinesRemaining := 0
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "fatal exception") {
			javaCrashLinesRemaining = 16
			if crashMarkerNamesPackage(line, packageName) {
				return true
			}
			continue
		}
		if strings.Contains(line, "fatal signal") ||
			strings.Contains(line, "app crash") ||
			strings.Contains(line, "process crashed") ||
			strings.Contains(line, "anr in ") {
			if crashMarkerNamesPackage(line, packageName) {
				return true
			}
		}
		// Android native tombstones identify the crashed executable using
		// Cmdline and >>> process <<< records. Those records are authoritative
		// even when the initial fatal-signal line contains only a PID.
		if strings.Contains(line, "cmdline:") || strings.Contains(line, ">>>") {
			if crashIdentityNamesPackage(line, packageName) {
				return true
			}
		}
		if javaCrashLinesRemaining > 0 {
			if strings.Contains(line, "process:") && crashIdentityNamesPackage(line, packageName) {
				return true
			}
			javaCrashLinesRemaining--
		}
	}
	return false
}

func diagnosticSummaryReportsCrash(summary string) bool {
	for _, line := range strings.Split(strings.ReplaceAll(summary, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "app_crash=true" {
			return true
		}
	}
	return false
}

func crashMarkerNamesPackage(line, packageName string) bool {
	for _, prefix := range []string{
		"anr in ",
		" in ",
		"process ",
		"package ",
	} {
		if packageIdentityAt(line, prefix, packageName) {
			return true
		}
	}
	return false
}

func crashIdentityNamesPackage(line, packageName string) bool {
	for _, prefix := range []string{
		"process: ",
		"cmdline: ",
		">>> ",
	} {
		if packageIdentityAt(line, prefix, packageName) {
			return true
		}
	}
	return false
}

func packageIdentityAt(line, prefix, packageName string) bool {
	searchFrom := 0
	for {
		index := strings.Index(line[searchFrom:], prefix)
		if index < 0 {
			return false
		}
		identityStart := searchFrom + index + len(prefix)
		if strings.HasPrefix(line[identityStart:], packageName) {
			identityEnd := identityStart + len(packageName)
			if identityEnd == len(line) || isProcessIdentityBoundary(line[identityEnd]) {
				return true
			}
		}
		searchFrom = identityStart
	}
}

func isProcessIdentityBoundary(character byte) bool {
	switch character {
	case ':', ',', ' ', '\t', '<', ')', ']':
		return true
	default:
		return false
	}
}

// Launch observations are diagnostic-only. They cannot satisfy instrumentation,
// qualification, receipt or launch-survival policy. Raw data is bounded in memory;
// only allow-listed, invocation-windowed fields can reach disk.
const maxLaunchDiagnosticBytes = 128 << 10

type diagnosticTiming struct {
	Phase      string    `json:"phase"`
	StartedUTC time.Time `json:"startedUtc"`
	ElapsedMS  int64     `json:"elapsedMs"`
	DurationMS int64     `json:"durationMs"`
	ExitCode   int       `json:"exitCode"`
	Status     string    `json:"status"`
}

type diagnosticTimeline struct {
	mu        sync.Mutex
	Started   time.Time
	Commands  []diagnosticTiming
	Truncated bool
}

func (timeline *diagnosticTimeline) record(phase string, started time.Time, err error) {
	if timeline == nil {
		return
	}
	timeline.mu.Lock()
	defer timeline.mu.Unlock()
	if len(timeline.Commands) == 1024 {
		timeline.Truncated = true
		return
	}
	status, code := diagnosticCommandStatus(err)
	timeline.Commands = append(timeline.Commands, diagnosticTiming{
		Phase: phase, StartedUTC: started.UTC(), ElapsedMS: started.Sub(timeline.Started).Milliseconds(),
		DurationMS: time.Since(started).Milliseconds(), ExitCode: code, Status: status,
	})
}

func diagnosticCommandStatus(err error) (string, int) {
	if err == nil {
		return "CAPTURED", 0
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "DEADLINE", -1
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELLED", -1
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return "ERROR", exit.ExitCode()
	}
	return "INCOMPLETE", -1
}

func writeDiagnosticJSON(path string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > maxLaunchDiagnosticBytes {
		return errors.New("diagnostics INCOMPLETE: output bound")
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o600)
}

type exceptionDetail struct {
	Class           string
	Message         string
	MessageRedacted bool
	Stack           []string
}

var diagnosticClassPattern = regexp.MustCompile("^[A-Za-z_$][A-Za-z0-9_$]*(?:\\.[A-Za-z_$][A-Za-z0-9_$]*)+$")
var diagnosticFramePattern = regexp.MustCompile("^\\s*at ([A-Za-z0-9_.$/@+-]+)\\(([A-Za-z0-9_.$-]+\\.(?:kt|java):[0-9]{1,7}|SourceFile:[0-9]{1,7}|Unknown Source|Native Method)\\)$")
var elidedFramePattern = regexp.MustCompile("^\\.\\.\\. [0-9]{1,4} more$")

func safeDiagnosticClass(value string) bool {
	if len(value) > 240 || !diagnosticClassPattern.MatchString(value) {
		return false
	}
	for _, prefix := range []string{"org.kurdistanvpn.", "android.", "androidx.", "java.", "javax.", "kotlin.", "kotlinx.", "dalvik.", "com.android.", "jdk.", "sun.", "org.junit.", "org.gradle.", "worker.org.gradle."} {
		if strings.HasPrefix(value, prefix) {
			return true
		}
	}
	return false
}

func diagnosticMessage(message string) (string, bool) {
	message = strings.TrimSpace(message)
	if len(message) > 2048 {
		return "[REDACTED_MESSAGE]", false
	}
	switch message {
	case "", "Failed requirement.", "Check failed.", "Required value was null.", "null",
		"SETTINGS_OWNER_CLOSED", "STALE_SETTINGS_PROJECTION", "SHARED_LEGACY_OWNER_CANNOT_BE_CLOSED":
		return message, true
	}
	for _, prefix := range []string{"Unable to create application ", "Unable to instantiate application ", "Unable to start activity "} {
		if strings.HasPrefix(message, prefix) {
			rest := strings.TrimPrefix(message, prefix)
			name, nested, found := strings.Cut(rest, ": ")
			if safeDiagnosticClass(name) {
				if !found {
					return prefix + name, true
				}
				value, complete := diagnosticMessage(nested)
				return prefix + name + ": " + value, complete
			}
		}
	}
	name, nested, found := strings.Cut(message, ": ")
	if found && safeExceptionIdentity(name) && safeDiagnosticClass(name) {
		value, complete := diagnosticMessage(nested)
		return name + ": " + value, complete
	}
	return "[REDACTED_MESSAGE]", false
}

func javaFailureDetails(input string) ([]exceptionDetail, bool) {
	if len(input) > maxLogcatInput {
		return nil, false
	}
	var details []exceptionDetail
	complete := true
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		line = strings.TrimPrefix(line, "Caused by: ")
		line = strings.TrimPrefix(line, "Suppressed: ")
		name, message, _ := strings.Cut(line, ": ")
		if safeExceptionIdentity(name) && safeDiagnosticClass(name) {
			if len(details) == 16 {
				complete = false
				break
			}
			safe, ok := diagnosticMessage(message)
			complete = complete && ok
			details = append(details, exceptionDetail{Class: name, Message: safe, MessageRedacted: !ok})
			continue
		}
		if len(details) == 0 {
			complete = false
			continue
		}
		if frame := diagnosticFramePattern.FindStringSubmatch(line); frame != nil {
			identity := frame[1]
			if slash := strings.LastIndex(identity, "/"); slash >= 0 {
				identity = identity[slash+1:]
			}
			if safeDiagnosticClass(identity) && len(details[len(details)-1].Stack) < 128 {
				details[len(details)-1].Stack = append(details[len(details)-1].Stack, "at "+identity+"("+frame[2]+")")
				continue
			}
		}
		if elidedFramePattern.MatchString(line) && len(details[len(details)-1].Stack) < 128 {
			details[len(details)-1].Stack = append(details[len(details)-1].Stack, line)
			continue
		}
		complete = false
	}
	return details, complete && len(details) != 0
}

func attributedJavaDetails(input, app string) []exceptionDetail {
	var selected []string
	active := false
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if at := strings.Index(line, "Process: "); at >= 0 {
			active = packageIdentityAt(line[at:], "Process: ", app)
			continue
		}
		if strings.Contains(line, "FATAL EXCEPTION") {
			active = false
			continue
		}
		if !active {
			continue
		}
		if at := strings.Index(line, "AndroidRuntime: "); at >= 0 {
			line = line[at+len("AndroidRuntime: "):]
		}
		selected = append(selected, line)
	}
	details, _ := javaFailureDetails(strings.Join(selected, "\n"))
	return details
}

func retainLaunchFailure(original error, preserve func() error) error {
	if err := preserve(); err != nil {
		fmt.Fprintln(os.Stderr, "launch diagnostics INCOMPLETE")
	}
	return original
}

type launchLogEvent struct {
	DeviceNanos int64
	PID         int
	TID         int
	Tag         string
	Text        string
}

var epochLogPattern = regexp.MustCompile("^\\s*([0-9]{1,12}\\.[0-9]{1,9})\\s+([0-9]+)\\s+([0-9]+)\\s+([VDIWEF])\\s+([A-Za-z0-9_.-]+)\\s*:\\s?(.*)$")
var processLogPattern = regexp.MustCompile("^Process: ([A-Za-z0-9_.:]+), PID: ([0-9]+)$")
var processSuffixPattern = regexp.MustCompile("^[A-Za-z0-9_.]+$")

func epochNanos(value string) (int64, error) {
	parts := strings.Split(strings.TrimSpace(value), ".")
	if len(parts) != 2 || len(parts[1]) > 9 || len(parts[1]) == 0 {
		return 0, errors.New("invalid diagnostic clock")
	}
	if strings.Trim(parts[0]+parts[1], "0123456789") != "" {
		return 0, errors.New("invalid diagnostic clock")
	}
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || seconds < 0 || seconds > 9_000_000_000 {
		return 0, errors.New("invalid diagnostic clock")
	}
	fraction, err := strconv.ParseInt(parts[1]+strings.Repeat("0", 9-len(parts[1])), 10, 64)
	if err != nil {
		return 0, err
	}
	return seconds*1_000_000_000 + fraction, nil
}

func parseEpochLog(line string) (launchLogEvent, bool) {
	match := epochLogPattern.FindStringSubmatch(line)
	if match == nil {
		return launchLogEvent{}, false
	}
	nanos, err := epochNanos(match[1])
	pid, pidErr := strconv.ParseInt(match[2], 10, 32)
	tid, tidErr := strconv.ParseInt(match[3], 10, 32)
	if err != nil || pidErr != nil || tidErr != nil || pid < 1 || tid < 1 {
		return launchLogEvent{}, false
	}
	return launchLogEvent{DeviceNanos: nanos, PID: int(pid), TID: int(tid), Tag: match[5], Text: match[6]}, true
}

func exactDiagnosticProcess(name, app string) bool {
	if name == app {
		return true
	}
	return strings.HasPrefix(name, app+":") && len(name) <= len(app)+40 &&
		processSuffixPattern.MatchString(strings.TrimPrefix(name, app+":"))
}

func launchWindowEvents(input, app string, start, end int64) ([]launchLogEvent, bool) {
	if len(input) > maxLogcatInput || start <= 0 || end <= start {
		return nil, false
	}
	var parsed []launchLogEvent
	pids := map[int]bool{}
	complete := true
	for _, line := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "---------") {
			continue
		}
		event, ok := parseEpochLog(line)
		if !ok {
			complete = false
			continue
		}
		if event.DeviceNanos <= start || event.DeviceNanos > end {
			continue
		}
		parsed = append(parsed, event)
		if event.Tag == "AndroidRuntime" {
			if match := processLogPattern.FindStringSubmatch(strings.TrimSpace(event.Text)); match != nil {
				pid, _ := strconv.Atoi(match[2])
				if pid == event.PID && exactDiagnosticProcess(match[1], app) {
					pids[pid] = true
				}
			}
		}
	}
	var events []launchLogEvent
	lifecycle := regexp.MustCompile("(Start proc|Killing) ([0-9]+):(" + regexp.QuoteMeta(app) + "(?::[A-Za-z0-9_.]+)?)/([A-Za-z0-9]+)(?:\\s|$)")
	death := regexp.MustCompile("Process (" + regexp.QuoteMeta(app) + "(?::[A-Za-z0-9_.]+)?) \\(pid ([0-9]+)\\) has died")
	for _, event := range parsed {
		if len(events) == 256 {
			complete = false
			break
		}
		if event.Tag == "AndroidRuntime" && pids[event.PID] {
			line := strings.TrimSpace(event.Text)
			switch {
			case strings.HasPrefix(line, "FATAL EXCEPTION:"):
				event.Text = "FATAL EXCEPTION"
			case processLogPattern.MatchString(line):
				match := processLogPattern.FindStringSubmatch(line)
				if !exactDiagnosticProcess(match[1], app) {
					complete = false
					continue
				}
				event.Text = line
			default:
				if frame := diagnosticFramePattern.FindStringSubmatch(line); frame != nil {
					identity := frame[1]
					if slash := strings.LastIndex(identity, "/"); slash >= 0 {
						identity = identity[slash+1:]
					}
					if !safeDiagnosticClass(identity) {
						complete = false
						continue
					}
					event.Text = "at " + identity + "(" + frame[2] + ")"
				} else if elidedFramePattern.MatchString(line) {
					event.Text = line
				} else {
					cause := strings.HasPrefix(line, "Caused by: ")
					details, ok := javaFailureDetails(line)
					if len(details) != 1 {
						complete = false
						continue
					}
					event.Text = details[0].Class + ": " + details[0].Message
					if cause {
						event.Text = "Caused by: " + event.Text
					}
					complete = complete && ok
				}
			}
			events = append(events, event)
		} else if event.Tag == "ActivityManager" || event.Tag == "ActivityTaskManager" {
			if match := lifecycle.FindStringSubmatch(event.Text); match != nil {
				uid, valid := diagnosticUID(match[4])
				if !valid {
					complete = false
					continue
				}
				event.Text = "process_lifecycle event=" + strings.ReplaceAll(match[1], " ", "_") + " pid=" + match[2] + " process=" + match[3] + " uid=" + strconv.Itoa(uid)
				events = append(events, event)
			} else if match := death.FindStringSubmatch(event.Text); match != nil {
				event.Text = "process_lifecycle event=died pid=" + match[2] + " process=" + match[1]
				events = append(events, event)
			}
		}
	}
	return events, complete
}

var launchTimingPattern = regexp.MustCompile("^(ThisTime|TotalTime|WaitTime|LaunchState): (?:[0-9]{1,12}|[A-Z_]+(?: \\([0-9]+\\))?)$")

func sanitizeLaunchOutput(input, app string) ([]string, bool) {
	if len(input) > maxCommandEvidence {
		return []string{"[TRUNCATED]"}, false
	}
	var output []string
	complete := true
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		line := strings.TrimSpace(raw)
		if line == "" {
			continue
		}
		if len(output) == 64 {
			return output, false
		}
		switch {
		case line == "Complete", line == "Status: ok", line == "Status: timeout", line == "Status: error":
			output = append(output, line)
		case launchTimingPattern.MatchString(line):
			output = append(output, line)
		case line == "Activity: "+app+"/org.kurdistanvpn.app.MainActivity":
			output = append(output, line)
		case strings.HasPrefix(line, "Starting: Intent {") && strings.Contains(line, "cmp="+app+"/org.kurdistanvpn.app.MainActivity"):
			output = append(output, "Starting: "+app+"/org.kurdistanvpn.app.MainActivity")
		default:
			output = append(output, "[REDACTED_UNRECOGNIZED_OUTPUT]")
			complete = false
		}
	}
	return output, complete
}

type diagnosticProcess struct {
	Name       string
	PID        int
	UID        int
	ParentPID  int
	StartTicks uint64
}

func parseProcessRows(input, app string) ([]diagnosticProcess, bool) {
	var rows []diagnosticProcess
	complete, header := true, false
	for _, raw := range strings.Split(input, "\n") {
		fields := strings.Fields(raw)
		if len(fields) == 4 && strings.Join(fields, " ") == "UID PID PPID NAME" {
			if header {
				complete = false
			}
			header = true
			continue
		}
		if len(fields) != 4 {
			if strings.TrimSpace(raw) != "" {
				complete = false
			}
			continue
		}
		if !header {
			complete = false
		}
		if !exactDiagnosticProcess(fields[3], app) {
			continue
		}
		uid, e1 := strconv.ParseInt(fields[0], 10, 32)
		pid, e2 := strconv.ParseInt(fields[1], 10, 32)
		parent, e3 := strconv.ParseInt(fields[2], 10, 32)
		if e1 != nil || e2 != nil || e3 != nil || uid < 0 || pid <= 0 || parent < 0 || len(rows) == 8 {
			complete = false
			continue
		}
		rows = append(rows, diagnosticProcess{Name: fields[3], UID: int(uid), PID: int(pid), ParentPID: int(parent)})
	}
	return rows, complete && header
}

func procStartTicks(input string, pid int) (uint64, error) {
	open, close := strings.Index(input, "("), strings.LastIndex(input, ")")
	if open < 1 || close <= open || strings.TrimSpace(input[:open]) != strconv.Itoa(pid) {
		return 0, errors.New("process identity unavailable")
	}
	fields := strings.Fields(input[close+1:])
	if len(fields) < 20 {
		return 0, errors.New("process stat incomplete")
	}
	ticks, err := strconv.ParseUint(fields[19], 10, 64)
	if err != nil || ticks == 0 {
		return 0, errors.New("invalid process epoch")
	}
	return ticks, nil
}

type diagnosticExit struct {
	Process   string
	PID       int
	UID       int
	Timestamp time.Time
	Reason    int
	Status    int
}

func parseExitRecords(input, app string, start, end time.Time, zone *time.Location) ([]diagnosticExit, bool) {
	if zone == nil || !end.After(start) || len(input) > maxLogcatInput {
		return nil, false
	}
	var records []diagnosticExit
	complete := true
	for _, block := range strings.Split(input, "ApplicationExitInfo ")[1:] {
		process := regexp.MustCompile("(?:^|\\s)process=([A-Za-z0-9_.:]+)").FindStringSubmatch(block)
		if process == nil {
			complete = false
			continue
		}
		if !exactDiagnosticProcess(process[1], app) {
			continue
		}
		stamp := regexp.MustCompile("timestamp=([0-9]{4}-[0-9]{2}-[0-9]{2} [0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{3})").FindStringSubmatch(block)
		if stamp == nil {
			complete = false
			continue
		}
		at, err := time.ParseInLocation("2006-01-02 15:04:05.000", stamp[1], zone)
		if err != nil {
			complete = false
			continue
		}
		if at.Before(start) || at.After(end) {
			continue
		}
		values := map[string]int{}
		for _, key := range []string{"pid", "realUid", "reason", "status"} {
			match := regexp.MustCompile("(?:^|\\s)" + key + "=([0-9]{1,10})(?:\\s|$)").FindStringSubmatch(block)
			if match == nil {
				complete = false
				continue
			}
			value, err := strconv.ParseInt(match[1], 10, 32)
			if err != nil {
				complete = false
				continue
			}
			values[key] = int(value)
		}
		if len(values) != 4 || values["pid"] < 1 || len(records) == 8 {
			complete = false
			continue
		}
		records = append(records, diagnosticExit{Process: process[1], PID: values["pid"], UID: values["realUid"], Timestamp: at, Reason: values["reason"], Status: values["status"]})
	}
	return records, complete
}

// Android UserHandle's ordinary application UID display, or a numeric UID.
// Isolated/unknown identities cannot establish this application's main process.
func diagnosticUID(label string) (int, bool) {
	if value, err := strconv.ParseInt(label, 10, 32); err == nil && value >= 0 {
		return int(value), true
	}
	match := regexp.MustCompile(`^u([0-9]{1,5})a([0-9]{1,5})$`).FindStringSubmatch(label)
	if match == nil {
		return 0, false
	}
	user, _ := strconv.ParseInt(match[1], 10, 64)
	app, _ := strconv.ParseInt(match[2], 10, 64)
	uid := user*100000 + app + 10000
	return int(uid), app < 90000 && uid <= 2147483647
}

type diagnosticProcessHealth struct {
	Process                                      string
	PID, UID                                     int
	Crashing, NotResponding, ErrorDialog, Killed bool
}

// AOSP API 26/34/36 dumps the error flags conditionally. Their absence is
// meaningful only inside a complete, identity-checked ProcessRecord section,
// never in an arbitrary fragment or a localized window title.
func parseProcessHealth(input, app string) ([]diagnosticProcessHealth, bool) {
	if len(input) > 256<<10 || !strings.HasPrefix(input, "ACTIVITY MANAGER RUNNING PROCESSES") ||
		!strings.Contains(input, "All known processes:") || !strings.Contains(input, "Process LRU list") {
		return nil, false
	}
	header := regexp.MustCompile(`^\s*\*APP\*.*ProcessRecord\{[0-9a-f]+ ([0-9]+):([A-Za-z0-9_.:]+)/([A-Za-z0-9]+)\}`)
	flags := regexp.MustCompile(`(?:^|\s)(crashing|mCrashing|notResponding|mNotResponding|killed|killedByAm|bad)=([^\s]+)`)
	var result []diagnosticProcessHealth
	var current *diagnosticProcessHealth
	var uidSeen, pidSeen, packagesSeen, stateSeen bool
	complete := true
	finish := func() {
		if current != nil {
			if !uidSeen || !pidSeen || !packagesSeen || !stateSeen || len(result) == 8 {
				complete = false
			} else {
				result = append(result, *current)
			}
		}
		current = nil
		uidSeen, pidSeen, packagesSeen, stateSeen = false, false, false, false
	}
	for _, raw := range strings.Split(input, "\n") {
		line := strings.TrimSpace(raw)
		if strings.Contains(line, "Process LRU list") {
			finish()
			break
		}
		if strings.HasPrefix(line, "*APP*") {
			finish()
			match := header.FindStringSubmatch(raw)
			if match == nil {
				complete = false
				continue
			}
			if !exactDiagnosticProcess(match[2], app) {
				continue
			}
			pid, err := strconv.ParseInt(match[1], 10, 32)
			uid, valid := diagnosticUID(match[3])
			if err != nil || pid < 1 || !valid {
				complete = false
				continue
			}
			current = &diagnosticProcessHealth{Process: match[2], PID: int(pid), UID: uid}
			continue
		}
		if current == nil {
			continue
		}
		if match := regexp.MustCompile(`^user #[0-9]+ uid=([0-9]+)(?:\s|$)`).FindStringSubmatch(line); match != nil {
			uid, err := strconv.ParseInt(match[1], 10, 32)
			if uidSeen || err != nil || int(uid) != current.UID {
				complete = false
			}
			uidSeen = true
		}
		if match := regexp.MustCompile(`^pid=([0-9]+)(?: starting=(true|false))?$`).FindStringSubmatch(line); match != nil {
			pid, err := strconv.ParseInt(match[1], 10, 32)
			if pidSeen || err != nil || int(pid) != current.PID || match[2] == "true" {
				complete = false
			}
			pidSeen = true
		}
		if strings.HasPrefix(line, "packageList={") && strings.HasSuffix(line, "}") {
			if packagesSeen {
				complete = false
			}
			for _, name := range strings.Split(strings.TrimSuffix(strings.TrimPrefix(line, "packageList={"), "}"), ",") {
				if strings.TrimSpace(name) == app {
					packagesSeen = true
				}
			}
		}
		if regexp.MustCompile(`(?:^|\s)curProcState=(?:[0-9]+|[A-Z]+)(?:\s|$)`).MatchString(line) {
			stateSeen = true
		}
		for _, match := range flags.FindAllStringSubmatch(line, -1) {
			if match[2] != "true" && match[2] != "false" {
				complete = false
				continue
			}
			value := match[2] == "true"
			switch match[1] {
			case "crashing", "mCrashing":
				current.Crashing = current.Crashing || value
			case "notResponding", "mNotResponding":
				current.NotResponding = current.NotResponding || value
			default:
				current.Killed = current.Killed || value
			}
		}
		if strings.Contains(line, "com.android.server.am.AppErrorDialog@") || strings.Contains(line, "com.android.server.am.AppNotRespondingDialog@") {
			current.ErrorDialog = true
		}
	}
	if current != nil {
		complete = false
	}
	return result, complete && len(result) > 0
}

var errLaunchIncomplete = errors.New("required startup evidence NOT_AVAILABLE")

func validateLaunchObservation(observation *launchObservation) error {
	if observation == nil || observation.Status != "CAPTURED" || len(observation.Issues) != 0 ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(observation.Invocation) ||
		observation.WindowStartNanos < observation.DeviceStartNanos || observation.WindowStartNanos <= 0 ||
		observation.WindowEndNanos <= observation.WindowStartNanos || observation.WindowEndNanos > observation.DeviceEndNanos ||
		!observation.FinishedUTC.After(observation.StartedUTC) || observation.ResolutionStatus != "CAPTURED" ||
		observation.ResolvedActivity != observation.app+"/org.kurdistanvpn.app.MainActivity" ||
		observation.ActivityProcessStatus != "CAPTURED" || len(observation.Processes) != 4 {
		return errLaunchIncomplete
	}
	var launch *diagnosticCommand
	for index := range observation.Commands {
		command := &observation.Commands[index]
		if command.Truncated || command.Status != "CAPTURED" || command.ExitCode != 0 || command.DurationMS < 0 ||
			command.StartedUTC.Before(observation.StartedUTC) || command.FinishedUTC.Before(command.StartedUTC) || command.FinishedUTC.After(observation.FinishedUTC) {
			return errLaunchIncomplete
		}
		if command.Phase == "am-start-W" {
			if launch != nil {
				return errLaunchIncomplete
			}
			launch = command
		}
	}
	if launch == nil || len(launch.Stderr) != 0 {
		return errLaunchIncomplete
	}
	phases := []string{"before-launch", "immediately-after-launch", "after-survival-interval", "terminal"}
	var previous, current *diagnosticProcess
	last := observation.StartedUTC
	for index, snapshot := range observation.Processes {
		if snapshot.Phase != phases[index] || snapshot.Status != "CAPTURED" || snapshot.ObservedUTC.Before(last) || snapshot.ObservedUTC.After(observation.FinishedUTC) {
			return errLaunchIncomplete
		}
		last = snapshot.ObservedUTC
		var found *diagnosticProcess
		for row := range snapshot.Processes {
			process := &snapshot.Processes[row]
			if process.Name == observation.app {
				if found != nil || process.PID <= 0 || process.UID < 10000 || process.StartTicks == 0 {
					return errLaunchIncomplete
				}
				found = process
			}
		}
		if index == 0 {
			previous = found
			continue
		}
		if found == nil {
			return errors.New("target process did not survive launch")
		}
		if index == 1 {
			current = found
		} else if *found != *current {
			return errors.New("target process identity changed during launch")
		}
		if snapshot.ObservedUTC.Before(launch.FinishedUTC) {
			return errLaunchIncomplete
		}
		if index == 2 && snapshot.ObservedUTC.Sub(launch.FinishedUTC) < 2*time.Second {
			return errLaunchIncomplete
		}
	}
	if current == nil || validateTerminalLaunch(launch.Stdout, true, observation.app) != nil {
		return errLaunchIncomplete
	}
	matched := 0
	for _, health := range observation.ProcessHealth {
		if health.Process != observation.app {
			continue
		}
		if health.PID != current.PID || health.UID != current.UID {
			return errLaunchIncomplete
		}
		matched++
		if health.Crashing || health.NotResponding || health.ErrorDialog || health.Killed {
			return errors.New("target process is crashing, unresponsive, or owns an error dialog")
		}
	}
	if matched != 1 {
		return errLaunchIncomplete
	}
	if (observation.api >= 30 && observation.ExitStatus != "CAPTURED") ||
		(observation.api >= 26 && observation.api < 30 && observation.ExitStatus != "UNSUPPORTED_API_BELOW_30") || observation.api < 26 {
		return errLaunchIncomplete
	}
	startPattern := regexp.MustCompile(`^process_lifecycle event=Start_proc pid=([0-9]+) process=([A-Za-z0-9_.:]+) uid=([0-9]+)$`)
	starts := map[int64]bool{}
	buffers := map[string]bool{}
	for _, buffer := range observation.Logs {
		if buffer.Source != "stream" || buffer.Status != "CAPTURED" || buffers[buffer.Buffer] ||
			(buffer.Buffer != "main" && buffer.Buffer != "system" && buffer.Buffer != "crash") {
			return errLaunchIncomplete
		}
		buffers[buffer.Buffer] = true
		lastNanos := observation.WindowStartNanos
		for _, event := range buffer.Events {
			if event.DeviceNanos < lastNanos || event.DeviceNanos <= observation.WindowStartNanos || event.DeviceNanos > observation.WindowEndNanos {
				return errLaunchIncomplete
			}
			lastNanos = event.DeviceNanos
			if match := startPattern.FindStringSubmatch(event.Text); match != nil && match[2] == current.Name && match[1] == strconv.Itoa(current.PID) {
				if match[3] != strconv.Itoa(current.UID) {
					return errLaunchIncomplete
				}
				starts[event.DeviceNanos] = true
			}
		}
	}
	if len(buffers) != 3 || len(starts) > 1 {
		return errLaunchIncomplete
	}
	epochStart := observation.WindowStartNanos
	if previous == nil || *previous != *current {
		if len(starts) != 1 {
			return errLaunchIncomplete
		}
		for at := range starts {
			epochStart = at
		}
	} else if len(starts) != 0 {
		return errLaunchIncomplete
	}
	// PID correlation is bounded by the observed process epoch and its OS start
	// event/UID. Reuse or missing continuity blocks admission; old or unrelated
	// events do not become evidence about the current target.
	for _, buffer := range observation.Logs {
		for _, event := range buffer.Events {
			if event.DeviceNanos < epochStart {
				continue
			}
			if event.Tag == "AndroidRuntime" && event.PID == current.PID {
				return errors.New("current target crash observed")
			}
			for _, kind := range []string{"died", "Killing"} {
				prefix := "process_lifecycle event=" + kind + " pid=" + strconv.Itoa(current.PID) + " process=" + current.Name
				if event.Text == prefix || strings.HasPrefix(event.Text, prefix+" uid=") {
					return errors.New("current target termination observed")
				}
			}
		}
	}
	for _, exit := range observation.ExitRecords {
		if exit.Process == current.Name && exit.PID == current.PID && exit.UID == current.UID &&
			exit.Timestamp.UnixNano()+int64(time.Millisecond) >= epochStart && exit.Timestamp.UnixNano() <= observation.WindowEndNanos {
			return errors.New("current target exit observed")
		}
	}
	return nil
}

type diagnosticCommand struct {
	combined    string
	Phase       string
	StartedUTC  time.Time
	FinishedUTC time.Time
	DurationMS  int64
	ExitCode    int
	Status      string
	Stdout      []string
	Stderr      []string
	Truncated   bool
}

type diagnosticProcessSnapshot struct {
	Phase       string
	ObservedUTC time.Time
	Status      string
	Processes   []diagnosticProcess
}

type diagnosticLogBuffer struct {
	Buffer string
	Source string
	Status string
	Events []launchLogEvent
}

type launchObservation struct {
	client                adbClient
	api                   int
	app                   string
	streams               []*launchLogStream
	Schema                string
	Invocation            string
	Status                string
	GateResult            string
	StartedUTC            time.Time
	FinishedUTC           time.Time
	DeviceStartNanos      int64
	DeviceEndNanos        int64
	WindowStartNanos      int64
	WindowEndNanos        int64
	ClockZone             string
	Commands              []diagnosticCommand
	Processes             []diagnosticProcessSnapshot
	Logs                  []diagnosticLogBuffer
	ExitRecords           []diagnosticExit
	ExitStatus            string
	ActivityProcessState  []string
	ActivityProcessStatus string
	ProcessHealth         []diagnosticProcessHealth
	ResolvedActivity      string
	ResolutionStatus      string
	LaunchCommand         []string
	Issues                []string
}

type launchLogStream struct {
	name            string
	command         *exec.Cmd
	cancel          context.CancelFunc
	done            chan error
	output          boundedBuffer
	stderr          boundedBuffer
	startErr        error
	endedBeforeStop bool
}

func (observation *launchObservation) incomplete(issue string) {
	observation.Status = "INCOMPLETE"
	if len(observation.Issues) < 32 {
		observation.Issues = append(observation.Issues, issue)
	}
}

// Split streams are recorded without changing the original combined-output
// bound or order consumed by launch validation.
type diagnosticOutput struct {
	mu       sync.Mutex
	combined boundedBuffer
	stdout   boundedBuffer
	stderr   boundedBuffer
}

type diagnosticSink struct {
	owner  *diagnosticOutput
	stderr bool
}

func (sink diagnosticSink) Write(value []byte) (int, error) {
	sink.owner.mu.Lock()
	defer sink.owner.mu.Unlock()
	_, _ = sink.owner.combined.Write(value)
	if sink.stderr {
		return sink.owner.stderr.Write(value)
	}
	return sink.owner.stdout.Write(value)
}

func (client adbClient) diagnosticCommand(ctx context.Context, phase string, limit int, args ...string) (string, string, diagnosticCommand, error) {
	started := time.Now()
	commandArgs := append([]string(nil), args...)
	if client.serial != "" {
		commandArgs = append([]string{"-s", client.serial}, commandArgs...)
	}
	command := exec.CommandContext(ctx, client.path, commandArgs...)
	command.WaitDelay = time.Second
	output := diagnosticOutput{combined: boundedBuffer{limit: limit}, stdout: boundedBuffer{limit: limit}, stderr: boundedBuffer{limit: limit}}
	command.Stdout, command.Stderr = diagnosticSink{owner: &output}, diagnosticSink{owner: &output, stderr: true}
	err := command.Run()
	if ctx.Err() != nil {
		err = ctx.Err()
	}
	status, code := diagnosticCommandStatus(err)
	record := diagnosticCommand{combined: output.combined.String(), Phase: phase, StartedUTC: started.UTC(), FinishedUTC: time.Now().UTC(), DurationMS: time.Since(started).Milliseconds(), ExitCode: code, Status: status, Truncated: output.combined.exceeded}
	if record.Truncated {
		record.Status = "INCOMPLETE"
	}
	client.timeline.record("diagnostic-"+phase, started, err)
	return output.stdout.String(), output.stderr.String(), record, err
}

func (observation *launchObservation) query(parent context.Context, phase string, args ...string) (string, bool) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	out, _, record, err := observation.client.diagnosticCommand(ctx, phase, 256<<10, args...)
	// General diagnostic command output is never serialized by this function.
	// Each consumer extracts a separate allow-listed record.
	observation.Commands = append(observation.Commands, record)
	ok := err == nil && !record.Truncated
	if !ok {
		observation.incomplete(phase + " unavailable")
	}
	return out, ok
}

func beginLaunchObservation(ctx context.Context, client adbClient, value options) *launchObservation {
	observation := &launchObservation{client: client, api: value.expectedAPI, app: value.appPackage, Schema: "kurdistan-launch-observation-v1", Status: "CAPTURED", GateResult: "NOT_EVALUATED", StartedUTC: time.Now().UTC(), ExitStatus: "INCOMPLETE", ActivityProcessStatus: "INCOMPLETE", ResolutionStatus: "INCOMPLETE"}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		observation.incomplete("invocation identity unavailable")
		return observation
	}
	observation.Invocation = fmt.Sprintf("%x", nonce)
	if !safeDiagnosticClass(value.appPackage) {
		observation.incomplete("unsupported diagnostic package identity")
		return observation
	}
	clock, ok := observation.query(ctx, "clock-before", "shell", "date", "+%s.%N")
	var err error
	observation.DeviceStartNanos, err = epochNanos(clock)
	if !ok || err != nil {
		observation.incomplete("device clock unavailable")
	}
	zone, ok := observation.query(ctx, "clock-zone", "shell", "date", "+%z")
	if ok && regexp.MustCompile("^[+-][0-9]{4}$").MatchString(strings.TrimSpace(zone)) {
		observation.ClockZone = strings.TrimSpace(zone)
	} else {
		observation.incomplete("device clock zone unavailable")
	}
	for _, buffer := range []string{"crash", "main", "system"} {
		logctx, cancel := context.WithCancel(ctx)
		args := []string{"shell", "logcat", "-b", buffer, "-v", "threadtime", "-v", "epoch", "-v", "usec", "-T", "1", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
		if client.serial != "" {
			args = append([]string{"-s", client.serial}, args...)
		}
		stream := &launchLogStream{name: buffer, cancel: cancel, done: make(chan error, 1), output: boundedBuffer{limit: 512 << 10}, stderr: boundedBuffer{limit: 8 << 10}}
		stream.command = exec.CommandContext(logctx, client.path, args...)
		stream.command.WaitDelay = time.Second
		stream.command.Stdout, stream.command.Stderr = &stream.output, &stream.stderr
		stream.startErr = stream.command.Start()
		if stream.startErr == nil {
			go func() { stream.done <- stream.command.Wait() }()
		} else {
			observation.incomplete("log stream unavailable")
		}
		observation.streams = append(observation.streams, stream)
	}
	_, _ = observation.query(ctx, "window-start", "shell", "log", "-p", "i", "-t", "KurdistanLaunchProbe", "START:"+observation.Invocation)
	observation.processSnapshot(ctx, "before-launch", time.Second)
	resolved, ok := observation.query(ctx, "resolve-activity", "shell", "cmd", "package", "resolve-activity", "--brief", "-n", value.appPackage+"/org.kurdistanvpn.app.MainActivity")
	for _, line := range strings.Split(resolved, "\n") {
		if strings.TrimSpace(line) == value.appPackage+"/org.kurdistanvpn.app.MainActivity" {
			observation.ResolvedActivity = strings.TrimSpace(line)
			if ok {
				observation.ResolutionStatus = "CAPTURED"
			}
		}
	}
	if observation.ResolutionStatus != "CAPTURED" {
		observation.incomplete("activity resolution unavailable")
	}
	return observation
}

func (observation *launchObservation) processSnapshot(parent context.Context, phase string, budget time.Duration) {
	ctx, cancel := context.WithTimeout(parent, budget)
	defer cancel()
	raw, ok := observation.query(ctx, phase, "shell", "ps", "-A", "-o", "UID,PID,PPID,NAME")
	rows, parsed := parseProcessRows(raw, observation.app)
	snapshot := diagnosticProcessSnapshot{Phase: phase, ObservedUTC: time.Now().UTC(), Status: "CAPTURED", Processes: rows}
	if !ok || !parsed {
		snapshot.Status = "INCOMPLETE"
		observation.incomplete(phase + " process identity unavailable")
	}
	for index := range snapshot.Processes {
		row := &snapshot.Processes[index]
		stat, readable := observation.query(ctx, phase+"-epoch", "shell", "cat", "/proc/"+strconv.Itoa(row.PID)+"/stat")
		ticks, err := procStartTicks(stat, row.PID)
		if !readable || err != nil {
			snapshot.Status = "INCOMPLETE"
			observation.incomplete(phase + " process epoch unavailable")
		} else {
			row.StartTicks = ticks
		}
	}
	observation.Processes = append(observation.Processes, snapshot)
}

func (observation *launchObservation) captureLaunch(ctx context.Context, name string, args ...string) (string, error) {
	// This uses the unchanged gate deadline, not the short observational timeout.
	out, stderr, record, err := observation.client.diagnosticCommand(ctx, "am-start-W", maxCommandEvidence, args...)
	observation.LaunchCommand = []string{"adb", "shell", "am", "start", "-W", "-f", "0x10008000", "-n", observation.app + "/org.kurdistanvpn.app.MainActivity"}
	var outComplete, errComplete bool
	record.Stdout, outComplete = sanitizeLaunchOutput(out, observation.app)
	record.Stderr, errComplete = sanitizeLaunchOutput(stderr, observation.app)
	if !outComplete || !errComplete || record.Truncated {
		observation.incomplete("launch command output incomplete")
	}
	observation.Commands = append(observation.Commands, record)
	// Keep the original public timing file, but never persist unfiltered stderr.
	sanitized := strings.Join(append(append([]string(nil), record.Stdout...), record.Stderr...), "\n") + "\n"
	if writeErr := os.WriteFile(filepath.Join(observation.client.evidenceDir, name), []byte(sanitized), 0o600); writeErr != nil {
		return record.combined, fmt.Errorf("write %s: %w", name, writeErr)
	}
	if record.Truncated {
		return record.combined, errors.New("adb evidence exceeded byte limit")
	}
	return record.combined, err
}

func (observation *launchObservation) finish(parent context.Context, failed bool) error {
	// Successful admission stays under the original deadline. Only a launch
	// already rejected may use the existing diagnostic-only grace afterward.
	ctx, cancel := context.WithTimeout(parent, 15*time.Second)
	defer cancel()
	observation.GateResult = "LAUNCH_OBSERVED_NOT_QUALIFIED"
	if failed {
		observation.GateResult = "FAIL"
	}
	observation.processSnapshot(ctx, "terminal", time.Second)
	rawState, readableState := observation.query(ctx, "activity-processes", "shell", "dumpsys", "activity", "processes", observation.app)
	observation.ActivityProcessState = sanitizeActivityProcessState(rawState, observation.app)
	var parsedState bool
	observation.ProcessHealth, parsedState = parseProcessHealth(rawState, observation.app)
	if readableState && parsedState {
		observation.ActivityProcessStatus = "CAPTURED"
	} else {
		observation.incomplete("activity process state unavailable or incomplete")
	}
	_, _ = observation.query(ctx, "window-end", "shell", "log", "-p", "i", "-t", "KurdistanLaunchProbe", "END:"+observation.Invocation)
	// A separate marker-only snapshot confirms the end even if the launch
	// deadline already terminated the streaming readers. It contains no crash
	// body and cannot supply an old invocation's marker.
	markers, markersOK := observation.query(ctx, "window-markers", "shell", "logcat", "-b", "main", "-d", "-t", "128", "-v", "threadtime", "-v", "epoch", "-v", "usec", "KurdistanLaunchProbe:I", "*:S")
	clock, ok := observation.query(ctx, "clock-after", "shell", "date", "+%s.%N")
	nanos, err := epochNanos(clock)
	if ok && err == nil {
		observation.DeviceEndNanos = nanos
	} else {
		observation.incomplete("terminal clock unavailable")
	}
	rawLogs := map[string]string{}
	for _, stream := range observation.streams {
		if stream.startErr == nil {
			select {
			case <-stream.done:
				stream.endedBeforeStop = true
				stream.cancel()
			default:
				stream.cancel()
				<-stream.done
			}
		} else {
			stream.cancel()
		}
		rawLogs[stream.name] = stream.output.String()
		if stream.startErr != nil || stream.endedBeforeStop || stream.output.exceeded || stream.stderr.buffer.Len() != 0 {
			observation.incomplete(stream.name + " stream incomplete")
		}
	}
	start, end, windowOK := launchMarkerWindow(rawLogs["main"], markers, observation.Invocation, observation.DeviceStartNanos, observation.DeviceEndNanos)
	if !markersOK || !windowOK {
		observation.incomplete("launch window markers missing or inconsistent")
		// Do not attribute possibly old crashes when the invocation cannot be bound.
		start, end = 0, 0
	}
	observation.WindowStartNanos, observation.WindowEndNanos = start, end
	for _, stream := range observation.streams {
		events, complete := launchWindowEvents(rawLogs[stream.name], observation.app, start, end)
		status := "CAPTURED"
		if !complete || stream.endedBeforeStop || stream.output.exceeded || stream.startErr != nil || stream.stderr.buffer.Len() != 0 {
			status = "INCOMPLETE"
			observation.incomplete(stream.name + " events incomplete")
		}
		observation.Logs = append(observation.Logs, diagnosticLogBuffer{Buffer: stream.name, Source: "stream", Status: status, Events: events})
	}
	if observation.api >= 30 {
		raw, readable := observation.query(ctx, "exit-info", "shell", "dumpsys", "activity", "exit-info", observation.app)
		var zone *time.Location
		if parsed, parseErr := time.Parse("-0700", observation.ClockZone); parseErr == nil {
			_, offset := parsed.Zone()
			zone = time.FixedZone("device", offset)
		}
		records, parsed := parseExitRecords(raw, observation.app, time.Unix(0, start), time.Unix(0, end), zone)
		observation.ExitRecords = records
		// A recognized, complete empty history is distinct from an empty or
		// unsupported command response. The latter is never absence of crashes.
		if readable && parsed && strings.HasPrefix(raw, "ACTIVITY MANAGER PROCESS EXIT INFO (dumpsys activity exit-info)") &&
			strings.Contains(raw, "Last Timestamp of Persistence Into Persistent Storage:") {
			observation.ExitStatus = "CAPTURED"
		} else {
			observation.incomplete("process exit reason unavailable")
		}
	} else if observation.api >= 26 {
		observation.ExitStatus = "UNSUPPORTED_API_BELOW_30"
	} else {
		observation.incomplete("process exit observation capability unknown")
	}
	if failed {
		// Read a bounded terminal snapshot as well as the streams. A stream may
		// have ended at the launch deadline or not yet drained its final record.
		// The two observation sources stay separate; no sorting or inferred event
		// is used to fill a capture gap.
		for _, buffer := range []string{"crash", "main", "system"} {
			raw, readable := observation.query(ctx, "terminal-"+buffer, "shell", "logcat", "-b", buffer, "-d", "-t", "2048", "-v", "threadtime", "-v", "epoch", "-v", "usec", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "*:S")
			events, parsed := launchWindowEvents(raw, observation.app, start, end)
			status := "CAPTURED"
			if !readable || !parsed {
				status = "INCOMPLETE"
				observation.incomplete(buffer + " terminal snapshot unavailable")
			}
			observation.Logs = append(observation.Logs, diagnosticLogBuffer{Buffer: buffer, Source: "terminal-snapshot", Status: status, Events: events})
		}
		if !hasCapturedFailureCause(observation.Logs, observation.ExitRecords) {
			observation.incomplete("failure cause unavailable")
		}
	}
	observation.FinishedUTC = time.Now().UTC()
	var admission error
	if !failed {
		admission = validateLaunchObservation(observation)
		if admission != nil {
			observation.GateResult = "FAIL"
			if errors.Is(admission, errLaunchIncomplete) {
				observation.GateResult = "BLOCKED"
				observation.incomplete("required startup evidence NOT_AVAILABLE")
			}
		}
	}
	if err := writeDiagnosticJSON(filepath.Join(observation.client.evidenceDir, "10-launch-details.txt"), observation); err != nil {
		return err
	}
	return admission
}

func hasCapturedFailureCause(logs []diagnosticLogBuffer, exits []diagnosticExit) bool {
	exception, frame := false, false
	for _, buffer := range logs {
		for _, event := range buffer.Events {
			if event.Tag != "AndroidRuntime" {
				continue
			}
			if diagnosticFramePattern.MatchString(event.Text) {
				frame = true
			}
			details, complete := javaFailureDetails(event.Text)
			if complete && len(details) == 1 {
				exception = true
			}
		}
	}
	return (exception && frame) || len(exits) > 0
}

func sanitizeActivityProcessState(input, app string) []string {
	var records []string
	pattern := regexp.MustCompile("ProcessRecord\\{[0-9a-f]+ ([0-9]+):(" + regexp.QuoteMeta(app) + "(?::[A-Za-z0-9_.]+)?)/([A-Za-z0-9]+)\\}")
	fields := regexp.MustCompile("(?:^|\\s)(curAdj|setAdj|curRawAdj|setRawAdj|curProcState|setProcState|curRawProcState|setRawProcState|repProcState|killed|killedByAm|hasForegroundActivities|foregroundServices)=(-?[0-9]{1,5}|true|false)(?:\\s|$)")
	active := false
	for _, line := range strings.Split(input, "\n") {
		if len(records) >= 64 {
			break
		}
		if strings.Contains(line, "ProcessRecord{") {
			active = false
		}
		if match := pattern.FindStringSubmatch(line); match != nil {
			active = true
			records = append(records, "pid="+match[1]+" process="+match[2]+" uid="+match[3])
		}
		if active {
			for _, field := range fields.FindAllStringSubmatch(line, -1) {
				if len(records) == 64 {
					break
				}
				records = append(records, field[1]+"="+field[2])
			}
		}
	}
	return records
}

func launchMarkerWindow(stream, snapshot, invocation string, before, after int64) (int64, int64, bool) {
	if !regexp.MustCompile("^[0-9a-f]{32}$").MatchString(invocation) || before <= 0 || after <= before {
		return 0, 0, false
	}
	starts, ends := map[int64]bool{}, map[int64]bool{}
	for _, input := range []string{stream, snapshot} {
		if len(input) > maxLogcatInput {
			return 0, 0, false
		}
		for _, line := range strings.Split(input, "\n") {
			event, ok := parseEpochLog(line)
			if !ok || event.Tag != "KurdistanLaunchProbe" {
				continue
			}
			switch event.Text {
			case "START:" + invocation:
				starts[event.DeviceNanos] = true
			case "END:" + invocation:
				ends[event.DeviceNanos] = true
			}
		}
	}
	if len(starts) != 1 || len(ends) != 1 {
		return 0, 0, false
	}
	var start, end int64
	for at := range starts {
		start = at
	}
	for at := range ends {
		end = at
	}
	return start, end, start >= before && end > start && end <= after
}

type junitDiagnosticCase struct {
	Name       string
	Exceptions []exceptionDetail
}

type junitDiagnosticReport struct {
	Schema      string
	Status      string
	Tests       int
	Failures    int
	Errors      int
	Cases       []junitDiagnosticCase
	Environment map[string]string
}

func junitFailureReport(raw []byte) (junitDiagnosticReport, error) {
	report := junitDiagnosticReport{Schema: "kurdistan-junit-diagnostic-v1", Status: "INCOMPLETE"}
	if len(raw) > maxLogcatInput {
		return report, errors.New("JUnit diagnostic input exceeded bound")
	}
	type failure struct {
		Text string `xml:",chardata"`
	}
	var suite struct {
		XMLName  xml.Name `xml:"testsuite"`
		Name     string   `xml:"name,attr"`
		Tests    int      `xml:"tests,attr"`
		Failures int      `xml:"failures,attr"`
		Errors   int      `xml:"errors,attr"`
		Cases    []struct {
			Name     string    `xml:"name,attr"`
			Class    string    `xml:"classname,attr"`
			Failures []failure `xml:"failure"`
			Errors   []failure `xml:"error"`
		} `xml:"testcase"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(raw))
	if err := decoder.Decode(&suite); err != nil {
		return report, errors.New("JUnit diagnostic XML malformed")
	}
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return report, errors.New("JUnit diagnostic trailing XML malformed")
		}
		text, ok := token.(xml.CharData)
		if !ok || strings.TrimSpace(string(text)) != "" {
			return report, errors.New("JUnit diagnostic trailing data")
		}
	}
	const target = "org.kurdistanvpn.data.settings.Phase13SettingsCodecTest"
	if suite.Name != target || suite.Tests < 1 || suite.Tests > 64 || len(suite.Cases) != suite.Tests ||
		suite.Failures < 0 || suite.Errors < 0 || suite.Failures+suite.Errors > 16 {
		return report, errors.New("JUnit diagnostic subject or counts invalid")
	}
	report.Tests, report.Failures, report.Errors = suite.Tests, suite.Failures, suite.Errors
	report.Status = "CAPTURED"
	count := 0
	for _, test := range suite.Cases {
		if test.Class != target || !safeTestIdentity(target+"#"+test.Name) {
			return report, errors.New("JUnit diagnostic case identity invalid")
		}
		for _, problem := range append(test.Failures, test.Errors...) {
			count++
			details, complete := javaFailureDetails(problem.Text)
			if !complete {
				report.Status = "INCOMPLETE"
			}
			report.Cases = append(report.Cases, junitDiagnosticCase{Name: test.Name, Exceptions: details})
		}
	}
	if count != suite.Failures+suite.Errors {
		return report, errors.New("JUnit diagnostic failure count mismatch")
	}
	return report, nil
}

// This separate command reads an existing report only. It neither reruns tests
// nor affects their exit status, and never exports JUnit stdout, paths or host IDs.
func runJUnitDiagnostics(args []string) int {
	flags := flag.NewFlagSet("diagnose-junit", flag.ContinueOnError)
	input := flags.String("in", "", "existing settings JUnit XML")
	output := flags.String("out", "", "bounded sanitized text diagnostic")
	if err := flags.Parse(args); err != nil || *input == "" || *output == "" || flags.NArg() != 0 {
		return 2
	}
	report := junitDiagnosticReport{Schema: "kurdistan-junit-diagnostic-v1", Status: "INCOMPLETE"}
	if file, err := os.Open(*input); err == nil {
		raw, readErr := io.ReadAll(io.LimitReader(file, maxLogcatInput+1))
		closeErr := file.Close()
		if readErr == nil && closeErr == nil {
			if parsed, parseErr := junitFailureReport(raw); parseErr == nil {
				report = parsed
			}
		}
	}
	report.Environment = junitDiagnosticEnvironment()
	if report.Environment["capture"] != "CAPTURED" {
		report.Status = "INCOMPLETE"
	}
	if err := os.MkdirAll(filepath.Dir(*output), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "JUnit diagnostics INCOMPLETE: output directory unavailable")
		return 1
	}
	if err := writeDiagnosticJSON(*output, report); err != nil {
		fmt.Fprintln(os.Stderr, "JUnit diagnostics INCOMPLETE: output unavailable")
		return 1
	}
	fmt.Printf("DIAGNOSTIC_ONLY status=%s failures=%d errors=%d\n", report.Status, report.Failures, report.Errors)
	return 0
}

func junitDiagnosticEnvironment() map[string]string {
	result := map[string]string{"capture": "INCOMPLETE", "go_os": runtime.GOOS, "go_arch": runtime.GOARCH}
	java := filepath.Join(os.Getenv("JAVA_HOME"), "bin", "java")
	if runtime.GOOS == "windows" {
		java += ".exe"
	}
	if !filepath.IsAbs(java) {
		return result
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, java, "-XshowSettings:properties", "-version")
	command.WaitDelay = time.Second
	var output = boundedBuffer{limit: 64 << 10}
	command.Stdout, command.Stderr = &output, &output
	if err := command.Run(); err != nil || output.exceeded {
		return result
	}
	safeValue := regexp.MustCompile("^[A-Za-z0-9 ._+()/-]{1,160}$")
	allowed := map[string]bool{
		"java.version": true, "java.runtime.version": true, "java.vendor": true,
		"file.encoding": true, "native.encoding": true, "sun.jnu.encoding": true,
		"user.language": true, "user.country": true, "os.name": true, "os.version": true, "os.arch": true,
	}
	for _, line := range strings.Split(output.String(), "\n") {
		key, value, found := strings.Cut(strings.TrimSpace(line), " = ")
		if !found {
			continue
		}
		if allowed[key] && safeValue.MatchString(value) {
			result[key] = value
		}
		if key == "java.io.tmpdir" {
			result["temp_path_characters"] = strconv.Itoa(len([]rune(value)))
			result["temp_has_short_alias"] = strconv.FormatBool(regexp.MustCompile("(?i)~[0-9]+").MatchString(value))
			result["temp_ascii_only"] = strconv.FormatBool(strings.IndexFunc(value, func(r rune) bool { return r > 127 }) < 0)
			info, err := os.Stat(value)
			result["temp_existing_directory"] = strconv.FormatBool(err == nil && info.IsDir())
		}
		if key == "line.separator" {
			if value == "\\r\\n" {
				result[key] = "CRLF"
			} else if value == "\\n" {
				result[key] = "LF"
			}
		}
	}
	if result["java.version"] != "" && result["temp_path_characters"] != "" {
		result["capture"] = "CAPTURED"
	}
	return result
}
