// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase9devicegate executes a labelled Android device suite and rejects
// false passes where instrumentation reports success while the app process
// crashes. It is intentionally separate from the host-only Android gate.
package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
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
	client := adbClient{path: adb, serial: value.serial, evidenceDir: value.evidenceDir}
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
	if err := prepareInstrumentationRuntime(ctx, client, value.appPackage, value.testPackage); err != nil {
		return err
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
	if _, err := client.capture(
		ctx,
		"04-clear-app-data.txt",
		"shell",
		"pm",
		"clear",
		value.appPackage,
	); err != nil {
		return fmt.Errorf("clear application data: %w", err)
	}
	if _, err := client.capture(
		ctx,
		"04a-authorize-test-vpn.txt",
		"shell",
		"appops",
		"set",
		value.appPackage,
		"ACTIVATE_VPN",
		"allow",
	); err != nil {
		return fmt.Errorf("authorize test VPN: %w", err)
	}
	if value.expectedAPI >= 33 {
		if _, err := client.capture(
			ctx,
			"04b-grant-notification-permission.txt",
			"shell",
			"pm",
			"grant",
			value.appPackage,
			"android.permission.POST_NOTIFICATIONS",
		); err != nil {
			return fmt.Errorf("grant notification permission: %w", err)
		}
	} else if err := os.WriteFile(
		filepath.Join(value.evidenceDir, "04b-grant-notification-permission.txt"),
		[]byte("not_applicable=api_below_33\n"),
		0o644,
	); err != nil {
		return fmt.Errorf("record notification permission applicability: %w", err)
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
	component := value.appPackage + "/org.kurdistanvpn.app.MainActivity"
	// NEW_TASK | CLEAR_TASK prevents a stale system picker, opened on behalf of
	// the app, from being restored as the top activity during the smoke launch.
	launchOutput, err := client.capture(
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
		return fmt.Errorf("launch smoke test: %w", err)
	}
	time.Sleep(2 * time.Second)
	pidOutput, pidErr := client.captureProcessState(ctx, "09-launch-process.txt", value.appPackage)
	if err := validateLaunchSmoke(launchOutput, pidOutput, value.appPackage, pidErr); err != nil {
		_, _ = client.captureDiagnostic(ctx, "10-launch-failure-diagnostics.txt", value.appPackage, diagnosticLogcatArgs("all")...)
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
	crashLog, crashLogErr := client.captureDiagnostic(ctx, "15-crash-diagnostics.txt", value.appPackage, "logcat", "-b", "crash", "-d", "-v", "brief")
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
	return []string{"logcat", "-b", buffer, "-d", "-v", "brief", "*:W"}
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
	return summary
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

func prepareInstrumentationRuntime(ctx context.Context, client adbClient, appPackage, testPackage string) error {
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
) error {
	for _, command := range commands {
		output, err := capture(ctx, command.evidence, command.args...)
		if err != nil && transientPackageServiceFailure(output) {
			stem := strings.TrimSuffix(command.evidence, filepath.Ext(command.evidence))
			if waitErr := waitForFramework(stem + "-retry"); waitErr != nil {
				return fmt.Errorf("prepare instrumentation runtime package service recovery (%s): %w", command.evidence, waitErr)
			}
			_, err = capture(ctx, stem+"-retry.txt", command.args...)
		}
		if err != nil {
			return fmt.Errorf("prepare instrumentation runtime (%s): %w", command.evidence, err)
		}
	}
	return nil
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
	for _, line := range strings.Split(launchOutput, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "Activity:") {
			continue
		}
		activity := strings.TrimSpace(strings.TrimPrefix(line, "Activity:"))
		if !strings.HasPrefix(activity, appPackage+"/") {
			return fmt.Errorf("launch resolved to another package: %s", activity)
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
		"logcat", "-b", "all", "-d", "-v", "brief",
	)
	crashSummary, crashErr := client.captureDiagnostic(
		ctx,
		stem+"-baseline-crash.txt",
		appPackage,
		"logcat", "-b", "crash", "-d", "-v", "brief",
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

func (client adbClient) capture(ctx context.Context, name string, args ...string) (string, error) {
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

func (client adbClient) captureDiagnostic(ctx context.Context, name, appPackage string, args ...string) (string, error) {
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
	return fmt.Sprintf(
		"schema=kurdistan-device-diagnostic-summary-v1\napp_package=%s\ninput_truncated=%t\napp_crash=%t\njava_crash=%t\nnative_crash=%t\nanr=%t\ninstrumentation_failure=%t\n",
		appPackage, truncated, appCrash, javaCrash, nativeCrash, anr, instrumentationFailure,
	)
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

func (client adbClient) captureOutput(ctx context.Context, args ...string) (string, error) {
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
