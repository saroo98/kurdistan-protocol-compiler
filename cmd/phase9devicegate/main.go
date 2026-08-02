// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase9devicegate executes a labelled Android device suite and rejects
// false passes where instrumentation reports success while the app process
// crashes. It is intentionally separate from the host-only Android gate.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
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
	if _, err := client.capture(ctx, "03-install-app.txt", "install", "-r", value.appAPK); err != nil {
		return fmt.Errorf("install application: %w", err)
	}
	if _, err := client.capture(ctx, "04-install-test.txt", "install", "-r", value.testAPK); err != nil {
		return fmt.Errorf("install instrumentation: %w", err)
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
	// POST_NOTIFICATIONS exists only on API 33 and newer. Record the result but
	// keep the device gate compatible with the Phase 9 minimum API.
	_, _ = client.capture(
		ctx,
		"04b-grant-notification-permission.txt",
		"shell",
		"pm",
		"grant",
		value.appPackage,
		"android.permission.POST_NOTIFICATIONS",
	)
	if err := clearLogcat(ctx, client, "05-clear-logcat.txt"); err != nil {
		return fmt.Errorf("clear logcat: %w", err)
	}
	_, _ = client.capture(ctx, "06-force-stop.txt", "shell", "am", "force-stop", value.appPackage)
	if _, err := client.capture(ctx, "07-dismiss-external-activity.txt", "shell", "input", "keyevent", "KEYCODE_BACK"); err != nil {
		return fmt.Errorf("dismiss external activity before launch: %w", err)
	}
	time.Sleep(300 * time.Millisecond)
	if _, err := client.capture(ctx, "07-home-before-launch.txt", "shell", "input", "keyevent", "KEYCODE_HOME"); err != nil {
		return fmt.Errorf("return device to Home before launch: %w", err)
	}
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
	pidOutput, pidErr := client.capture(ctx, "09-launch-pid.txt", "shell", "pidof", value.appPackage)
	if err := validateLaunchSmoke(launchOutput, pidOutput, value.appPackage, pidErr); err != nil {
		_, _ = client.capture(ctx, "10-launch-failure-logcat.txt", "logcat", "-b", "all", "-d", "-v", "threadtime")
		return err
	}
	_, _ = client.capture(ctx, "11-pre-test-force-stop.txt", "shell", "am", "force-stop", value.appPackage)
	if err := clearLogcat(ctx, client, "12-pre-test-clear-logcat.txt"); err != nil {
		return fmt.Errorf("clear pre-test logcat: %w", err)
	}
	instrumentation, instrumentationErr := client.capture(
		ctx,
		"13-instrumentation.txt",
		"shell",
		"am",
		"instrument",
		"-w",
		"-r",
		value.testPackage+"/"+value.runner,
	)
	logcat, logcatErr := client.capture(ctx, "14-logcat-all.txt", "logcat", "-b", "all", "-d", "-v", "threadtime")
	crashLog, crashLogErr := client.capture(ctx, "15-logcat-crash.txt", "logcat", "-b", "crash", "-d", "-v", "threadtime")
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

func clearLogcat(ctx context.Context, client adbClient, evidenceName string) error {
	if _, err := client.capture(ctx, evidenceName, logcatClearArgs()...); err == nil {
		return nil
	}
	// API 26 can transiently fail the first clear immediately after package
	// installation while logd reopens its buffers. Retry once, preserve both
	// command results as evidence, and still fail closed if the retry fails.
	time.Sleep(250 * time.Millisecond)
	retryName := strings.TrimSuffix(evidenceName, filepath.Ext(evidenceName)) + "-retry.txt"
	_, err := client.capture(ctx, retryName, logcatClearArgs()...)
	return err
}

type adbClient struct {
	path        string
	serial      string
	evidenceDir string
}

func (client adbClient) capture(ctx context.Context, name string, args ...string) (string, error) {
	commandArgs := make([]string, 0, len(args)+2)
	if client.serial != "" {
		commandArgs = append(commandArgs, "-s", client.serial)
	}
	commandArgs = append(commandArgs, args...)
	command := exec.CommandContext(ctx, client.path, commandArgs...)
	var combined bytes.Buffer
	command.Stdout = &combined
	command.Stderr = &combined
	err := command.Run()
	if writeErr := os.WriteFile(filepath.Join(client.evidenceDir, name), combined.Bytes(), 0o644); writeErr != nil {
		return combined.String(), fmt.Errorf("write %s: %w", name, writeErr)
	}
	return combined.String(), err
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
	if containsAppCrash(logcat, appPackage) {
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
