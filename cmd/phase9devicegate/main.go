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
	defaultAppPackage                 = "org.kurdistanvpn.app.debug"
	defaultTestPackage                = "org.kurdistanvpn.app.debug.test"
	defaultRunner                     = "androidx.test.runner.AndroidJUnitRunner"
	monotonicClockDomain              = "CLOCK_MONOTONIC_LOGCAT"
	clockProbeTag                     = "KurdistanClockProbe"
	launchProbeTag                    = "KurdistanLaunchProbe"
	launchMarkerVersion               = "KLG1"
	launchMarkerEmitter               = "phase9devicegate"
	nativeFilesystemAuthorizationV1   = "kurdistan-phase17-filesystem-authorization-v1\x00"
	maxCommandEvidence                = 2 << 20
	maxLogcatInput                    = 4 << 20
	maxDiagnosticBytes                = 16 << 10
	maxInstrumentationDiagnosticBytes = 64 << 10
	deviceGateTimeout                 = 35 * time.Minute
)

var nativeFilesystemChildren = []string{
	"existing-directory",
	"leaf-owner",
	"read-link-identity",
	"writer-replacement",
}

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
	startupSubject        startupSubjectBinding
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
	startupSubject, err := resolveStartupSubjectBinding(value)
	if err != nil {
		return fmt.Errorf("bind immutable startup subject: %w", err)
	}
	value.startupSubject = startupSubject
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
	client := newADBClient(adb, value.serial, value.evidenceDir, timeline)
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
	instrumentationArgs, err := prepareNativeFilesystemInstrumentation(
		ctx,
		client,
		value.appPackage,
		value.testPackage,
		value.testPackage+"/"+value.runner,
	)
	if err != nil {
		return err
	}
	instrumentation, instrumentationErr := client.captureInstrumentation(
		ctx,
		"13-instrumentation-summary.txt",
		instrumentationArgs...,
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
	observation.captureStartupProcess(ctx, "immediately-after-launch")
	if remaining := time.Until(survivalAt); remaining > 0 {
		time.Sleep(remaining)
	}
	pidOutput, pidErr := client.captureProcessState(ctx, "09-launch-process.txt", value.appPackage)
	observation.processSnapshot(ctx, "after-survival-interval", time.Second)
	observation.captureStartupProcess(ctx, "after-survival-interval")
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
	started := time.Now()
	commandArgs := make([]string, 0, len(args)+2)
	if client.serial != "" {
		commandArgs = append(commandArgs, "-s", client.serial)
	}
	commandArgs = append(commandArgs, args...)
	capture := newInstrumentationCaptureBuffer(time.Now)
	err := client.runCommand(ctx, commandArgs, capture, capture, 0)
	finished := time.Now()
	output, chunks, truncated := capture.snapshot()
	status, exitCode := diagnosticCommandStatus(err)
	command := diagnosticCommand{
		Phase:       "instrumentation",
		StartedUTC:  started.UTC(),
		FinishedUTC: finished.UTC(),
		DurationMS:  finished.Sub(started).Milliseconds(),
		ExitCode:    exitCode,
		Status:      status,
		Truncated:   truncated,
	}
	client.timeline.record("instrumentation", started, err)
	detailStem := strings.TrimSuffix(name, filepath.Ext(name))
	detailStem = strings.TrimSuffix(detailStem, "-summary")
	detailName := detailStem + "-details.json"
	detail := buildInstrumentationDiagnostic(chunks, command, truncated)
	if writeErr := writeInstrumentationDiagnostic(filepath.Join(client.evidenceDir, detailName), detail); writeErr != nil {
		return output, fmt.Errorf("write %s: %w", detailName, writeErr)
	}
	summary := summarizeInstrumentation(output)
	if len(summary) > maxDiagnosticBytes {
		return output, errors.New("instrumentation summary exceeded its byte limit")
	}
	if writeErr := os.WriteFile(filepath.Join(client.evidenceDir, name), []byte(summary), 0o644); writeErr != nil {
		return output, fmt.Errorf("write %s: %w", name, writeErr)
	}
	if truncated {
		return output, fmt.Errorf("adb instrumentation output exceeded %d bytes", maxCommandEvidence)
	}
	return output, err
}

type instrumentationDiagnosticChunk struct {
	ObservedUTC time.Time
	Raw         string
}

type instrumentationCaptureBuffer struct {
	mu     sync.Mutex
	output boundedBuffer
	chunks []instrumentationDiagnosticChunk
	now    func() time.Time
}

func newInstrumentationCaptureBuffer(now func() time.Time) *instrumentationCaptureBuffer {
	if now == nil {
		now = time.Now
	}
	return &instrumentationCaptureBuffer{output: boundedBuffer{limit: maxCommandEvidence}, now: now}
}

func (capture *instrumentationCaptureBuffer) Write(input []byte) (int, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	before := capture.output.buffer.Len()
	_, _ = capture.output.Write(input)
	after := capture.output.buffer.Len()
	if after > before {
		capture.chunks = append(capture.chunks, instrumentationDiagnosticChunk{
			ObservedUTC: capture.now().UTC(),
			Raw:         string(append([]byte(nil), input[:after-before]...)),
		})
	}
	return len(input), nil
}

func (capture *instrumentationCaptureBuffer) snapshot() (string, []instrumentationDiagnosticChunk, bool) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	chunks := make([]instrumentationDiagnosticChunk, len(capture.chunks))
	copy(chunks, capture.chunks)
	return capture.output.String(), chunks, capture.output.exceeded
}

type instrumentationTestDiagnostic struct {
	Class            string
	Method           string
	Status           string
	ObservedUTC      time.Time
	StartedUTC       time.Time
	FinishedUTC      time.Time
	DurationMS       int64
	Category         string
	ExceptionType    string
	ExceptionTypes   []string
	Message          string
	Expected         string
	Actual           string
	SetupState       []string
	Stack            []string
	ApplicationStack []string
}

type instrumentationDiagnosticReport struct {
	Schema                 string
	Status                 string
	Command                diagnosticCommand
	InstrumentationStarted bool
	TestsBegan             int
	TestsCompleted         int
	LastObserved           *instrumentationTestDiagnostic
	Failures               []instrumentationTestDiagnostic
	Issues                 []string
}

type timedInstrumentationLine struct {
	ObservedUTC time.Time
	Text        string
}

func instrumentationDiagnosticLines(chunks []instrumentationDiagnosticChunk) ([]timedInstrumentationLine, bool) {
	lines := make([]timedInstrumentationLine, 0)
	pending := ""
	complete := true
	lastObserved := time.Time{}
	for _, chunk := range chunks {
		if chunk.ObservedUTC.IsZero() || len(chunk.Raw) > maxCommandEvidence || len(pending)+len(chunk.Raw) > maxCommandEvidence {
			return lines, false
		}
		lastObserved = chunk.ObservedUTC.UTC()
		pending += chunk.Raw
		for {
			index := strings.IndexByte(pending, '\n')
			if index < 0 {
				break
			}
			line := strings.TrimSuffix(pending[:index], "\r")
			lines = append(lines, timedInstrumentationLine{ObservedUTC: lastObserved, Text: line})
			pending = pending[index+1:]
		}
	}
	if pending != "" {
		lines = append(lines, timedInstrumentationLine{ObservedUTC: lastObserved, Text: strings.TrimSuffix(pending, "\r")})
		complete = false
	}
	return lines, complete
}

func splitTestIdentity(identity string) (string, string, bool) {
	className, method, found := strings.Cut(identity, "#")
	return className, method, found && safeTestIdentity(identity)
}

func buildInstrumentationDiagnostic(chunks []instrumentationDiagnosticChunk, command diagnosticCommand, truncated bool) instrumentationDiagnosticReport {
	report := instrumentationDiagnosticReport{
		Schema:  "kurdistan-instrumentation-diagnostic-v1",
		Status:  "CAPTURED",
		Command: command,
	}
	incomplete := func(issue string) {
		report.Status = "INCOMPLETE"
		if len(report.Issues) < 32 {
			report.Issues = append(report.Issues, issue)
		}
	}
	if truncated || command.Truncated {
		incomplete("instrumentation output truncated")
	}
	lines, complete := instrumentationDiagnosticLines(chunks)
	if !complete {
		incomplete("instrumentation output framing incomplete")
	}

	type activeTest struct {
		started time.Time
	}
	active := map[string][]activeTest{}
	className, methodName := "", ""
	stackLines := make([]string, 0)
	stackActive := false
	lastEventAt := command.FinishedUTC
	setLast := func(detail instrumentationTestDiagnostic) {
		copy := detail
		report.LastObserved = &copy
	}
	addFailure := func(detail instrumentationTestDiagnostic) {
		if len(report.Failures) == 16 {
			incomplete("instrumentation failure detail limit exceeded")
			return
		}
		report.Failures = append(report.Failures, detail)
	}
	for _, observed := range lines {
		line := strings.TrimSpace(observed.Text)
		if line == "" {
			continue
		}
		lastEventAt = observed.ObservedUTC
		switch {
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: class="):
			className = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: class="))
			stackActive = false
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: test="):
			methodName = strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: test="))
			stackActive = false
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS: stack="):
			stackLines = []string{strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS: stack="))}
			stackActive = true
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS:"):
			stackActive = false
		case strings.HasPrefix(line, "INSTRUMENTATION_STATUS_CODE:"):
			code, codeErr := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(line, "INSTRUMENTATION_STATUS_CODE:")))
			identity := className + "#" + methodName
			class, method, identityOK := splitTestIdentity(identity)
			if codeErr != nil || !identityOK {
				incomplete("instrumentation status identity or code invalid")
				className, methodName, stackLines, stackActive = "", "", nil, false
				continue
			}
			detail := instrumentationTestDiagnostic{Class: class, Method: method, ObservedUTC: observed.ObservedUTC}
			switch {
			case code == 1:
				detail.Status = "STARTED"
				detail.StartedUTC = observed.ObservedUTC
				detail.DurationMS = 0
				active[identity] = append(active[identity], activeTest{started: observed.ObservedUTC})
				report.TestsBegan++
				report.InstrumentationStarted = true
				setLast(detail)
			case code <= 0:
				report.TestsCompleted++
				switch code {
				case 0:
					detail.Status = "PASS"
				case -1:
					detail.Status = "ERROR"
				case -2:
					detail.Status = "FAIL"
				case -3:
					detail.Status = "IGNORED"
				case -4:
					detail.Status = "ASSUMPTION_FAILURE"
				default:
					detail.Status = "UNKNOWN"
					incomplete("instrumentation terminal status unsupported")
				}
				queue := active[identity]
				if len(queue) == 0 {
					detail.DurationMS = -1
					incomplete("instrumentation terminal event lacks matching start")
				} else {
					detail.StartedUTC = queue[0].started
					detail.FinishedUTC = observed.ObservedUTC
					detail.DurationMS = observed.ObservedUTC.Sub(queue[0].started).Milliseconds()
					if detail.DurationMS < 0 {
						incomplete("instrumentation event timestamps reversed")
					}
					if len(queue) == 1 {
						delete(active, identity)
					} else {
						active[identity] = queue[1:]
					}
				}
				if code == -1 || code == -2 || code == -4 {
					stack := strings.Join(stackLines, "\n")
					detail.Category, detail.ExceptionType = instrumentationFailureDetails(stack)
					exceptions, stackComplete := javaFailureDetails(stack)
					if len(exceptions) == 0 {
						incomplete("instrumentation failure exception unavailable")
					} else {
						detail.ExceptionType = exceptions[0].Class
						detail.Message = exceptions[0].Message
						if expected, actual, setup, ok := structuredTestSetup(detail.Message); ok {
							detail.Expected = expected
							detail.Actual = actual
							detail.SetupState = append([]string(nil), setup...)
						}
						for _, exception := range exceptions {
							detail.ExceptionTypes = append(detail.ExceptionTypes, exception.Class)
							for _, frame := range exception.Stack {
								if len(detail.Stack) == 16 {
									stackComplete = false
									break
								}
								detail.Stack = append(detail.Stack, frame)
								if strings.HasPrefix(frame, "at org.kurdistanvpn.") && len(detail.ApplicationStack) < 8 {
									detail.ApplicationStack = append(detail.ApplicationStack, frame)
								}
							}
						}
					}
					if !stackComplete {
						incomplete("instrumentation failure stack redacted or truncated")
					}
					addFailure(detail)
				}
				setLast(detail)
			default:
				incomplete("instrumentation status code unsupported")
			}
			className, methodName, stackLines, stackActive = "", "", nil, false
		default:
			if stackActive {
				if len(stackLines) == 256 {
					incomplete("instrumentation stack input limit exceeded")
				} else {
					stackLines = append(stackLines, line)
				}
			}
		}
	}
	if command.Status == "DEADLINE" {
		for identity, queue := range active {
			class, method, ok := splitTestIdentity(identity)
			if !ok {
				incomplete("timed-out instrumentation identity invalid")
				continue
			}
			for _, item := range queue {
				detail := instrumentationTestDiagnostic{
					Class: class, Method: method, Status: "TIMEOUT", Category: "test_timeout",
					ObservedUTC: lastEventAt, StartedUTC: item.started, FinishedUTC: command.FinishedUTC,
					DurationMS: command.FinishedUTC.Sub(item.started).Milliseconds(),
				}
				addFailure(detail)
				setLast(detail)
			}
		}
	} else if len(active) != 0 {
		incomplete("instrumentation tests lack terminal status")
	}
	return report
}

func writeInstrumentationDiagnostic(path string, report instrumentationDiagnosticReport) error {
	encoded, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return err
	}
	if len(encoded) > maxInstrumentationDiagnosticBytes {
		fallback := instrumentationDiagnosticReport{
			Schema: report.Schema, Status: "INCOMPLETE", Command: report.Command,
			InstrumentationStarted: report.InstrumentationStarted,
			TestsBegan:             report.TestsBegan, TestsCompleted: report.TestsCompleted,
			LastObserved: report.LastObserved,
			Issues:       append(append([]string(nil), report.Issues...), "instrumentation diagnostic output bound exceeded"),
		}
		encoded, err = json.MarshalIndent(fallback, "", "  ")
		if err != nil || len(encoded) > maxInstrumentationDiagnosticBytes {
			return errors.New("instrumentation diagnostics INCOMPLETE: output bound")
		}
	}
	return os.WriteFile(path, append(encoded, '\n'), 0o600)
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

type nativeFilesystemInvocationPlan struct {
	OwnerPackage  string
	TestPackage   string
	DataDir       string
	Root          string
	Authorization string
	Children      []string
}

func nativeFilesystemInstrumentationPlan(ownerPackage, testPackage, dataDir, invocation string) (nativeFilesystemInvocationPlan, error) {
	packagePattern := regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_]*(?:\.[A-Za-z][A-Za-z0-9_]*)+$`)
	if !packagePattern.MatchString(ownerPackage) || !packagePattern.MatchString(testPackage) ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(invocation) {
		return nativeFilesystemInvocationPlan{}, errors.New("invalid native-filesystem invocation identity")
	}
	wantDataDir := regexp.MustCompile(`^/data/(?:user/[0-9]+|data)/` + regexp.QuoteMeta(ownerPackage) + `$`)
	if !wantDataDir.MatchString(dataDir) {
		return nativeFilesystemInvocationPlan{}, errors.New("test-owned package directory unavailable")
	}
	children := append([]string(nil), nativeFilesystemChildren...)
	root := dataDir + "/cache/phase17-disposable-" + invocation
	preimage := nativeFilesystemAuthorizationV1 + root + "\x00" + strings.Join(children, "\x00")
	digest := sha256.Sum256([]byte(preimage))
	return nativeFilesystemInvocationPlan{
		OwnerPackage: ownerPackage, TestPackage: testPackage, DataDir: dataDir,
		Root: root, Authorization: fmt.Sprintf("%x", digest), Children: children,
	}, nil
}

func nativeFilesystemPreparationArgs(plan nativeFilesystemInvocationPlan) [][]string {
	prefix := strings.TrimPrefix(plan.Root, plan.DataDir+"/")
	commands := [][]string{
		{"shell", "run-as", plan.OwnerPackage, "mkdir", prefix},
		{"shell", "run-as", plan.OwnerPackage, "chmod", "700", prefix},
	}
	for _, child := range plan.Children {
		path := prefix + "/" + child
		commands = append(commands,
			[]string{"shell", "run-as", plan.OwnerPackage, "mkdir", path},
			[]string{"shell", "run-as", plan.OwnerPackage, "chmod", "700", path},
		)
	}
	return commands
}

func nativeFilesystemInstrumentationArgs(plan nativeFilesystemInvocationPlan, runner string) []string {
	return []string{
		"shell", "am", "instrument", "-w", "-r",
		"-e", "phase17.disposableRoot", plan.Root,
		"-e", "phase17.filesystemAuthorization", plan.Authorization,
		runner,
	}
}

func validateNativeFilesystemInstrumentationArgs(args []string, ownerPackage, testPackage string) error {
	if len(args) != 12 || !reflectDeepEqualStrings(args[:5], []string{"shell", "am", "instrument", "-w", "-r"}) ||
		args[5] != "-e" || args[6] != "phase17.disposableRoot" ||
		args[8] != "-e" || args[9] != "phase17.filesystemAuthorization" ||
		!strings.HasPrefix(args[11], testPackage+"/") {
		return errors.New("native-filesystem instrumentation argument framing invalid")
	}
	rootPattern := regexp.MustCompile(`^(/data/(?:user/[0-9]+|data)/` + regexp.QuoteMeta(ownerPackage) + `)/cache/phase17-disposable-([0-9a-f]{32})$`)
	match := rootPattern.FindStringSubmatch(args[7])
	if match == nil || !regexp.MustCompile(`^[0-9a-f]{64}$`).MatchString(args[10]) {
		return errors.New("native-filesystem instrumentation argument value invalid")
	}
	plan, err := nativeFilesystemInstrumentationPlan(ownerPackage, testPackage, match[1], match[2])
	if err != nil || plan.Root != args[7] || plan.Authorization != args[10] {
		return errors.New("native-filesystem instrumentation authorization mismatch")
	}
	return nil
}

func reflectDeepEqualStrings(left, right []string) bool {
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

func prepareNativeFilesystemInstrumentation(ctx context.Context, client adbClient, ownerPackage, testPackage, runner string) ([]string, error) {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, errors.New("native-filesystem invocation identity unavailable")
	}
	raw, err := client.capture(ctx, "12a-target-package-root.txt", "shell", "run-as", ownerPackage, "pwd")
	if err != nil {
		return nil, fmt.Errorf("read test-owned package root: %w", err)
	}
	dataDir := strings.TrimSpace(raw)
	plan, err := nativeFilesystemInstrumentationPlan(ownerPackage, testPackage, dataDir, fmt.Sprintf("%x", nonce))
	if err != nil {
		return nil, err
	}
	for index, args := range nativeFilesystemPreparationArgs(plan) {
		name := fmt.Sprintf("12b-native-root-%02d.txt", index+1)
		if _, err := client.capture(ctx, name, args...); err != nil {
			return nil, fmt.Errorf("prepare invocation-owned native-filesystem root step %d: %w", index+1, err)
		}
	}
	args := nativeFilesystemInstrumentationArgs(plan, runner)
	if err := validateNativeFilesystemInstrumentationArgs(args, ownerPackage, testPackage); err != nil {
		return nil, err
	}
	return args, nil
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
	transport   *commandTransport
}

// The transport owns only child execution. Callers retain command ordering,
// bounded writers, deadlines, sanitization, correlation and gate derivation.
// Production construction always installs the real transport; it is not
// selectable through flags, environment variables or other external input.
type commandTransport struct {
	run   func(context.Context, string, []string, io.Writer, io.Writer, time.Duration) error
	start func(context.Context, string, []string, io.Writer, io.Writer, time.Duration) (func() error, error)
}

func newADBClient(path, serial, evidenceDir string, timeline *diagnosticTimeline) adbClient {
	return adbClient{
		path: path, serial: serial, evidenceDir: evidenceDir, timeline: timeline,
		transport: &commandTransport{run: runRealCommand, start: startRealCommand},
	}
}

func realCommand(ctx context.Context, path string, args []string, stdout, stderr io.Writer, waitDelay time.Duration) *exec.Cmd {
	command := exec.CommandContext(ctx, path, args...)
	command.Stdout, command.Stderr = stdout, stderr
	command.WaitDelay = waitDelay
	return command
}

func runRealCommand(ctx context.Context, path string, args []string, stdout, stderr io.Writer, waitDelay time.Duration) error {
	return realCommand(ctx, path, args, stdout, stderr, waitDelay).Run()
}

func startRealCommand(ctx context.Context, path string, args []string, stdout, stderr io.Writer, waitDelay time.Duration) (func() error, error) {
	command := realCommand(ctx, path, args, stdout, stderr, waitDelay)
	if err := command.Start(); err != nil {
		return nil, err
	}
	return command.Wait, nil
}

func (client adbClient) runCommand(ctx context.Context, args []string, stdout, stderr io.Writer, waitDelay time.Duration) error {
	if client.transport == nil || client.transport.run == nil {
		return errors.New("command transport unavailable")
	}
	return client.transport.run(ctx, client.path, args, stdout, stderr, waitDelay)
}

func (client adbClient) startCommand(ctx context.Context, args []string, stdout, stderr io.Writer, waitDelay time.Duration) (func() error, error) {
	if client.transport == nil || client.transport.start == nil {
		return nil, errors.New("command transport unavailable")
	}
	wait, err := client.transport.start(ctx, client.path, args, stdout, stderr, waitDelay)
	if err == nil && wait == nil {
		return nil, errors.New("command completion unavailable")
	}
	return wait, err
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

type launchStreamSequence struct {
	mu    sync.Mutex
	value uint64
}

func (sequence *launchStreamSequence) mark() (uint64, time.Time) {
	sequence.mu.Lock()
	defer sequence.mu.Unlock()
	sequence.value++
	return sequence.value, time.Now().UTC()
}

type launchStreamCapture struct {
	mu            sync.Mutex
	sequence      *launchStreamSequence
	buffer        boundedBuffer
	bytes         int64
	firstUTC      time.Time
	lastUTC       time.Time
	firstSequence uint64
	lastSequence  uint64
}

type launchStreamCaptureSnapshot struct {
	text          string
	bytes         int64
	truncated     bool
	firstUTC      time.Time
	lastUTC       time.Time
	firstSequence uint64
	lastSequence  uint64
}

func newLaunchStreamCapture(limit int, sequence *launchStreamSequence) *launchStreamCapture {
	return &launchStreamCapture{sequence: sequence, buffer: boundedBuffer{limit: limit}}
}

func (capture *launchStreamCapture) Write(input []byte) (int, error) {
	if len(input) == 0 {
		return 0, nil
	}
	sequence, observed := capture.sequence.mark()
	capture.mu.Lock()
	defer capture.mu.Unlock()
	written, err := capture.buffer.Write(input)
	capture.bytes += int64(written)
	if capture.firstSequence == 0 {
		capture.firstSequence = sequence
		capture.firstUTC = observed
	}
	capture.lastSequence = sequence
	capture.lastUTC = observed
	return written, err
}

func (capture *launchStreamCapture) snapshot() launchStreamCaptureSnapshot {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return launchStreamCaptureSnapshot{
		text: capture.buffer.String(), bytes: capture.bytes, truncated: capture.buffer.exceeded,
		firstUTC: capture.firstUTC, lastUTC: capture.lastUTC,
		firstSequence: capture.firstSequence, lastSequence: capture.lastSequence,
	}
}

func (client adbClient) capture(ctx context.Context, name string, args ...string) (output string, resultErr error) {
	started := time.Now()
	defer func() { client.timeline.record(name, started, resultErr) }()
	commandArgs := make([]string, 0, len(args)+2)
	if client.serial != "" {
		commandArgs = append(commandArgs, "-s", client.serial)
	}
	commandArgs = append(commandArgs, args...)
	combined := boundedBuffer{limit: maxCommandEvidence}
	err := client.runCommand(ctx, commandArgs, &combined, &combined, 0)
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
	combined := boundedBuffer{limit: maxLogcatInput}
	commandErr := client.runCommand(ctx, commandArgs, &combined, &combined, 0)
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
	combined := boundedBuffer{limit: maxCommandEvidence}
	err := client.runCommand(ctx, commandArgs, &combined, &combined, 0)
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
var structuredTestSetupPattern = regexp.MustCompile(`^KURDISTAN_TEST_SETUP expected=([A-Z0-9_|-]{1,96}) actual=([A-Z0-9_|-]{1,96}) setup=([A-Z0-9_|,-]{1,256})$`)
var structuredQuiescenceDiagnosticPattern = regexp.MustCompile(`^KURDISTAN_QUIESCENCE_DIAGNOSTIC poisoned=[0-9]{1,4} outcome=[A-Z_]{1,48} timeout=(?:true|false) interruption=(?:true|false) thread_interrupted=(?:true|false) elapsed_ms=[0-9]{1,12} future_began=(?:true|false) replied=(?:true|false) replied_late=(?:true|false) cleanup=[A-Z_]{1,32} late_authorization=(?:true|false)$`)

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
	if structuredTestSetupPattern.MatchString(message) || structuredQuiescenceDiagnosticPattern.MatchString(message) {
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

func structuredTestSetup(message string) (string, string, []string, bool) {
	match := structuredTestSetupPattern.FindStringSubmatch(message)
	if match == nil {
		return "", "", nil, false
	}
	setup := strings.Split(match[3], ",")
	for _, value := range setup {
		if value == "" {
			return "", "", nil, false
		}
	}
	return match[1], match[2], setup, true
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

type diagnosticClockEvidence struct {
	Phase           string
	Domain          string
	ObservedUTC     time.Time
	Raw             string
	RawStatus       string
	ParseStatus     string
	Rejection       string
	ParsedNanos     int64
	CommandStatus   string
	CommandExitCode int
}

var epochLogPattern = regexp.MustCompile("^\\s*([0-9]{1,12}\\.[0-9]{1,9})\\s+([0-9]+)\\s+([0-9]+)\\s+([VDIWEF])\\s+([A-Za-z0-9_.-]+)\\s*:\\s?(.*)$")
var processLogPattern = regexp.MustCompile("^Process: ([A-Za-z0-9_.:]+), PID: ([0-9]+)$")
var processSuffixPattern = regexp.MustCompile("^[A-Za-z0-9_.]+$")

func parseEpochNanos(value string) (int64, string) {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return 0, "EMPTY"
	}
	if strings.ContainsAny(trimmed, "\r\n") {
		return 0, "MULTILINE"
	}
	parts := strings.Split(trimmed, ".")
	if len(parts) != 2 {
		return 0, "FORMAT"
	}
	if parts[0] == "" {
		return 0, "SECONDS_EMPTY"
	}
	if parts[1] == "" {
		return 0, "FRACTION_EMPTY"
	}
	if len(parts[1]) > 9 {
		return 0, "FRACTION_PRECISION"
	}
	if strings.Trim(parts[0], "0123456789") != "" {
		return 0, "SECONDS_NON_NUMERIC"
	}
	if strings.Trim(parts[1], "0123456789") != "" {
		return 0, "FRACTION_NON_NUMERIC"
	}
	seconds, err := strconv.ParseInt(parts[0], 10, 64)
	if err != nil || seconds < 0 || seconds > 9_000_000_000 {
		return 0, "SECONDS_OUT_OF_RANGE"
	}
	fraction, err := strconv.ParseInt(parts[1]+strings.Repeat("0", 9-len(parts[1])), 10, 64)
	if err != nil {
		return 0, "FRACTION_OUT_OF_RANGE"
	}
	return seconds*1_000_000_000 + fraction, ""
}

func epochNanos(value string) (int64, error) {
	nanos, rejection := parseEpochNanos(value)
	if rejection != "" {
		return 0, fmt.Errorf("invalid diagnostic clock: %s", rejection)
	}
	return nanos, nil
}

func clockDiagnostic(raw string, command diagnosticCommand) diagnosticClockEvidence {
	trimmed := strings.TrimSpace(raw)
	evidence := diagnosticClockEvidence{
		Phase: command.Phase, ObservedUTC: command.FinishedUTC,
		RawStatus: "REDACTED", ParseStatus: "REJECTED",
		CommandStatus: command.Status, CommandExitCode: command.ExitCode,
	}
	safeRaw := regexp.MustCompile("^[+-]?[0-9%N]{1,16}(?:\\.[0-9%N]{0,16})?$")
	if len(trimmed) <= 64 && safeRaw.MatchString(trimmed) {
		evidence.Raw = trimmed
		evidence.RawStatus = "CAPTURED"
	}
	evidence.ParsedNanos, evidence.Rejection = parseEpochNanos(raw)
	if evidence.Rejection == "" {
		evidence.ParseStatus = "CAPTURED"
	}
	return evidence
}

func monotonicClockProbePlan(phase, invocation string) (string, [][]string, error) {
	if !regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`).MatchString(phase) ||
		!regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(invocation) {
		return "", nil, errors.New("invalid monotonic clock probe identity")
	}
	marker := "CLOCK:" + phase + ":" + invocation
	return marker, [][]string{
		{"shell", "log", "-p", "i", "-t", clockProbeTag, marker},
		{"shell", "logcat", "-b", "main", "-d", "-t", "64", "-v", "threadtime", "-v", "monotonic", "-v", "usec", clockProbeTag + ":I", "*:S"},
	}, nil
}

func monotonicClockDiagnostic(raw, marker string, command diagnosticCommand) diagnosticClockEvidence {
	evidence := diagnosticClockEvidence{
		Phase: command.Phase, Domain: monotonicClockDomain, ObservedUTC: command.FinishedUTC,
		RawStatus: "REDACTED", ParseStatus: "REJECTED",
		CommandStatus: command.Status, CommandExitCode: command.ExitCode,
	}
	if len(raw) > maxLogcatInput || !regexp.MustCompile(`^CLOCK:[a-z][a-z0-9-]{0,31}:[0-9a-f]{32}$`).MatchString(marker) {
		evidence.Rejection = "INPUT_INVALID"
		return evidence
	}
	var matches []launchLogEvent
	malformed := false
	for _, line := range strings.Split(strings.ReplaceAll(raw, "\r\n", "\n"), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "---------") {
			continue
		}
		event, ok := parseEpochLog(line)
		if !ok {
			if strings.Contains(line, clockProbeTag) || strings.Contains(line, marker) {
				malformed = true
			}
			continue
		}
		if event.Tag == clockProbeTag && event.Text == marker {
			matches = append(matches, event)
		}
	}
	switch {
	case malformed:
		evidence.Rejection = "MARKER_MALFORMED"
	case len(matches) == 0:
		evidence.Rejection = "MARKER_MISSING"
	case len(matches) != 1:
		evidence.Rejection = "MARKER_AMBIGUOUS"
	default:
		evidence.Raw = strconv.FormatInt(matches[0].DeviceNanos/1_000_000_000, 10) + "." +
			fmt.Sprintf("%09d", matches[0].DeviceNanos%1_000_000_000)
		evidence.RawStatus = "CAPTURED"
		evidence.ParsedNanos = matches[0].DeviceNanos
		evidence.ParseStatus = "CAPTURED"
	}
	return evidence
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
	Process        string
	PID            int
	UID            int
	Timestamp      time.Time
	DeviceNanos    int64
	DeviceEndNanos int64
	Reason         int
	Status         int
}

func parseExitRecords(input, app string, startNanos, endNanos int64, correlation diagnosticClockCorrelation, zone *time.Location) ([]diagnosticExit, bool) {
	if zone == nil || startNanos <= 0 || endNanos <= startNanos || correlation.Status != "CAPTURED" ||
		correlation.WallMinusMonotonicLowerNanos <= 0 || correlation.WallMinusMonotonicUpperNanos < correlation.WallMinusMonotonicLowerNanos || len(input) > maxLogcatInput {
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
		wallNanos := at.UnixNano()
		if wallNanos <= 0 {
			complete = false
			continue
		}
		deviceNanos := wallNanos - correlation.WallMinusMonotonicUpperNanos
		deviceEndNanos := wallNanos - correlation.WallMinusMonotonicLowerNanos
		// ApplicationExitInfo exposes milliseconds. Preserve the existing one-
		// millisecond lower-bound tolerance without expanding the launch window.
		if deviceEndNanos+int64(time.Millisecond) < startNanos || deviceNanos > endNanos {
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
		records = append(records, diagnosticExit{Process: process[1], PID: values["pid"], UID: values["realUid"], Timestamp: at, DeviceNanos: deviceNanos, DeviceEndNanos: deviceEndNanos, Reason: values["reason"], Status: values["status"]})
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
	if observation == nil || observation.Schema != startupObserverSchema ||
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
		optional := command.Phase == "collector-main-probe" || command.Phase == "collector-system-probe"
		if command.DurationMS < 0 || command.StartedUTC.Before(observation.StartedUTC) ||
			command.FinishedUTC.Before(command.StartedUTC) || command.FinishedUTC.After(observation.FinishedUTC) ||
			(!optional && (command.Truncated || command.Status != "CAPTURED" || command.ExitCode != 0)) {
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
	if err := validateCompositeStartup(observation, previous, current); err != nil {
		return err
	}
	if (observation.api >= 30 && observation.ExitStatus != "CAPTURED") ||
		(observation.api >= 26 && observation.api < 30 && observation.ExitStatus != "UNSUPPORTED_API_BELOW_30") || observation.api < 26 {
		return errLaunchIncomplete
	}
	requiredStreams := map[string]bool{"crash": false, "events": false}
	streamNames := map[string]bool{}
	if len(observation.StreamLifecycle) != 4 {
		return errLaunchIncomplete
	}
	for _, lifecycle := range observation.StreamLifecycle {
		if streamNames[lifecycle.Buffer] || (lifecycle.Buffer != "crash" && lifecycle.Buffer != "events" && lifecycle.Buffer != "main" && lifecycle.Buffer != "system") {
			return errLaunchIncomplete
		}
		streamNames[lifecycle.Buffer] = true
		if _, required := requiredStreams[lifecycle.Buffer]; required {
			if lifecycle.TerminalStatus != "DRAINED" || !lifecycle.ParserComplete || lifecycle.OutputTruncated || lifecycle.StderrTruncated {
				return errLaunchIncomplete
			}
			requiredStreams[lifecycle.Buffer] = true
		}
	}
	if !requiredStreams["crash"] || !requiredStreams["events"] {
		return errLaunchIncomplete
	}
	logStreams := map[string]bool{}
	for _, buffer := range observation.Logs {
		if buffer.Source != "stream" || logStreams[buffer.Buffer] ||
			(buffer.Buffer != "main" && buffer.Buffer != "system" && buffer.Buffer != "crash" && buffer.Buffer != "events") {
			return errLaunchIncomplete
		}
		logStreams[buffer.Buffer] = true
		if (buffer.Buffer == "crash" || buffer.Buffer == "events") && buffer.Status != "CAPTURED" {
			return errLaunchIncomplete
		}
		lastNanos := observation.WindowStartNanos
		for _, event := range buffer.Events {
			if event.DeviceNanos < lastNanos || event.DeviceNanos <= observation.WindowStartNanos || event.DeviceNanos > observation.WindowEndNanos {
				return errLaunchIncomplete
			}
			lastNanos = event.DeviceNanos
		}
	}
	if len(logStreams) != 4 {
		return errLaunchIncomplete
	}
	epochStart := observation.WindowStartNanos
	for _, event := range observation.SystemEvents.Events {
		if event.Type == "PROCESS_START" && event.PID == current.PID && event.Process == current.Name {
			epochStart = event.DeviceNanos
			break
		}
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
			exit.DeviceEndNanos+int64(time.Millisecond) >= epochStart && exit.DeviceNanos <= observation.WindowEndNanos {
			return errors.New("current target exit observed")
		}
	}
	if observation.Status != "CAPTURED" || len(observation.Issues) != 0 {
		return errLaunchIncomplete
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

type diagnosticStreamLifecycle struct {
	Buffer                     string
	CommandCategory            string
	Command                    []string
	ExecutionBoundary          string
	CommandIdentityStatus      string
	CommandUID                 int
	CommandGID                 int
	CommandSELinuxContext      string
	StartStatus                string
	ReadinessStatus            string
	TerminalStatus             string
	TerminalReason             string
	CommandStatus              string
	ExitCode                   int
	ExitSignal                 string
	ContextCancellationState   string
	CancellationRequestedUTC   time.Time
	FirstStderrUTC             time.Time
	LastStderrUTC              time.Time
	CommandExitedUTC           time.Time
	CancellationSequence       uint64
	FirstStderrSequence        uint64
	LastStderrSequence         uint64
	CommandExitSequence        uint64
	ExitRelativeToCancellation string
	OutputTruncated            bool
	StderrTruncated            bool
	StderrObserved             bool
	StdoutBytes                int64
	StderrBytes                int64
	StderrSHA256               string
	StderrExcerpt              []string
	LastParsedRecord           diagnosticLaunchStreamRecord
	StartCapturedBeforeStop    bool
	EndCapturedBeforeStop      bool
	IntentionallyStopped       bool
	ParserComplete             bool
}

type diagnosticCollectorCommand struct {
	Phase         string
	Argv          []string
	StartedUTC    time.Time
	FinishedUTC   time.Time
	DurationMS    int64
	CommandStatus string
	TerminalCause string
	ExitCode      int
	StdoutBytes   int64
	StderrBytes   int64
	StderrExcerpt []string
	Truncated     bool
}

type diagnosticCollectorIdentity struct {
	Status         string
	Rejection      string
	Execution      string
	UID            int
	User           string
	GID            int
	Group          string
	SELinuxContext string
	HelpStatus     string
	Commands       []diagnosticCollectorCommand
}

type diagnosticCollectorProbe struct {
	Buffer        string
	Status        string
	Rejection     string
	Argv          []string
	StartedUTC    time.Time
	FinishedUTC   time.Time
	DurationMS    int64
	CommandStatus string
	TerminalCause string
	ExitCode      int
	StdoutBytes   int64
	StderrBytes   int64
	StderrExcerpt []string
	Truncated     bool
}

type diagnosticLaunchStreamRecord struct {
	DeviceNanos int64
	PID         int
	TID         int
	Category    string
}

type diagnosticMarkerEvidence struct {
	Source          string
	Value           string
	DeviceNanos     int64
	InvocationMatch bool
	MarkerType      string
	EventNonce      string
	Emitter         string
	CommandEpoch    string
}

type diagnosticMarkerWindow struct {
	Status                  string
	Rejection               string
	DeviceStartNanos        int64
	DeviceEndNanos          int64
	Markers                 []diagnosticMarkerEvidence
	MatchingStartTimestamps []int64
	MatchingEndTimestamps   []int64
	IgnoredMarkers          int
	MalformedMarkers        int
}

type diagnosticClockCorrelation struct {
	Status                       string
	Rejection                    string
	WallMinusMonotonicNanos      int64
	WallMinusMonotonicLowerNanos int64
	WallMinusMonotonicUpperNanos int64
	StartOffsetNanos             int64
	EndOffsetNanos               int64
	StartOffsetLowerNanos        int64
	StartOffsetUpperNanos        int64
	EndOffsetLowerNanos          int64
	EndOffsetUpperNanos          int64
}

type launchObservation struct {
	client                adbClient
	api                   int
	app                   string
	streams               []*launchLogStream
	startMarker           launchMarkerIdentity
	endMarker             launchMarkerIdentity
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
	Clocks                []diagnosticClockEvidence
	Commands              []diagnosticCommand
	Processes             []diagnosticProcessSnapshot
	Logs                  []diagnosticLogBuffer
	StreamLifecycle       []diagnosticStreamLifecycle
	CollectorIdentity     diagnosticCollectorIdentity
	CollectorProbes       []diagnosticCollectorProbe
	ExitRecords           []diagnosticExit
	ExitStatus            string
	ActivityProcessState  []string
	ActivityProcessStatus string
	ProcessHealth         []diagnosticProcessHealth
	ResolvedActivity      string
	ResolutionStatus      string
	LaunchCommand         []string
	MarkerWindow          diagnosticMarkerWindow
	ClockCorrelation      diagnosticClockCorrelation
	Subject               startupSubjectBinding
	BootSession           startupBootSession
	CompositeSources      []startupCompositeSource
	ActivityStates        []startupActivityState
	ProcessCrossChecks    []startupProcessCrossCheck
	PackageState          []startupPackageState
	SystemEvents          startupSystemEventEvidence
	Issues                []string
}

type launchLogStream struct {
	name                 string
	command              []string
	ctx                  context.Context
	cancel               context.CancelFunc
	sequence             *launchStreamSequence
	done                 chan launchStreamTermination
	output               *launchStreamCapture
	stderr               *launchStreamCapture
	startErr             error
	terminalErr          error
	terminalUTC          time.Time
	terminalSequence     uint64
	cancelUTC            time.Time
	cancelSequence       uint64
	intentionallyStopped bool
	endedBeforeStop      bool
}

type launchStreamTermination struct {
	err      error
	observed time.Time
	sequence uint64
}

func (stream *launchLogStream) requestCancellation(intentional bool) {
	if stream.cancelSequence == 0 {
		stream.cancelSequence, stream.cancelUTC = stream.sequence.mark()
	}
	stream.intentionallyStopped = intentional
	stream.cancel()
}

func (stream *launchLogStream) acceptTermination(termination launchStreamTermination) {
	stream.terminalErr = termination.err
	stream.terminalUTC = termination.observed
	stream.terminalSequence = termination.sequence
}

var launchStreamStderrSafeTokenPattern = regexp.MustCompile(`(?i)\b(?:logcat|error|failed|failure|invalid|unknown|unsupported|option|argument|buffer|configuration|permission|denied|closed|cancelled|canceled|cancellation|owned|killed|signal|eof|pipe|read|write|transport|device|offline|timeout|terminated|stream|usage)\b`)
var launchStreamSignalPattern = regexp.MustCompile(`^signal: ([A-Za-z0-9]+)$`)

func sanitizeLaunchStreamStderr(input string) []string {
	const maxLines = 4
	const maxBytes = 320
	var result []string
	remaining := maxBytes
	for _, raw := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		if len(result) == maxLines || remaining == 0 {
			break
		}
		matches := launchStreamStderrSafeTokenPattern.FindAllString(strings.TrimSpace(raw), -1)
		if len(matches) == 0 {
			if strings.TrimSpace(raw) == "" {
				continue
			}
			matches = []string{"[REDACTED_DIAGNOSTIC]"}
		}
		line := strings.ToLower(strings.Join(matches, " "))
		if len(line) > remaining {
			line = line[:remaining]
		}
		result = append(result, line)
		remaining -= len(line)
	}
	return result
}

func launchStreamContextState(ctx context.Context) string {
	switch {
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return "DEADLINE"
	case errors.Is(ctx.Err(), context.Canceled):
		return "CANCELED"
	case ctx.Err() == nil:
		return "ACTIVE"
	default:
		return "UNKNOWN"
	}
}

func launchStreamExitSignal(err error) string {
	var exit *exec.ExitError
	if !errors.As(err, &exit) || exit.ProcessState == nil {
		return ""
	}
	match := launchStreamSignalPattern.FindStringSubmatch(exit.ProcessState.String())
	if match == nil {
		return ""
	}
	return strings.ToUpper(match[1])
}

func launchStreamCancellationDriven(err error, ctx context.Context) bool {
	if !errors.Is(ctx.Err(), context.Canceled) {
		return false
	}
	if errors.Is(err, context.Canceled) {
		return true
	}
	// CommandContext reports an owned process kill as a signalled ExitError on
	// Unix. An ordinary nonzero exit after cancellation is causally ambiguous
	// and must remain incomplete rather than being attributed to the harness.
	return launchStreamExitSignal(err) != ""
}

func lastLaunchStreamRecord(input string) diagnosticLaunchStreamRecord {
	var result diagnosticLaunchStreamRecord
	for _, line := range strings.Split(strings.ReplaceAll(input, "\r\n", "\n"), "\n") {
		event, ok := parseEpochLog(line)
		if !ok {
			continue
		}
		category := "OTHER_FILTERED_RECORD"
		switch event.Tag {
		case launchProbeTag:
			if marker, valid := parseLaunchMarkerIdentity(event.Text); valid {
				category = marker.Type + "_MARKER"
			} else {
				category = "MALFORMED_LAUNCH_MARKER"
			}
		case "AndroidRuntime":
			category = "ANDROID_RUNTIME"
		case "ActivityManager":
			category = "ACTIVITY_MANAGER"
		case "ActivityTaskManager":
			category = "ACTIVITY_TASK_MANAGER"
		}
		result = diagnosticLaunchStreamRecord{DeviceNanos: event.DeviceNanos, PID: event.PID, TID: event.TID, Category: category}
	}
	return result
}

func markerCaptureStatus(window diagnosticMarkerWindow) (bool, bool) {
	start, end := false, false
	for _, marker := range window.Markers {
		if !marker.InvocationMatch {
			continue
		}
		start = start || marker.MarkerType == "START"
		end = end || marker.MarkerType == "END"
	}
	return start, end
}

func diagnoseLaunchStreamLifecycle(stream *launchLogStream, stdout, stderr launchStreamCaptureSnapshot, parserComplete, startCaptured, endCaptured bool) diagnosticStreamLifecycle {
	terminalErr := stream.terminalErr
	if stream.startErr != nil {
		terminalErr = stream.startErr
	}
	commandStatus, exitCode := diagnosticCommandStatus(terminalErr)
	lifecycle := diagnosticStreamLifecycle{
		Buffer: stream.name, CommandCategory: "ADB_LOGCAT_STREAM", Command: append([]string(nil), stream.command...),
		StartStatus: "START_FAILED", ReadinessStatus: "NOT_AVAILABLE", TerminalStatus: "INCOMPLETE", TerminalReason: "START_FAILED",
		CommandStatus: commandStatus, ExitCode: exitCode, ExitSignal: launchStreamExitSignal(terminalErr),
		ContextCancellationState: launchStreamContextState(stream.ctx),
		CancellationRequestedUTC: stream.cancelUTC, FirstStderrUTC: stderr.firstUTC, LastStderrUTC: stderr.lastUTC,
		CommandExitedUTC: stream.terminalUTC, CancellationSequence: stream.cancelSequence,
		FirstStderrSequence: stderr.firstSequence, LastStderrSequence: stderr.lastSequence,
		CommandExitSequence: stream.terminalSequence, OutputTruncated: stdout.truncated, StderrTruncated: stderr.truncated,
		StderrObserved: stderr.bytes != 0, StdoutBytes: stdout.bytes, StderrBytes: stderr.bytes,
		StderrExcerpt: sanitizeLaunchStreamStderr(stderr.text), LastParsedRecord: lastLaunchStreamRecord(stdout.text),
		StartCapturedBeforeStop: startCaptured, EndCapturedBeforeStop: endCaptured,
		IntentionallyStopped: stream.intentionallyStopped, ParserComplete: parserComplete,
	}
	if stderr.bytes != 0 {
		digest := sha256.Sum256([]byte(stderr.text))
		lifecycle.StderrSHA256 = fmt.Sprintf("%x", digest)
	}
	switch {
	case stream.cancelSequence == 0 || stream.terminalSequence == 0:
		lifecycle.ExitRelativeToCancellation = "UNKNOWN"
	case stream.terminalSequence < stream.cancelSequence:
		lifecycle.ExitRelativeToCancellation = "BEFORE_OWNED_CANCELLATION"
	case stream.terminalSequence > stream.cancelSequence:
		lifecycle.ExitRelativeToCancellation = "AFTER_OWNED_CANCELLATION"
	default:
		lifecycle.ExitRelativeToCancellation = "AMBIGUOUS"
	}
	if stream.startErr == nil {
		lifecycle.StartStatus = "STARTED"
		lifecycle.ReadinessStatus = "OUTPUT_SINK_READY"
	}
	stderrBeforeCancellation := stderr.bytes != 0 && (stream.cancelSequence == 0 || stderr.firstSequence == 0 || stderr.firstSequence < stream.cancelSequence)
	stderrAfterCancellation := stderr.bytes != 0 && stream.cancelSequence != 0 && stderr.firstSequence > stream.cancelSequence
	transportComplete := stream.startErr == nil && !stream.endedBeforeStop && stdout.truncated == false && stderr.truncated == false &&
		parserComplete && startCaptured && endCaptured && lifecycle.ExitRelativeToCancellation == "AFTER_OWNED_CANCELLATION" &&
		stream.intentionallyStopped && launchStreamCancellationDriven(stream.terminalErr, stream.ctx)
	switch {
	case stream.startErr != nil && stderr.bytes != 0:
		lifecycle.TerminalReason = "COMMAND_OR_BUFFER_REJECTED"
	case stream.startErr != nil:
	case stdout.truncated:
		lifecycle.TerminalReason = "OUTPUT_TRUNCATED"
	case stderr.truncated:
		lifecycle.TerminalReason = "STDERR_TRUNCATED"
	case stderrBeforeCancellation:
		lifecycle.TerminalReason = "STDERR_BEFORE_OWNED_CANCELLATION"
	case stream.endedBeforeStop || lifecycle.ExitRelativeToCancellation == "BEFORE_OWNED_CANCELLATION":
		lifecycle.TerminalReason = "EOF_BEFORE_STOP"
	case !parserComplete:
		lifecycle.TerminalReason = "PARSER_INCOMPLETE"
	case !startCaptured || !endCaptured:
		lifecycle.TerminalReason = "MARKER_INCOMPLETE"
	case stderrAfterCancellation && transportComplete:
		lifecycle.TerminalStatus = "DRAINED"
		lifecycle.TerminalReason = "EXPECTED_OWNED_SHUTDOWN"
	case stderrAfterCancellation:
		lifecycle.TerminalReason = "POST_CANCELLATION_TRANSPORT_UNPROVEN"
	case transportComplete:
		lifecycle.TerminalStatus = "DRAINED"
		lifecycle.TerminalReason = "CANCELLED_AFTER_CAPTURE"
	default:
		lifecycle.TerminalReason = "TRANSPORT_COMPLETION_UNPROVEN"
	}
	return lifecycle
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
	output := diagnosticOutput{combined: boundedBuffer{limit: limit}, stdout: boundedBuffer{limit: limit}, stderr: boundedBuffer{limit: limit}}
	err := client.runCommand(ctx, commandArgs, diagnosticSink{owner: &output}, diagnosticSink{owner: &output, stderr: true}, time.Second)
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

func (observation *launchObservation) queryClock(parent context.Context, phase string) (int64, bool) {
	marker, commands, err := monotonicClockProbePlan(phase, observation.Invocation)
	if err != nil {
		observation.incomplete(phase + " identity unavailable")
		return 0, false
	}
	_, emitOK := observation.query(parent, phase+"-emit", commands[0]...)
	raw, commandOK := observation.query(parent, phase+"-snapshot", commands[1]...)
	if len(observation.Commands) == 0 {
		observation.incomplete(phase + " command record unavailable")
		return 0, false
	}
	evidence := monotonicClockDiagnostic(raw, marker, observation.Commands[len(observation.Commands)-1])
	evidence.Phase = phase
	observation.Clocks = append(observation.Clocks, evidence)
	return evidence.ParsedNanos, emitOK && commandOK && evidence.ParseStatus == "CAPTURED"
}

var diagnosticADBSerialPattern = regexp.MustCompile(`^emulator-[0-9]{4,6}$`)
var diagnosticShellIdentityPattern = regexp.MustCompile(`^uid=([0-9]{1,10})\(([A-Za-z0-9_.-]{1,64})\) gid=([0-9]{1,10})\(([A-Za-z0-9_.-]{1,64})\)(?: groups=[A-Za-z0-9_.,() -]{1,1000})?(?: context=[A-Za-z0-9_.:-]{1,128})?$`)
var diagnosticSELinuxContextPattern = regexp.MustCompile(`^u:r:shell:s0$`)

func diagnosticADBArgv(serial string, args ...string) []string {
	result := []string{"adb"}
	if serial != "" {
		if diagnosticADBSerialPattern.MatchString(serial) {
			result = append(result, "-s", serial)
		} else {
			result = append(result, "-s", "[REDACTED_SERIAL]")
		}
	}
	return append(result, args...)
}

func diagnosticCollectorTerminalCause(record diagnosticCommand) string {
	if record.Truncated {
		return "OUTPUT_TRUNCATED"
	}
	switch record.Status {
	case "CAPTURED":
		return "EXITED_SUCCESSFULLY"
	case "DEADLINE":
		return "CONTEXT_DEADLINE"
	case "CANCELLED":
		return "CONTEXT_CANCELLED"
	case "ERROR":
		return "COMMAND_FAILED"
	default:
		return "UNKNOWN"
	}
}

func parseDiagnosticShellIdentity(raw string) (int, string, int, string, bool) {
	value := strings.TrimSpace(raw)
	if strings.ContainsAny(value, "\r\n\x00") {
		return 0, "", 0, "", false
	}
	match := diagnosticShellIdentityPattern.FindStringSubmatch(value)
	if match == nil {
		return 0, "", 0, "", false
	}
	uid, uidErr := strconv.Atoi(match[1])
	gid, gidErr := strconv.Atoi(match[3])
	if uidErr != nil || gidErr != nil {
		return 0, "", 0, "", false
	}
	return uid, match[2], gid, match[4], true
}

func parseDiagnosticSELinuxContext(raw string) (string, bool) {
	value := strings.Trim(raw, " \t\r\n\x00")
	return value, diagnosticSELinuxContextPattern.MatchString(value)
}

func diagnosticLogcatHelpRecognized(stdout, stderr string) bool {
	value := strings.ToLower(strings.ReplaceAll(stdout+"\n"+stderr, "\r\n", "\n"))
	return strings.Contains(value, "usage:") && strings.Contains(value, "logcat") &&
		regexp.MustCompile(`(?:^|\s)-b(?:\s|=|<)`).MatchString(value) && strings.Contains(value, "buffer")
}

func diagnosticPermissionDenied(raw string) bool {
	value := strings.ToLower(raw)
	return strings.Contains(value, "permission denied") || strings.Contains(value, "not permitted")
}

func (observation *launchObservation) collectorCommand(parent context.Context, phase string, args ...string) (string, string, diagnosticCollectorCommand, error) {
	ctx, cancel := context.WithTimeout(parent, 2*time.Second)
	defer cancel()
	stdout, stderr, record, err := observation.client.diagnosticCommand(ctx, phase, 32<<10, args...)
	observation.Commands = append(observation.Commands, record)
	evidence := diagnosticCollectorCommand{
		Phase: phase, Argv: diagnosticADBArgv(observation.client.serial, args...),
		StartedUTC: record.StartedUTC, FinishedUTC: record.FinishedUTC, DurationMS: record.DurationMS,
		CommandStatus: record.Status, TerminalCause: diagnosticCollectorTerminalCause(record), ExitCode: record.ExitCode,
		StdoutBytes: int64(len(stdout)), StderrBytes: int64(len(stderr)),
		StderrExcerpt: sanitizeLaunchStreamStderr(stderr), Truncated: record.Truncated,
	}
	return stdout, stderr, evidence, err
}

func collectorProbeFromCommand(buffer string, command diagnosticCollectorCommand) diagnosticCollectorProbe {
	return diagnosticCollectorProbe{
		Buffer: buffer, Status: "INCOMPLETE", Rejection: "UNKNOWN",
		Argv: append([]string(nil), command.Argv...), StartedUTC: command.StartedUTC, FinishedUTC: command.FinishedUTC,
		DurationMS: command.DurationMS, CommandStatus: command.CommandStatus, TerminalCause: command.TerminalCause,
		ExitCode: command.ExitCode, StdoutBytes: command.StdoutBytes, StderrBytes: command.StderrBytes,
		StderrExcerpt: append([]string(nil), command.StderrExcerpt...), Truncated: command.Truncated,
	}
}

func (observation *launchObservation) captureCollectorCapability(parent context.Context) bool {
	identity := diagnosticCollectorIdentity{Status: "INCOMPLETE", Rejection: "UNKNOWN", Execution: "ADB_SHELL", HelpStatus: "INCOMPLETE"}
	rawID, idStderr, idCommand, idErr := observation.collectorCommand(parent, "collector-shell-id", "shell", "id")
	identity.Commands = append(identity.Commands, idCommand)
	uid, user, gid, group, idParsed := parseDiagnosticShellIdentity(rawID)
	identity.UID, identity.User, identity.GID, identity.Group = uid, user, gid, group
	idOK := idErr == nil && !idCommand.Truncated && idStderr == "" && idParsed && uid == 2000 && user == "shell" && gid == 2000 && group == "shell"
	switch {
	case idErr != nil:
		identity.Rejection = "IDENTITY_COMMAND_FAILED"
	case idCommand.Truncated:
		identity.Rejection = "IDENTITY_OUTPUT_TRUNCATED"
	case idStderr != "":
		identity.Rejection = "IDENTITY_STDERR_OBSERVED"
	case !idParsed:
		identity.Rejection = "IDENTITY_MALFORMED"
	case !idOK:
		identity.Rejection = "IDENTITY_NOT_SHELL"
	}
	rawContext, contextStderr, contextCommand, contextErr := observation.collectorCommand(parent, "collector-shell-selinux", "shell", "cat", "/proc/self/attr/current")
	identity.Commands = append(identity.Commands, contextCommand)
	contextValue, contextParsed := parseDiagnosticSELinuxContext(rawContext)
	identity.SELinuxContext = contextValue
	contextOK := contextErr == nil && !contextCommand.Truncated && contextStderr == "" && contextParsed
	if idOK && !contextOK {
		switch {
		case contextErr != nil:
			identity.Rejection = "SELINUX_COMMAND_FAILED"
		case contextCommand.Truncated:
			identity.Rejection = "SELINUX_OUTPUT_TRUNCATED"
		case contextStderr != "":
			identity.Rejection = "SELINUX_STDERR_OBSERVED"
		default:
			identity.Rejection = "SELINUX_CONTEXT_UNKNOWN"
		}
	}
	helpOut, helpStderr, helpCommand, helpErr := observation.collectorCommand(parent, "collector-logcat-help", "shell", "logcat", "--help")
	identity.Commands = append(identity.Commands, helpCommand)
	helpOK := helpErr == nil && !helpCommand.Truncated && !diagnosticPermissionDenied(helpStderr) && diagnosticLogcatHelpRecognized(helpOut, helpStderr)
	if helpOK {
		identity.HelpStatus = "CAPTURED"
	} else if idOK && contextOK {
		identity.Rejection = "LOGCAT_HELP_UNAVAILABLE"
	}
	if idOK && contextOK && helpOK {
		identity.Status = "CAPTURED"
		identity.Rejection = ""
	}
	observation.CollectorIdentity = identity

	requiredProbesOK := true
	for _, buffer := range []string{"crash", "events", "main", "system"} {
		args := []string{"shell", "logcat", "-b", buffer, "-d", "-t", "1", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
		if buffer == "events" {
			args = []string{"shell", "logcat", "-b", "events", "-d", "-t", "1", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "am_proc_start:I", "am_proc_died:I", "am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
		}
		_, stderr, command, err := observation.collectorCommand(parent, "collector-"+buffer+"-probe", args...)
		probe := collectorProbeFromCommand(buffer, command)
		switch {
		case command.Truncated:
			probe.Rejection = "OUTPUT_TRUNCATED"
		case err != nil:
			probe.Rejection = "COMMAND_FAILED"
		case stderr != "":
			probe.Rejection = "STDERR_OBSERVED"
		default:
			probe.Status = "CAPTURED"
			probe.Rejection = ""
		}
		if (buffer == "crash" || buffer == "events") && probe.Status != "CAPTURED" {
			requiredProbesOK = false
		}
		observation.CollectorProbes = append(observation.CollectorProbes, probe)
	}
	return identity.Status == "CAPTURED" && requiredProbesOK
}

func beginLaunchObservation(ctx context.Context, client adbClient, value options) *launchObservation {
	observation := &launchObservation{client: client, api: value.expectedAPI, app: value.appPackage, Schema: startupObserverSchema, Status: "CAPTURED", GateResult: "NOT_EVALUATED", StartedUTC: time.Now().UTC(), ExitStatus: "INCOMPLETE", ActivityProcessStatus: "INCOMPLETE", ResolutionStatus: "INCOMPLETE", Subject: value.startupSubject}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		observation.incomplete("invocation identity unavailable")
		return observation
	}
	observation.Invocation = fmt.Sprintf("%x", nonce)
	var markerErr error
	observation.startMarker, markerErr = newLaunchMarkerIdentity("START", observation.Invocation)
	if markerErr == nil {
		observation.endMarker, markerErr = newLaunchMarkerIdentity("END", observation.Invocation)
	}
	if markerErr != nil {
		observation.incomplete("launch marker identity unavailable")
		return observation
	}
	if !safeDiagnosticClass(value.appPackage) {
		observation.incomplete("unsupported diagnostic package identity")
		return observation
	}
	if !validStartupSubject(observation.Subject, observation) {
		observation.incomplete("immutable startup subject unavailable")
		return observation
	}
	var ok bool
	observation.DeviceStartNanos, ok = observation.queryClock(ctx, "clock-before")
	if !ok {
		observation.incomplete("device clock unavailable")
	}
	zone, ok := observation.query(ctx, "clock-zone", "shell", "date", "+%z")
	if ok && regexp.MustCompile("^[+-][0-9]{4}$").MatchString(strings.TrimSpace(zone)) {
		observation.ClockZone = strings.TrimSpace(zone)
	} else {
		observation.incomplete("device clock zone unavailable")
	}
	if !observation.captureCollectorCapability(ctx) {
		observation.incomplete("collector shell capability unavailable")
	}
	observation.captureStartupBoot(ctx, "before-launch")
	observation.captureStartupPackage(ctx, "before-launch")
	for _, buffer := range []string{"crash", "events", "main", "system"} {
		logctx, cancel := context.WithCancel(ctx)
		command := []string{"shell", "logcat", "-b", buffer, "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "KurdistanLaunchProbe:I", "*:S"}
		if buffer == "events" {
			command = []string{"shell", "logcat", "-b", "events", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "-T", "1", "am_proc_start:I", "am_proc_died:I", "am_kill:I", "am_anr:I", "am_crash:I", "*:S"}
		}
		args := append([]string(nil), command...)
		if client.serial != "" {
			args = append([]string{"-s", client.serial}, args...)
		}
		sequence := &launchStreamSequence{}
		stream := &launchLogStream{
			name: buffer, command: diagnosticADBArgv(client.serial, command...), ctx: logctx, cancel: cancel, sequence: sequence,
			done:   make(chan launchStreamTermination, 1),
			output: newLaunchStreamCapture(512<<10, sequence), stderr: newLaunchStreamCapture(8<<10, sequence),
		}
		var wait func() error
		wait, stream.startErr = client.startCommand(logctx, args, stream.output, stream.stderr, time.Second)
		if stream.startErr == nil {
			go func() {
				err := wait()
				terminalSequence, terminalUTC := stream.sequence.mark()
				stream.done <- launchStreamTermination{err: err, observed: terminalUTC, sequence: terminalSequence}
			}()
		} else {
			stream.terminalSequence, stream.terminalUTC = stream.sequence.mark()
			if buffer == "crash" || buffer == "events" {
				observation.incomplete(buffer + " log stream unavailable")
			}
		}
		observation.streams = append(observation.streams, stream)
	}
	_, _ = observation.query(ctx, "window-start", "shell", "log", "-p", "i", "-t", launchProbeTag, observation.startMarker.String())
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
	observation.captureStartupProcess(ctx, "terminal")
	rawState, readableState := observation.query(ctx, "activity-processes", "shell", "dumpsys", "activity", "processes", observation.app)
	observation.ActivityProcessState = sanitizeActivityProcessState(rawState, observation.app)
	var parsedState bool
	observation.ProcessHealth, parsedState = parseProcessHealth(rawState, observation.app)
	if readableState && parsedState {
		observation.ActivityProcessStatus = "CAPTURED"
	} else {
		observation.incomplete("activity process state unavailable or incomplete")
	}
	observation.captureStartupActivity(ctx, "terminal")
	observation.captureStartupPackage(ctx, "terminal")
	observation.captureStartupBoot(ctx, "terminal")
	_, _ = observation.query(ctx, "window-end", "shell", "log", "-p", "i", "-t", launchProbeTag, observation.endMarker.String())
	// A separate marker-only snapshot confirms the end even if the launch
	// deadline already terminated the streaming readers. It contains no crash
	// body and cannot supply an old invocation's marker.
	markerArgs, markerArgsErr := launchMarkerSnapshotArgs(observation.Invocation, observation.DeviceStartNanos, "monotonic")
	if markerArgsErr != nil {
		observation.incomplete("marker snapshot identity unavailable")
	}
	markers, markersOK := observation.query(ctx, "window-markers", markerArgs...)
	nanos, ok := observation.queryClock(ctx, "clock-after")
	if ok {
		observation.DeviceEndNanos = nanos
	} else {
		observation.incomplete("terminal clock unavailable")
	}
	wallMarkerArgs, wallMarkerArgsErr := launchMarkerSnapshotArgs(observation.Invocation, observation.DeviceStartNanos, "epoch")
	if wallMarkerArgsErr != nil {
		observation.incomplete("wall marker snapshot identity unavailable")
	}
	wallMarkers, wallMarkersOK := observation.query(ctx, "window-markers-wall", wallMarkerArgs...)
	observation.ClockCorrelation = correlateLaunchMarkerClocks(markers, wallMarkers, observation.Invocation)
	if !wallMarkersOK || observation.ClockCorrelation.Status != "CAPTURED" {
		observation.incomplete("monotonic-to-wall clock correlation unavailable")
	}
	rawLogs := map[string]string{}
	stdoutSnapshots := map[string]launchStreamCaptureSnapshot{}
	stderrSnapshots := map[string]launchStreamCaptureSnapshot{}
	for _, stream := range observation.streams {
		if stream.startErr == nil {
			select {
			case terminal := <-stream.done:
				stream.endedBeforeStop = true
				stream.acceptTermination(terminal)
				stream.requestCancellation(false)
			default:
				stream.requestCancellation(true)
				stream.acceptTermination(<-stream.done)
			}
		} else {
			stream.requestCancellation(false)
		}
		stdoutSnapshots[stream.name] = stream.output.snapshot()
		stderrSnapshots[stream.name] = stream.stderr.snapshot()
		rawLogs[stream.name] = stdoutSnapshots[stream.name].text
	}
	observation.MarkerWindow = diagnoseLaunchMarkerWindow(rawLogs["main"], markers, observation.Invocation, observation.DeviceStartNanos, observation.DeviceEndNanos)
	start, end := observation.MarkerWindow.MatchingWindow()
	windowOK := observation.MarkerWindow.Status == "CAPTURED"
	if !markersOK || !windowOK {
		observation.incomplete("launch window markers missing or inconsistent")
		// Do not attribute possibly old crashes when the invocation cannot be bound.
		start, end = 0, 0
	}
	observation.WindowStartNanos, observation.WindowEndNanos = start, end
	startCaptured, endCaptured := markerCaptureStatus(observation.MarkerWindow)
	for _, stream := range observation.streams {
		events, complete := launchWindowEvents(rawLogs[stream.name], observation.app, start, end)
		if stream.name == "events" {
			observation.SystemEvents = parseStartupSystemEvents(rawLogs[stream.name], observation.app, start, end)
			complete = observation.SystemEvents.Status == "CAPTURED"
			events = nil
		}
		lifecycle := diagnoseLaunchStreamLifecycle(stream, stdoutSnapshots[stream.name], stderrSnapshots[stream.name], complete, startCaptured, endCaptured)
		lifecycle.ExecutionBoundary = observation.CollectorIdentity.Execution
		lifecycle.CommandIdentityStatus = observation.CollectorIdentity.Status
		lifecycle.CommandUID = observation.CollectorIdentity.UID
		lifecycle.CommandGID = observation.CollectorIdentity.GID
		lifecycle.CommandSELinuxContext = observation.CollectorIdentity.SELinuxContext
		observation.StreamLifecycle = append(observation.StreamLifecycle, lifecycle)
		required := stream.name == "crash" || stream.name == "events"
		if required && lifecycle.TerminalStatus != "DRAINED" {
			observation.incomplete(stream.name + " stream incomplete")
		}
		status := "CAPTURED"
		if !complete || lifecycle.TerminalStatus != "DRAINED" {
			status = "OPTIONAL_SOURCE_UNAVAILABLE"
			if required {
				status = "INCOMPLETE"
				observation.incomplete(stream.name + " events incomplete")
			}
		}
		observation.Logs = append(observation.Logs, diagnosticLogBuffer{Buffer: stream.name, Source: "stream", Status: status, Events: events})
		if stream.name == "events" {
			parsed := observation.SystemEvents.Status == "CAPTURED"
			canonicalEvents := canonicalStartupSystemEventEvidence(observation.SystemEvents.Events)
			observation.recordCompositeSource("launch-window", "ACTIVITY_MANAGER_EVENTS", startupEventParserV2, canonicalEvents, lifecycle.TerminalStatus == "DRAINED", parsed, observation.SystemEvents.Rejection, len(observation.SystemEvents.Events))
			if lifecycle.TerminalStatus != "DRAINED" {
				observation.SystemEvents.Status = "INCOMPLETE"
				observation.SystemEvents.Rejection = "EVENT_STREAM_NOT_DRAINED"
			}
		}
	}
	if observation.api >= 30 {
		raw, readable := observation.query(ctx, "exit-info", "shell", "dumpsys", "activity", "exit-info", observation.app)
		var zone *time.Location
		if parsed, parseErr := time.Parse("-0700", observation.ClockZone); parseErr == nil {
			_, offset := parsed.Zone()
			zone = time.FixedZone("device", offset)
		}
		records, parsed := parseExitRecords(raw, observation.app, start, end, observation.ClockCorrelation, zone)
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
			raw, readable := observation.query(ctx, "terminal-"+buffer, "shell", "logcat", "-b", buffer, "-d", "-t", "2048", "-v", "threadtime", "-v", "monotonic", "-v", "usec", "AndroidRuntime:E", "ActivityManager:I", "ActivityTaskManager:I", "*:S")
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

func (window diagnosticMarkerWindow) MatchingWindow() (int64, int64) {
	if len(window.MatchingStartTimestamps) == 0 || len(window.MatchingEndTimestamps) == 0 {
		return 0, 0
	}
	// START uses the latest observation and END the earliest observation. This
	// is the conservative intersection of one logical event observed through
	// multiple collectors whose timestamp rendering can differ slightly.
	start := window.MatchingStartTimestamps[0]
	for _, observed := range window.MatchingStartTimestamps[1:] {
		if observed > start {
			start = observed
		}
	}
	end := window.MatchingEndTimestamps[0]
	for _, observed := range window.MatchingEndTimestamps[1:] {
		if observed < end {
			end = observed
		}
	}
	return start, end
}

type launchMarkerIdentity struct {
	Type         string
	Invocation   string
	EventNonce   string
	Emitter      string
	CommandEpoch string
}

var launchMarkerFieldPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func (identity launchMarkerIdentity) String() string {
	return strings.Join([]string{
		launchMarkerVersion, identity.Type, identity.Invocation, identity.EventNonce, identity.Emitter, identity.CommandEpoch,
	}, ":")
}

func parseLaunchMarkerIdentity(value string) (launchMarkerIdentity, bool) {
	fields := strings.Split(value, ":")
	if len(fields) != 6 || fields[0] != launchMarkerVersion ||
		(fields[1] != "START" && fields[1] != "END") ||
		!launchMarkerFieldPattern.MatchString(fields[2]) ||
		!launchMarkerFieldPattern.MatchString(fields[3]) ||
		fields[4] != launchMarkerEmitter ||
		!launchMarkerFieldPattern.MatchString(fields[5]) {
		return launchMarkerIdentity{}, false
	}
	return launchMarkerIdentity{
		Type: fields[1], Invocation: fields[2], EventNonce: fields[3], Emitter: fields[4], CommandEpoch: fields[5],
	}, true
}

func newLaunchMarkerIdentity(markerType, invocation string) (launchMarkerIdentity, error) {
	if (markerType != "START" && markerType != "END") || !launchMarkerFieldPattern.MatchString(invocation) {
		return launchMarkerIdentity{}, errors.New("invalid launch marker identity")
	}
	var eventNonce, commandEpoch [16]byte
	if _, err := rand.Read(eventNonce[:]); err != nil {
		return launchMarkerIdentity{}, err
	}
	if _, err := rand.Read(commandEpoch[:]); err != nil {
		return launchMarkerIdentity{}, err
	}
	return launchMarkerIdentity{
		Type: markerType, Invocation: invocation, EventNonce: fmt.Sprintf("%x", eventNonce),
		Emitter: launchMarkerEmitter, CommandEpoch: fmt.Sprintf("%x", commandEpoch),
	}, nil
}

func launchMarkerSnapshotArgs(invocation string, startNanos int64, domain string) ([]string, error) {
	if !launchMarkerFieldPattern.MatchString(invocation) || startNanos <= 0 || (domain != "monotonic" && domain != "epoch") {
		return nil, errors.New("invalid launch marker snapshot boundary")
	}
	start := strconv.FormatInt(startNanos/1_000_000_000, 10) + "." + fmt.Sprintf("%09d", startNanos%1_000_000_000)
	return []string{
		"shell", "logcat", "-b", "main", "-d", "-T", start, "-e", invocation,
		"-v", "threadtime", "-v", domain, "-v", "usec", launchProbeTag + ":I", "*:S",
	}, nil
}

func exactLaunchMarkerPair(input, invocation string) (int64, int64, string) {
	window := diagnoseLaunchMarkerWindow(input, "", invocation, 1, 9_000_000_000_000_000_000)
	if window.Status != "CAPTURED" {
		return 0, 0, window.Rejection
	}
	start, end := window.MatchingWindow()
	return start, end, ""
}

func correlateLaunchMarkerClocks(monotonic, wall, invocation string) diagnosticClockCorrelation {
	correlation := diagnosticClockCorrelation{Status: "REJECTED"}
	monotonicStart, monotonicEnd, rejection := exactLaunchMarkerPair(monotonic, invocation)
	if rejection != "" {
		correlation.Rejection = "MONOTONIC_" + rejection
		return correlation
	}
	wallStart, wallEnd, rejection := exactLaunchMarkerPair(wall, invocation)
	if rejection != "" {
		correlation.Rejection = "WALL_" + rejection
		return correlation
	}
	if wallStart <= monotonicStart || wallEnd <= monotonicEnd {
		correlation.Rejection = "OFFSET_INVALID"
		return correlation
	}
	startOffset := wallStart - monotonicStart
	endOffset := wallEnd - monotonicEnd
	// Logcat renders these snapshots at microsecond precision. Each paired
	// marker therefore supplies an offset interval, not an exact offset. The
	// controlling launch order remains monotonic; wall correlation is bounded
	// by the two observed boundary samples and is used only for wall-timestamped
	// exit metadata.
	const renderUncertainty = int64(time.Microsecond - time.Nanosecond)
	correlation.StartOffsetNanos = startOffset
	correlation.EndOffsetNanos = endOffset
	correlation.StartOffsetLowerNanos = startOffset - renderUncertainty
	correlation.StartOffsetUpperNanos = startOffset + renderUncertainty
	correlation.EndOffsetLowerNanos = endOffset - renderUncertainty
	correlation.EndOffsetUpperNanos = endOffset + renderUncertainty
	// Both observations describe one stable wall-minus-monotonic relationship.
	// Retain only their mathematical intersection; a union would silently make
	// incompatible clock samples appear coherent.
	correlation.WallMinusMonotonicLowerNanos = correlation.StartOffsetLowerNanos
	if correlation.EndOffsetLowerNanos > correlation.WallMinusMonotonicLowerNanos {
		correlation.WallMinusMonotonicLowerNanos = correlation.EndOffsetLowerNanos
	}
	correlation.WallMinusMonotonicUpperNanos = correlation.StartOffsetUpperNanos
	if correlation.EndOffsetUpperNanos < correlation.WallMinusMonotonicUpperNanos {
		correlation.WallMinusMonotonicUpperNanos = correlation.EndOffsetUpperNanos
	}
	if correlation.WallMinusMonotonicLowerNanos <= 0 {
		correlation.Rejection = "OFFSET_INTERVAL_INVALID"
		return correlation
	}
	if correlation.WallMinusMonotonicUpperNanos < correlation.WallMinusMonotonicLowerNanos {
		correlation.Rejection = "OFFSET_INTERVAL_INCOMPATIBLE"
		return correlation
	}
	correlation.Status = "CAPTURED"
	correlation.WallMinusMonotonicNanos = correlation.WallMinusMonotonicLowerNanos +
		(correlation.WallMinusMonotonicUpperNanos-correlation.WallMinusMonotonicLowerNanos)/2
	return correlation
}

func diagnoseLaunchMarkerWindow(stream, snapshot, invocation string, before, after int64) diagnosticMarkerWindow {
	window := diagnosticMarkerWindow{Status: "REJECTED", DeviceStartNanos: before, DeviceEndNanos: after}
	if !regexp.MustCompile("^[0-9a-f]{32}$").MatchString(invocation) {
		window.Rejection = "INVOCATION_INVALID"
		return window
	}
	if before <= 0 {
		window.Rejection = "DEVICE_START_CLOCK_INVALID"
		return window
	}
	if after <= before {
		window.Rejection = "DEVICE_END_CLOCK_INVALID"
		return window
	}
	type markerState struct {
		identity   string
		timestamps []int64
		bySource   map[string]int64
	}
	states := map[string]*markerState{
		"START": {bySource: make(map[string]int64)},
		"END":   {bySource: make(map[string]int64)},
	}
	for _, source := range []struct {
		name  string
		input string
	}{{"stream", stream}, {"snapshot", snapshot}} {
		if len(source.input) > maxLogcatInput {
			window.Rejection = strings.ToUpper(source.name) + "_INPUT_OVERSIZE"
			return window
		}
		for _, line := range strings.Split(source.input, "\n") {
			if strings.TrimSpace(line) == "" {
				continue
			}
			event, ok := parseEpochLog(line)
			if !ok {
				if strings.Contains(line, launchProbeTag) {
					window.MalformedMarkers++
					window.Rejection = "MARKER_IDENTITY_MALFORMED"
					return window
				}
				continue
			}
			if event.Tag != launchProbeTag {
				continue
			}
			identity, valid := parseLaunchMarkerIdentity(event.Text)
			if !valid {
				window.MalformedMarkers++
				window.Rejection = "MARKER_IDENTITY_MALFORMED"
				return window
			}
			matching := identity.Invocation == invocation
			if len(window.Markers) < 64 {
				window.Markers = append(window.Markers, diagnosticMarkerEvidence{
					Source: source.name, Value: event.Text, DeviceNanos: event.DeviceNanos, InvocationMatch: matching,
					MarkerType: identity.Type, EventNonce: identity.EventNonce, Emitter: identity.Emitter, CommandEpoch: identity.CommandEpoch,
				})
			} else {
				window.MalformedMarkers++
				window.Rejection = "MARKER_EVIDENCE_OVERSIZE"
				return window
			}
			if !matching {
				window.IgnoredMarkers++
				window.Rejection = "INVOCATION_MISMATCH"
				return window
			}
			state := states[identity.Type]
			canonical := identity.String()
			if state.identity != "" && state.identity != canonical {
				window.Rejection = identity.Type + "_IDENTITY_AMBIGUOUS"
				return window
			}
			state.identity = canonical
			if prior, found := state.bySource[source.name]; found && prior != event.DeviceNanos {
				window.Rejection = identity.Type + "_SOURCE_CONFLICT"
				return window
			}
			state.bySource[source.name] = event.DeviceNanos
			state.timestamps = append(state.timestamps, event.DeviceNanos)
		}
	}
	window.MatchingStartTimestamps = append(window.MatchingStartTimestamps, states["START"].timestamps...)
	window.MatchingEndTimestamps = append(window.MatchingEndTimestamps, states["END"].timestamps...)
	switch {
	case states["START"].identity == "":
		window.Rejection = "START_MISSING"
	case states["END"].identity == "":
		window.Rejection = "END_MISSING"
	default:
		start, end := window.MatchingWindow()
		switch {
		case start < before:
			window.Rejection = "START_BEFORE_DEVICE_CLOCK"
		case end <= start:
			window.Rejection = "END_NOT_AFTER_START"
		case end > after:
			window.Rejection = "END_AFTER_DEVICE_CLOCK"
		default:
			window.Status = "CAPTURED"
		}
	}
	return window
}

func launchMarkerWindow(stream, snapshot, invocation string, before, after int64) (int64, int64, bool) {
	window := diagnoseLaunchMarkerWindow(stream, snapshot, invocation, before, after)
	start, end := window.MatchingWindow()
	return start, end, window.Status == "CAPTURED"
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
	const target = "org.kurdistanvpn.app.RuntimeAuthorityReissueServiceTest"
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
