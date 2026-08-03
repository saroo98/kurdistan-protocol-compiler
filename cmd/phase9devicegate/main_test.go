// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClearKnownEvidenceFilesRemovesOnlyGateEvidence(t *testing.T) {
	directory := t.TempDir()
	stale := filepath.Join(directory, "11-instrumentation.txt")
	unrelated := filepath.Join(directory, "notes.md")
	if err := os.WriteFile(stale, []byte("stale"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(unrelated, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := clearKnownEvidenceFiles(directory); err != nil {
		t.Fatalf("clearKnownEvidenceFiles() error = %v", err)
	}
	if _, err := os.Stat(stale); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("stale evidence still exists: %v", err)
	}
	if _, err := os.Stat(unrelated); err != nil {
		t.Fatalf("unrelated file was removed: %v", err)
	}
}

func TestValidateLaunchSmokeAcceptsExpectedActivityAndLiveProcess(t *testing.T) {
	launch := "Activity: org.kurdistanvpn.app.debug/org.kurdistanvpn.app.MainActivity"
	if err := validateLaunchSmoke(launch, "7781\n", defaultAppPackage, nil); err != nil {
		t.Fatalf("validateLaunchSmoke() error = %v", err)
	}
}

func TestValidateLaunchSmokeRejectsStaleSystemPicker(t *testing.T) {
	launch := "Activity: com.google.android.documentsui/com.android.documentsui.picker.PickActivity"
	if err := validateLaunchSmoke(launch, "7781\n", defaultAppPackage, nil); err == nil {
		t.Fatal("validateLaunchSmoke() accepted a system picker as the app launch")
	}
}

func TestValidateLaunchSmokeRejectsMissingProcess(t *testing.T) {
	if err := validateLaunchSmoke("", "", defaultAppPackage, errors.New("pidof failed")); err == nil {
		t.Fatal("validateLaunchSmoke() accepted a missing app process")
	}
}

func TestLogcatClearUsesDeviceShellForMinimumSdkCompatibility(t *testing.T) {
	arguments := logcatClearArgs()
	if got := strings.Join(arguments, " "); got != "shell logcat -b all -c" {
		t.Fatalf("logcatClearArgs() = %q, want device-shell clearing", got)
	}
}

func TestDiagnosticBaselineAcceptsUnsupportedClearWithoutAppCrash(t *testing.T) {
	main := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=false\n"
	crash := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=false\n"
	if !diagnosticBaselineIsClean(main, crash) {
		t.Fatal("diagnosticBaselineIsClean rejected a clean bounded baseline")
	}
}

func TestDiagnosticBaselineRejectsPreExistingAppCrash(t *testing.T) {
	main := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=false\n"
	crash := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=true\n"
	if diagnosticBaselineIsClean(main, crash) {
		t.Fatal("diagnosticBaselineIsClean accepted a pre-existing app crash")
	}
}

func TestFrameworkServicesReadyRequiresExactHealthyServices(t *testing.T) {
	if !frameworkServicesReady("Service activity: found\n", nil, "Service package: found\n", nil) {
		t.Fatal("frameworkServicesReady rejected healthy activity and package services")
	}
	for _, test := range []struct {
		activityOutput string
		activityErr    error
		packageOutput  string
		packageErr     error
	}{
		{activityOutput: "Service activity: not found", packageOutput: "Service package: found"},
		{activityOutput: "activity: found", packageOutput: "Service package: found"},
		{activityOutput: "Service activity: found", packageOutput: "Service package: not found"},
		{activityOutput: "Service activity: found", activityErr: errors.New("broken pipe"), packageOutput: "Service package: found"},
		{activityOutput: "Service activity: found", packageOutput: "Service package: found", packageErr: errors.New("broken pipe")},
	} {
		if frameworkServicesReady(test.activityOutput, test.activityErr, test.packageOutput, test.packageErr) {
			t.Fatalf("frameworkServicesReady accepted unhealthy services: %+v", test)
		}
	}
}

func TestTransientPackageServiceFailureIsNarrow(t *testing.T) {
	if !transientPackageServiceFailure("Failure calling service package: Broken pipe (32)") {
		t.Fatal("transientPackageServiceFailure rejected the observed package-service restart")
	}
	for _, output := range []string{
		"INSTALL_FAILED_INVALID_APK",
		"Failure calling service activity: Broken pipe (32)",
		"Failure calling service package: Permission denied",
	} {
		if transientPackageServiceFailure(output) {
			t.Fatalf("transientPackageServiceFailure accepted permanent failure %q", output)
		}
	}
}

func TestEvaluateInstrumentationAcceptsCompletedCrashFreeRun(t *testing.T) {
	output := `
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: 0
INSTRUMENTATION_STATUS_CODE: 0
OK (4 tests)
`
	if err := evaluateInstrumentation(output, "clean device log", defaultAppPackage, 4); err != nil {
		t.Fatalf("evaluateInstrumentation() error = %v", err)
	}
}

func TestExpectedTestManifestRequiresExactCompletedTests(t *testing.T) {
	output := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.example.ProductTest",
		"INSTRUMENTATION_STATUS: test=first",
		"INSTRUMENTATION_STATUS_CODE: 0",
		"INSTRUMENTATION_STATUS: class=org.example.ProductTest",
		"INSTRUMENTATION_STATUS: test=second",
		"INSTRUMENTATION_STATUS_CODE: 0",
	}, "\n")
	if err := verifyExpectedTests(output, []string{
		"org.example.ProductTest#first",
		"org.example.ProductTest#second",
	}); err != nil {
		t.Fatalf("verifyExpectedTests() error = %v", err)
	}
	if err := verifyExpectedTests(output, []string{"org.example.ProductTest#first"}); err == nil {
		t.Fatal("verifyExpectedTests accepted an unexpected executed test")
	}
}

func TestReadExpectedTestsRejectsDuplicateEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tests.txt")
	if err := os.WriteFile(path, []byte("a.b.Test#one\na.b.Test#one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readExpectedTests(path); err == nil {
		t.Fatal("readExpectedTests accepted duplicates")
	}
}

func TestExpectedTestsForSDKFiltersGuardedCasesWithoutWeakeningExactManifest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tests.txt")
	manifest := "a.b.Test#always\nminSdk=34 a.b.Test#accessibility\n"
	if err := os.WriteFile(path, []byte(manifest), 0o600); err != nil {
		t.Fatal(err)
	}
	tests, err := readExpectedTests(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(expectedTestsForSDK(tests, 26), "\n"); got != "a.b.Test#always" {
		t.Fatalf("API 26 manifest = %q", got)
	}
	if got := strings.Join(expectedTestsForSDK(tests, 34), "\n"); got != "a.b.Test#accessibility\na.b.Test#always" {
		t.Fatalf("API 34 manifest = %q", got)
	}
}

func TestEvaluateInstrumentationRejectsZeroTests(t *testing.T) {
	if err := evaluateInstrumentation("OK (0 tests)", "clean", defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted a zero-test run")
	}
}

func TestEvaluateInstrumentationRejectsReportedProcessCrash(t *testing.T) {
	output := "Test run failed to complete. Instrumentation run failed due to Process crashed."
	if err := evaluateInstrumentation(output, "", defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted an instrumentation process crash")
	}
}

func TestEvaluateInstrumentationRejectsFalsePassWithConcurrentNativeCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := "Fatal signal 4 (SIGILL) in org.kurdistanvpn.app.debug"
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted an apparent pass with a native crash")
	}
}

func TestEvaluateInstrumentationDoesNotAttributeAnotherAppsCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := "FATAL EXCEPTION in com.example.unrelated"
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err != nil {
		t.Fatalf("evaluateInstrumentation() error = %v", err)
	}
}

func TestEvaluateInstrumentationDoesNotAttributeSystemNativeCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := `
org.kurdistanvpn.app.debug completed a test
Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 687, pid 624
*** *** *** *** *** *** *** ***
Executable: /vendor/bin/hw/android.hardware.camera.provider.ranchu
Cmdline: /vendor/bin/hw/android.hardware.camera.provider.ranchu
pid: 624, tid: 687, name: binder:624_1  >>> /vendor/bin/hw/android.hardware.camera.provider.ranchu <<<
`
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err != nil {
		t.Fatalf("evaluateInstrumentation() attributed a system camera crash to the app: %v", err)
	}
}

func TestEvaluateInstrumentationRejectsJavaAppCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := `
FATAL EXCEPTION: main
Process: org.kurdistanvpn.app.debug, PID: 7781
java.lang.IllegalStateException: regression fixture
`
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted a Java app crash")
	}
}

func TestEvaluateInstrumentationRejectsNativeAppSubprocessCrash(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := `
Fatal signal 6 (SIGABRT), code -1 (SI_QUEUE) in tid 7782, pid 7781
Cmdline: org.kurdistanvpn.app.debug:vpn
pid: 7781, tid: 7782, name: vpn  >>> org.kurdistanvpn.app.debug:vpn <<<
`
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted a native app subprocess crash")
	}
}

func TestEvaluateInstrumentationRejectsAppANR(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	logcat := "ANR in org.kurdistanvpn.app.debug (org.kurdistanvpn.app.debug/.MainActivity)"
	if err := evaluateInstrumentation(output, logcat, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation() accepted an app ANR")
	}
}

func TestDiagnosticSummaryPreservesCrashClassWithoutRawLogData(t *testing.T) {
	raw := strings.Join([]string{
		"FATAL EXCEPTION: main",
		"Process: org.kurdistanvpn.app.debug, PID: 7781",
		"java.lang.IllegalStateException: token=secret-value https://10.0.0.8/profile",
		"at org.kurdistanvpn.app.MainActivity.onCreate(MainActivity.kt:42)",
	}, "\n")
	summary := summarizeDiagnostics(raw, defaultAppPackage, false)
	for _, required := range []string{
		"schema=kurdistan-device-diagnostic-summary-v1",
		"app_crash=true",
		"java_crash=true",
		"input_truncated=false",
	} {
		if !strings.Contains(summary, required) {
			t.Fatalf("summary %q is missing %q", summary, required)
		}
	}
	for _, forbidden := range []string{"secret-value", "10.0.0.8", "https://", "7781", "MainActivity.kt"} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("summary retained private raw log content %q: %q", forbidden, summary)
		}
	}
	if len(summary) > maxDiagnosticBytes {
		t.Fatalf("summary size = %d, limit = %d", len(summary), maxDiagnosticBytes)
	}
}

func TestEvaluateInstrumentationRejectsCategoricalCrashSummary(t *testing.T) {
	output := "INSTRUMENTATION_STATUS_CODE: 0\nOK (1 test)"
	summary := "schema=kurdistan-device-diagnostic-summary-v1\napp_crash=true\n"
	if err := evaluateInstrumentation(output, summary, defaultAppPackage, 1); err == nil {
		t.Fatal("evaluateInstrumentation accepted a categorical app-crash result")
	}
}

func TestInstrumentationSummaryKeepsOnlyBoundedTestIdentity(t *testing.T) {
	raw := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.ProfileImportTest",
		"INSTRUMENTATION_STATUS: test=rejectsForgedProfile",
		"INSTRUMENTATION_STATUS: stack=token=secret-value https://10.0.0.8/profile",
		"INSTRUMENTATION_STATUS_CODE: -2",
		"FAILURES!!!",
	}, "\n")
	summary := summarizeInstrumentation(raw)
	if !strings.Contains(summary, "failed_test=org.kurdistanvpn.app.ProfileImportTest#rejectsForgedProfile") {
		t.Fatalf("summary omitted safe failed-test identity: %q", summary)
	}
	for _, forbidden := range []string{"secret-value", "10.0.0.8", "https://", "stack="} {
		if strings.Contains(summary, forbidden) {
			t.Fatalf("summary retained raw instrumentation data %q: %q", forbidden, summary)
		}
	}
	if safeTestIdentity("org.example.Test#method\ninjected=true") {
		t.Fatal("safeTestIdentity accepted a line-injection payload")
	}
}

func TestInstrumentationSummaryRecordsOnlySafeProgressIdentities(t *testing.T) {
	raw := strings.Join([]string{
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.FirstTest",
		"INSTRUMENTATION_STATUS: test=completedCase",
		"INSTRUMENTATION_STATUS_CODE: 1",
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.FirstTest",
		"INSTRUMENTATION_STATUS: test=completedCase",
		"INSTRUMENTATION_STATUS_CODE: 0",
		"INSTRUMENTATION_STATUS: class=org.kurdistanvpn.app.SecondTest",
		"INSTRUMENTATION_STATUS: test=runningCase",
		"INSTRUMENTATION_STATUS_CODE: 1",
	}, "\n")
	summary := summarizeInstrumentation(raw)
	for _, expected := range []string{
		"last_started_test=org.kurdistanvpn.app.SecondTest#runningCase",
		"last_completed_test=org.kurdistanvpn.app.FirstTest#completedCase",
	} {
		if !strings.Contains(summary, expected) {
			t.Fatalf("summary omitted %q: %q", expected, summary)
		}
	}
}

func TestInstrumentationPreparationDisablesAnimationsAndCompilesExactPackages(t *testing.T) {
	commands := instrumentationPreparationCommands("org.example.app", "org.example.app.test")
	if len(commands) != 5 {
		t.Fatalf("preparation command count = %d, want 5", len(commands))
	}
	joined := make([]string, 0, len(commands))
	for _, command := range commands {
		joined = append(joined, command.evidence+":"+strings.Join(command.args, " "))
	}
	actual := strings.Join(joined, "\n")
	for _, expected := range []string{
		"settings put global window_animation_scale 0",
		"settings put global transition_animation_scale 0",
		"settings put global animator_duration_scale 0",
		"cmd package compile -m speed -f org.example.app",
		"cmd package compile -m speed -f org.example.app.test",
	} {
		if !strings.Contains(actual, expected) {
			t.Fatalf("preparation commands omitted %q: %q", expected, actual)
		}
	}
}

func TestBoundedBufferRetainsPrefixAndSignalsOverflow(t *testing.T) {
	buffer := boundedBuffer{limit: 4}
	if written, err := buffer.Write([]byte("abcdef")); err != nil || written != 6 {
		t.Fatalf("Write() = (%d, %v), want (6, nil)", written, err)
	}
	if got := buffer.String(); got != "abcd" {
		t.Fatalf("buffer = %q, want %q", got, "abcd")
	}
	if !buffer.exceeded {
		t.Fatal("bounded buffer did not report overflow")
	}
}

func TestInstalledPackageIdentityParsersDoNotRetainPaths(t *testing.T) {
	paths := "package:/data/app/~~stable-device-token/base.apk\npackage:/data/app/split.apk\n"
	if got := installedPathCount(paths); got != 2 {
		t.Fatalf("installedPathCount() = %d, want 2", got)
	}
	runner := "instrumentation:org.kurdistanvpn.app.internal.test/androidx.test.runner.AndroidJUnitRunner (target=org.kurdistanvpn.app.internal)"
	if !containsExactLine(runner+"\n", runner) {
		t.Fatal("containsExactLine rejected the exact instrumentation identity")
	}
	if containsExactLine(runner+".suffix\n", runner) {
		t.Fatal("containsExactLine accepted an instrumentation identity suffix collision")
	}
}

func TestContainsAppCrashRejectsPackagePrefixCollision(t *testing.T) {
	logcat := "FATAL EXCEPTION in org.kurdistanvpn.app.debugger"
	if containsAppCrash(logcat, defaultAppPackage) {
		t.Fatal("containsAppCrash() accepted a longer package name with the same prefix")
	}
}

func TestEvidenceLabelIsBoundedAndNonExecutable(t *testing.T) {
	for _, value := range []string{"PHASE 9", "PHASE 11", "ANDROID-LOCAL"} {
		if !validLabel(value) {
			t.Fatalf("valid label rejected: %q", value)
		}
	}
	for _, value := range []string{
		"",
		"phase 11",
		"PHASE_11",
		"PHASE 11\nINJECTED",
		strings.Repeat("A", 33),
	} {
		if validLabel(value) {
			t.Fatalf("invalid label accepted: %q", value)
		}
	}
}

func TestDeviceEvidencePropertyAllowListExcludesStableIdentifiers(t *testing.T) {
	joined := strings.ToLower(fmt.Sprint(deviceEvidenceProperties))
	for _, forbidden := range []string{"serial", "fingerprint", "android_id", "imei"} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("device evidence allow-list contains stable identifier %q", forbidden)
		}
	}
}

func TestPackageListContainsExactRejectsPrefixAndSuffixCollisions(t *testing.T) {
	output := strings.Join([]string{
		"package:org.kurdistanvpn.app.internal.debug",
		"package:example.org.kurdistanvpn.app.internal",
		"package:org.kurdistanvpn.app.internal.test",
	}, "\n")
	if packageListContainsExact(output, "org.kurdistanvpn.app.internal") {
		t.Fatal("packageListContainsExact accepted a package-name collision")
	}
	if !packageListContainsExact(
		output+"\npackage:org.kurdistanvpn.app.internal\n",
		"org.kurdistanvpn.app.internal",
	) {
		t.Fatal("packageListContainsExact rejected the exact package")
	}
	if packageListContainsExact(output, "") {
		t.Fatal("packageListContainsExact accepted an empty package")
	}
}

func TestExpectedDeviceIdentityRejectsWrongAPI(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(34, "x86_64", 36, "x86_64"); err == nil {
		t.Fatal("API 34 lane accepted an API 36 device")
	}
}

func TestExpectedDeviceIdentityRejectsWrongPrimaryABI(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(34, "x86_64", 34, "arm64-v8a"); err == nil {
		t.Fatal("x86_64 lane accepted an arm64-v8a device")
	}
}

func TestExpectedDeviceIdentityRequiresAPIBandABIAsPair(t *testing.T) {
	for _, expected := range []struct {
		api int
		abi string
	}{
		{api: 34},
		{abi: "x86_64"},
	} {
		if err := verifyExpectedDeviceIdentity(expected.api, expected.abi, 34, "x86_64"); err == nil {
			t.Fatalf("incomplete expected identity passed: API %d ABI %q", expected.api, expected.abi)
		}
	}
}

func TestExpectedDeviceIdentityRejectsInvalidExpectation(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(-1, "x86_64", 34, "x86_64"); err == nil {
		t.Fatal("negative expected API passed")
	}
}

func TestExpectedDeviceIdentityRejectsUnknownABI(t *testing.T) {
	if err := verifyExpectedDeviceIdentity(34, "x86_64;unexpected", 34, "x86_64;unexpected"); err == nil {
		t.Fatal("unknown expected ABI passed")
	}
}
