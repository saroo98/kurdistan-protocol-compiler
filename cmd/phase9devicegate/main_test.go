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
