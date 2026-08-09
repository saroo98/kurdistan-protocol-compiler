// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17devicegate runs the exact current Phase 17 instrumentation
// inventory through the hardened Android device runner.
package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

var requiredPhase17DeviceTests = []string{
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#dnsFailClosedAcceptsBoundedNetworkFailuresOnlyWhenUnavailabilityIsExpected",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#liveIpv4LifecycleProtectsSocketBeforeConnectAndStopsCleanly",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#permissionRevocationAndProcessDeathRequireFreshAuthority",
	"org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#emergencyStopLeavesNoRuntimeOrSecretEvidence",
	"minSdk=34 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#dualStackDnsHandoverAndReconnectRemainPolicyBound",
	"minSdk=34 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#profileRevocationAndBackupRestoreFailClosed",
	"minSdk=36 org.kurdistanvpn.app.Phase17LiveDataPlaneDeviceTest#completeCurrentManifestAccessibilityAndLifecycleRemainTruthful",
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
