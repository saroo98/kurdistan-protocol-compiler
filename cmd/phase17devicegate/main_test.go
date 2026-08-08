// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestValidatePhase17InventoryRejectsMissingLiveDataPlaneTest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tests.txt")
	if err := os.WriteFile(path, []byte(requiredPhase17DeviceTests[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePhase17Inventory(path); err == nil {
		t.Fatal("incomplete Phase 17 device inventory was accepted")
	}
}

func TestBuildDelegateArgsPreservesExactLaneAndArtifacts(t *testing.T) {
	value := options{
		adbPath:            "adb",
		serial:             "emulator-5554",
		appAPK:             "app.apk",
		testAPK:            "test.apk",
		appPackage:         "org.kurdistanvpn.app.internal",
		testPackage:        "org.kurdistanvpn.app.internal.test",
		conflictingPackage: "org.kurdistanvpn.app.debug",
		expectedTests:      "tests.txt",
		evidenceDir:        "evidence",
		minimumTests:       1,
		expectedAPI:        34,
		expectedABI:        "x86_64",
	}
	want := []string{
		"run", "./cmd/phase9devicegate",
		"-label", "PHASE 17",
		"-adb", "adb",
		"-serial", "emulator-5554",
		"-app-apk", "app.apk",
		"-test-apk", "test.apk",
		"-app-package", "org.kurdistanvpn.app.internal",
		"-test-package", "org.kurdistanvpn.app.internal.test",
		"-conflicting-app-package", "org.kurdistanvpn.app.debug",
		"-minimum-tests", "1",
		"-expected-api", "34",
		"-expected-abi", "x86_64",
		"-expected-tests", "tests.txt",
		"-evidence-dir", "evidence",
	}
	if got := buildDelegateArgs(value); !reflect.DeepEqual(got, want) {
		t.Fatalf("delegate args = %#v, want %#v", got, want)
	}
}

func TestValidateOptionsRejectsPartialLaneIdentity(t *testing.T) {
	value := options{appAPK: "app.apk", testAPK: "test.apk", expectedTests: "tests.txt", expectedAPI: 34}
	if err := validateOptions(value); err == nil {
		t.Fatal("expected API without ABI was accepted")
	}
}
