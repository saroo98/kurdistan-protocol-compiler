// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/phase17qualification"
)

func TestCanonicalGateRequiresExactJourneySetAndOwnerAuthenticatedRoster(t *testing.T) {
	for _, purpose := range []string{"ENGINEERING_REHEARSAL", "CANDIDATE_CAMPAIGN"} {
		want := canonicalGateJourneys(purpose)
		if len(want) != map[string]int{"ENGINEERING_REHEARSAL": 2, "CANDIDATE_CAMPAIGN": 8}[purpose] {
			t.Fatal("required journey set changed")
		}
	}
	if canonicalGateJourneys("Functional") != nil {
		t.Fatal("legacy field result is not canonical journey evidence")
	}
	seed := bytes.Repeat([]byte{31}, ed25519.SeedSize)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	roster := canonicalGateRoster{Schema: canonicalGateRosterSchema, Purpose: "ENGINEERING_REHEARSAL"}
	raw, _ := phase17qualification.MarshalCanonical(roster)
	if _, err := authenticateCanonicalGateRoster(raw, public, roster.Purpose); err == nil {
		t.Fatal("unsigned roster accepted")
	}
	roster.Signature = hex.EncodeToString(ed25519.Sign(private, canonicalGateRosterMessage(roster)))
	raw, _ = phase17qualification.MarshalCanonical(roster)
	if _, err := authenticateCanonicalGateRoster(raw, public, roster.Purpose); err == nil {
		t.Fatal("empty signed roster accepted")
	}
	if code := runCanonicalGate([]string{}, &bytes.Buffer{}); code == 0 {
		t.Fatal("missing evidence accepted")
	}
}

func TestCanonicalGateFileReaderRejectsDirectoriesLinksAndOversize(t *testing.T) {
	root := t.TempDir()
	if _, err := readCanonicalGateFile(root, 8); err == nil {
		t.Fatal("directory accepted")
	}
	path := filepath.Join(root, "bounded")
	if err := os.WriteFile(path, []byte("123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCanonicalGateFile(path, 8); err == nil {
		t.Fatal("oversize input accepted")
	}
	if raw, err := readCanonicalGateFile(path, 9); err != nil || string(raw) != "123456789" {
		t.Fatal("bounded regular input rejected")
	}
}

func TestValidatePhase17InventoryRejectsMissingLiveDataPlaneTest(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tests.txt")
	if err := os.WriteFile(path, []byte(requiredPhase17DeviceTests[0]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := validatePhase17Inventory(path); err == nil {
		t.Fatal("incomplete Phase 17 device inventory was accepted")
	}
}

func TestValidatePhase17InventoryRejectsEachNewContractRequirement(t *testing.T) {
	newRequirements := []string{}
	for _, required := range requiredPhase17DeviceTests {
		if strings.Contains(required, "Phase17BootQualificationDeviceTest#") || strings.Contains(required, "Phase17CanonicalDeviceEvidenceHarnessContractTest#") || strings.Contains(required, "Phase17ProtectedStateIntegrityDeviceTest#") {
			newRequirements = append(newRequirements, required)
		}
	}
	if len(newRequirements) != 24 {
		t.Fatalf("new required contract inventory count=%d", len(newRequirements))
	}
	for _, missing := range newRequirements {
		t.Run(missing, func(t *testing.T) {
			entries := make([]string, 0, len(requiredPhase17DeviceTests)-1)
			for _, required := range requiredPhase17DeviceTests {
				if required != missing {
					entries = append(entries, required)
				}
			}
			path := filepath.Join(t.TempDir(), "tests.txt")
			if err := os.WriteFile(path, []byte(strings.Join(entries, "\n")+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := validatePhase17Inventory(path); err == nil {
				t.Fatalf("missing contract requirement accepted: %s", missing)
			}
		})
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
