// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRepositoryDeviceInventoryIsExact(t *testing.T) {
	if err := verifyDeviceTestInventory(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
}

func TestCurrentDeviceInventoryPreservesFrozenNamesAndLanes(t *testing.T) {
	root := filepath.Join("..", "..")
	if err := verifyCurrentDeviceInventory(root); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(root, "android/config/phase18-current-device-tests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	frozen, err := os.ReadFile(filepath.Join(root, "android/config/phase17-required-device-tests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"always-on-on-26": []byte(strings.Replace(string(raw), "minSdk=36 org.kurdistanvpn.app.ProductionProxyServiceDeviceTest#systemAlwaysOnRestartsTheKilledProcessWithLockdownStillEnabled", "org.kurdistanvpn.app.ProductionProxyServiceDeviceTest#systemAlwaysOnRestartsTheKilledProcessWithLockdownStillEnabled", 1)),
		"locale-on-26":    []byte(strings.Replace(string(raw), "minSdk=34 org.kurdistanvpn.app.ProductLocaleLifecycleDeviceTest", "org.kurdistanvpn.app.ProductLocaleLifecycleDeviceTest", 1)),
		"frozen-metadata": []byte(strings.Replace(string(raw), "minSdk=34 org.kurdistanvpn.app.Phase17", "minSdk=26 org.kurdistanvpn.app.Phase17", 1)),
		"duplicate":       append(append([]byte(nil), raw...), strings.Split(string(raw), "\n")[0]+"\n"...),
		"crlf":            []byte(strings.ReplaceAll(string(raw), "\n", "\r\n")),
		"missing-newline": raw[:len(raw)-1],
	} {
		t.Run(name, func(t *testing.T) {
			if string(bad) == string(raw) {
				t.Fatal("fixture mutation did not change bytes")
			}
			if _, err := validateCurrentDeviceManifest(bad, frozen); err == nil {
				t.Fatal("invalid current roster accepted")
			}
		})
	}
}

func TestHistoricalInventoryIgnoresCurrentExtraSource(t *testing.T) {
	if err := verifyPhase17HistoricalDeviceInventory(filepath.Join("..", "..")); err != nil {
		t.Fatal(err)
	}
}

func TestDeviceInventoryRequiresExactSourceTests(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "android", "app", "src", "androidTest", "kotlin", "org", "example")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "ExactTest.kt"), []byte(`package org.example
import org.junit.Test
class ExactTest {
    @Test
    fun works() {}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "android", "config", "phase17-required-device-tests.txt")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("minSdk=34 org.example.ExactTest#works\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceInventoryFixture(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("minSdk=34 org.example.ExactTest#renamed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceInventoryFixture(root); err == nil {
		t.Fatal("renamed required device test was accepted")
	}
}

func TestDeviceInventoryRejectsUnexpectedSourceTest(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "android", "app", "src", "androidTest", "kotlin")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "ExactTest.kt"), []byte(`package org.example
import org.junit.Test
class ExactTest {
    @Test
    fun works() {}
    @Test
    fun hidden() {}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	manifest := filepath.Join(root, "android", "config", "phase17-required-device-tests.txt")
	if err := os.MkdirAll(filepath.Dir(manifest), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("org.example.ExactTest#works\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceInventoryFixture(root); err == nil {
		t.Fatal("unexpected device test was accepted")
	}
}

func TestDiscoverAndroidDeviceTestsIncludesSameLineAnnotations(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "androidTest", "kotlin")
	if err := os.MkdirAll(source, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(source, "ExactTest.kt"), []byte(`package org.example
import org.junit.Test
class ExactTest {
    @Test fun works() {}
    @Test fun hidden() {}
}`), 0o600); err != nil {
		t.Fatal(err)
	}
	tests, err := discoverAndroidDeviceTests(root)
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"org.example.ExactTest#works", "org.example.ExactTest#hidden"} {
		if _, ok := tests[name]; !ok {
			t.Fatalf("same-line annotated device test %q was not discovered", name)
		}
	}
}

func verifyDeviceInventoryFixture(root string) error {
	manifest, _, err := readDeviceManifest(filepath.Join(root, "android/config/phase17-required-device-tests.txt"))
	if err != nil {
		return err
	}
	source, err := discoverAndroidDeviceTests(filepath.Join(root, "android/app/src/androidTest/kotlin"))
	if err != nil {
		return err
	}
	return verifyExactDeviceInventory(manifest, source)
}

func TestExactCurrentInventoryRejectsSourceDriftAndDuplicateMethods(t *testing.T) {
	const base = "package org.example\nclass ExactTest {\n@Test fun works() {}\n}\n"
	manifest := map[string]int{"org.example.ExactTest#works": 26}
	for _, tc := range []struct{ name, source, want string }{
		{"extra", strings.Replace(base, "}\n}", "}\n@Test fun hidden() {}\n}", 1), "unexpected device test"},
		{"removed", "package org.example\nclass ExactTest {}\n", "does not exist in source"},
		{"renamed", strings.Replace(base, "works", "renamed", 1), "does not exist in source"},
		{"duplicate", strings.Replace(base, "}\n}", "}\n@Test fun works() {}\n}", 1), "duplicate Android device test"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			source, err := discoverAndroidDeviceTestFiles(map[string][]byte{"ExactTest.kt": []byte(base)})
			if err != nil {
				t.Fatal(err)
			}
			if err := verifyExactDeviceInventory(manifest, source); err != nil {
				t.Fatalf("positive: %v", err)
			}
			source, err = discoverAndroidDeviceTestFiles(map[string][]byte{"ExactTest.kt": []byte(tc.source)})
			if err == nil {
				err = verifyExactDeviceInventory(manifest, source)
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("want %s got %v", tc.want, err)
			}
		})
	}
}

func TestFrozenInventoryRejectsWorkingTreeByteMutation(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "android/config/phase17-required-device-tests.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyFrozenDeviceManifestDigest(raw); err != nil {
		t.Fatalf("positive: %v", err)
	}
	if err := verifyFrozenDeviceManifestDigest(append(raw, '\n')); err == nil || !strings.Contains(err.Error(), "not authoritative") {
		t.Fatalf("mutated frozen inventory accepted: %v", err)
	}
}
