// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
	if err := verifyDeviceTestInventory(root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifest, []byte("minSdk=34 org.example.ExactTest#renamed\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := verifyDeviceTestInventory(root); err == nil {
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
	if err := verifyDeviceTestInventory(root); err == nil {
		t.Fatal("unexpected device test was accepted")
	}
}
