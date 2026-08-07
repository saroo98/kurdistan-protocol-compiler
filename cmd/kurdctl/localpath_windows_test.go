// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package main

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsPrivateOutputIsProtectedAtCreation(t *testing.T) {
	root := filepath.Join(t.TempDir(), "private-output")
	if err := createWindowsPrivateDirectory(root); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsPrivatePath(root, true); err != nil {
		t.Fatalf("created directory was not born private: %v", err)
	}
	file := filepath.Join(root, "artifact")
	if err := createWindowsPrivateFile(file, []byte("artifact")); err != nil {
		t.Fatal(err)
	}
	if err := verifyWindowsPrivatePath(file, false); err != nil {
		t.Fatalf("created file was not born private: %v", err)
	}
	if value, err := os.ReadFile(file); err != nil || string(value) != "artifact" {
		t.Fatalf("value=%q err=%v", value, err)
	}
}
