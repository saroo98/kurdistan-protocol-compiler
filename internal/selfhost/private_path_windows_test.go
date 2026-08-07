// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWindowsSelfhostSecretsAreProtectedAtCreation(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "private-state")
	if err := createSelfhostPrivateDirectory(directory); err != nil {
		t.Fatal(err)
	}
	if err := verifySelfhostPrivatePath(directory, true); err != nil {
		t.Fatalf("created directory was not born private: %v", err)
	}
	path := filepath.Join(directory, "registry.key")
	if err := writeSelfhostPrivateFileExclusive(path, []byte("01234567890123456789012345678901")); err != nil {
		t.Fatal(err)
	}
	if err := verifySelfhostPrivatePath(path, false); err != nil {
		t.Fatalf("created key was not born private: %v", err)
	}
	if value, err := os.ReadFile(path); err != nil || len(value) != 32 {
		t.Fatalf("len=%d err=%v", len(value), err)
	}
}
