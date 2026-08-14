// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package phase17qualification

import (
	"os"
	"path/filepath"
	"testing"
	"unicode/utf16"

	"golang.org/x/sys/windows"
)

func TestValidateNoLinkedPathAcceptsWindowsShortNameAlias(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "qualification long path segment")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	longPointer, err := windows.UTF16PtrFromString(directory)
	if err != nil {
		t.Fatal(err)
	}
	buffer := make([]uint16, windows.MAX_PATH)
	length, err := windows.GetShortPathName(longPointer, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || length >= uint32(len(buffer)) {
		t.Skipf("Windows short paths unavailable: length=%d err=%v", length, err)
	}
	shortPath := string(utf16.Decode(buffer[:length]))
	if samePath(directory, shortPath) {
		t.Skip("filesystem did not provide a distinct short path alias")
	}
	if err := ValidateNoLinkedPath(shortPath); err != nil {
		t.Fatalf("non-reparse short path alias rejected: %v", err)
	}
}
