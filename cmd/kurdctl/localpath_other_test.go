// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !windows && !js && !plan9

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestPrivateOutputRejectsSymlinkedParentComponent(t *testing.T) {
	base := t.TempDir()
	realParent := filepath.Join(base, "real")
	if err := os.Mkdir(realParent, 0o700); err != nil {
		t.Fatal(err)
	}
	linkParent := filepath.Join(base, "linked")
	if err := os.Symlink("real", linkParent); err != nil {
		t.Fatal(err)
	}
	root, err := createPrivateOutputRoot(filepath.Join(linkParent, "profile"))
	if root != nil {
		_ = root.Close()
	}
	if !errors.Is(err, errUnsupportedFilesystem) {
		t.Fatalf("symlinked output parent err=%v", err)
	}
	if _, statErr := os.Lstat(filepath.Join(realParent, "profile")); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("symlinked output path was created: %v", statErr)
	}
}
