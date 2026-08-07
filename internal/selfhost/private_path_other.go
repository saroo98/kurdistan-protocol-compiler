// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !windows && !js && !plan9

package selfhost

import (
	"errors"
	"os"
)

func protectSelfhostPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return ErrRecipientRegistry
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if err := os.Chmod(path, want); err != nil {
		return ErrRecipientRegistry
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode().Perm() != want {
		return ErrRecipientRegistry
	}
	return nil
}

func createSelfhostPrivateDirectory(path string) error {
	if path == "" {
		return ErrRecipientRegistry
	}
	if err := os.Mkdir(path, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return ErrBusy
		}
		return ErrRecipientRegistry
	}
	if protectSelfhostPrivatePath(path, true) != nil {
		return ErrRecipientRegistry
	}
	return nil
}

func ensureSelfhostPrivateDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return ErrRecipientRegistry
	}
	return protectSelfhostPrivatePath(path, true)
}

func writeSelfhostPrivateFileExclusive(path string, value []byte) error {
	if len(value) == 0 || writeExclusive(path, value, 0o600) != nil || protectSelfhostPrivatePath(path, false) != nil {
		return ErrRecipientRegistry
	}
	return nil
}
