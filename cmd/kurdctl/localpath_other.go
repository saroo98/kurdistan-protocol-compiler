// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !windows && !js && !plan9

package main

import (
	"errors"
	"os"
	"path/filepath"
)

func localPathRoot(path string) (string, error) {
	if path == "" || path[0] != os.PathSeparator {
		return "", errors.New("absolute path required")
	}
	return string(os.PathSeparator), nil
}

func protectPrivatePath(path string, directory bool) error {
	info, err := os.Lstat(path)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || directory != info.IsDir() || !directory && !info.Mode().IsRegular() {
		return errUnsupportedFilesystem
	}
	want := os.FileMode(0o600)
	if directory {
		want = 0o700
	}
	if err := os.Chmod(path, want); err != nil {
		return errUnsupportedFilesystem
	}
	info, err = os.Lstat(path)
	if err != nil || info.Mode().Perm() != want {
		return errUnsupportedFilesystem
	}
	return nil
}

func syncLocalDirectory(path string) error {
	directory, err := os.Open(path)
	if err != nil {
		return err
	}
	defer directory.Close()
	return directory.Sync()
}

func createPrivateOutputRoot(path string) (*privateOutputRoot, error) {
	if path == "" {
		return nil, selfhostInvalidInput()
	}
	parent, leaf, err := openLocalParent(path)
	if err != nil {
		return nil, err
	}
	defer parent.Close()
	if err := parent.Mkdir(leaf, 0o700); err != nil {
		if errors.Is(err, os.ErrExist) {
			return nil, errOutputExists
		}
		return nil, errOutputIncomplete
	}
	fullPath := filepath.Join(parent.Name(), leaf)
	if err := protectPrivatePath(fullPath, true); err != nil {
		_ = parent.Remove(leaf)
		return nil, errUnsupportedFilesystem
	}
	if err := syncLocalDirectory(parent.Name()); err != nil {
		_ = parent.Remove(leaf)
		return nil, errUnsupportedFilesystem
	}
	root, err := parent.OpenRoot(leaf)
	if err != nil {
		return nil, errUnsupportedFilesystem
	}
	return &privateOutputRoot{path: fullPath, root: root}, nil
}

func writePrivateFile(root *privateOutputRoot, name string, value []byte) error {
	if root == nil || root.root == nil || !filepath.IsLocal(name) || len(value) == 0 {
		return errOutputIncomplete
	}
	file, err := root.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return errOutputExists
		}
		return errOutputIncomplete
	}
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = root.root.Remove(name)
		}
	}()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || protectPrivatePath(filepath.Join(root.path, name), false) != nil {
		return errUnsupportedFilesystem
	}
	if written, err := file.Write(value); err != nil || written != len(value) || file.Sync() != nil || file.Close() != nil || syncLocalDirectory(root.path) != nil {
		return errOutputIncomplete
	}
	remove = false
	return nil
}
