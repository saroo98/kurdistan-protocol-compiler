// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"kurdistan/internal/winprivate"
)

func mapWindowsPrivateError(err error) error {
	if err == nil {
		return nil
	}
	switch value := err.(type) {
	case *winprivate.OpError:
		return privatePathFailure(value.Op, mapWindowsPrivateError(value.Err))
	case interface{ Unwrap() []error }:
		causes := value.Unwrap()
		mapped := make([]error, len(causes))
		for i, cause := range causes {
			mapped[i] = mapWindowsPrivateError(cause)
		}
		return errors.Join(mapped...)
	}
	if errors.Is(err, winprivate.ErrExists) {
		return errOutputExists
	}
	if errors.Is(err, winprivate.ErrIncomplete) {
		return errOutputIncomplete
	}
	return err
}

func localPathRoot(path string) (string, error) { return winprivate.Root(path) }

func protectPrivatePath(path string, directory bool) error {
	return mapWindowsPrivateError(winprivate.Protect(path, directory))
}

func createWindowsPrivateDirectory(path string) error {
	created, err := winprivate.CreateDirectory(path)
	return completeWindowsPrivateDirectory(path, created, err)
}

func completeWindowsPrivateDirectory(path string, created bool, err error) error {
	if created && err != nil {
		_ = os.Remove(path)
	}
	return mapWindowsPrivateError(err)
}

func createWindowsPrivateFile(path string, value []byte) error {
	return mapWindowsPrivateError(winprivate.WriteFileExclusive(path, value))
}

func privatePathFailure(operation string, err error) error {
	if err == nil {
		return fmt.Errorf("%w: %s", errUnsupportedFilesystem, operation)
	}
	return fmt.Errorf("kurdctl private path: %s: %w", operation, err)
}

func syncLocalDirectory(string) error { return nil }

func createPrivateOutputRoot(path string) (*privateOutputRoot, error) {
	if err := createWindowsPrivateDirectory(path); err != nil {
		return nil, err
	}
	return &privateOutputRoot{path: filepath.Clean(path)}, nil
}

func writePrivateFile(root *privateOutputRoot, name string, value []byte) error {
	if root == nil || !filepath.IsLocal(name) || filepath.Base(name) != name {
		return errOutputIncomplete
	}
	return createWindowsPrivateFile(filepath.Join(root.path, name), value)
}
