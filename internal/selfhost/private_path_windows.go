// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package selfhost

import (
	"errors"
	"fmt"

	"kurdistan/internal/winprivate"
)

func mapSelfhostWindowsError(err error) error {
	if err == nil {
		return nil
	}
	switch value := err.(type) {
	case *winprivate.OpError:
		return selfhostPrivatePathFailure(value.Op, mapSelfhostWindowsError(value.Err))
	case interface{ Unwrap() []error }:
		causes := value.Unwrap()
		mapped := make([]error, len(causes))
		for i, cause := range causes {
			mapped[i] = mapSelfhostWindowsError(cause)
		}
		return errors.Join(mapped...)
	}
	if errors.Is(err, winprivate.ErrUnsafe) || errors.Is(err, winprivate.ErrExists) ||
		errors.Is(err, winprivate.ErrIncomplete) {
		return ErrRecipientRegistry
	}
	return err
}

func protectSelfhostPrivatePath(path string, directory bool) error {
	return mapSelfhostWindowsError(winprivate.Protect(path, directory))
}

func createSelfhostPrivateDirectory(path string) error {
	_, err := winprivate.CreateDirectory(path)
	if err == nil {
		return nil
	}
	if errors.Is(err, winprivate.ErrExists) {
		return ErrBusy
	}
	return ErrRecipientRegistry
}

func ensureSelfhostPrivateDirectory(path string) error {
	if winprivate.EnsureDirectory(path) != nil {
		return ErrRecipientRegistry
	}
	return nil
}

func writeSelfhostPrivateFileExclusive(path string, value []byte) error {
	if winprivate.WriteFileExclusive(path, value) != nil {
		return ErrRecipientRegistry
	}
	return nil
}

func selfhostPrivatePathFailure(operation string, err error) error {
	if err == nil {
		return ErrRecipientRegistry
	}
	return errors.Join(ErrRecipientRegistry, fmt.Errorf("selfhost: %s: %w", operation, err))
}
