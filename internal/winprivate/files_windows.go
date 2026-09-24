// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package winprivate

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func Root(path string) (string, error) {
	cleaned := strings.ReplaceAll(path, "/", "\\")
	volume := filepath.VolumeName(cleaned)
	if !filepath.IsAbs(path) || strings.HasPrefix(cleaned, "\\\\") || strings.HasPrefix(cleaned, "\\?\\") || strings.HasPrefix(cleaned, "\\.\\") || strings.HasPrefix(volume, "\\") || len(volume) != 2 || volume[1] != ':' {
		return "", errors.New("absolute local drive path required")
	}
	return volume + string(os.PathSeparator), nil
}

func rejectWindowsReparseComponents(path string, includeFinal bool) error {
	anchor, err := Root(path)
	if err != nil {
		return ErrUnsafe
	}
	cleaned := filepath.Clean(path)
	relative, err := filepath.Rel(anchor, cleaned)
	if err != nil || !filepath.IsLocal(relative) {
		return ErrUnsafe
	}
	parts := strings.Split(relative, string(os.PathSeparator))
	if !includeFinal && len(parts) > 0 {
		parts = parts[:len(parts)-1]
	}
	current := anchor
	for _, part := range parts {
		current = filepath.Join(current, part)
		pointer, err := windows.UTF16PtrFromString(current)
		if err != nil {
			return ErrUnsafe
		}
		attributes, err := windows.GetFileAttributes(pointer)
		if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return ErrUnsafe
		}
	}
	return nil
}

type creationOperations struct {
	verify func(string, bool) error
}

func defaultCreationOperations() creationOperations {
	return creationOperations{verify: Verify}
}

func CreateDirectory(path string) (bool, error) {
	return createDirectoryWithOperations(path, defaultCreationOperations())
}

func WriteFileExclusive(path string, value []byte) error {
	return writeFileWithOperations(path, value, defaultCreationOperations())
}

func EnsureDirectory(path string) error {
	_, err := CreateDirectory(path)
	if err == nil {
		return nil
	}
	if !errors.Is(err, ErrExists) {
		return ErrUnsafe
	}
	info, statErr := os.Lstat(path)
	if statErr != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 ||
		rejectWindowsReparseComponents(path, true) != nil {
		return ErrUnsafe
	}
	return Verify(path, true)
}

func createDirectoryWithOperations(path string, operations creationOperations) (bool, error) {
	if operations.verify == nil {
		return false, ErrUnsafe
	}
	if path == "" || rejectWindowsReparseComponents(path, false) != nil {
		return false, ErrUnsafe
	}
	security, err := windowsPrivateSecurityAttributes(true)
	if err != nil {
		return false, err
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return false, ErrUnsafe
	}
	if err := windows.CreateDirectory(pointer, security); err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return false, ErrExists
		}
		return false, ErrIncomplete
	}
	if err := rejectWindowsReparseComponents(path, true); err != nil || operations.verify(path, true) != nil {
		return true, ErrUnsafe
	}
	return true, nil
}

func writeFileWithOperations(path string, value []byte, operations creationOperations) error {
	if operations.verify == nil {
		return ErrUnsafe
	}
	if path == "" || len(value) == 0 || rejectWindowsReparseComponents(path, false) != nil {
		return ErrIncomplete
	}
	security, err := windowsPrivateSecurityAttributes(false)
	if err != nil {
		return err
	}
	pointer, err := windows.UTF16PtrFromString(filepath.Clean(path))
	if err != nil {
		return ErrUnsafe
	}
	handle, err := windows.CreateFile(pointer, windows.GENERIC_WRITE|windows.READ_CONTROL, 0, security, windows.CREATE_NEW, windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_WRITE_THROUGH, 0)
	if err != nil {
		if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
			return ErrExists
		}
		return ErrIncomplete
	}
	file := os.NewFile(uintptr(handle), path)
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(path)
		}
	}()
	if err := operations.verify(path, false); err != nil {
		return err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return ErrIncomplete
	}
	if written, err := file.Write(value); err != nil || written != len(value) || file.Sync() != nil || file.Close() != nil {
		return ErrIncomplete
	}
	remove = false
	return nil
}
