// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package phase17qualification

import (
	"errors"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

func validateNoLinkedPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	cleaned := filepath.Clean(abs)
	windowsPath := strings.ReplaceAll(cleaned, "/", "\\")
	volume := filepath.VolumeName(windowsPath)
	if !filepath.IsAbs(cleaned) || strings.HasPrefix(windowsPath, "\\\\") || strings.HasPrefix(windowsPath, "\\?\\") ||
		strings.HasPrefix(windowsPath, "\\.\\") || strings.HasPrefix(volume, "\\") || len(volume) != 2 || volume[1] != ':' {
		return errors.New("qualification path is not an absolute local drive path")
	}
	anchor := volume + string(os.PathSeparator)
	relative, err := filepath.Rel(anchor, cleaned)
	if err != nil || (!filepath.IsLocal(relative) && relative != ".") {
		return errors.New("qualification path escapes its local drive")
	}
	current := anchor
	if relative == "." {
		return validateWindowsPathComponent(current)
	}
	for _, component := range strings.Split(relative, string(os.PathSeparator)) {
		current = filepath.Join(current, component)
		if err := validateWindowsPathComponent(current); err != nil {
			return err
		}
	}
	return nil
}

func validateWindowsPathComponent(path string) error {
	pointer, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("qualification path contains a reparse point")
	}
	return nil
}
