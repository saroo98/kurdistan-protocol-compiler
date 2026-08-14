// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !windows

package phase17qualification

import (
	"errors"
	"path/filepath"
)

func validateNoLinkedPath(path string) error {
	abs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return err
	}
	if !samePath(abs, resolved) {
		return errors.New("qualification path contains a symbolic link")
	}
	return nil
}
