//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"os"
	"syscall"
)

func preserveOwnership(path, reference string) error {
	info, err := os.Stat(reference)
	if err != nil {
		return err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return ErrStateCorrupt
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}
