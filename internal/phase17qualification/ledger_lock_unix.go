// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build !windows

package phase17qualification

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockLedgerFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}

func unlockLedgerFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_UN)
}
