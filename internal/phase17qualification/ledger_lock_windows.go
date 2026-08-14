// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build windows

package phase17qualification

import (
	"os"

	"golang.org/x/sys/windows"
)

func lockLedgerFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.LockFileEx(
		windows.Handle(file.Fd()),
		windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
		0, 1, 0, &overlapped,
	)
}

func unlockLedgerFile(file *os.File) error {
	var overlapped windows.Overlapped
	return windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped)
}
