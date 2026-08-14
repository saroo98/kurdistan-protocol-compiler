// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"errors"
	"os"
)

func acquireLedgerAppendLock(directory string) (func() error, error) {
	lockPath := directory + ".append.lock"
	before, beforeErr := os.Lstat(lockPath)
	if beforeErr != nil && !errors.Is(beforeErr, os.ErrNotExist) {
		return nil, errors.New("qualification ledger append lock unavailable")
	}
	if beforeErr == nil && (before.Mode()&os.ModeSymlink != 0 || !before.Mode().IsRegular()) {
		return nil, errors.New("qualification ledger append lock rejected")
	}
	file, err := os.OpenFile(lockPath, os.O_RDWR|os.O_CREATE, 0o600)
	if err != nil {
		return nil, errors.New("qualification ledger append lock unavailable")
	}
	reject := func() (func() error, error) {
		_ = file.Close()
		return nil, errors.New("qualification ledger append lock rejected")
	}
	after, err := os.Lstat(lockPath)
	opened, statErr := file.Stat()
	if err != nil || statErr != nil || after.Mode()&os.ModeSymlink != 0 || !after.Mode().IsRegular() || !os.SameFile(after, opened) {
		return reject()
	}
	if err := file.Chmod(0o600); err != nil {
		return reject()
	}
	if err := lockLedgerFile(file); err != nil {
		_ = file.Close()
		return nil, errors.New("qualification ledger append already active")
	}
	closed := false
	return func() error {
		if closed {
			return errors.New("qualification ledger append lock already released")
		}
		closed = true
		unlockErr := unlockLedgerFile(file)
		closeErr := file.Close()
		return errors.Join(unlockErr, closeErr)
	}, nil
}
