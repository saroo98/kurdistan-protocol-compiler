// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "errors"

type hostWakeAcquire func() (func(), error)

func runWithHostWakeGuard(acquire hostWakeAcquire, run func() error) error {
	if acquire == nil || run == nil {
		return errors.New("host wake inhibition unavailable")
	}
	release, err := acquire()
	if err != nil || release == nil {
		return errors.New("host wake inhibition unavailable")
	}
	defer release()
	return run()
}
