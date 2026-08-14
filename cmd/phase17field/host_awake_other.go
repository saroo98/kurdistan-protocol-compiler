//go:build !windows

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import "errors"

func acquireHostWakeInhibitor() (func(), error) {
	return nil, errors.New("host wake inhibition unsupported")
}
