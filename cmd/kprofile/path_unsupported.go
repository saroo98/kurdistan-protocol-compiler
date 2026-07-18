// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

//go:build js || plan9

package main

import "errors"

// os.Root cannot provide the required TOCTOU protection on these targets.
func localPathRoot(string) (string, error) {
	return "", errors.New("secure local path operations unsupported on this platform")
}
