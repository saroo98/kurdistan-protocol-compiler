// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command executableevidence runs the mandatory nested executable-evidence
// matrix outside ordinary package tests.
package main

import (
	"context"
	"fmt"
	"os"

	"kurdistan/internal/assurance"
)

func main() {
	root, err := os.Getwd()
	if err == nil {
		err = assurance.RunExecutableEvidence(context.Background(), root, os.Stdout)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "executable evidence:", err)
		os.Exit(1)
	}
	fmt.Fprintln(os.Stdout, "EXECUTABLE EVIDENCE PASSED")
}
