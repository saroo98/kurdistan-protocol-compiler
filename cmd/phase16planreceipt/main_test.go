// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"os"
	"os/exec"
	"testing"
)

func TestMissingModeFailsClosed(t *testing.T) {
	if os.Getenv("PHASE16_RECEIPT_HELPER") == "1" {
		main()
		return
	}
	command := exec.Command(os.Args[0], "-test.run=TestMissingModeFailsClosed")
	command.Env = append(os.Environ(), "PHASE16_RECEIPT_HELPER=1")
	if err := command.Run(); err == nil {
		t.Fatal("receipt command accepted missing authority inputs")
	}
}
