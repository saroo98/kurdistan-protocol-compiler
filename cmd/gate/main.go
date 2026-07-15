// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command gate runs the repository's full validation bar in one step: the same
// gates documented in docs/GOVERNANCE.md. It exists to give a single
// reproducible pre-merge check in a repository that has no external CI.
//
// Usage:
//
//	go run ./cmd/gate           # build + vet + test + full audit
//	go run ./cmd/gate -quick    # build + vet + test + quick audit (faster)
//
// It exits non-zero if any step fails.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type step struct {
	name string
	args []string
}

func gateSteps(quick bool, jsonOut, statusOut string) []step {
	auditMode := "--full"
	if quick {
		auditMode = "--quick"
	}
	return []step{
		{"build", []string{"build", "./..."}},
		{"vet", []string{"vet", "./..."}},
		{"test", []string{"test", "-count=1", "./..."}},
		{"audit", []string{"run", "./cmd/kcheck", auditMode, "--out", jsonOut, "--status", statusOut}},
	}
}

func main() {
	quick := false
	for _, a := range os.Args[1:] {
		if a == "-quick" || a == "--quick" {
			quick = true
		}
	}

	statusOut := filepath.Join(os.TempDir(), "kcheck-gate-status.md")
	jsonOut := filepath.Join(os.TempDir(), "kcheck-gate-report.json")
	steps := gateSteps(quick, jsonOut, statusOut)

	failed := []string{}
	for _, s := range steps {
		fmt.Printf("== gate: %s (go %v) ==\n", s.name, s.args)
		start := time.Now()
		cmd := exec.Command("go", s.args...)
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		err := cmd.Run()
		dur := time.Since(start).Round(time.Millisecond)
		if err != nil {
			fmt.Printf("-- gate: %s FAILED in %s: %v\n", s.name, dur, err)
			failed = append(failed, s.name)
		} else {
			fmt.Printf("-- gate: %s ok in %s\n", s.name, dur)
		}
	}

	fmt.Println()
	if len(failed) > 0 {
		fmt.Printf("GATE FAILED: %v\n", failed)
		os.Exit(1)
	}
	fmt.Println("GATE PASSED: build, vet, test, audit all green")
}
