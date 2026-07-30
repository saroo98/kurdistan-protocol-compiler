// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command gate runs the repository's full validation bar in one step: the same
// gates documented in docs/GOVERNANCE.md. It exists to give a single
// reproducible pre-merge check locally and in the repository CI workflow.
//
// Usage:
//
//	go run ./cmd/gate           # build + vet + test + full audit
//	go run ./cmd/gate -quick    # build + vet + test + quick audit (faster)
//	go run ./cmd/gate -android  # Go gate plus the current Android Phase 11 gate
//
// It exits non-zero if any step fails.
package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"time"
)

type step struct {
	name    string
	program string
	args    []string
	dir     string
}

func gateSteps(quick bool, jsonOut, statusOut string) []step {
	auditMode := "--full"
	if quick {
		auditMode = "--quick"
	}
	return []step{
		{"build", "go", []string{"build", "./..."}, ""},
		{"vet", "go", []string{"vet", "./..."}, ""},
		{"test", "go", []string{"test", "-count=1", "./..."}, ""},
		{"audit", "go", []string{"run", "./cmd/kcheck", auditMode, "--out", jsonOut, "--status", statusOut}, ""},
	}
}

func main() {
	quick := false
	android := false
	for _, a := range os.Args[1:] {
		if a == "-quick" || a == "--quick" {
			quick = true
		}
		if a == "-android" || a == "--android" {
			android = true
		}
	}

	statusOut := filepath.Join(os.TempDir(), "kcheck-gate-status.md")
	jsonOut := filepath.Join(os.TempDir(), "kcheck-gate-report.json")
	steps := gateSteps(quick, jsonOut, statusOut)
	if android {
		steps = append(steps, androidStep())
	}

	failed := []string{}
	for _, s := range steps {
		fmt.Printf("== gate: %s (%s %v) ==\n", s.name, s.program, s.args)
		start := time.Now()
		cmd := exec.Command(s.program, s.args...)
		cmd.Dir = s.dir
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
	if android {
		fmt.Println("GATE PASSED: build, vet, test, audit, and Android Phase 11 all green")
	} else {
		fmt.Println("GATE PASSED: build, vet, test, audit all green")
	}
}

func androidStep() step {
	if runtime.GOOS == "windows" {
		return step{
			name:    "android-phase11",
			program: "cmd",
			args:    []string{"/c", "gradlew.bat", "phase11Gate", "--no-build-cache"},
			dir:     "android",
		}
	}
	return step{
		name:    "android-phase11",
		program: "./gradlew",
		args:    []string{"phase11Gate", "--no-build-cache"},
		dir:     "android",
	}
}
