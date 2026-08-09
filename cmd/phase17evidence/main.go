// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17evidence validates the redacted Phase 17 evidence boundary.
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	phase17 "kurdistan/internal/phase17evidence"
)

type predecessor = phase17.Predecessor
type predecessorArtifacts = phase17.PredecessorArtifacts
type supersession = phase17.Supersession
type acceptance = phase17.Acceptance

func main() {
	root := flag.String("root", ".", "repository root")
	input := flag.String("input", "", "sanitized Phase 17 field evidence input")
	output := flag.String("output", "", "acceptance-status output path")
	flag.Parse()

	if (*input == "") != (*output == "") {
		fmt.Fprintln(os.Stderr, "PHASE 17 EVIDENCE FAILED: input and output must be provided together")
		os.Exit(2)
	}
	if *input != "" {
		if err := convertOwnedVPSFiles(*input, *output); err != nil {
			fmt.Fprintf(os.Stderr, "PHASE 17 EVIDENCE FAILED: %v\n", err)
			os.Exit(1)
		}
		fmt.Println("PHASE 17 EVIDENCE CONVERTED")
		return
	}
	if err := phase17.Verify(*root); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 EVIDENCE FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 17 EVIDENCE PASSED")
}

func convertOwnedVPSFiles(input, output string) error {
	raw, err := os.ReadFile(input)
	if err != nil {
		return fmt.Errorf("read sanitized field evidence: %w", err)
	}
	currentRaw, err := os.ReadFile(output)
	if err != nil {
		return fmt.Errorf("read acceptance status: %w", err)
	}
	var current acceptance
	if err := decodeStrict(currentRaw, &current); err != nil {
		return fmt.Errorf("decode acceptance status: %w", err)
	}
	updated, err := phase17.ConvertOwnedVPS(raw, current)
	if err != nil {
		return err
	}
	encoded, err := phase17.MarshalCanonical(updated)
	if err != nil {
		return err
	}
	directory := filepath.Dir(output)
	temporary, err := os.CreateTemp(directory, ".phase17-acceptance-*.tmp")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	failed := true
	defer func() {
		_ = temporary.Close()
		if failed {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := temporary.Chmod(0o600); err != nil {
		return err
	}
	if _, err := temporary.Write(encoded); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, output); err != nil {
		return err
	}
	failed = false
	return nil
}

func decodeStrict(raw []byte, target any) error {
	return phase17.DecodeStrict(raw, target)
}

func validateSupersession(value supersession) error {
	return phase17.ValidateSupersession(value)
}

func validateAcceptance(value acceptance) error {
	return phase17.ValidateAcceptance(value)
}
