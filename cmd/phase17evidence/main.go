// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17evidence validates the redacted Phase 17 evidence boundary.
package main

import (
	"flag"
	"fmt"
	"os"

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
		fmt.Fprintln(os.Stderr, "PHASE 17 EVIDENCE FAILED: sanitized field-evidence conversion is unavailable until the owned-VPS schema is frozen")
		os.Exit(2)
	}
	if err := phase17.Verify(*root); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 17 EVIDENCE FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 17 EVIDENCE PASSED")
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
