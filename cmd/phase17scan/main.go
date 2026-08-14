// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17scan is the independent Go implementation of the Phase 17
// privacy scanner. It intentionally does not import qualification or evidence
// packages.
package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"kurdistan/internal/phase17privacy/scannera"
)

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "phase17scan: scanner unavailable")
		os.Exit(1)
	}
}

func run(arguments []string, stdout io.Writer) error {
	return runWithInput(arguments, os.Stdin, stdout)
}

func runWithInput(arguments []string, stdin io.Reader, stdout io.Writer) error {
	flags := flag.NewFlagSet("phase17scan", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "bounded private observation stream")
	expectedBytes := flags.Int64("expected-bytes", 0, "exact stdin byte count")
	if err := flags.Parse(arguments); err != nil || flags.NArg() != 0 || *inputPath == "" || stdin == nil || stdout == nil ||
		*expectedBytes < 0 || *expectedBytes > scannera.MaximumBytes {
		return errors.New("scanner arguments rejected")
	}
	if *inputPath == "-" {
		if *expectedBytes == 0 {
			return errors.New("scanner stdin length rejected")
		}
		receipt := scannera.Scan(stdin, *expectedBytes)
		encoder := json.NewEncoder(stdout)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(receipt)
	}
	if *expectedBytes != 0 {
		return errors.New("scanner file length override rejected")
	}
	info, err := os.Lstat(*inputPath)
	if err != nil || info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 0 || info.Size() > scannera.MaximumBytes {
		return errors.New("scanner input rejected")
	}
	file, err := os.Open(*inputPath)
	if err != nil {
		return err
	}
	receipt := scannera.Scan(file, info.Size())
	closeErr := file.Close()
	if closeErr != nil {
		return closeErr
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(receipt)
}
