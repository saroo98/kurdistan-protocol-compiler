// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase17evidence validates the redacted Phase 17 evidence boundary.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

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
	sanitizeV3Input := flag.String("sanitize-v3-input", "", "exact canonical raw v3 field result")
	sanitizeV3Output := flag.String("sanitize-v3-output", "", "exclusive sanitized v3 evidence output")
	flag.Parse()
	if *sanitizeV3Input != "" || *sanitizeV3Output != "" {
		if *sanitizeV3Input == "" || *sanitizeV3Output == "" || *input != "" || *output != "" || flag.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "PHASE 17 EVIDENCE FAILED")
			os.Exit(2)
		}
		if err := sanitizeOwnedVPSV3Files(*sanitizeV3Input, *sanitizeV3Output); err != nil {
			fmt.Fprintln(os.Stderr, "PHASE 17 EVIDENCE FAILED")
			os.Exit(1)
		}
		fmt.Println("PHASE 17 V3 EVIDENCE SANITIZED")
		return
	}

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

func sanitizeOwnedVPSV3Files(input, output string) error {
	raw, err := readRegularBounded(input, 4<<20)
	if err != nil {
		return err
	}
	sanitized, err := phase17.SanitizeOwnedVPSV3(raw)
	if err != nil {
		return err
	}
	return writeExclusiveSynced(output, sanitized)
}

func readRegularBounded(path string, maximum int64) ([]byte, error) {
	if path == "" || maximum <= 0 {
		return nil, errors.New("field evidence input rejected")
	}
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Size() < 1 || info.Size() > maximum {
		return nil, errors.New("field evidence input rejected")
	}
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	opened, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if !os.SameFile(info, opened) {
		_ = file.Close()
		return nil, errors.New("field evidence input changed while opening")
	}
	raw, readErr := io.ReadAll(io.LimitReader(file, maximum+1))
	closed, statErr := file.Stat()
	closeErr := file.Close()
	if readErr != nil {
		return nil, readErr
	}
	if statErr != nil {
		return nil, statErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if int64(len(raw)) > maximum || int64(len(raw)) != opened.Size() || !os.SameFile(opened, closed) ||
		opened.Size() != closed.Size() || opened.ModTime() != closed.ModTime() {
		return nil, errors.New("field evidence input changed while reading")
	}
	return raw, nil
}

func writeExclusiveSynced(path string, raw []byte) (resultErr error) {
	return writeExclusiveSyncedWith(path, raw, syncEvidenceDirectory)
}

func writeExclusiveSyncedWith(path string, raw []byte, syncDirectory func(string) error) (resultErr error) {
	if path == "" || len(raw) == 0 || syncDirectory == nil {
		return errors.New("field evidence output rejected")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	directoryAbs, err := filepath.Abs(directory)
	if err != nil {
		return err
	}
	resolved, err := filepath.EvalSymlinks(directoryAbs)
	if err != nil || !samePath(directoryAbs, resolved) {
		return errors.New("field evidence output directory rejected")
	}
	file, err := os.CreateTemp(directory, ".phase17-evidence-*.tmp")
	if err != nil {
		return err
	}
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		_ = os.Remove(file.Name())
		return err
	}
	temporaryPath := file.Name()
	remove := true
	defer func() {
		_ = file.Close()
		if remove {
			_ = os.Remove(temporaryPath)
		}
	}()
	if _, err := file.Write(raw); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	if err := os.Link(temporaryPath, path); err != nil {
		return err
	}
	if err := os.Remove(temporaryPath); err != nil {
		return err
	}
	if err := syncDirectory(directory); err != nil {
		return err
	}
	remove = false
	return nil
}

func syncEvidenceDirectory(directory string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	file, err := os.Open(directory)
	if err != nil {
		return err
	}
	syncErr := file.Sync()
	closeErr := file.Close()
	return errors.Join(syncErr, closeErr)
}

func samePath(left, right string) bool {
	left = filepath.Clean(left)
	right = filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
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
