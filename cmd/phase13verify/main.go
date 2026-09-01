// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase13verify enforces the Android product-completion source and
// evidence boundary. Artifact-level checks remain in cmd/phase9verify.
package main

import (
	"encoding/hex"
	"encoding/xml"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"kurdistan/internal/testkit/evidenceoverlay"
)

var errHistoricalEvidenceNotAvailable = errors.New("historical evidence not available")

var historicalEvidenceFiles = []string{
	"docs/KZ-evidence-ref-042",
	"docs/PZ-evidence-ref-050",
	"docs/PZ-evidence-ref-051",
}

var requiredFiles = []string{
	"testdata/evidence/phase13/acceptance-status.json",
	"android/config/phase13-required-device-tests.txt",
}

var forbiddenClaims = []string{
	"uncensorable",
	"undetectable",
	"guaranteed bypass",
	"production-ready",
}

func main() {
	os.Exit(runWithVerifier(os.Args[1:], os.Stdout, os.Stderr, verify))
}

func runWithVerifier(args []string, stdout, stderr io.Writer, verifier func(string) error) int {
	flags := flag.NewFlagSet("phase13verify", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return 2
	}
	if flags.NArg() != 0 {
		fmt.Fprintf(stderr, "PHASE 13 VERIFICATION FAILED: unexpected arguments: %v\n", flags.Args())
		return 2
	}
	if err := verifier(*root); err != nil {
		if errors.Is(err, errHistoricalEvidenceNotAvailable) {
			fmt.Fprintln(stdout, "PHASE 13 VERIFICATION NOT_AVAILABLE; CURRENT QUALIFICATION REMAINS BLOCKED")
			return 0
		}
		fmt.Fprintf(stderr, "PHASE 13 VERIFICATION FAILED: %v\n", err)
		return 1
	}
	fmt.Fprintln(stdout, "PHASE 13 VERIFICATION PASSED")
	return 0
}

func verify(root string) error {
	unavailable := make([]string, 0, len(historicalEvidenceFiles))
	for _, relative := range historicalEvidenceFiles {
		available, err := verifyHistoricalEvidenceFile(root, relative)
		if err != nil {
			return err
		}
		if !available {
			unavailable = append(unavailable, relative)
		}
	}
	for _, relative := range requiredFiles {
		info, err := os.Stat(filepath.Join(root, filepath.FromSlash(relative)))
		if err != nil || !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("required non-empty file %s: %w", relative, err)
		}
	}
	if err := verifyLocaleParity(filepath.Join(root, "android", "core", "ui", "src", "main", "res")); err != nil {
		return err
	}
	if err := verifyManifest(filepath.Join(root, "android", "app", "src", "main", "AndroidManifest.xml")); err != nil {
		return err
	}
	if err := verifyProductClaims(filepath.Join(root, "android")); err != nil {
		return err
	}
	if len(unavailable) != 0 {
		return fmt.Errorf("%w: authenticated historical documents are unavailable in the sanitized subject: %s", errHistoricalEvidenceNotAvailable, strings.Join(unavailable, ", "))
	}
	return nil
}

func verifyHistoricalEvidenceFile(root, relative string) (bool, error) {
	raw, err := evidenceoverlay.ReadSubjectFile(root, relative)
	if err == nil {
		if len(raw) == 0 {
			return false, fmt.Errorf("historical evidence file %s is empty", relative)
		}
		return true, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return false, fmt.Errorf("read historical evidence file %s: %w", relative, err)
	}
	digest, err := evidenceoverlay.ResolveCurrentSHA256(root, relative)
	if err != nil {
		return false, fmt.Errorf("authenticate sanitized historical evidence file %s: %w", relative, err)
	}
	decoded, err := hex.DecodeString(digest)
	if err != nil || len(decoded) != sha256DigestBytes {
		return false, fmt.Errorf("invalid authenticated predecessor digest for %s", relative)
	}
	return false, nil
}

const sha256DigestBytes = 32

type resources struct {
	Strings []struct {
		Name string `xml:"name,attr"`
	} `xml:"string"`
	Plurals []struct {
		Name string `xml:"name,attr"`
	} `xml:"plurals"`
}

func resourceNames(path string) ([]string, error) {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var value resources
	if err := xml.Unmarshal(encoded, &value); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(value.Strings)+len(value.Plurals))
	seen := map[string]bool{}
	for _, entry := range value.Strings {
		if entry.Name == "" || seen[entry.Name] {
			return nil, fmt.Errorf("invalid or duplicate string resource in %s", path)
		}
		seen[entry.Name] = true
		names = append(names, entry.Name)
	}
	for _, entry := range value.Plurals {
		if entry.Name == "" || seen[entry.Name] {
			return nil, fmt.Errorf("invalid or duplicate plural resource in %s", path)
		}
		seen[entry.Name] = true
		names = append(names, entry.Name)
	}
	sort.Strings(names)
	return names, nil
}

func verifyLocaleParity(resRoot string) error {
	base, err := resourceNames(filepath.Join(resRoot, "values", "strings.xml"))
	if err != nil {
		return fmt.Errorf("base resources: %w", err)
	}
	for _, locale := range []string{"values-ar", "values-b+ku+Latn", "values-ckb", "values-fa"} {
		names, err := resourceNames(filepath.Join(resRoot, locale, "strings.xml"))
		if err != nil {
			return fmt.Errorf("%s resources: %w", locale, err)
		}
		if strings.Join(base, "\n") != strings.Join(names, "\n") {
			return fmt.Errorf("%s resource keys differ from base", locale)
		}
	}
	return nil
}

func verifyManifest(path string) error {
	encoded, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(encoded))
	for _, forbidden := range []string{
		"android.permission.query_all_packages",
		"android.permission.access_fine_location",
		"android.permission.access_coarse_location",
		"android.permission.read_external_storage",
		"android.permission.write_external_storage",
		"android.permission.ad_id",
	} {
		if strings.Contains(lower, forbidden) {
			return fmt.Errorf("forbidden manifest capability %s", forbidden)
		}
	}
	return nil
}

func verifyProductClaims(androidRoot string) error {
	return filepath.WalkDir(androidRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == "build" || name == ".gradle" || name == ".kotlin" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Ext(path) != ".kt" && filepath.Ext(path) != ".xml" {
			return nil
		}
		encoded, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		lower := strings.ToLower(string(encoded))
		for _, claim := range forbiddenClaims {
			if strings.Contains(lower, claim) {
				return fmt.Errorf("unsupported product claim %q in %s", claim, path)
			}
		}
		return nil
	})
}
