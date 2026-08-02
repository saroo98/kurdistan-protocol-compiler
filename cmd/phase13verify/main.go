// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase13verify enforces the Android product-completion source and
// evidence boundary. Artifact-level checks remain in cmd/phase9verify.
package main

import (
	"encoding/xml"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

var requiredFiles = []string{
	"docs/KIP-0088-phase13-android-product-completion.md",
	"docs/PHASE13_EVIDENCE_INDEX.md",
	"docs/PHASE13_FEATURE_COVERAGE.md",
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
	root := flag.String("root", ".", "repository root")
	flag.Parse()
	if err := verify(*root); err != nil {
		fmt.Fprintf(os.Stderr, "PHASE 13 VERIFICATION FAILED: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("PHASE 13 VERIFICATION PASSED")
}

func verify(root string) error {
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
	return verifyProductClaims(filepath.Join(root, "android"))
}

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
