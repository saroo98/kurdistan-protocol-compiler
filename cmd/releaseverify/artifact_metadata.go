// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const artifactMetadataSchema = "kpc-android-artifact-metadata-v1"

var artifactNamePattern = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

type artifactSpec struct {
	Name    string
	Pattern string
}

type artifactMetadata struct {
	Schema        string                  `json:"schema"`
	Subject       string                  `json:"subject"`
	Authoritative bool                    `json:"authoritative"`
	Release       artifactRelease         `json:"release"`
	Artifacts     []artifactMetadataEntry `json:"artifacts"`
	Limitations   []string                `json:"limitations"`
}

type artifactRelease struct {
	VersionName string `json:"versionName"`
	VersionCode int    `json:"versionCode"`
}

type artifactMetadataEntry struct {
	Name   string `json:"name"`
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func writeArtifactMetadata(root string, version versionProperties, subject string, specs []artifactSpec, output string) error {
	if subject != "DEVICE_TEST_SET" && subject != "UNSIGNED_ENGINEERING_CANDIDATE" {
		return fmt.Errorf("unsupported artifact subject %q", subject)
	}
	if len(specs) == 0 {
		return errors.New("at least one artifact is required")
	}
	rootAbsolute, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	entries := make([]artifactMetadataEntry, 0, len(specs))
	seenNames := map[string]bool{}
	seenPaths := map[string]bool{}
	for _, spec := range specs {
		if !artifactNamePattern.MatchString(spec.Name) || seenNames[spec.Name] {
			return fmt.Errorf("invalid or duplicate artifact name %q", spec.Name)
		}
		seenNames[spec.Name] = true
		resolved, relative, err := resolveArtifact(rootAbsolute, spec.Pattern)
		if err != nil {
			return fmt.Errorf("artifact %s: %w", spec.Name, err)
		}
		if seenPaths[relative] {
			return fmt.Errorf("artifact path %q is declared more than once", relative)
		}
		seenPaths[relative] = true
		info, err := os.Stat(resolved)
		if err != nil {
			return fmt.Errorf("stat %s: %w", relative, err)
		}
		if !info.Mode().IsRegular() || info.Size() == 0 {
			return fmt.Errorf("artifact %s is not a non-empty regular file", relative)
		}
		digest, err := hashFile(resolved)
		if err != nil {
			return fmt.Errorf("hash %s: %w", relative, err)
		}
		entries = append(entries, artifactMetadataEntry{
			Name: spec.Name, Path: filepath.ToSlash(relative), Size: info.Size(), SHA256: digest,
		})
	}
	sort.Slice(entries, func(left, right int) bool { return entries[left].Name < entries[right].Name })
	metadata := artifactMetadata{
		Schema:        artifactMetadataSchema,
		Subject:       subject,
		Authoritative: false,
		Release:       artifactRelease{VersionName: version.Name, VersionCode: version.Code},
		Artifacts:     entries,
		Limitations: []string{
			"engineering metadata only; does not authorize signing, upload, promotion, or release",
		},
	}
	raw, err := json.MarshalIndent(metadata, "", "  ")
	if err != nil {
		return fmt.Errorf("encode artifact metadata: %w", err)
	}
	raw = append(raw, '\n')
	outputAbsolute := output
	if !filepath.IsAbs(outputAbsolute) {
		outputAbsolute = filepath.Join(rootAbsolute, filepath.FromSlash(outputAbsolute))
	}
	outputRelative, err := pathWithinRoot(rootAbsolute, outputAbsolute)
	if err != nil {
		return fmt.Errorf("artifact metadata output: %w", err)
	}
	if seenPaths[outputRelative] {
		return errors.New("artifact metadata output cannot overwrite an input artifact")
	}
	if err := os.MkdirAll(filepath.Dir(outputAbsolute), 0o755); err != nil {
		return fmt.Errorf("create artifact metadata directory: %w", err)
	}
	if err := os.WriteFile(outputAbsolute, raw, 0o644); err != nil {
		return fmt.Errorf("write artifact metadata: %w", err)
	}
	return nil
}

func resolveArtifact(rootAbsolute, pattern string) (string, string, error) {
	if strings.TrimSpace(pattern) == "" || filepath.IsAbs(pattern) {
		return "", "", errors.New("artifact pattern must be a non-empty repository-relative path")
	}
	joined := filepath.Join(rootAbsolute, filepath.FromSlash(pattern))
	matches, err := filepath.Glob(joined)
	if err != nil {
		return "", "", fmt.Errorf("invalid artifact glob: %w", err)
	}
	if len(matches) != 1 {
		return "", "", fmt.Errorf("artifact pattern matched %d files, require exactly one", len(matches))
	}
	relative, err := pathWithinRoot(rootAbsolute, matches[0])
	if err != nil {
		return "", "", err
	}
	return matches[0], relative, nil
}

func pathWithinRoot(rootAbsolute, path string) (string, error) {
	pathAbsolute, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(rootAbsolute, pathAbsolute)
	if err != nil {
		return "", err
	}
	if relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) || filepath.IsAbs(relative) {
		return "", errors.New("path escapes repository root")
	}
	return relative, nil
}

func hashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}
