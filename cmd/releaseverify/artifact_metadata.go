// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/rand"
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
	rootInputAbsolute, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	rootAbsolute, err := filepath.EvalSymlinks(rootInputAbsolute)
	if err != nil {
		return fmt.Errorf("resolve repository root symlinks: %w", err)
	}
	rootInfo, err := os.Stat(rootAbsolute)
	if err != nil {
		return fmt.Errorf("stat repository root: %w", err)
	}
	if !rootInfo.IsDir() {
		return errors.New("repository root is not a directory")
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
		size, digest, err := hashRegularFileNoSymlink(resolved)
		if err != nil {
			return fmt.Errorf("hash %s: %w", relative, err)
		}
		if size == 0 {
			return fmt.Errorf("artifact %s is not a non-empty regular file", relative)
		}
		entries = append(entries, artifactMetadataEntry{
			Name: spec.Name, Path: filepath.ToSlash(relative), Size: size, SHA256: digest,
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
	outputRelative, err := outputPathWithinRoot(rootInputAbsolute, rootAbsolute, output)
	if err != nil {
		return fmt.Errorf("artifact metadata output: %w", err)
	}
	if seenPaths[outputRelative] {
		return errors.New("artifact metadata output cannot overwrite an input artifact")
	}
	if err := writeFileAtomicallyUnderRoot(rootAbsolute, outputRelative, raw, 0o644); err != nil {
		return fmt.Errorf("write artifact metadata: %w", err)
	}
	return nil
}

func outputPathWithinRoot(inputRoot, canonicalRoot, output string) (string, error) {
	if !filepath.IsAbs(output) {
		return pathWithinRoot(canonicalRoot, filepath.Join(canonicalRoot, filepath.FromSlash(output)))
	}
	for _, root := range []string{inputRoot, canonicalRoot} {
		relative, err := pathWithinRoot(root, output)
		if err == nil {
			return relative, nil
		}
	}
	return "", errors.New("path escapes repository root")
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
	if err := rejectSymlinkComponents(rootAbsolute, matches[0], false); err != nil {
		return "", "", err
	}
	resolved, err := filepath.EvalSymlinks(matches[0])
	if err != nil {
		return "", "", fmt.Errorf("resolve artifact path: %w", err)
	}
	relative, err := pathWithinRoot(rootAbsolute, resolved)
	if err != nil {
		return "", "", err
	}
	return resolved, relative, nil
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

func hashRegularFileNoSymlink(path string) (int64, string, error) {
	pathInfo, err := os.Lstat(path)
	if err != nil {
		return 0, "", err
	}
	if pathInfo.Mode()&os.ModeSymlink != 0 {
		return 0, "", errors.New("symbolic-link artifacts are not allowed")
	}
	if !pathInfo.Mode().IsRegular() {
		return 0, "", errors.New("artifact is not a regular file")
	}
	file, err := os.Open(path)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return 0, "", err
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return 0, "", errors.New("artifact changed while being opened")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return 0, "", err
	}
	return openedInfo.Size(), hex.EncodeToString(hash.Sum(nil)), nil
}

func rejectSymlinkComponents(rootAbsolute, target string, allowMissing bool) error {
	relative, err := pathWithinRoot(rootAbsolute, target)
	if err != nil {
		return err
	}
	current := rootAbsolute
	for _, component := range strings.Split(relative, string(filepath.Separator)) {
		if component == "" || component == "." {
			continue
		}
		current = filepath.Join(current, component)
		info, err := os.Lstat(current)
		if err != nil {
			if allowMissing && errors.Is(err, os.ErrNotExist) {
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("symbolic-link path component %q is not allowed", component)
		}
	}
	return nil
}

func writeFileAtomicallyUnderRoot(rootPath, relative string, content []byte, mode os.FileMode) (err error) {
	if filepath.IsAbs(relative) || relative == "." || relative == "" {
		return errors.New("artifact metadata output must be a repository-relative file")
	}
	directory, err := openDirectoryUnderRootNoSymlinks(rootPath, filepath.Dir(relative))
	if err != nil {
		return err
	}
	defer directory.Close()
	name := filepath.Base(relative)
	if existing, statErr := directory.Lstat(name); statErr == nil {
		if existing.Mode()&os.ModeSymlink != 0 {
			return errors.New("symbolic-link output target is not allowed")
		}
		if !existing.Mode().IsRegular() {
			return errors.New("output target is not a regular file")
		}
	} else if !errors.Is(statErr, os.ErrNotExist) {
		return statErr
	}

	temporaryName, err := randomTemporaryName()
	if err != nil {
		return err
	}
	temporary, err := directory.OpenFile(temporaryName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	defer func() {
		_ = temporary.Close()
		if err != nil {
			_ = directory.Remove(temporaryName)
		}
	}()
	if _, err = temporary.Write(content); err != nil {
		return err
	}
	if err = temporary.Sync(); err != nil {
		return err
	}
	if err = temporary.Close(); err != nil {
		return err
	}
	if err = directory.Rename(temporaryName, name); err != nil {
		return err
	}
	return nil
}

func openDirectoryUnderRootNoSymlinks(rootPath, relative string) (*os.Root, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	if relative == "." || relative == "" {
		return root, nil
	}
	current := root
	for _, component := range strings.Split(filepath.Clean(relative), string(filepath.Separator)) {
		if component == "" || component == "." || component == ".." {
			current.Close()
			return nil, errors.New("artifact metadata output directory is invalid")
		}
		info, statErr := current.Lstat(component)
		if errors.Is(statErr, os.ErrNotExist) {
			if mkdirErr := current.Mkdir(component, 0o755); mkdirErr != nil && !errors.Is(mkdirErr, os.ErrExist) {
				current.Close()
				return nil, mkdirErr
			}
			info, statErr = current.Lstat(component)
		}
		if statErr != nil {
			current.Close()
			return nil, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			current.Close()
			return nil, fmt.Errorf("output directory component %q is not a real directory", component)
		}
		next, openErr := current.OpenRoot(component)
		current.Close()
		if openErr != nil {
			return nil, openErr
		}
		current = next
	}
	return current, nil
}

func randomTemporaryName() (string, error) {
	var random [16]byte
	if _, err := rand.Read(random[:]); err != nil {
		return "", err
	}
	return ".artifact-metadata-" + hex.EncodeToString(random[:]), nil
}
