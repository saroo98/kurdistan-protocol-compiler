// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"kurdistan/internal/assurance"
)

const candidateProvenanceSchema = "kpc-engineering-candidate-provenance-v1"

var (
	fullSHA256Pattern = regexp.MustCompile(`^[0-9a-f]{64}$`)
	fullGitSHAPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
	repositoryPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}/[A-Za-z0-9_.-]{1,100}$`)
)

type candidateProvenance struct {
	Schema            string              `json:"schema"`
	Repository        string              `json:"repository"`
	Commit            string              `json:"commit"`
	Tree              string              `json:"tree"`
	Assurance         candidateAssurance  `json:"assurance"`
	SelectedBuilder   string              `json:"selectedBuilder"`
	SelectedArtifacts []candidateArtifact `json:"selectedArtifacts"`
	ComparisonSHA256  string              `json:"comparisonSha256"`
	Authoritative     bool                `json:"authoritative"`
	Limitations       []string            `json:"limitations"`
}

type candidateAssurance struct {
	RunID             string              `json:"runId"`
	RunAttempt        int                 `json:"runAttempt"`
	Trigger           string              `json:"trigger"`
	WorkflowPath      string              `json:"workflowPath"`
	CertificatePath   string              `json:"certificatePath"`
	CertificateSHA256 string              `json:"certificateSha256"`
	Receipts          []candidateArtifact `json:"receipts"`
	Inventories       []candidateArtifact `json:"inventories"`
}

type candidateArtifact struct {
	Path   string `json:"path"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

func runCandidateValidate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("candidate validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "workspace root")
	provenancePath := flags.String("provenance", "candidate-provenance.json", "provenance path under root")
	candidateRoot := flags.String("candidate-root", "", "selected candidate directory under root")
	assuranceRoot := flags.String("assurance-root", "verified-assurance", "verified assurance directory under root")
	comparisonPath := flags.String("comparison", "candidate-comparison.json", "comparison document under root")
	expectedRepository := flags.String("expected-repository", "", "exact repository owner/name")
	expectedCommit := flags.String("expected-commit", "", "exact candidate commit")
	expectedTree := flags.String("expected-tree", "", "exact candidate tree")
	expectedRunID := flags.String("expected-run-id", "", "exact assurance run id")
	expectedRunAttempt := flags.Int("expected-run-attempt", 0, "exact assurance run attempt")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *candidateRoot == "" || *expectedRepository == "" || *expectedCommit == "" || *expectedTree == "" || *expectedRunID == "" || *expectedRunAttempt < 1 {
		return errors.New("candidate validate requires candidate roots and exact repository, commit, tree, run id, and run attempt")
	}
	raw, err := readRootFile(*root, *provenancePath)
	if err != nil {
		return fmt.Errorf("read candidate provenance: %w", err)
	}
	var provenance candidateProvenance
	if err := assurance.DecodeStrict(bytes.NewReader(raw), &provenance); err != nil {
		return fmt.Errorf("decode candidate provenance: %w", err)
	}
	if provenance.Repository != *expectedRepository || provenance.Commit != *expectedCommit || provenance.Tree != *expectedTree || provenance.Assurance.RunID != *expectedRunID || provenance.Assurance.RunAttempt != *expectedRunAttempt {
		return errors.New("candidate provenance does not match the expected exact subject and assurance run")
	}
	if err := validateCandidateProvenance(*root, *candidateRoot, *assuranceRoot, *comparisonPath, provenance); err != nil {
		return err
	}
	certificatePath := filepath.ToSlash(filepath.Join(*assuranceRoot, provenance.Assurance.CertificatePath))
	receiptsRoot := filepath.ToSlash(filepath.Clean(*assuranceRoot))
	inventoriesRoot := filepath.ToSlash(filepath.Join(*assuranceRoot, "inventories"))
	certificateArgs := []string{
		"-root", *root,
		"-certificate", certificatePath,
		"-receipts-root", receiptsRoot,
		"-inventories-root", inventoriesRoot,
		"-expected-repository", *expectedRepository,
		"-expected-commit", *expectedCommit,
		"-expected-tree", *expectedTree,
		"-expected-run-id", *expectedRunID,
		"-expected-run-attempt", fmt.Sprint(*expectedRunAttempt),
		"-expected-trigger", provenance.Assurance.Trigger,
		"-expected-workflow-path", provenance.Assurance.WorkflowPath,
		"-expected-workflow-source-commit", *expectedCommit,
	}
	for _, proof := range []string{"android-device-api26", "android-device-api34", "android-device-api36", "android-host", "dependency-freshness", "docs-evidence", "go-audit", "go-core", "go-executable-evidence", "linux-netns", "operator"} {
		certificateArgs = append(certificateArgs, "-required", proof)
	}
	if err := runCertificateValidate(certificateArgs, io.Discard, stderr); err != nil {
		return fmt.Errorf("revalidate carried assurance certificate: %w", err)
	}
	_, err = fmt.Fprintln(stdout, "valid unsigned engineering candidate provenance")
	return err
}

func validateCandidateProvenance(root, candidateRoot, assuranceRoot, comparisonPath string, provenance candidateProvenance) error {
	if provenance.Schema != candidateProvenanceSchema || !repositoryPattern.MatchString(provenance.Repository) || !fullGitSHAPattern.MatchString(provenance.Commit) || !fullGitSHAPattern.MatchString(provenance.Tree) {
		return errors.New("candidate provenance identity is invalid")
	}
	if provenance.Authoritative || provenance.SelectedBuilder != "a" || len(provenance.Limitations) != 1 || provenance.Limitations[0] != "unsigned engineering candidate; signing, upload, promotion, and release remain unauthorized" {
		return errors.New("candidate provenance authority or limitations are invalid")
	}
	if provenance.Assurance.RunID == "" || provenance.Assurance.RunAttempt < 1 || (provenance.Assurance.Trigger != "push" && provenance.Assurance.Trigger != "workflow_dispatch") || provenance.Assurance.WorkflowPath != ".github/workflows/assurance.yml" || provenance.Assurance.CertificatePath != "assurance-certificate.json" || !fullSHA256Pattern.MatchString(provenance.Assurance.CertificateSHA256) {
		return errors.New("candidate assurance identity is invalid")
	}
	if len(provenance.Assurance.Receipts) != 16 {
		return fmt.Errorf("candidate assurance contains %d receipts, require 16", len(provenance.Assurance.Receipts))
	}
	if len(provenance.Assurance.Inventories) != 3 {
		return fmt.Errorf("candidate assurance contains %d device inventories, require 3", len(provenance.Assurance.Inventories))
	}
	if len(provenance.SelectedArtifacts) == 0 || !fullSHA256Pattern.MatchString(provenance.ComparisonSHA256) {
		return errors.New("candidate artifact or comparison inventory is invalid")
	}
	comparisonSize, comparisonDigest, err := digestRootFile(root, comparisonPath)
	if err != nil || comparisonSize < 1 || comparisonDigest != provenance.ComparisonSHA256 {
		return errors.New("candidate comparison digest mismatch")
	}
	certificatePath := filepath.ToSlash(filepath.Join(assuranceRoot, provenance.Assurance.CertificatePath))
	certificateSize, certificateDigest, err := digestRootFile(root, certificatePath)
	if err != nil || certificateSize < 1 || certificateDigest != provenance.Assurance.CertificateSHA256 {
		return errors.New("candidate assurance certificate digest mismatch")
	}
	receipts := make([]candidateArtifact, len(provenance.Assurance.Receipts))
	for index, receipt := range provenance.Assurance.Receipts {
		if !strings.HasPrefix(receipt.Path, "receipts/") {
			return fmt.Errorf("candidate assurance receipt %q is outside the portable receipt directory", receipt.Path)
		}
		receipt.Path = strings.TrimPrefix(receipt.Path, "receipts/")
		receipts[index] = receipt
	}
	if err := validateDeclaredArtifacts(root, filepath.ToSlash(filepath.Join(assuranceRoot, "receipts")), receipts, true); err != nil {
		return fmt.Errorf("candidate assurance receipts: %w", err)
	}
	if err := validateDeclaredArtifacts(root, filepath.ToSlash(filepath.Join(assuranceRoot, "inventories")), provenance.Assurance.Inventories, true); err != nil {
		return fmt.Errorf("candidate assurance inventories: %w", err)
	}
	if err := validateDeclaredArtifacts(root, candidateRoot, provenance.SelectedArtifacts, true); err != nil {
		return fmt.Errorf("selected candidate artifacts: %w", err)
	}
	return nil
}

func validateDeclaredArtifacts(root, directory string, declared []candidateArtifact, requireExactInventory bool) error {
	seen := map[string]bool{}
	for _, artifact := range declared {
		if !safeRelativePath(artifact.Path) || artifact.Size < 1 || !fullSHA256Pattern.MatchString(artifact.SHA256) || seen[artifact.Path] {
			return fmt.Errorf("invalid or duplicate artifact %q", artifact.Path)
		}
		seen[artifact.Path] = true
		path := filepath.ToSlash(filepath.Join(directory, filepath.FromSlash(artifact.Path)))
		size, digest, err := digestRootFile(root, path)
		if err != nil || size != artifact.Size || digest != artifact.SHA256 {
			return fmt.Errorf("artifact %q identity mismatch", artifact.Path)
		}
	}
	if !requireExactInventory {
		return nil
	}
	resolved, err := resolveRootDirectory(root, directory)
	if err != nil {
		return err
	}
	actual := []string{}
	err = filepath.WalkDir(resolved, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("candidate inventory contains a symbolic link")
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil || !info.Mode().IsRegular() {
			return errors.New("candidate inventory contains a non-regular file")
		}
		relative, err := filepath.Rel(resolved, path)
		if err != nil {
			return err
		}
		actual = append(actual, filepath.ToSlash(relative))
		return nil
	})
	if err != nil {
		return err
	}
	sort.Strings(actual)
	if len(actual) != len(seen) {
		return errors.New("candidate artifact inventory is incomplete")
	}
	for _, path := range actual {
		if !seen[path] {
			return fmt.Errorf("undeclared candidate artifact %q", path)
		}
	}
	return nil
}

func digestRootFile(root, relative string) (int64, string, error) {
	resolvedRoot, err := resolveRootDirectory(root, ".")
	if err != nil {
		return 0, "", err
	}
	if !safeRelativePath(relative) {
		return 0, "", errors.New("unsafe artifact path")
	}
	path := filepath.Join(resolvedRoot, filepath.FromSlash(relative))
	pathInfo, err := os.Lstat(path)
	if err != nil || !pathInfo.Mode().IsRegular() || pathInfo.Mode()&os.ModeSymlink != 0 {
		return 0, "", errors.New("artifact is not a regular non-symlink file")
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || !withinDirectory(resolvedRoot, resolved) {
		return 0, "", errors.New("artifact escapes root")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return 0, "", err
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(pathInfo, openedInfo) {
		return 0, "", errors.New("artifact changed while being opened")
	}
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return 0, "", err
	}
	return openedInfo.Size(), hex.EncodeToString(hash.Sum(nil)), nil
}
