// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command assure validates fail-closed assurance policy and evidence documents.
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"kurdistan/internal/assurance"
)

const maxInputBytes = 4 << 20

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		fmt.Fprintln(os.Stderr, "assure:", err)
		os.Exit(1)
	}
}

func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("expected receipt, certificate, policy, inventory, impact, timings, workflow, or candidate subcommand")
	}
	switch args[0] {
	case "receipt":
		if len(args) < 2 {
			return errors.New("expected receipt issue or receipt validate")
		}
		switch args[1] {
		case "issue":
			return runReceiptIssue(args[2:], stdout, stderr)
		case "validate":
			return runReceiptValidate(args[2:], stdout, stderr)
		default:
			return errors.New("expected receipt issue or receipt validate")
		}
	case "certificate":
		if len(args) < 2 {
			return errors.New("expected certificate issue or certificate validate")
		}
		switch args[1] {
		case "issue":
			return runCertificateIssue(args[2:], stdout, stderr)
		case "validate":
			return runCertificateValidate(args[2:], stdout, stderr)
		default:
			return errors.New("expected certificate issue or certificate validate")
		}
	case "policy":
		if len(args) < 2 || args[1] != "inventory" {
			return errors.New("expected policy inventory")
		}
		return runPolicyInventory(args[2:], stdout, stderr)
	case "inventory":
		return runPolicyInventory(args[1:], stdout, stderr)
	case "impact":
		return runImpact(args[1:], stdout, stderr)
	case "timings":
		return runTimings(args[1:], stdout, stderr)
	case "workflow":
		return runWorkflow(args[1:], stdout, stderr)
	case "candidate":
		if len(args) < 2 || args[1] != "validate" {
			return errors.New("expected candidate validate")
		}
		return runCandidateValidate(args[2:], stdout, stderr)
	default:
		return fmt.Errorf("unknown subcommand %q", args[0])
	}
}

func runWorkflow(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("workflow", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("workflow does not accept positional arguments")
	}
	absoluteRoot, err := filepath.Abs(*root)
	if err != nil {
		return err
	}
	command := exec.Command("go", "-C", filepath.Join(absoluteRoot, "tools"), "run", "./cmd/workflowverify", "-root", absoluteRoot)
	command.Stdout = stdout
	command.Stderr = stderr
	if err := command.Run(); err != nil {
		return fmt.Errorf("workflow verifier: %w", err)
	}
	return nil
}

func runReceiptValidate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("receipt validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "config/ci/proof-policy.json", "proof policy path under root")
	receiptPath := flags.String("receipt", "", "receipt path under root")
	nowText := flags.String("now", "", "validation time in canonical UTC RFC3339")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *receiptPath == "" {
		return errors.New("receipt validate requires exactly one -receipt path")
	}
	policy, policyRaw, err := readProofPolicy(*root, *policyPath)
	if err != nil {
		return err
	}
	receiptRaw, err := readRootFile(*root, *receiptPath)
	if err != nil {
		return fmt.Errorf("read receipt: %w", err)
	}
	receipt, err := assurance.DecodeReceipt(bytes.NewReader(receiptRaw))
	if err != nil {
		return err
	}
	if err := validateReceiptWorkflow(*root, receipt); err != nil {
		return err
	}
	now, err := validationTime(*nowText)
	if err != nil {
		return err
	}
	policyDigest := fmt.Sprintf("%x", sha256.Sum256(policyRaw))
	if err := assurance.ValidateReceipt(receipt, policy, policyDigest, now); err != nil {
		return err
	}
	if receipt.Result != "PASS" {
		return fmt.Errorf("receipt %q has terminal result %s", receipt.ReceiptID, receipt.Result)
	}
	_, err = fmt.Fprintf(stdout, "valid receipt %s\n", receipt.ReceiptID)
	return err
}

func runCertificateValidate(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("certificate validate", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "config/ci/proof-policy.json", "proof policy path under root")
	certificatePath := flags.String("certificate", "", "certificate path under root")
	receiptsRoot := flags.String("receipts-root", ".", "receipt directory under root")
	inventoriesRoot := flags.String("inventories-root", "", "optional certified device inventory directory under root")
	nowText := flags.String("now", "", "validation time in canonical UTC RFC3339")
	expectedRepository := flags.String("expected-repository", "", "optional exact repository owner/name")
	expectedCommit := flags.String("expected-commit", "", "optional exact subject commit")
	expectedTree := flags.String("expected-tree", "", "optional exact subject tree")
	expectedRunID := flags.String("expected-run-id", "", "optional exact workflow run id")
	expectedRunAttempt := flags.Int("expected-run-attempt", 0, "optional exact workflow run attempt")
	expectedTrigger := flags.String("expected-trigger", "", "optional exact workflow trigger")
	expectedWorkflowPath := flags.String("expected-workflow-path", "", "optional exact executed workflow path")
	expectedWorkflowSource := flags.String("expected-workflow-source-commit", "", "optional exact executed workflow source commit")
	var required stringList
	flags.Var(&required, "required", "required proof id; repeat for multiple proofs")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *certificatePath == "" || len(required) == 0 {
		return errors.New("certificate validate requires -certificate and at least one -required proof")
	}
	policy, policyRaw, err := readProofPolicy(*root, *policyPath)
	if err != nil {
		return err
	}
	certificateRaw, err := readRootFile(*root, *certificatePath)
	if err != nil {
		return fmt.Errorf("read certificate: %w", err)
	}
	certificate, err := assurance.DecodeCertificate(bytes.NewReader(certificateRaw))
	if err != nil {
		return err
	}
	if *expectedRepository != "" && certificate.Subject.Repository != *expectedRepository {
		return errors.New("certificate repository does not match expected subject")
	}
	if *expectedCommit != "" && certificate.Subject.Commit != *expectedCommit {
		return errors.New("certificate commit does not match expected subject")
	}
	if *expectedTree != "" && certificate.Subject.Tree != *expectedTree {
		return errors.New("certificate tree does not match expected subject")
	}
	receiptDirectory, err := resolveRootDirectory(*root, *receiptsRoot)
	if err != nil {
		return fmt.Errorf("resolve receipt directory: %w", err)
	}
	documents := make([]assurance.ReceiptDocument, 0, len(certificate.Receipts))
	for _, reference := range certificate.Receipts {
		raw, err := readRootFile(receiptDirectory, reference.Path)
		if err != nil {
			return fmt.Errorf("read receipt %q: %w", reference.Path, err)
		}
		receipt, decodeErr := assurance.DecodeReceipt(bytes.NewReader(raw))
		if decodeErr != nil {
			return fmt.Errorf("decode receipt %q: %w", reference.Path, decodeErr)
		}
		if err := validateReceiptWorkflow(*root, receipt); err != nil {
			return fmt.Errorf("receipt %q: %w", reference.Path, err)
		}
		if *expectedRunID != "" && receipt.Execution.RunID != *expectedRunID || *expectedRunAttempt != 0 && receipt.Execution.Attempt != *expectedRunAttempt || *expectedTrigger != "" && receipt.Execution.Trigger != *expectedTrigger {
			return fmt.Errorf("receipt %q does not match the expected workflow execution", reference.Path)
		}
		if *expectedWorkflowPath != "" && receipt.Workflow.Path != *expectedWorkflowPath || *expectedWorkflowSource != "" && receipt.Workflow.SourceCommit != *expectedWorkflowSource {
			return fmt.Errorf("receipt %q does not match the expected workflow source", reference.Path)
		}
		documents = append(documents, assurance.ReceiptDocument{Path: reference.Path, Raw: raw})
	}
	now, err := validationTime(*nowText)
	if err != nil {
		return err
	}
	policyDigest := fmt.Sprintf("%x", sha256.Sum256(policyRaw))
	if err := assurance.ValidateCertificate(certificate, documents, policy, policyDigest, []string(required), now); err != nil {
		return err
	}
	if *inventoriesRoot != "" {
		if err := validateCertificateDeviceInventories(*root, *receiptsRoot, *inventoriesRoot, certificate); err != nil {
			return fmt.Errorf("validate certified device inventories: %w", err)
		}
	}
	_, err = fmt.Fprintf(stdout, "valid certificate %s\n", certificate.CertificateID)
	return err
}

func validateReceiptWorkflow(root string, receipt assurance.Receipt) error {
	raw, err := readGitBlob(root, receipt.Workflow.SourceCommit, receipt.Workflow.Path)
	if err != nil {
		return fmt.Errorf("read receipt workflow source: %w", err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(raw))
	if digest != receipt.Workflow.SHA256 {
		return errors.New("receipt workflow digest does not match its recorded source commit")
	}
	return nil
}

func runPolicyInventory(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("policy inventory", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "config/ci/proof-policy.json", "proof policy path under root")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("policy inventory does not accept positional arguments")
	}
	policy, raw, err := readProofPolicy(*root, *policyPath)
	if err != nil {
		return err
	}
	inventory, err := assurance.BuildPolicyInventory(policy, fmt.Sprintf("%x", sha256.Sum256(raw)))
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(inventory)
}

type impactSelection struct {
	Schema string   `json:"schema"`
	Paths  []string `json:"paths"`
	Proofs []string `json:"proofs"`
}

func runImpact(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("impact", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "config/ci/impact-policy.json", "impact policy path under root")
	proofPolicyPath := flags.String("proof-policy", "config/ci/proof-policy.json", "proof policy path under root")
	pathsFile := flags.String("paths-file", "", "newline-delimited changed paths under root")
	var explicit stringList
	flags.Var(&explicit, "path", "changed repository path; repeat for multiple paths")
	if err := flags.Parse(args); err != nil {
		return err
	}
	paths := append([]string{}, explicit...)
	paths = append(paths, flags.Args()...)
	if *pathsFile != "" {
		raw, err := readRootFile(*root, *pathsFile)
		if err != nil {
			return fmt.Errorf("read changed paths file: %w", err)
		}
		for _, line := range strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n") {
			if line != "" {
				paths = append(paths, line)
			}
		}
	}
	paths = sortedUnique(paths)
	policyRaw, err := readRootFile(*root, *policyPath)
	if err != nil {
		return fmt.Errorf("read impact policy: %w", err)
	}
	policy, err := assurance.DecodeImpactPolicy(bytes.NewReader(policyRaw))
	if err != nil {
		return err
	}
	proofPolicy, _, err := readProofPolicy(*root, *proofPolicyPath)
	if err != nil {
		return err
	}
	if err := assurance.ValidateImpactProofReferences(policy, proofPolicy); err != nil {
		return err
	}
	proofs, err := policy.ProofsForPaths(paths)
	if err != nil {
		return err
	}
	selection := impactSelection{Schema: "kurdistan-impact-selection-v1", Paths: paths, Proofs: proofs}
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	return encoder.Encode(selection)
}

type stringList []string

func (values *stringList) String() string { return strings.Join(*values, ",") }

func (values *stringList) Set(value string) error {
	if value == "" {
		return errors.New("value must not be empty")
	}
	*values = append(*values, value)
	return nil
}

func readProofPolicy(root, path string) (assurance.ProofPolicy, []byte, error) {
	raw, err := readRootFile(root, path)
	if err != nil {
		return assurance.ProofPolicy{}, nil, fmt.Errorf("read proof policy: %w", err)
	}
	policy, err := assurance.DecodeProofPolicy(bytes.NewReader(raw))
	if err != nil {
		return assurance.ProofPolicy{}, nil, err
	}
	return policy, raw, nil
}

func readRootFile(root, relative string) ([]byte, error) {
	resolvedRoot, err := resolveRootDirectory(root, ".")
	if err != nil {
		return nil, err
	}
	if !safeRelativePath(relative) {
		return nil, fmt.Errorf("unsafe relative path %q", relative)
	}
	candidate := filepath.Join(resolvedRoot, filepath.FromSlash(relative))
	info, err := os.Lstat(candidate)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("path %q is not a regular non-symlink file", relative)
	}
	resolvedCandidate, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return nil, err
	}
	if !withinDirectory(resolvedRoot, resolvedCandidate) {
		return nil, fmt.Errorf("path %q escapes root", relative)
	}
	file, err := os.Open(resolvedCandidate)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	raw, err := io.ReadAll(io.LimitReader(file, maxInputBytes+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxInputBytes {
		return nil, fmt.Errorf("file %q exceeds %d bytes", relative, maxInputBytes)
	}
	return raw, nil
}

func resolveRootDirectory(root, relative string) (string, error) {
	absoluteRoot, err := filepath.Abs(root)
	if err != nil {
		return "", err
	}
	resolvedRoot, err := filepath.EvalSymlinks(absoluteRoot)
	if err != nil {
		return "", err
	}
	info, err := os.Stat(resolvedRoot)
	if err != nil || !info.IsDir() {
		return "", fmt.Errorf("root is not a directory")
	}
	if relative == "." {
		return resolvedRoot, nil
	}
	if !safeRelativePath(relative) {
		return "", fmt.Errorf("unsafe relative directory %q", relative)
	}
	candidate, err := filepath.EvalSymlinks(filepath.Join(resolvedRoot, filepath.FromSlash(relative)))
	if err != nil {
		return "", err
	}
	info, err = os.Stat(candidate)
	if err != nil || !info.IsDir() || !withinDirectory(resolvedRoot, candidate) {
		return "", fmt.Errorf("directory %q is outside root or is not a directory", relative)
	}
	return candidate, nil
}

func safeRelativePath(value string) bool {
	if value == "" || len(value) > 512 || strings.Contains(value, "\\") || strings.ContainsRune(value, '\x00') || filepath.IsAbs(value) || filepath.VolumeName(value) != "" {
		return false
	}
	clean := filepath.ToSlash(filepath.Clean(filepath.FromSlash(value)))
	return clean == value && clean != "." && !strings.HasPrefix(clean, "../")
}

func withinDirectory(root, candidate string) bool {
	relative, err := filepath.Rel(root, candidate)
	return err == nil && relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator)) && !filepath.IsAbs(relative)
}

func validationTime(value string) (time.Time, error) {
	if value == "" {
		return time.Now().UTC(), nil
	}
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || !strings.HasSuffix(value, "Z") || parsed.Format(time.RFC3339Nano) != value {
		return time.Time{}, errors.New("-now must be canonical UTC RFC3339")
	}
	return parsed, nil
}

func sortedUnique(values []string) []string {
	result := append([]string{}, values...)
	sort.Strings(result)
	write := 0
	for _, value := range result {
		if write == 0 || result[write-1] != value {
			result[write] = value
			write++
		}
	}
	return result[:write]
}
