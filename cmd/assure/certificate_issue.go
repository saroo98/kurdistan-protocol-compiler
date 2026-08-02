// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"io"
	"sort"
	"time"

	"kurdistan/internal/assurance"
)

func runCertificateIssue(args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("certificate issue", flag.ContinueOnError)
	flags.SetOutput(stderr)
	root := flags.String("root", ".", "repository root")
	policyPath := flags.String("policy", "config/ci/proof-policy.json", "proof policy path under root")
	outPath := flags.String("out", "", "certificate output path under root")
	certificateID := flags.String("certificate-id", "", "bounded certificate identity")
	var required stringList
	var receiptPaths stringList
	flags.Var(&required, "required", "required proof id; repeatable")
	flags.Var(&receiptPaths, "receipt", "receipt path under root; repeatable")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || *outPath == "" || *certificateID == "" || len(required) == 0 || len(receiptPaths) == 0 {
		return errors.New("certificate issue requires -out, -certificate-id, -required, and -receipt")
	}
	policy, policyRaw, err := readProofPolicy(*root, *policyPath)
	if err != nil {
		return err
	}
	policyDigest := digestBytes(policyRaw)
	requiredProofs := sortedUnique(required)
	if len(requiredProofs) != len(required) {
		return errors.New("duplicate required proof")
	}
	sortedPaths := sortedUnique(receiptPaths)
	if len(sortedPaths) != len(receiptPaths) {
		return errors.New("duplicate receipt path")
	}
	documents := make([]assurance.ReceiptDocument, 0, len(sortedPaths))
	references := make([]assurance.ReceiptReference, 0, len(sortedPaths))
	var subject assurance.Subject
	var issuedAt time.Time
	var expiresAt time.Time
	for _, path := range sortedPaths {
		raw, readErr := readRootFile(*root, path)
		if readErr != nil {
			return fmt.Errorf("read receipt %q: %w", path, readErr)
		}
		receipt, decodeErr := assurance.DecodeReceipt(bytes.NewReader(raw))
		if decodeErr != nil {
			return fmt.Errorf("receipt %q: %w", path, decodeErr)
		}
		if receipt.Result != "PASS" {
			return fmt.Errorf("receipt %q did not pass", path)
		}
		if len(documents) == 0 {
			subject = receipt.Subject
		} else if receipt.Subject != subject {
			return errors.New("receipt subjects do not match")
		}
		completed, _ := time.Parse(time.RFC3339Nano, receipt.Timing.CompletedAt)
		if completed.After(issuedAt) {
			issuedAt = completed
		}
		if receipt.ExpiresAt != "" {
			expires, _ := time.Parse(time.RFC3339Nano, receipt.ExpiresAt)
			if expiresAt.IsZero() || expires.Before(expiresAt) {
				expiresAt = expires
			}
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(raw))
		references = append(references, assurance.ReceiptReference{
			ProofID: receipt.Proof.ID, OperatingSystem: receipt.Runner.OperatingSystem,
			ReceiptID: receipt.ReceiptID, Path: path, SHA256: digest,
		})
		documents = append(documents, assurance.ReceiptDocument{Path: path, Raw: raw})
	}
	sort.Slice(references, func(i, j int) bool {
		if references[i].ProofID != references[j].ProofID {
			return references[i].ProofID < references[j].ProofID
		}
		return references[i].OperatingSystem < references[j].OperatingSystem
	})
	certificate := assurance.Certificate{
		Schema: assurance.CertificateSchema, CertificateID: *certificateID, Subject: subject,
		PolicySHA256: policyDigest, RequiredProofs: requiredProofs, Receipts: references,
		IssuedAt: issuedAt.UTC().Format(time.RFC3339Nano), Status: "PASS",
	}
	if !expiresAt.IsZero() {
		certificate.ExpiresAt = expiresAt.UTC().Format(time.RFC3339Nano)
	}
	if err := assurance.ValidateCertificate(certificate, documents, policy, policyDigest, requiredProofs, issuedAt); err != nil {
		return fmt.Errorf("issued certificate is invalid: %w", err)
	}
	if err := writeJSONAtomicUnderRoot(*root, *outPath, certificate); err != nil {
		return err
	}
	_, err = fmt.Fprintf(stdout, "issued assurance certificate %s\n", certificate.CertificateID)
	return err
}
