// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestValidateCertificateAcceptsExactReceiptSet(t *testing.T) {
	certificate, documents, policy := validCertificateFixture(t)
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{"go-core"}, time.Date(2026, 8, 2, 10, 3, 0, 0, time.UTC)); err != nil {
		t.Fatalf("ValidateCertificate: %v", err)
	}
}

func TestDecodeCertificateRejectsUnknownDuplicateAndTruncatedJSON(t *testing.T) {
	certificate, _, _ := validCertificateFixture(t)
	raw, err := json.Marshal(certificate)
	if err != nil {
		t.Fatal(err)
	}
	unknown := strings.Replace(string(raw), `"certificateId":`, `"unknown":true,"certificateId":`, 1)
	if _, err := DecodeCertificate(strings.NewReader(unknown)); err == nil {
		t.Fatal("expected unknown certificate field rejection")
	}
	duplicate := strings.Replace(string(raw), `"repository":"saroo98/kurdistan-protocol-compiler"`, `"repository":"saroo98/kurdistan-protocol-compiler","repository":"saroo98/kurdistan-protocol-compiler"`, 1)
	if _, err := DecodeCertificate(strings.NewReader(duplicate)); err == nil {
		t.Fatal("expected duplicate nested certificate key rejection")
	}
	if _, err := DecodeCertificate(strings.NewReader(string(raw[:len(raw)-1]))); err == nil {
		t.Fatal("expected truncated certificate rejection")
	}
}

func TestValidateCertificateRejectsReplayedReceipt(t *testing.T) {
	certificate, documents, policy := validCertificateFixture(t)
	certificate.Receipts = append(certificate.Receipts, certificate.Receipts[0])
	documents = append(documents, documents[0])
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{"go-core"}, time.Date(2026, 8, 2, 10, 3, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected replayed receipt rejection")
	}
}

func TestValidateCertificateRejectsReceiptFromAnotherWorkflowRun(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(validReceiptJSON))
	if err != nil {
		t.Fatal(err)
	}
	windowsReceipt := receipt
	windowsReceipt.ReceiptID = "run-124-go-core-windows"
	windowsReceipt.Runner.OperatingSystem = "windows"
	windowsReceipt.Execution.RunID = "124"
	windowsRaw, err := json.Marshal(windowsReceipt)
	if err != nil {
		t.Fatal(err)
	}
	linuxRaw := []byte(validReceiptJSON)
	policy := testProofPolicy()
	policy.Proofs[0].OperatingSystems = []string{"linux", "windows"}
	certificate := Certificate{
		Schema: CertificateSchema, CertificateID: "mixed-run-assurance", Subject: receipt.Subject,
		PolicySHA256: receipt.Proof.PolicySHA256, RequiredProofs: []string{"go-core"},
		Receipts: []ReceiptReference{
			{ProofID: "go-core", OperatingSystem: "linux", ReceiptID: receipt.ReceiptID, Path: "receipts/linux.json", SHA256: fmt.Sprintf("%x", sha256.Sum256(linuxRaw))},
			{ProofID: "go-core", OperatingSystem: "windows", ReceiptID: windowsReceipt.ReceiptID, Path: "receipts/windows.json", SHA256: fmt.Sprintf("%x", sha256.Sum256(windowsRaw))},
		},
		IssuedAt: "2026-08-02T10:02:00Z", Status: "PASS",
	}
	documents := []ReceiptDocument{{Path: "receipts/linux.json", Raw: linuxRaw}, {Path: "receipts/windows.json", Raw: windowsRaw}}
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{"go-core"}, time.Date(2026, 8, 2, 10, 3, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected cross-run receipt replay rejection")
	}
}

func TestValidateCertificateRejectsReceiptSubjectMismatch(t *testing.T) {
	certificate, documents, policy := validCertificateFixture(t)
	certificate.Subject.Commit = strings.Repeat("2", 40)
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{"go-core"}, time.Date(2026, 8, 2, 10, 3, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected receipt subject mismatch rejection")
	}
}

func TestValidateCertificateRejectsExpiredReceipt(t *testing.T) {
	certificate, _, policy := validCertificateFixture(t)
	receipt, err := DecodeReceipt(strings.NewReader(validReceiptJSON))
	if err != nil {
		t.Fatal(err)
	}
	receipt.Proof.ID = "dependency-freshness"
	receipt.ReceiptID = "run-123-dependency-linux"
	receipt.ExpiresAt = "2026-08-02T10:02:00Z"
	policy.Proofs[0].ID = receipt.Proof.ID
	policy.Proofs[0].Deterministic = false
	policy.Proofs[0].FreshnessSeconds = 60
	raw, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	certificate.RequiredProofs = []string{receipt.Proof.ID}
	certificate.Receipts[0].ProofID = receipt.Proof.ID
	certificate.Receipts[0].ReceiptID = receipt.ReceiptID
	certificate.Receipts[0].SHA256 = fmt.Sprintf("%x", sha256.Sum256(raw))
	certificate.IssuedAt = "2026-08-02T10:01:30Z"
	certificate.ExpiresAt = receipt.ExpiresAt
	documents := []ReceiptDocument{{Path: certificate.Receipts[0].Path, Raw: raw}}
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{receipt.Proof.ID}, time.Date(2026, 8, 2, 10, 1, 45, 0, time.UTC)); err != nil {
		t.Fatalf("fresh certificate rejected before expiry: %v", err)
	}
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{receipt.Proof.ID}, time.Date(2026, 8, 2, 10, 2, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected expired receipt rejection")
	}
}

func TestValidateCertificateRejectsReceiptDigestMismatch(t *testing.T) {
	certificate, documents, policy := validCertificateFixture(t)
	certificate.Receipts[0].SHA256 = strings.Repeat("f", 64)
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{"go-core"}, time.Date(2026, 8, 2, 10, 3, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected receipt digest mismatch rejection")
	}
}

func TestValidateCertificateRejectsReceiptReferenceTraversal(t *testing.T) {
	certificate, documents, policy := validCertificateFixture(t)
	certificate.Receipts[0].Path = "../go-core-linux.json"
	documents[0].Path = certificate.Receipts[0].Path
	if err := ValidateCertificate(certificate, documents, policy, certificate.PolicySHA256, []string{"go-core"}, time.Date(2026, 8, 2, 10, 3, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected certificate receipt path traversal rejection")
	}
}

func validCertificateFixture(t *testing.T) (Certificate, []ReceiptDocument, ProofPolicy) {
	t.Helper()
	receipt, err := DecodeReceipt(strings.NewReader(validReceiptJSON))
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256([]byte(validReceiptJSON)))
	certificate := Certificate{
		Schema:         CertificateSchema,
		CertificateID:  "main-8fe2d590-assurance",
		Subject:        receipt.Subject,
		PolicySHA256:   receipt.Proof.PolicySHA256,
		RequiredProofs: []string{"go-core"},
		Receipts: []ReceiptReference{{
			ProofID:         receipt.Proof.ID,
			OperatingSystem: receipt.Runner.OperatingSystem,
			ReceiptID:       receipt.ReceiptID,
			Path:            "receipts/go-core-linux.json",
			SHA256:          digest,
		}},
		IssuedAt: "2026-08-02T10:02:00Z",
		Status:   "PASS",
	}
	documents := []ReceiptDocument{{Path: "receipts/go-core-linux.json", Raw: []byte(validReceiptJSON)}}
	return certificate, documents, testProofPolicy()
}
