// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"sort"
	"time"
)

const CertificateSchema = "kurdistan-assurance-certificate-v1"

type Certificate struct {
	Schema         string             `json:"schema"`
	CertificateID  string             `json:"certificateId"`
	Subject        Subject            `json:"subject"`
	PolicySHA256   string             `json:"policySha256"`
	RequiredProofs []string           `json:"requiredProofs"`
	Receipts       []ReceiptReference `json:"receipts"`
	IssuedAt       string             `json:"issuedAt"`
	ExpiresAt      string             `json:"expiresAt,omitempty"`
	Status         string             `json:"status"`
}

type ReceiptReference struct {
	ProofID         string `json:"proofId"`
	OperatingSystem string `json:"operatingSystem"`
	ReceiptID       string `json:"receiptId"`
	Path            string `json:"path"`
	SHA256          string `json:"sha256"`
}

type ReceiptDocument struct {
	Path string
	Raw  []byte
}

func DecodeCertificate(reader io.Reader) (Certificate, error) {
	var value Certificate
	if err := decodeStrict(reader, &value); err != nil {
		return Certificate{}, fmt.Errorf("decode assurance certificate: %w", err)
	}
	if err := value.Validate(); err != nil {
		return Certificate{}, err
	}
	return value, nil
}

func (value Certificate) Validate() error {
	if value.Schema != CertificateSchema || !receiptIDPattern.MatchString(value.CertificateID) {
		return errors.New("invalid assurance certificate identity")
	}
	if !repositoryPattern.MatchString(value.Subject.Repository) || !gitObjectPattern.MatchString(value.Subject.Commit) || !gitObjectPattern.MatchString(value.Subject.Tree) || !validRef(value.Subject.Ref) {
		return errors.New("invalid assurance certificate subject")
	}
	if !sha256Pattern.MatchString(value.PolicySHA256) {
		return errors.New("invalid assurance certificate policy digest")
	}
	if err := validateSortedIdentifiers("required proof", value.RequiredProofs); err != nil {
		return err
	}
	if len(value.Receipts) == 0 || len(value.Receipts) > 256 {
		return errors.New("assurance certificate receipt set has invalid cardinality")
	}
	paths := map[string]bool{}
	ids := map[string]bool{}
	digests := map[string]bool{}
	lanes := map[string]bool{}
	for _, reference := range value.Receipts {
		lane := reference.ProofID + "\x00" + reference.OperatingSystem
		if !identifierPattern.MatchString(reference.ProofID) || reference.OperatingSystem == "" || !receiptIDPattern.MatchString(reference.ReceiptID) || !validRelativePath(reference.Path) || !sha256Pattern.MatchString(reference.SHA256) || paths[reference.Path] || ids[reference.ReceiptID] || digests[reference.SHA256] || lanes[lane] {
			return fmt.Errorf("invalid, duplicate, or replayed assurance receipt reference %q", reference.Path)
		}
		paths[reference.Path] = true
		ids[reference.ReceiptID] = true
		digests[reference.SHA256] = true
		lanes[lane] = true
	}
	issued, err := parseCanonicalUTC("issuedAt", value.IssuedAt)
	if err != nil {
		return err
	}
	if value.Status != "PASS" {
		return errors.New("assurance certificate must have terminal PASS status")
	}
	if value.ExpiresAt != "" {
		expires, err := parseCanonicalUTC("expiresAt", value.ExpiresAt)
		if err != nil {
			return err
		}
		if !expires.After(issued) {
			return errors.New("assurance certificate expiry must follow issuance")
		}
	}
	return nil
}

func ValidateCertificate(value Certificate, documents []ReceiptDocument, policy ProofPolicy, policySHA256 string, requiredProofs []string, now time.Time) error {
	if err := value.Validate(); err != nil {
		return err
	}
	if err := policy.Validate(); err != nil {
		return fmt.Errorf("invalid proof policy: %w", err)
	}
	if !sha256Pattern.MatchString(policySHA256) || value.PolicySHA256 != policySHA256 {
		return errors.New("assurance certificate proof policy digest mismatch")
	}
	wanted := append([]string(nil), requiredProofs...)
	sort.Strings(wanted)
	if err := validateSortedIdentifiers("required proof", wanted); err != nil {
		return err
	}
	if !stringSlicesEqual(value.RequiredProofs, wanted) {
		return errors.New("assurance certificate required proof inventory mismatch")
	}
	proofs := make(map[string]Proof, len(policy.Proofs))
	for _, proof := range policy.Proofs {
		proofs[proof.ID] = proof
	}
	expectedLanes := map[string]bool{}
	for _, proofID := range wanted {
		proof, ok := proofs[proofID]
		if !ok {
			return fmt.Errorf("required proof %q is not present in policy", proofID)
		}
		for _, operatingSystem := range proof.OperatingSystems {
			expectedLanes[proofID+"\x00"+operatingSystem] = true
		}
	}
	if len(value.Receipts) != len(expectedLanes) || len(documents) != len(value.Receipts) {
		return errors.New("assurance certificate receipt inventory cardinality mismatch")
	}
	documentByPath := map[string][]byte{}
	for _, document := range documents {
		if !validRelativePath(document.Path) || documentByPath[document.Path] != nil || len(document.Raw) == 0 || len(document.Raw) > maxJSONDocumentBytes {
			return fmt.Errorf("invalid or duplicate receipt document path %q", document.Path)
		}
		documentByPath[document.Path] = document.Raw
	}
	issued, _ := parseCanonicalUTC("issuedAt", value.IssuedAt)
	if now.IsZero() || issued.After(now) {
		return errors.New("assurance certificate issuance is in the future")
	}
	seenLanes := map[string]bool{}
	var earliestExpiry time.Time
	var executionRunID string
	var executionAttempt int
	var executionTrigger string
	var workflow WorkflowIdentity
	for _, reference := range value.Receipts {
		lane := reference.ProofID + "\x00" + reference.OperatingSystem
		if !expectedLanes[lane] || seenLanes[lane] {
			return fmt.Errorf("unexpected or replayed assurance receipt lane %q", lane)
		}
		seenLanes[lane] = true
		raw, ok := documentByPath[reference.Path]
		if !ok {
			return fmt.Errorf("missing assurance receipt document %q", reference.Path)
		}
		digest := fmt.Sprintf("%x", sha256.Sum256(raw))
		if digest != reference.SHA256 {
			return fmt.Errorf("assurance receipt digest mismatch for %q", reference.Path)
		}
		receipt, err := DecodeReceipt(bytes.NewReader(raw))
		if err != nil {
			return fmt.Errorf("receipt %q: %w", reference.Path, err)
		}
		if receipt.ReceiptID != reference.ReceiptID || receipt.Proof.ID != reference.ProofID || receipt.Runner.OperatingSystem != reference.OperatingSystem || receipt.Subject != value.Subject || receipt.Proof.PolicySHA256 != value.PolicySHA256 {
			return fmt.Errorf("assurance receipt identity or subject mismatch for %q", reference.Path)
		}
		if executionRunID == "" {
			executionRunID = receipt.Execution.RunID
			executionAttempt = receipt.Execution.Attempt
			executionTrigger = receipt.Execution.Trigger
			workflow = receipt.Workflow
		} else if receipt.Execution.RunID != executionRunID || receipt.Execution.Attempt != executionAttempt || receipt.Execution.Trigger != executionTrigger || receipt.Workflow != workflow {
			return fmt.Errorf("assurance receipt %q was replayed from another workflow execution", reference.Path)
		}
		if err := ValidateReceipt(receipt, policy, policySHA256, now); err != nil {
			return fmt.Errorf("receipt %q: %w", reference.Path, err)
		}
		if receipt.Result != "PASS" {
			return fmt.Errorf("receipt %q did not pass", reference.Path)
		}
		completed, _ := parseCanonicalUTC("completedAt", receipt.Timing.CompletedAt)
		if completed.After(issued) {
			return fmt.Errorf("receipt %q completed after certificate issuance", reference.Path)
		}
		if receipt.ExpiresAt != "" {
			expires, _ := parseCanonicalUTC("expiresAt", receipt.ExpiresAt)
			if earliestExpiry.IsZero() || expires.Before(earliestExpiry) {
				earliestExpiry = expires
			}
		}
	}
	if len(seenLanes) != len(expectedLanes) {
		return errors.New("assurance certificate is missing a required receipt lane")
	}
	if earliestExpiry.IsZero() {
		if value.ExpiresAt != "" {
			return errors.New("deterministic assurance certificate must not expire by wall clock")
		}
		return nil
	}
	certificateExpiry, err := parseCanonicalUTC("expiresAt", value.ExpiresAt)
	if err != nil || !certificateExpiry.Equal(earliestExpiry) || !now.Before(certificateExpiry) {
		return errors.New("assurance certificate expiry does not match its earliest receipt expiry")
	}
	return nil
}

func validateSortedIdentifiers(name string, values []string) error {
	if len(values) == 0 || len(values) > 64 {
		return fmt.Errorf("%s set has invalid cardinality", name)
	}
	last := ""
	for _, value := range values {
		if !identifierPattern.MatchString(value) || value <= last {
			return fmt.Errorf("%s set is not strictly sorted and unique", name)
		}
		last = value
	}
	return nil
}

func stringSlicesEqual(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
