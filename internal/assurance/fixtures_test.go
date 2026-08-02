// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCheckedInAssuranceFixturesValidateExactly(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "assurance", "valid")
	policyRaw := readFixture(t, filepath.Join(root, "proof-policy.json"))
	policy, err := DecodeProofPolicy(bytes.NewReader(policyRaw))
	if err != nil {
		t.Fatal(err)
	}
	policyDigest := fmt.Sprintf("%x", sha256.Sum256(policyRaw))
	receiptRaw := readFixture(t, filepath.Join(root, "receipt-go-core-linux.json"))
	receipt, err := DecodeReceipt(bytes.NewReader(receiptRaw))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceipt(receipt, policy, policyDigest, time.Date(2026, 8, 2, 10, 2, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	certificateRaw := readFixture(t, filepath.Join(root, "certificate.json"))
	certificate, err := DecodeCertificate(bytes.NewReader(certificateRaw))
	if err != nil {
		t.Fatal(err)
	}
	documents := []ReceiptDocument{{Path: "receipt-go-core-linux.json", Raw: receiptRaw}}
	if err := ValidateCertificate(certificate, documents, policy, policyDigest, []string{"go-core"}, time.Date(2026, 8, 2, 10, 2, 0, 0, time.UTC)); err != nil {
		t.Fatal(err)
	}
	inventoryRaw := readFixture(t, filepath.Join(root, "proof-inventory.json"))
	inventory, err := DecodePolicyInventory(bytes.NewReader(inventoryRaw))
	if err != nil {
		t.Fatal(err)
	}
	wantInventory, err := BuildPolicyInventory(policy, policyDigest)
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprintf("%+v", inventory) != fmt.Sprintf("%+v", wantInventory) {
		t.Fatalf("inventory fixture mismatch\n got: %+v\nwant: %+v", inventory, wantInventory)
	}
}

func TestCheckedInInvalidAssuranceFixturesFailClosed(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "assurance", "invalid")
	tests := []struct {
		name string
		file string
		load func([]byte) error
	}{
		{name: "duplicate", file: "duplicate-key-receipt.json", load: func(raw []byte) error { _, err := DecodeReceipt(bytes.NewReader(raw)); return err }},
		{name: "truncated", file: "truncated-certificate.json", load: func(raw []byte) error { _, err := DecodeCertificate(bytes.NewReader(raw)); return err }},
		{name: "traversal", file: "traversal-certificate.json", load: func(raw []byte) error { _, err := DecodeCertificate(bytes.NewReader(raw)); return err }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := test.load(readFixture(t, filepath.Join(root, test.file))); err == nil {
				t.Fatal("expected fixture rejection")
			}
		})
	}
}

func TestAssuranceSchemasAreStrictDraft202012Documents(t *testing.T) {
	root := filepath.Join("..", "..", "testdata", "schemas")
	for _, name := range []string{"assurance-receipt-v1.schema.json", "assurance-certificate-v1.schema.json", "proof-inventory-v1.schema.json"} {
		raw := readFixture(t, filepath.Join(root, name))
		if !bytes.Contains(raw, []byte(`"$schema": "https://json-schema.org/draft/2020-12/schema"`)) || !bytes.Contains(raw, []byte(`"additionalProperties": false`)) {
			t.Fatalf("schema %s is not strict draft 2020-12", name)
		}
		if strings.Count(string(raw), "{") != strings.Count(string(raw), "}") {
			t.Fatalf("schema %s appears truncated", name)
		}
	}
}

func readFixture(t *testing.T, path string) []byte {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
