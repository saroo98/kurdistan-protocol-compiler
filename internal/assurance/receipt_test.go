// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package assurance

import (
	"strings"
	"testing"
	"time"
)

func TestDecodeReceiptAcceptsExactValidDocument(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(validReceiptJSON))
	if err != nil {
		t.Fatalf("DecodeReceipt: %v", err)
	}
	if receipt.ReceiptID != "run-123-go-core-linux" || receipt.Proof.ID != "go-core" {
		t.Fatalf("unexpected receipt identity: %+v", receipt)
	}
}

func TestDecodeReceiptAcceptsStringJobID(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(validReceiptJSON))
	if err != nil {
		t.Fatalf("DecodeReceipt: %v", err)
	}
	if receipt.Execution.JobID != "test-linux" {
		t.Fatalf("job id = %q", receipt.Execution.JobID)
	}
}

func TestDecodeReceiptAcceptsTerminalFailureWithoutArtifactsOrLimitations(t *testing.T) {
	failed := strings.Replace(validReceiptJSON, `"result": "PASS"`, `"result": "FAIL"`, 1)
	failed = strings.Replace(failed, `"artifacts": [
    {
      "path": "reports/go-test.json",
      "size": 123,
      "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ]`, `"artifacts": []`, 1)
	failed = strings.Replace(failed, `"limitations": ["none"]`, `"limitations": []`, 1)
	if _, err := DecodeReceipt(strings.NewReader(failed)); err != nil {
		t.Fatalf("DecodeReceipt terminal failure: %v", err)
	}
}

func TestDecodeReceiptRejectsMissingOrFalseTerminalMarker(t *testing.T) {
	missing := strings.Replace(validReceiptJSON, `  "terminal": true,
`, "", 1)
	if _, err := DecodeReceipt(strings.NewReader(missing)); err == nil {
		t.Fatal("expected missing terminal marker rejection")
	}
	partial := strings.Replace(validReceiptJSON, `"terminal": true`, `"terminal": false`, 1)
	if _, err := DecodeReceipt(strings.NewReader(partial)); err == nil {
		t.Fatal("expected nonterminal receipt rejection")
	}
}

func TestDecodeReceiptRejectsDuplicateJSONKeys(t *testing.T) {
	duplicate := strings.Replace(validReceiptJSON,
		`"commit": "83e262921d3ae8ecd8c04a2a440699b6cccace7b",`,
		`"commit": "83e262921d3ae8ecd8c04a2a440699b6cccace7b", "commit": "83e262921d3ae8ecd8c04a2a440699b6cccace7b",`, 1)
	if _, err := DecodeReceipt(strings.NewReader(duplicate)); err == nil {
		t.Fatal("expected duplicate JSON key rejection")
	}
}

func TestDecodeReceiptRejectsArtifactPathTraversal(t *testing.T) {
	traversal := strings.Replace(validReceiptJSON, `"path": "reports/go-test.json"`, `"path": "../go-test.json"`, 1)
	if _, err := DecodeReceipt(strings.NewReader(traversal)); err == nil {
		t.Fatal("expected artifact path traversal rejection")
	}
}

func TestDecodeReceiptRejectsUnknownFields(t *testing.T) {
	unknown := strings.Replace(validReceiptJSON, `"receiptId":`, `"unexpected": true, "receiptId":`, 1)
	if _, err := DecodeReceipt(strings.NewReader(unknown)); err == nil {
		t.Fatal("expected unknown field rejection")
	}
}

func TestDecodeReceiptRejectsTruncatedJSON(t *testing.T) {
	if _, err := DecodeReceipt(strings.NewReader(validReceiptJSON[:len(validReceiptJSON)-1])); err == nil {
		t.Fatal("expected truncated JSON rejection")
	}
}

func TestDecodeReceiptRejectsInputBeyondBound(t *testing.T) {
	oversized := validReceiptJSON + strings.Repeat(" ", maxJSONDocumentBytes)
	if _, err := DecodeReceipt(strings.NewReader(oversized)); err == nil {
		t.Fatal("expected oversized JSON rejection")
	}
}

func TestValidateReceiptRejectsPolicyDigestMismatch(t *testing.T) {
	receipt, err := DecodeReceipt(strings.NewReader(validReceiptJSON))
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateReceipt(receipt, testProofPolicy(), strings.Repeat("f", 64), time.Date(2026, 8, 2, 10, 2, 0, 0, time.UTC)); err == nil {
		t.Fatal("expected proof policy digest mismatch rejection")
	}
}

func testProofPolicy() ProofPolicy {
	return ProofPolicy{
		Schema: ProofPolicySchema,
		Proofs: []Proof{{
			ID:               "go-core",
			Commands:         [][]string{{"go", "test", "-count=1", "./..."}},
			OperatingSystems: []string{"linux"},
			CachePolicy:      CacheIndependent,
			Deterministic:    true,
			InvalidatedBy:    []string{"go.mod"},
			AuthorizedPhase:  16,
		}},
	}
}

const validReceiptJSON = `{
  "schema": "kurdistan-assurance-receipt-v1",
  "receiptId": "run-123-go-core-linux",
  "subject": {
    "repository": "saroo98/kurdistan-protocol-compiler",
    "commit": "83e262921d3ae8ecd8c04a2a440699b6cccace7b",
    "tree": "1111111111111111111111111111111111111111",
    "ref": "refs/heads/main"
  },
  "workflow": {
    "path": ".github/workflows/assurance.yml",
    "sourceCommit": "9999999999999999999999999999999999999999",
    "sha256": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  },
  "execution": {"runId": "123", "jobId": "test-linux", "attempt": 1, "trigger": "push"},
  "proof": {
    "id": "go-core",
    "policySha256": "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  },
  "inventories": [
    {"name": "go-tests", "sha256": "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"}
  ],
  "toolchain": [
    {"name": "go", "version": "go1.26.5", "sha256": "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"}
  ],
  "runner": {
    "operatingSystem": "linux",
    "architecture": "amd64",
    "requestedLabel": "ubuntu-24.04",
    "image": "ubuntu",
    "imageVersion": "20260801.1"
  },
  "commands": [["go", "test", "-count=1", "./..."]],
  "timing": {
    "startedAt": "2026-08-02T10:00:00Z",
    "completedAt": "2026-08-02T10:01:00Z",
    "durationMillis": 60000
  },
  "cachePolicy": "CACHE_INDEPENDENT",
  "result": "PASS",
  "terminal": true,
  "artifacts": [
    {
      "path": "reports/go-test.json",
      "size": 123,
      "sha256": "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
    }
  ],
  "limitations": ["none"]
}`
