// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase16receipt

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReceiptRoundTripAndFailureModes(t *testing.T) {
	directory := t.TempDir()
	write := func(name, value string) string {
		t.Helper()
		path := filepath.Join(directory, name)
		if err := os.WriteFile(path, []byte(value), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	input := Inputs{
		SubjectSHA: strings.Repeat("1", 40), TreeSHA: strings.Repeat("2", 40),
		PlanPath: write("plan", "plan"), PlanJSONPath: write("plan.json", "{}"),
		PolicyPath: write("policy.rego", "package phase16"), PolicyResultPath: write("policy.result", "0\n"),
		TerraformVariablesPath: write("tfvars.json", "{}"),
		WorkflowPath:           ".github/workflows/phase16-production-plan.yml",
		WorkflowFilePath:       write("workflow.yml", "workflow"),
		AuthorizationID:        "authorization-123", OPAVersion: "1.19.0",
		RunID: 11, RunAttempt: 2, CreatedAt: 100, ExpiresAt: 700,
	}
	receipt, err := Create(input)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := Verify(raw, input, 200)
	if err != nil || verified != receipt {
		t.Fatalf("round trip failed: %v", err)
	}
	if _, err := Verify(raw, input, 700); !errors.Is(err, ErrReceipt) {
		t.Fatalf("expired receipt accepted: %v", err)
	}
	tampered := bytesReplaceOnce(raw, []byte(`"result": "PASS"`), []byte(`"result": "FAIL"`))
	if _, err := Verify(tampered, input, 200); !errors.Is(err, ErrReceipt) {
		t.Fatalf("tampered receipt accepted: %v", err)
	}
	derivedTime := input
	derivedTime.CreatedAt = 0
	derivedTime.ExpiresAt = 0
	if _, err := Verify(raw, derivedTime, 200); err != nil {
		t.Fatalf("receipt-bound timestamps were not accepted: %v", err)
	}
	duplicate := bytesReplaceOnce(raw, []byte(`"schema": "phase16-production-plan-receipt-v1",`), []byte(`"schema": "phase16-production-plan-receipt-v1", "schema": "phase16-production-plan-receipt-v1",`))
	if _, err := Verify(duplicate, input, 200); !errors.Is(err, ErrReceipt) {
		t.Fatalf("duplicate JSON key accepted: %v", err)
	}
	if err := os.WriteFile(input.PlanPath, []byte("changed-plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(raw, input, 200); !errors.Is(err, ErrReceipt) {
		t.Fatalf("changed plan accepted: %v", err)
	}
	if err := os.WriteFile(input.PlanPath, []byte("plan"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(input.PolicyResultPath, []byte("1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Create(input); !errors.Is(err, ErrReceipt) {
		t.Fatalf("denied policy result produced a receipt: %v", err)
	}
}

func bytesReplaceOnce(raw, old, next []byte) []byte {
	return []byte(strings.Replace(string(raw), string(old), string(next), 1))
}
