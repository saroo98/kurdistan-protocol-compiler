// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"kurdistan/internal/operator/controlplane"
)

func TestDisposableDemoIsDeterministicRedactedAndRecoverable(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "control-plane.journal")
	output := filepath.Join(dir, "evidence.json")
	if err := runDemo(journal, output, 1_900_000_000); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(output)
	if err != nil {
		t.Fatal(err)
	}
	var result demoResult
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	if result.Schema != "kurdistan-phase12-disposable-evidence-v1" ||
		result.Scope != "local-disposable-control-plane" ||
		result.Health.PendingEffects != 0 ||
		result.Health.ExecutedOperations != 9 ||
		result.Claims["production_ready"] ||
		result.ExternalEvidence["hsm_kms_custody"] != "[UNVERIFIED]" {
		t.Fatalf("unexpected evidence: %+v", result)
	}
	secondDir := t.TempDir()
	secondOutput := filepath.Join(secondDir, "evidence.json")
	if err := runDemo(
		filepath.Join(secondDir, "control-plane.journal"),
		secondOutput,
		1_900_000_000,
	); err != nil {
		t.Fatal(err)
	}
	secondRaw, err := os.ReadFile(secondOutput)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(raw, secondRaw) {
		t.Fatal("ephemeral local credentials changed redacted evidence semantics")
	}
	if err := runDemo(journal, filepath.Join(dir, "second.json"), 1_900_000_000); err == nil {
		t.Fatal("demo overwrote an existing journal")
	}
}

func TestDisposableDemoRejectsPreexistingEmptyJournal(t *testing.T) {
	dir := t.TempDir()
	journal := filepath.Join(dir, "control-plane.journal")
	output := filepath.Join(dir, "evidence.json")
	if err := os.WriteFile(journal, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := runDemo(journal, output, 1_900_000_000); !errors.Is(err, controlplane.ErrConflict) {
		t.Fatalf("preexisting empty journal should conflict, got %v", err)
	}
	info, err := os.Stat(journal)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() != 0 {
		t.Fatalf("preexisting journal was modified: %d bytes", info.Size())
	}
	if _, err := os.Stat(output); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("evidence should not be created, got %v", err)
	}
}

func TestDemoEphemeralES256IssuanceIsStable(t *testing.T) {
	for iteration := 0; iteration < 20; iteration++ {
		credentials, err := newDemoCredentials()
		if err != nil {
			t.Fatalf("iteration %d credentials: %v", iteration, err)
		}
		request, _, err := buildDemoActivationRequest(credentials, 1_900_000_000)
		if err != nil {
			t.Fatalf("iteration %d issuance: %v", iteration, err)
		}
		if _, _, err := controlplane.NewVerifiedProfileIssueRequest(
			"operation-issue-001", request,
			0, "idem-operation-issue-001",
		); err != nil {
			t.Fatalf("iteration %d admission: %v", iteration, err)
		}
	}
}

func TestVerifyRunsBoundedDisposableScenario(t *testing.T) {
	if err := runVerify(); err != nil {
		t.Fatal(err)
	}
}
