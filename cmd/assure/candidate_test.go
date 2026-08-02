// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestCandidateProvenanceSchemaTracksStrictModel(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "testdata", "schemas", "engineering-candidate-provenance-v1.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Dialect              string         `json:"$schema"`
		AdditionalProperties bool           `json:"additionalProperties"`
		Properties           map[string]any `json:"properties"`
	}
	if err := json.Unmarshal(raw, &schema); err != nil {
		t.Fatal(err)
	}
	if schema.Dialect != "https://json-schema.org/draft/2020-12/schema" || schema.AdditionalProperties || schema.Properties["assurance"] == nil || schema.Properties["selectedArtifacts"] == nil {
		t.Fatalf("candidate provenance schema does not track strict model: %+v", schema)
	}
}

func TestValidateCandidateProvenanceBindsEveryCarriedByte(t *testing.T) {
	root := t.TempDir()
	writeCandidateFile(t, root, "candidate/a/app.aab", "candidate")
	writeCandidateFile(t, root, "verified/assurance-certificate.json", "certificate")
	writeCandidateFile(t, root, "comparison.json", "comparison")
	receipts := make([]candidateArtifact, 15)
	for index := range receipts {
		path := fmt.Sprintf("receipts/%02d.json", index)
		writeCandidateFile(t, root, filepath.ToSlash(filepath.Join("verified", path)), fmt.Sprintf("receipt-%d", index))
		receipts[index] = candidateEntry(t, root, "verified", path)
	}
	inventories := make([]candidateArtifact, 0, 3)
	for _, api := range []int{26, 34, 36} {
		name := fmt.Sprintf("emulator-api%d-identity.json", api)
		writeCandidateFile(t, root, "verified/inventories/"+name, fmt.Sprintf("identity-%d", api))
		inventories = append(inventories, candidateEntry(t, root, "verified/inventories", name))
	}
	provenance := candidateProvenance{
		Schema: candidateProvenanceSchema, Repository: "saroo98/kurdistan-protocol-compiler",
		Commit: "1111111111111111111111111111111111111111", Tree: "2222222222222222222222222222222222222222",
		Assurance:       candidateAssurance{RunID: "123", RunAttempt: 1, Trigger: "push", WorkflowPath: ".github/workflows/assurance.yml", CertificatePath: "assurance-certificate.json", CertificateSHA256: candidateEntry(t, root, "verified", "assurance-certificate.json").SHA256, Receipts: receipts, Inventories: inventories},
		SelectedBuilder: "a", SelectedArtifacts: []candidateArtifact{candidateEntry(t, root, "candidate/a", "app.aab")},
		ComparisonSHA256: candidateEntry(t, root, ".", "comparison.json").SHA256,
		Limitations:      []string{"unsigned engineering candidate; signing, upload, promotion, and release remain unauthorized"},
	}
	if err := validateCandidateProvenance(root, "candidate/a", "verified", "comparison.json", provenance); err != nil {
		t.Fatalf("valid provenance rejected: %v", err)
	}
	allInventories := provenance.Assurance.Inventories
	provenance.Assurance.Inventories = provenance.Assurance.Inventories[:2]
	if err := validateCandidateProvenance(root, "candidate/a", "verified", "comparison.json", provenance); err == nil {
		t.Fatal("missing device inventory passed")
	}
	provenance.Assurance.Inventories = allInventories
	writeCandidateFile(t, root, "candidate/a/app.aab", "mutated")
	if err := validateCandidateProvenance(root, "candidate/a", "verified", "comparison.json", provenance); err == nil {
		t.Fatal("post-verification candidate mutation passed")
	}
}

func TestValidateCandidateProvenanceRejectsUndeclaredArtifact(t *testing.T) {
	root := t.TempDir()
	writeCandidateFile(t, root, "candidate/a/app.aab", "candidate")
	writeCandidateFile(t, root, "candidate/a/extra.txt", "extra")
	provenance := candidateProvenance{SelectedArtifacts: []candidateArtifact{candidateEntry(t, root, "candidate/a", "app.aab")}}
	if err := validateDeclaredArtifacts(root, "candidate/a", provenance.SelectedArtifacts, true); err == nil {
		t.Fatal("undeclared candidate artifact passed")
	}
}

func candidateEntry(t *testing.T, root, directory, relative string) candidateArtifact {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(directory), filepath.FromSlash(relative)))
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(raw)
	return candidateArtifact{Path: relative, Size: int64(len(raw)), SHA256: fmt.Sprintf("%x", digest)}
}

func writeCandidateFile(t *testing.T, root, relative, content string) {
	t.Helper()
	path := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
