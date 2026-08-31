// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package phase8assurance generates deterministic Phase 8 release evidence.
package phase8assurance

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"

	"kurdistan/internal/testkit/evidenceoverlay"
)

type Entry struct {
	ID                  string `json:"id"`
	Kind                string `json:"kind"`
	SourcePath          string `json:"source_path"`
	SourceSHA256        string `json:"source_sha256"`
	GeneratorPath       string `json:"generator_path"`
	GeneratorSHA256     string `json:"generator_sha256"`
	Provenance          string `json:"provenance"`
	LicensePath         string `json:"license_path"`
	ExpectedDecision    string `json:"expected_decision"`
	ExpectedBytesSHA256 string `json:"expected_bytes_sha256"`
}

type Manifest struct {
	Schema      string   `json:"schema"`
	Entries     []Entry  `json:"entries"`
	Limitations []string `json:"limitations"`
}

type FuzzTarget struct {
	Target           string `json:"target"`
	Package          string `json:"package"`
	Boundary         string `json:"boundary"`
	Command          string `json:"command"`
	DurationSeconds  int    `json:"duration_seconds"`
	SeedSource       string `json:"seed_source"`
	SeedCorpusSHA256 string `json:"seed_corpus_sha256"`
	Status           string `json:"status"`
	CampaignReport   string `json:"campaign_report"`
}

func Generate(repoRoot string) ([]byte, error) {
	independentPath := "testdata/evidence/phase8-independent-interop-report.json"
	independentRaw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(independentPath)))
	if err != nil {
		return nil, err
	}
	var independent struct {
		Fixtures []struct {
			ID             string `json:"id"`
			Kind           string `json:"kind"`
			OutputHex      string `json:"output_hex"`
			SealedFrameHex string `json:"sealed_frame_hex"`
			SignatureHex   string `json:"signature_hex"`
		} `json:"fixtures"`
	}
	if err := json.Unmarshal(independentRaw, &independent); err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(independent.Fixtures)+24)
	for _, fixture := range independent.Fixtures {
		expectedHex := fixture.OutputHex
		if expectedHex == "" {
			expectedHex = fixture.SealedFrameHex
		}
		if expectedHex == "" {
			expectedHex = fixture.SignatureHex
		}
		expected, err := hex.DecodeString(expectedHex)
		if err != nil || len(expected) == 0 {
			return nil, fmt.Errorf("release corpus fixture %s has no expected bytes", fixture.ID)
		}
		entries = append(entries, newEntry(repoRoot, fixture.ID, "independent-vector", independentPath, "testdata/evidence/independent/phase8_interop.py", "locally reproduced by pinned independent Python libraries", "docs/third-party/phase8-profile-cryptography.md", "accept", hash(expected)))
	}
	issuanceManifestPath := "internal/product/profile/testdata/phase8-issuance/fixture-manifest.json"
	issuanceRaw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(issuanceManifestPath)))
	if err != nil {
		return nil, err
	}
	var issuance struct {
		Fixtures map[string]string `json:"fixtures"`
	}
	if err := json.Unmarshal(issuanceRaw, &issuance); err != nil {
		return nil, err
	}
	fixtureNames := make([]string, 0, len(issuance.Fixtures))
	for name := range issuance.Fixtures {
		fixtureNames = append(fixtureNames, name)
	}
	sort.Strings(fixtureNames)
	for _, name := range fixtureNames {
		decision := "accept"
		if len(name) >= 8 && name[:8] == "invalid-" {
			decision = "reject"
		}
		path := "internal/product/profile/testdata/phase8-issuance/" + name
		entries = append(entries, newEntry(repoRoot, "issuance-"+name, "local-issuance-fixture", path, "internal/testkit/phase8issuancefixture/generate.go", "deterministic test-only Go generator with independent standard-library consumers", "docs/KZ-evidence-ref-035", decision, issuance.Fixtures[name]))
	}
	for _, path := range []string{"testdata/evidence/phase8-fuzz-campaign-report.json", "testdata/evidence/phase8-suite-decision-matrix.json", "testdata/evidence/phase8-toolchain-randomness-report.json", "docs/third-party/phase8-profile-cryptography.md"} {
		entries = append(entries, newEntry(repoRoot, filepath.Base(path), "release-source", path, path, "repository-controlled standards and dependency evidence", "docs/third-party/phase8-profile-cryptography.md", "informational", fileHash(repoRoot, path)))
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ID < entries[j].ID })
	manifest := Manifest{Schema: "kurdistan.phase8.release-corpus-manifest.v1", Entries: entries, Limitations: []string{"No Android, live-network, HSM, production-key, or field validation is represented.", "Long fuzz campaign measurements are local evidence bound through the separate campaign report; they are not production-readiness evidence.", "Independent fixtures demonstrate interoperability for the mandatory classical suite only."}}
	raw, err := json.MarshalIndent(manifest, "", "  ")
	return append(raw, '\n'), err
}

func GenerateFuzzCommandManifest(repoRoot string) ([]byte, error) {
	type target struct{ name, pkg, boundary, source string }
	targets := []target{
		{"FuzzPhase8ProfileCodec", "./internal/product/envelope", "canonical-profile-cbor", "internal/product/envelope/phase8_profile_codec_fuzz_test.go"},
		{"FuzzPhase8SignedParser", "./internal/product/envelope", "cose-sign1-framing", "internal/product/envelope/phase8_profile_codec_fuzz_test.go"},
		{"FuzzPhase8SealedParser", "./internal/product/envelope", "sealed-hpke-framing", "internal/product/envelope/phase8_profile_codec_fuzz_test.go"},
		{"FuzzPhase8URIIngress", "./internal/product/envelope", "uri-ingress", "internal/product/envelope/phase8_profile_codec_fuzz_test.go"},
		{"FuzzPhase8QRIngress", "./internal/product/envelope", "qr-ingress", "internal/product/envelope/phase8_profile_codec_fuzz_test.go"},
		{"FuzzActivateVerifiedProfileStateMachine", "./internal/product/profile", "authority-revocation-activation", "internal/product/profile/phase8_activation_fuzz_test.go"},
		{"FuzzApplyVerifiedStateMachine", "./internal/product/lifecycle", "verified-lifecycle", "internal/product/lifecycle/phase8_verified_fuzz_test.go"},
	}
	rows := make([]FuzzTarget, 0, len(targets))
	for _, item := range targets {
		seedSource := item.source + " embedded f.Add corpus"
		if item.name == "FuzzActivateVerifiedProfileStateMachine" {
			seedSource += " plus internal/product/profile/testdata/fuzz/FuzzActivateVerifiedProfileStateMachine/5c3e9efa06c432c0 persisted regression corpus"
		}
		rows = append(rows, FuzzTarget{Target: item.name, Package: item.pkg, Boundary: item.boundary, Command: "go test -count=1 " + item.pkg + " -run=^$ -fuzz=^" + item.name + "$ -fuzztime=10m", DurationSeconds: 600, SeedSource: seedSource, SeedCorpusSHA256: fileHash(repoRoot, item.source), Status: "passed", CampaignReport: "testdata/evidence/phase8-fuzz-campaign-report.json"})
	}
	value := map[string]any{"schema": "kurdistan.phase8.fuzz-command-manifest.v1", "targets": rows, "required_run_observations": []string{"exact command", "wall duration", "executions", "coverage signal", "peak allocation", "timeout threshold", "resulting corpus hash"}, "limitations": "Campaign status is supported by the separate hash-bound Phase 8 fuzz campaign report; the command manifest does not by itself prove execution."}
	raw, err := json.MarshalIndent(value, "", "  ")
	return append(raw, '\n'), err
}

func newEntry(root, id, kind, source, generator, provenance, license, decision, expected string) Entry {
	return Entry{ID: id, Kind: kind, SourcePath: source, SourceSHA256: fileHash(root, source), GeneratorPath: generator, GeneratorSHA256: fileHash(root, generator), Provenance: provenance, LicensePath: license, ExpectedDecision: decision, ExpectedBytesSHA256: expected}
}

func fileHash(root, path string) string {
	digest, err := evidenceoverlay.ResolvePhase17PredecessorSHA256(root, path)
	if err != nil {
		panic(err)
	}
	return digest
}

func hash(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}
