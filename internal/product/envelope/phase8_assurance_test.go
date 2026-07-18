// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"kurdistan/internal/testkit/phase8assurance"
)

func TestWO807ReleaseCorpusManifestReproducesExactly(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	generated, err := phase8assurance.Generate(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := os.ReadFile(filepath.Join(repoRoot, "testdata", "evidence", "phase8-release-corpus-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, checked) {
		t.Fatal("release corpus manifest drift")
	}
	var manifest phase8assurance.Manifest
	if err := json.Unmarshal(checked, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "kurdistan.phase8.release-corpus-manifest.v1" || len(manifest.Entries) < 39 || len(manifest.Limitations) != 3 {
		t.Fatalf("incomplete release corpus: entries=%d limitations=%d", len(manifest.Entries), len(manifest.Limitations))
	}
	for _, entry := range manifest.Entries {
		if entry.ID == "" || len(entry.SourceSHA256) != 64 || len(entry.GeneratorSHA256) != 64 || len(entry.ExpectedBytesSHA256) != 64 || entry.Provenance == "" || entry.LicensePath == "" || entry.ExpectedDecision == "" {
			t.Fatalf("incomplete release corpus entry: %+v", entry)
		}
	}
}

func TestWO807FuzzCampaignEvidenceIsCompleteAndBound(t *testing.T) {
	repoRoot := filepath.Join("..", "..", "..")
	generated, err := phase8assurance.GenerateFuzzCommandManifest(repoRoot)
	if err != nil {
		t.Fatal(err)
	}
	checked, err := os.ReadFile(filepath.Join(repoRoot, "testdata", "evidence", "phase8-fuzz-command-manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(generated, checked) {
		t.Fatal("fuzz command manifest drift")
	}
	var manifest struct {
		Schema  string                       `json:"schema"`
		Targets []phase8assurance.FuzzTarget `json:"targets"`
	}
	if err := json.Unmarshal(checked, &manifest); err != nil || manifest.Schema != "kurdistan.phase8.fuzz-command-manifest.v1" || len(manifest.Targets) != 7 {
		t.Fatalf("fuzz manifest targets=%d err=%v", len(manifest.Targets), err)
	}
	type sourceInput struct {
		Path   string `json:"path"`
		SHA256 string `json:"sha256"`
	}
	type campaign struct {
		Target                         string        `json:"target"`
		Boundary                       string        `json:"boundary"`
		ExactCommand                   string        `json:"exact_command"`
		WallSeconds                    float64       `json:"wall_seconds"`
		RequestedFuzzSeconds           int           `json:"requested_fuzz_seconds"`
		ExitCode                       int           `json:"exit_code"`
		Result                         string        `json:"result"`
		Executions                     uint64        `json:"executions"`
		NewInterestingInputs           uint64        `json:"new_interesting_inputs"`
		TotalInterestingInputs         uint64        `json:"total_interesting_inputs"`
		CoverageSignal                 string        `json:"coverage_signal"`
		PeakProcessTreeWorkingSetBytes uint64        `json:"peak_process_tree_working_set_bytes"`
		PeakMeasurement                string        `json:"peak_measurement"`
		TimeoutThreshold               string        `json:"timeout_threshold"`
		CorpusCacheEntryCount          uint64        `json:"corpus_cache_entry_count"`
		CorpusCacheTreeSHA256          string        `json:"corpus_cache_tree_sha256"`
		SourceInputs                   []sourceInput `json:"source_inputs"`
		StdoutSHA256                   string        `json:"stdout_sha256"`
		StderrSHA256                   string        `json:"stderr_sha256"`
	}
	var report struct {
		Schema    string     `json:"schema"`
		Status    string     `json:"status"`
		Campaigns []campaign `json:"campaigns"`
		Summary   struct {
			RequiredTargets int    `json:"required_targets"`
			PassedTargets   int    `json:"passed_targets"`
			FailedTargets   int    `json:"failed_targets"`
			TotalExecutions uint64 `json:"total_executions"`
		} `json:"summary"`
	}
	reportPath := filepath.Join(repoRoot, "testdata", "evidence", "phase8-fuzz-campaign-report.json")
	reportRaw, err := os.ReadFile(reportPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(reportRaw, &report); err != nil || report.Schema != "kurdistan.phase8.fuzz-campaign-report.v1" || report.Status != "passed" || len(report.Campaigns) != 7 {
		t.Fatalf("invalid fuzz campaign report: schema=%q status=%q campaigns=%d err=%v", report.Schema, report.Status, len(report.Campaigns), err)
	}
	reported := make(map[string]campaign, len(report.Campaigns))
	var executions uint64
	for _, item := range report.Campaigns {
		if _, duplicate := reported[item.Target]; duplicate {
			t.Fatalf("duplicate fuzz campaign target %q", item.Target)
		}
		if item.WallSeconds < 600 || item.RequestedFuzzSeconds != 600 || item.ExitCode != 0 || item.Result != "PASS" || item.Executions == 0 || item.TotalInterestingInputs < item.NewInterestingInputs || item.CoverageSignal == "" || item.PeakProcessTreeWorkingSetBytes == 0 || item.PeakMeasurement == "" || item.TimeoutThreshold != "-fuzztime=10m" || item.CorpusCacheEntryCount == 0 || len(item.CorpusCacheTreeSHA256) != 64 || len(item.StdoutSHA256) != 64 || len(item.StderrSHA256) != 64 || len(item.SourceInputs) == 0 {
			t.Fatalf("incomplete fuzz campaign: %+v", item)
		}
		for _, source := range item.SourceInputs {
			if source.Path == "" || len(source.SHA256) != 64 {
				t.Fatalf("incomplete fuzz source input for %s: %+v", item.Target, source)
			}
			raw, err := os.ReadFile(filepath.Join(repoRoot, filepath.FromSlash(source.Path)))
			if err != nil {
				t.Fatal(err)
			}
			digest := sha256.Sum256(raw)
			if fmt.Sprintf("%x", digest) != source.SHA256 {
				t.Fatalf("fuzz source input drift for %s: %s", item.Target, source.Path)
			}
		}
		reported[item.Target] = item
		executions += item.Executions
	}
	if report.Summary.RequiredTargets != 7 || report.Summary.PassedTargets != 7 || report.Summary.FailedTargets != 0 || report.Summary.TotalExecutions != executions {
		t.Fatalf("fuzz campaign summary mismatch: %+v executions=%d", report.Summary, executions)
	}
	for _, target := range manifest.Targets {
		item, ok := reported[target.Target]
		if !ok || target.DurationSeconds != 600 || target.Status != "passed" || len(target.SeedCorpusSHA256) != 64 || target.CampaignReport != "testdata/evidence/phase8-fuzz-campaign-report.json" || item.Boundary != target.Boundary || item.ExactCommand != target.Command {
			t.Fatalf("invalid or unbound fuzz target: manifest=%+v report=%+v", target, item)
		}
	}
	activation := reported["FuzzActivateVerifiedProfileStateMachine"]
	if len(activation.SourceInputs) < 2 || !strings.Contains(string(checked), "internal/product/profile/testdata/fuzz/FuzzActivateVerifiedProfileStateMachine/5c3e9efa06c432c0") {
		t.Fatal("activation campaign is not bound to its persisted regression corpus")
	}
	for _, prohibited := range []string{"C:\\\\Users\\\\", "/home/", "username", "hostname"} {
		if strings.Contains(strings.ToLower(string(reportRaw)), strings.ToLower(prohibited)) {
			t.Fatalf("campaign report contains host-specific or identity-bearing text %q", prohibited)
		}
	}
}

func TestWO807BoundedConcurrentCorruptionParsing(t *testing.T) {
	report := loadInteropReport(t)
	inputs := make([][]byte, 0, len(report.Fixtures))
	for _, fixture := range report.Fixtures {
		encoded := fixture.OutputHex
		sealed := false
		if fixture.SealedFrameHex != "" {
			encoded, sealed = fixture.SealedFrameHex, true
		}
		if encoded == "" {
			continue
		}
		raw := mustHex(t, encoded)
		inputs = append(inputs, raw)
		corrupt := append([]byte(nil), raw...)
		corrupt[len(corrupt)/2] ^= 0x80
		if sealed {
			if parsed, err := ParseSealedProfileOpaque(corrupt); err == nil && bytes.Equal(parsed.ExactFrame, raw) {
				t.Fatal("corrupted sealed input reproduced original bytes")
			}
		} else if parsed, err := ParseSignedProfileOpaque(corrupt); err == nil && bytes.Equal(parsed.ExactObject, raw) {
			t.Fatal("corrupted signed input reproduced original bytes")
		}
	}
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for round := 0; round < 32; round++ {
				for _, input := range inputs {
					_, _ = ParseSignedProfileOpaque(input)
					_, _ = ParseSealedProfileOpaque(input)
				}
			}
		}()
	}
	wait.Wait()
}

func TestWO807IndependentCorpusMutationRejectsCryptographically(t *testing.T) {
	report := loadInteropReport(t)
	for _, fixture := range report.Fixtures {
		switch fixture.Kind {
		case "artifact-signed-public":
			signature := mustHex(t, fixture.SignatureHex)
			signature[len(signature)-1] ^= 1
			r, s, err := DecodeRawES256Signature(signature)
			if err != nil {
				continue
			}
			public := &ecdsa.PublicKey{Curve: elliptic.P256(), X: new(big.Int).SetBytes(mustHex(t, fixture.PublicXHex)), Y: new(big.Int).SetBytes(mustHex(t, fixture.PublicYHex))}
			digest := sha256.Sum256(mustHex(t, fixture.MessageHex))
			if ecdsa.Verify(public, digest[:], r, s) {
				t.Fatalf("mutated signature accepted for %s", fixture.ID)
			}
		case "hpke-open":
			key, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair(mustHex(t, fixture.RecipientIKMHex))
			if err != nil {
				t.Fatal(err)
			}
			recipient, err := hpke.NewRecipient(mustHex(t, fixture.EncHex), key, hpke.HKDFSHA256(), hpke.AES256GCM(), mustHex(t, fixture.InfoHex))
			if err != nil {
				t.Fatal(err)
			}
			ciphertext := mustHex(t, fixture.CiphertextHex)
			ciphertext[len(ciphertext)-1] ^= 1
			if _, err := recipient.Open(mustHex(t, fixture.AADHex), ciphertext); err == nil {
				t.Fatalf("mutated ciphertext accepted for %s", fixture.ID)
			}
		}
	}
}
