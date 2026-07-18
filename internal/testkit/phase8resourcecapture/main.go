// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase8resourcecapture captures privacy-safe WO-803 parser resource observations.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
)

const iterations = 1000

type observation struct {
	Name                   string `json:"name"`
	ObservedWallUS         int64  `json:"observed_wall_us"`
	ObservedAllocations    int    `json:"observed_allocations"`
	ObservedErrorBytes     int    `json:"observed_error_bytes"`
	ObservedTimeoutWallUS  int64  `json:"observed_timeout_wall_us"`
	CompletedBeforeTimeout bool   `json:"completed_before_timeout"`
}

func main() {
	out := flag.String("out", filepath.FromSlash("internal/product/envelope/testdata/phase8-codec"), "evidence output directory")
	flag.Parse()
	if err := os.MkdirAll(*out, 0o755); err != nil {
		fatal(err)
	}
	root, err := os.Getwd()
	if err != nil {
		fatal(err)
	}
	source := filepath.Join(root, "internal", "testkit", "phase8resourcecapture", "main.go")
	fixture := filepath.Join(root, "internal", "product", "envelope", "testdata", "phase8-codec", "canonical-profile-v1.hex")

	profile := envelope.CanonicalProfileV1{
		ContentID: "content.0001", ProfileID: "profile.0001", LineageID: "lineage.0001", ProviderID: "provider.0001",
		ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial",
		Generation: 7, RequiredSafetyFloor: 1, ValidFrom: 1_700_000_000, ValidUntil: 1_800_000_000, RootEpoch: 3, RevocationEpoch: 4,
		RelayIDs: []string{"relay.0001", "relay.0002"}, StrategyIDs: []string{"strategy.0001", "strategy.0002"}, Policy: []byte{0xa1, 0x01, 0xf5},
	}
	encoded, err := envelope.EncodeCanonicalProfileV1(profile)
	if err != nil {
		fatal(err)
	}
	metadata := envelope.ArtifactMetadata{Class: envelope.ArtifactDeviceRecipient, AudienceClass: envelope.AudienceProvisionedDevice, RecipientHint: "fixture_hint_0001", RecipientEpoch: 7}
	protected, err := envelope.BuildSignedProtectedHeaders([]byte("issuer-key.0001"), metadata)
	if err != nil {
		fatal(err)
	}
	signature, err := envelope.EncodeRawES256Signature(big.NewInt(1), big.NewInt(1))
	if err != nil {
		fatal(err)
	}
	signed, err := envelope.BuildTaggedCOSESign1(protected, encoded, signature)
	if err != nil {
		fatal(err)
	}
	outer, err := envelope.BuildSealProtected(metadata)
	if err != nil {
		fatal(err)
	}
	sealed, err := envelope.BuildSealedFrame(outer, make([]byte, envelope.HPKEP256EncSize), make([]byte, envelope.HPKEAEADTagSize+1))
	if err != nil {
		fatal(err)
	}
	uri, err := envelope.EncodeArtifactURI(encoded)
	if err != nil {
		fatal(err)
	}
	qr, err := envelope.EncodeQRChunks(encoded, 97)
	if err != nil {
		fatal(err)
	}

	operations := []struct {
		name string
		run  func()
		fail func() error
	}{
		{"profile", func() { _, _ = envelope.DecodeCanonicalProfileV1(encoded) }, func() error { _, e := envelope.DecodeCanonicalProfileV1([]byte{0xff}); return e }},
		{"signed", func() { _, _ = envelope.ParseSignedProfileOpaque(signed) }, func() error { _, e := envelope.ParseSignedProfileOpaque([]byte{0xff}); return e }},
		{"sealed", func() { _, _ = envelope.ParseSealedProfileOpaque(sealed) }, func() error { _, e := envelope.ParseSealedProfileOpaque([]byte{0xff}); return e }},
		{"uri", func() {
			_, _ = envelope.NormalizeProfileIngress(envelope.ProfileIngress{Kind: envelope.IngressURI, Text: uri})
		}, func() error {
			_, e := envelope.NormalizeProfileIngress(envelope.ProfileIngress{Kind: envelope.IngressURI, Text: "kurd://artifact/="})
			return e
		}},
		{"qr", func() {
			_, _ = envelope.NormalizeProfileIngress(envelope.ProfileIngress{Kind: envelope.IngressQRChunks, Chunks: qr})
		}, func() error {
			_, e := envelope.NormalizeProfileIngress(envelope.ProfileIngress{Kind: envelope.IngressQRChunks, Chunks: []string{"KURD1/01/1/AQ"}})
			return e
		}},
	}
	rows := make([]observation, 0, len(operations))
	for _, op := range operations {
		start := time.Now()
		for i := 0; i < iterations; i++ {
			op.run()
		}
		wall := max(int64(1), time.Since(start).Microseconds()/iterations)
		allocs := int(testing.AllocsPerRun(100, op.run))
		parseErr := op.fail()
		if parseErr == nil {
			fatal(fmt.Errorf("%s negative operation returned nil", op.name))
		}
		start = time.Now()
		done := make(chan struct{})
		go func() { op.run(); close(done) }()
		completed := false
		select {
		case <-done:
			completed = true
		case <-time.After(5 * time.Second):
		}
		rows = append(rows, observation{Name: op.name, ObservedWallUS: wall, ObservedAllocations: allocs, ObservedErrorBytes: len(parseErr.Error()), ObservedTimeoutWallUS: max(int64(1), time.Since(start).Microseconds()), CompletedBeforeTimeout: completed})
	}
	raw := map[string]any{
		"schema": "kurdistan.phase8.reference-host-resource-raw.v1", "host_alias": "reference-windows-amd64",
		"command":    "go run ./internal/testkit/phase8resourcecapture -out internal/product/envelope/testdata/phase8-codec",
		"go_version": runtime.Version(), "goos": runtime.GOOS, "goarch": runtime.GOARCH,
		"captured_at_utc": time.Now().UTC().Format(time.RFC3339), "iterations": iterations,
		"source_sha256": fileHash(source), "fixture_sha256": fileHash(fixture), "stages": rows,
		"privacy": map[string]bool{"username_recorded": false, "machine_name_recorded": false, "absolute_path_recorded": false, "payload_recorded": false, "key_material_recorded": false},
	}
	rawBytes := encode(raw)
	write(*out, "reference-host-resource-raw.json", rawBytes)
	rawSum := sha256.Sum256(rawBytes)
	reportRows := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		reportRows = append(reportRows, map[string]any{"name": row.Name, "wall_time_ceiling_ms": 2000, "allocation_ceiling": 500, "error_output_ceiling_bytes": 512, "timeout_ceiling_ms": 5000, "observed_wall_us": row.ObservedWallUS, "observed_allocations": row.ObservedAllocations, "observed_error_bytes": row.ObservedErrorBytes, "observed_timeout_wall_us": row.ObservedTimeoutWallUS, "completed_before_timeout": row.CompletedBeforeTimeout})
	}
	write(*out, "reference-host-resource-report.json", encode(map[string]any{"schema": "kurdistan.phase8.reference-host-resource-report.v3", "host_alias": "reference-windows-amd64", "raw_evidence": "reference-host-resource-raw.json", "raw_sha256": hex.EncodeToString(rawSum[:]), "stages": reportRows}))
}

func fileHash(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		fatal(err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
func encode(value any) []byte {
	b, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		fatal(err)
	}
	return append(b, '\n')
}
func write(dir, name string, b []byte) {
	if err := os.WriteFile(filepath.Join(dir, name), b, 0o644); err != nil {
		fatal(err)
	}
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
