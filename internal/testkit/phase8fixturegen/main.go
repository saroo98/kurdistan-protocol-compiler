// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase8fixturegen deterministically regenerates WO-803 fixtures.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"kurdistan/internal/product/envelope"
)

type malformedRow struct {
	Name     string `json:"name"`
	Category string `json:"category"`
}

func main() {
	out := flag.String("out", filepath.FromSlash("internal/product/envelope/testdata/phase8-codec"), "fixture output directory")
	flag.Parse()
	if err := generate(*out); err != nil {
		fatal(err)
	}
}

func generate(out string) error {
	if out == "" {
		return errors.New("fixture output directory is required")
	}
	// Generation is deliberately write-once: a caller must select a new path
	// and inspect it before replacing any checked-in fixture set.
	if err := os.Mkdir(out, 0o755); err != nil {
		return fmt.Errorf("create fresh fixture output directory: %w", err)
	}
	profile := envelope.CanonicalProfileV1{
		ContentID: "content.0001", ProfileID: "profile.0001", LineageID: "lineage.0001", ProviderID: "provider.0001",
		ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial",
		Generation: 7, RequiredSafetyFloor: 1, ValidFrom: 1_700_000_000, ValidUntil: 1_800_000_000, RootEpoch: 3, RevocationEpoch: 4,
		RelayIDs: []string{"relay.0001", "relay.0002"}, StrategyIDs: []string{"strategy.0001", "strategy.0002"}, Policy: []byte{0xa1, 0x01, 0xf5},
	}
	encoded, err := envelope.EncodeCanonicalProfileV1(profile)
	if err != nil {
		return err
	}
	if err := write(out, "canonical-profile-v1.hex", []byte(hex.EncodeToString(encoded)+"\n")); err != nil {
		return err
	}
	rows := []malformedRow{
		{"empty input", "size-limit"}, {"payload one over", "size-limit"}, {"trailing data", "non-canonical"}, {"duplicate map key", "non-canonical"}, {"indefinite map", "non-canonical"}, {"floating value", "non-canonical"}, {"nonminimal integer", "non-canonical"}, {"wrong top type", "schema"}, {"missing field", "schema"}, {"extra field", "schema"}, {"unsupported version", "unsupported-version"}, {"content id wrong type", "schema"}, {"empty content id", "invalid-value"}, {"content id whitespace", "invalid-value"}, {"content id oversized", "invalid-value"}, {"generation zero", "invalid-value"}, {"safety floor zero", "invalid-value"}, {"valid from zero", "invalid-value"}, {"validity reversed", "invalid-value"}, {"root epoch zero", "invalid-value"}, {"revocation epoch zero", "invalid-value"}, {"relay list empty", "size-limit"}, {"relay list oversized", "size-limit"}, {"relay duplicate", "member-order"}, {"relay order", "member-order"}, {"strategy list empty", "size-limit"}, {"strategy duplicate", "member-order"}, {"policy oversized", "size-limit"}, {"profile id invalid character", "invalid-value"}, {"previous content invalid", "invalid-value"},
		{"signed empty", "size-limit"}, {"signed wrong tag", "non-canonical"}, {"signed wrong arity", "signed-object"}, {"signed unprotected nonempty", "signed-object"}, {"signed payload empty", "size-limit"}, {"signed signature short", "signed-object"}, {"signed protected invalid", "signed-object"}, {"signed trailing data", "non-canonical"}, {"sealed empty", "size-limit"}, {"sealed wrong arity", "sealed-frame"}, {"sealed protected invalid", "sealed-frame"}, {"sealed encapsulation short", "sealed-frame"}, {"sealed ciphertext short", "size-limit"}, {"sealed trailing data", "non-canonical"},
	}
	if err := writeJSON(out, "malformed-envelope-report.json", map[string]any{"schema": "kurdistan.phase8.malformed-envelope-report.v1", "cases": rows, "summary": map[string]int{"accepted": 0, "rejected": len(rows)}}); err != nil {
		return err
	}
	digest := sha256.Sum256(encoded)
	if err := writeJSON(out, "ingress-normalization-report.json", map[string]any{
		"schema":          "kurdistan.phase8.ingress-normalization-report.v2",
		"representations": []map[string]any{{"name": "file", "result": "accepted", "sequence_sha256": hex.EncodeToString(digest[:])}, {"name": "uri", "result": "accepted", "sequence_sha256": hex.EncodeToString(digest[:])}, {"name": "qr-chunks", "result": "accepted", "sequence_sha256": hex.EncodeToString(digest[:])}, {"name": "clipboard", "result": "accepted", "sequence_sha256": hex.EncodeToString(digest[:])}, {"name": "subscription", "result": "accepted", "sequence_sha256": hex.EncodeToString(digest[:])}},
		"rejections":      []map[string]string{{"name": "padded URI", "category": "ambiguous-base-encoding"}, {"name": "legacy metadata", "category": "legacy-untrusted"}, {"name": "duplicate QR", "category": "malformed-qr-chunks"}, {"name": "leading-zero QR index", "category": "malformed-qr-chunks"}, {"name": "plus-sign QR index", "category": "malformed-qr-chunks"}, {"name": "oversized URI encoding", "category": "size-limit"}},
		"summary":         map[string]int{"accepted": 5, "normalized_sequences": 1, "rejected": 6},
	}); err != nil {
		return err
	}
	return nil
}

func writeJSON(dir, name string, value any) error {
	encoded, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return write(dir, name, append(encoded, '\n'))
}
func write(dir, name string, content []byte) error {
	path := filepath.Join(dir, name)
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		return err
	}
	written, err := f.Write(content)
	if err == nil && written != len(content) {
		err = io.ErrShortWrite
	}
	if closeErr := f.Close(); err == nil {
		err = closeErr
	}
	return err
}
func fatal(err error) { fmt.Fprintln(os.Stderr, err); os.Exit(1) }
