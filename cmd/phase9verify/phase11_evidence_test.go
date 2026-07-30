// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type phase11AcceptanceStatusV1 struct {
	Schema   string            `json:"schema"`
	Scope    string            `json:"scope"`
	Local    map[string]string `json:"local"`
	External map[string]string `json:"external"`
	Claims   map[string]bool   `json:"claims"`
}

func TestPhase11EvidenceCannotOverstateExternalOrProductClaims(t *testing.T) {
	path := filepath.Join("..", "..", "testdata", "evidence", "phase11", "acceptance-status.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var status phase11AcceptanceStatusV1
	if err := json.Unmarshal(raw, &status); err != nil {
		t.Fatal(err)
	}
	if status.Schema != "kurdistan.phase11.acceptance-status.v1" ||
		status.Scope != "bounded-loopback-conformance" {
		t.Fatalf("unexpected Phase 11 evidence identity: %+v", status)
	}
	for name, value := range status.Local {
		switch value {
		case "pending", "passed", "verified-by-local-test", "verified-by-emulator-test":
		default:
			t.Fatalf("local result %q has unsupported value %q", name, value)
		}
	}
	for name, value := range status.External {
		if value != "[UNVERIFIED]" {
			t.Fatalf("external result %q was overstated as %q", name, value)
		}
	}
	for name, claimed := range status.Claims {
		if claimed {
			t.Fatalf("unsupported product claim %q was enabled", name)
		}
	}
	for _, required := range []string{
		"go_gate",
		"go_race",
		"android_phase11_gate",
		"emulator_phase11_device_gate",
		"process_separation",
		"tls13_tcp",
		"authenticated_kurd_records",
		"bounded_fallback",
		"android_tun_integration",
	} {
		if _, ok := status.Local[required]; !ok {
			t.Fatalf("missing local evidence field %q", required)
		}
	}
}
