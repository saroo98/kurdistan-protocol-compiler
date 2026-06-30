// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/transportbundle"
)

func TestTransportBundleGatesPassAndDetectControls(t *testing.T) {
	set, err := transportbundle.GenerateFixtureSet(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	report := transportbundle.CompareFixtureSets(set, set)
	gates := TransportBundleGates(set, report)
	required := map[string]bool{
		"transportbundle_policy_validation":        false,
		"transportbundle_seed_planning":            false,
		"transportbundle_family_coverage":          false,
		"transportbundle_adaptivepath_mapping":     false,
		"transportbundle_relay_binding":            false,
		"transportbundle_fallback_hints":           false,
		"transportbundle_collapse_detection":       false,
		"transportbundle_generated_backend_parity": false,
		"transportbundle_trace_hygiene":            false,
		"transportbundle_mutant_detection":         false,
		"transportbundle_fixture_drift":            false,
	}
	for _, gate := range gates {
		if _, ok := required[gate.Name]; ok {
			required[gate.Name] = true
		}
		if !gate.Passed {
			t.Fatalf("gate %s failed: %+v", gate.Name, gate)
		}
	}
	for name, seen := range required {
		if !seen {
			t.Fatalf("missing gate %s", name)
		}
	}
}

func BenchmarkTransportBundleQuickAudit(b *testing.B) {
	cfg := DefaultConfig("quick")
	for i := 0; i < b.N; i++ {
		if _, err := RunTransportBundleAudit(context.Background(), cfg); err != nil {
			b.Fatal(err)
		}
	}
}
