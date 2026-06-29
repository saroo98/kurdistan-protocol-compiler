// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"
)

func TestSecurityAuditQuickGates(t *testing.T) {
	cfg := DefaultConfig("quick")
	cfg.ProfileCount = 3
	report, err := RunSecurityAudit(context.Background(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	required := []string{
		"security_transcript_binding",
		"security_key_schedule",
		"security_nonce_uniqueness",
		"security_replay_rejection",
		"security_downgrade_resistance",
		"security_capability_negotiation",
		"security_profile_compatibility",
		"security_config_hygiene",
		"security_secret_trace_hygiene",
		"security_mutant_detection",
		"security_generated_backend_parity",
	}
	seen := map[string]bool{}
	for _, gate := range report.Gates {
		seen[gate.Name] = true
		if !gate.Passed {
			t.Fatalf("gate %s failed: %s details=%v", gate.Name, gate.Summary, gate.Details)
		}
	}
	for _, name := range required {
		if !seen[name] {
			t.Fatalf("missing security gate %s", name)
		}
	}
	if report.Conclusion != "passed" {
		t.Fatalf("unexpected conclusion %q", report.Conclusion)
	}
}
