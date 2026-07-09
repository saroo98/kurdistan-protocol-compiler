// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package audit

import (
	"context"
	"testing"

	"kurdistan/internal/testkit/mutant"
	"kurdistan/internal/protocol/ir"
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

// TestSecurityMutantReasonsDiscriminates is the de-hollowing regression guard for
// Stage 6 (Option B). The security mutant gate is a detector self-test, so its
// only honest guarantee is that the detector DISCRIMINATES: a canonical-strong
// profile (declared policy fields set to values no mutant forces) must yield zero
// reasons, and every mutant must yield at least one. This pins the removal of the
// previously unconditional ModeReusedNonce reason, which fired for any profile.
func TestSecurityMutantReasonsDiscriminates(t *testing.T) {
	modes := []string{
		mutant.ModeNoTranscriptBinding,
		mutant.ModeReusedNonce,
		mutant.ModeAcceptsReplay,
		mutant.ModeAcceptsDowngrade,
		mutant.ModeCapabilityMismatchAccepted,
		mutant.ModeProfileMismatchAccepted,
		mutant.ModeUnsafeConfigAllowed,
		mutant.ModeSecretTraceLeak,
	}
	clean := &ir.Profile{}
	clean.Security.TranscriptMode = "canonical_full_binding_v1"
	clean.Security.NonceMode = "directional_counter"
	clean.Security.DowngradePolicy = "strict_suite_and_capabilities"
	clean.Security.CapabilityNegotiationPolicy = "strict_required"
	clean.Security.ProfileCompatibilityPolicy = "full_policy_binding"
	clean.Security.ConfigValidationPolicy = "strict_profile_bound"
	clean.Security.SecureEnvelopeMode = "full_context_bound_envelope"
	clean.InvalidInput.Replay = "reject_nonce"
	for _, mode := range modes {
		if reasons := securityMutantReasons(mode, []*ir.Profile{clean}); len(reasons) != 0 {
			t.Fatalf("canonical-strong clean profile flagged for %s: %v", mode, reasons)
		}
		profiles, err := mutant.GenerateProfiles(mode, 4100, 3)
		if err != nil {
			t.Fatalf("GenerateProfiles(%s): %v", mode, err)
		}
		if reasons := securityMutantReasons(mode, profiles); len(reasons) == 0 {
			t.Fatalf("mutant %s produced no detector reasons (self-test would pass vacuously)", mode)
		}
	}
}
