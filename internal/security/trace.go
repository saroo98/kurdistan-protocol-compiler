// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import ktrace "kurdistan/internal/trace"

func SecureEnvelopeTrace(ctx SecurityContext, env SecureEnvelope) ktrace.Event {
	return ktrace.Event{
		EventType:                 "security_envelope",
		ProfileID:                 ctx.ProfileID,
		StreamLabel:               streamBucket(env.StreamID),
		Semantic:                  env.Semantic,
		CarrierFamilyBucket:       env.CarrierFamily,
		SecuritySuiteBucket:       ctx.Suite.KDF + "/" + ctx.Suite.AEAD,
		TranscriptModeBucket:      ctx.Suite.Transcript,
		NonceModeBucket:           "directional_counter",
		ReplayPolicyBucket:        "windowed_replay",
		CapabilityPolicyBucket:    "strict_required",
		CompatibilityPolicyBucket: "full_policy_binding",
		SecureEnvelopeModeBucket:  "synthetic_aead_test",
		SecretHygieneResult:       "redacted",
		FrameBytes:                env.CiphertextBytes,
		Note:                      "transcript=" + ctx.TranscriptHash[:min(12, len(ctx.TranscriptHash))] + " capability=" + ctx.CapabilityHash[:min(12, len(ctx.CapabilityHash))],
	}
}

func streamBucket(id uint64) string {
	return "stream_bucket_" + string(rune('0'+(id%8)))
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
