// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"testing"

	ktrace "kurdistan/internal/observe/trace"
)

func TestSecurityStrictTraceSequenceV1(t *testing.T) {
	ctx := SecurityContext{ProfileID: "profile-secret", TranscriptHash: "transcript-secret", CapabilityHash: "capability-secret", Suite: DefaultSuite()}
	env := SecureEnvelope{StreamID: 91, Semantic: "data", CarrierFamily: "destination-secret", CiphertextBytes: 513, Ciphertext: []byte("ciphertext-secret"), Nonce: []byte("nonce-secret")}
	event, err := SecureEnvelopeDiagnosticV1(ctx, env)
	if err != nil {
		t.Fatal(err)
	}
	if event.EventClass != "security_envelope" || event.SizeBucket != "medium" || event.HygieneResult != "redacted" {
		t.Fatalf("unexpected diagnostic: %+v", event)
	}
	if ktrace.ContainsSensitiveValue(event, []byte(ctx.ProfileID), []byte(ctx.TranscriptHash), []byte(ctx.CapabilityHash), env.Ciphertext, env.Nonce, []byte(env.CarrierFamily)) {
		t.Fatal("security diagnostic retained sensitive value")
	}
}
