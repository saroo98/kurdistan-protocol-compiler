// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import ktrace "kurdistan/internal/observe/trace"

func SecureEnvelopeTrace(ctx SecurityContext, env SecureEnvelope) ktrace.Event {
	return ktrace.Event{
		EventType:           "security_envelope",
		Semantic:            env.Semantic,
		SecuritySuiteBucket: ctx.Suite.KDF + "/" + ctx.Suite.AEAD,
		SecretHygieneResult: "redacted",
		RuntimeFrameBucket:  frameSizeBucket(env.CiphertextBytes),
	}
}

func SecureEnvelopeDiagnosticV1(_ SecurityContext, env SecureEnvelope) (ktrace.DiagnosticEventV1, error) {
	event := ktrace.DiagnosticEventV1{SchemaVersion: ktrace.DiagnosticSchemaV1, EventClass: "security_envelope", OutcomeBucket: "accepted", SizeBucket: frameSizeBucket(env.CiphertextBytes), CountBucket: "one", HygieneResult: "redacted"}
	if err := ktrace.ValidateDiagnosticEventV1(event); err != nil {
		return ktrace.DiagnosticEventV1{}, err
	}
	return event, nil
}

func frameSizeBucket(size int) string {
	switch {
	case size <= 0:
		return "none"
	case size <= 256:
		return "small"
	case size <= 4096:
		return "medium"
	default:
		return "large"
	}
}
