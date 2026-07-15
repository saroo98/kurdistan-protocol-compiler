// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import "kurdistan/internal/protocol/ir"

// policyMatrixTupleV1 is a value-only projection used by recurrence guards.
// It adds no validation or defaults; all values remain owned by their existing
// admission, envelope, replay, and lifecycle implementations.
type policyMatrixTupleV1 struct {
	Transcript, Nonce, Replay, Downgrade, Capability, Compatibility string
	Rotation, Config, Envelope                                      string
	ReplayWindow, MaxSession, MaxKey                                int
}

func policyMatrixTupleFromPolicyV1(policy ir.SecurityPolicy) policyMatrixTupleV1 {
	return policyMatrixTupleV1{
		Transcript: policy.TranscriptMode, Nonce: policy.NonceMode, Replay: policy.ReplayPolicy,
		Downgrade: policy.DowngradePolicy, Capability: policy.CapabilityNegotiationPolicy,
		Compatibility: policy.ProfileCompatibilityPolicy, Rotation: policy.KeyRotationPolicy,
		Config: policy.ConfigValidationPolicy, Envelope: policy.SecureEnvelopeMode,
		ReplayWindow: policy.ReplayWindowSize, MaxSession: policy.MaxSessionMessages, MaxKey: policy.MaxKeyLifetimeMessages,
	}
}
