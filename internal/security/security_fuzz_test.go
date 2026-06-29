// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"strings"
	"testing"
)

func FuzzTranscriptCanonicalizer(f *testing.F) {
	f.Add("profile", strings.Repeat("a", 64), "stream_carrier", []byte("nonce-1234567890"))
	f.Fuzz(func(t *testing.T, profileID, profileHash, carrier string, nonce []byte) {
		if len(profileID) > 256 || len(profileHash) > 256 || len(carrier) > 256 || len(nonce) > 128 {
			t.Skip()
		}
		input := TranscriptInput{
			ProfileID:     profileID,
			ProfileHash:   profileHash,
			CarrierPolicy: carrier,
			Capabilities:  DefaultCapabilities().Features,
			SessionNonce:  nonce,
			Suite:         DefaultSuite(),
		}
		_, _ = CanonicalTranscript(input)
		_, _ = TranscriptHash(input)
	})
}

func FuzzSecurityConfigValidator(f *testing.F) {
	f.Add("profile", strings.Repeat("a", 64), []byte("secret"), 32, 1024, 8, false)
	f.Fuzz(func(t *testing.T, profileID, profileHash string, secret []byte, replayWindow, maxEnvelope, queueDepth int, debug bool) {
		if len(profileID) > 256 || len(profileHash) > 256 || len(secret) > 512 {
			t.Skip()
		}
		cfg := SecurityConfig{
			ProfileID:        profileID,
			ProfileHash:      profileHash,
			InputSecret:      secret,
			Suite:            DefaultSuite(),
			ReplayWindow:     replayWindow,
			MaxEnvelopeBytes: maxEnvelope,
			QueueDepth:       queueDepth,
			Capabilities:     DefaultCapabilities().Features,
			Debug:            debug,
		}
		_ = ValidateConfig(cfg)
		_ = RedactConfig(cfg)
	})
}

func FuzzReplayWindowInput(f *testing.F) {
	f.Add("windowed_replay", 4, uint64(1))
	f.Fuzz(func(t *testing.T, policy string, window int, seq uint64) {
		if len(policy) > 64 || window > 8192 || seq > 1<<30 {
			t.Skip()
		}
		r := NewReplayWindow(policy, window)
		_ = r.Accept(seq)
		_ = r.Accept(seq)
	})
}

func FuzzCapabilityParser(f *testing.F) {
	f.Add("multi_stream")
	f.Fuzz(func(t *testing.T, capability string) {
		if len(capability) > 128 {
			t.Skip()
		}
		_, _ = (CapabilitySet{Features: []string{capability}}).Hash()
	})
}
