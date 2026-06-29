// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"testing"

	"kurdistan/internal/carrier"
	"kurdistan/internal/compiler"
	"kurdistan/internal/framing"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/security"
)

func FuzzTraceHygieneScanner(f *testing.F) {
	f.Add([]byte(`{"event_type":"clean"}`))
	f.Add([]byte(`{"raw_secret":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		_ = ScanJSON(raw)
	})
}

func FuzzHardeningFramePanicWrapper(f *testing.F) {
	p, err := compiler.Generate(14002)
	if err != nil {
		f.Fatal(err)
	}
	f.Add([]byte{1, 2, 3})
	f.Fuzz(func(t *testing.T, raw []byte) {
		result := MustNotPanic("frame", func() {
			_, _ = framing.DecodeFrame(p, raw)
		})
		if !result.Passed {
			t.Fatalf("panic: %s", result.Details)
		}
	})
}

func FuzzRuntimeConfigValidator(f *testing.F) {
	f.Add("runtime", []byte("secret"))
	f.Fuzz(func(t *testing.T, runtimeID string, secret []byte) {
		cfg := kruntime.DefaultConfig(kruntime.RoleClient, runtimeID, secret)
		_ = kruntime.ValidateConfig(cfg)
	})
}

func FuzzCarrierEnvelopeValidation(f *testing.F) {
	p, err := compiler.Generate(14003)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint64(1), 1, 1)
	f.Fuzz(func(t *testing.T, seq uint64, messageCount int, byteCount int) {
		_ = carrier.ValidateEnvelope(p, carrier.Envelope{CarrierFamily: p.CarrierPolicy.CarrierFamily, Sequence: seq, Kind: "data", MessageCount: messageCount, ByteCount: byteCount})
	})
}

func FuzzSecureEnvelopeValidation(f *testing.F) {
	p, err := compiler.Generate(14004)
	if err != nil {
		f.Fatal(err)
	}
	ctx, keys, err := securityContextForProfile(p)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint64(1), []byte("bad"))
	f.Fuzz(func(t *testing.T, seq uint64, nonce []byte) {
		codec, err := security.NewEnvelopeCodec(ctx, keys, "client")
		if err != nil {
			t.Fatal(err)
		}
		_, _ = codec.Open(security.SecureEnvelope{Sequence: seq, TranscriptHash: ctx.TranscriptHash, CapabilityHash: ctx.CapabilityHash, Nonce: nonce, Ciphertext: []byte("x")})
	})
}
