// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"testing"

	"kurdistan/internal/compiler"
)

func benchmarkInput(b *testing.B) TranscriptInput {
	b.Helper()
	p, err := compiler.Generate(12201)
	if err != nil {
		b.Fatal(err)
	}
	hash, err := ProfileHash(p)
	if err != nil {
		b.Fatal(err)
	}
	return TranscriptInput{
		ProfileID:     p.ID,
		ProfileHash:   hash,
		CarrierPolicy: p.CarrierPolicy.CarrierFamily,
		StreamPolicy:  p.Stream.IDStrategy,
		ProxyPolicy:   p.ProxySemantics.TargetDescriptorEncoding,
		Capabilities:  DefaultCapabilities().Features,
		SessionNonce:  []byte("benchmark-session-nonce"),
		Suite:         DefaultSuite(),
	}
}

func BenchmarkTranscriptConstruction(b *testing.B) {
	input := benchmarkInput(b)
	for i := 0; i < b.N; i++ {
		if _, err := TranscriptHash(input); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkKeyScheduleDerivation(b *testing.B) {
	input := benchmarkInput(b)
	hash, err := TranscriptHash(input)
	if err != nil {
		b.Fatal(err)
	}
	secret := []byte("benchmark security secret")
	for i := 0; i < b.N; i++ {
		if _, err := DeriveKeySchedule(secret, hash, DefaultSuite()); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkNonceGeneration(b *testing.B) {
	manager := NewNonceManager("client", []byte("123456789012"), "directional_counter")
	for i := 0; i < b.N; i++ {
		if _, _, err := manager.Next(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkReplayWindowUpdate(b *testing.B) {
	window := NewReplayWindow("windowed_replay", b.N+1)
	for i := 0; i < b.N; i++ {
		if err := window.Accept(uint64(i + 1)); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCapabilityHashConstruction(b *testing.B) {
	caps := DefaultCapabilities()
	for i := 0; i < b.N; i++ {
		if _, err := caps.Hash(); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkSecureEnvelopeRoundTrip(b *testing.B) {
	input := benchmarkInput(b)
	ctx, err := BuildContext(input)
	if err != nil {
		b.Fatal(err)
	}
	keys, err := DeriveKeySchedule([]byte("benchmark security secret"), ctx.TranscriptHash, ctx.Suite)
	if err != nil {
		b.Fatal(err)
	}
	codec, err := NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		b.Fatal(err)
	}
	payload := make([]byte, 256)
	for i := 0; i < b.N; i++ {
		env, err := codec.Seal(EnvelopeMetadata{StreamID: 1, Semantic: "data", CarrierFamily: "stream_carrier"}, payload)
		if err != nil {
			b.Fatal(err)
		}
		if _, err := codec.Open(env); err != nil {
			b.Fatal(err)
		}
	}
}
