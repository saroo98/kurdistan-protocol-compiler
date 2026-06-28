// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import (
	"testing"

	"kurdistan/internal/compiler"
)

func TestRegistryAndCarrierRoundTrips(t *testing.T) {
	p, err := compiler.Generate(11001)
	if err != nil {
		t.Fatal(err)
	}
	messages := []SemanticMessage{
		{StreamID: 1, Semantic: "open_relay", ByteCount: 64, PriorityClass: "interactive", MetadataClass: "control"},
		{StreamID: 1, Semantic: "target_response", ByteCount: p.CarrierPolicy.MaxEnvelopeBytes + 128, PriorityClass: "bulk", MetadataClass: "large"},
		{StreamID: 2, Semantic: "target_error", ByteCount: 16, PriorityClass: "control", MetadataClass: "error"},
	}
	for _, family := range RequiredFamilies() {
		t.Run(family, func(t *testing.T) {
			model, err := NewModel(p, family)
			if err != nil {
				t.Fatalf("NewModel(%q) error = %v", family, err)
			}
			envelopes, err := model.Encode(messages)
			if err != nil {
				t.Fatalf("Encode(%q) error = %v", family, err)
			}
			if len(envelopes) == 0 {
				t.Fatalf("%q emitted no envelopes", family)
			}
			for _, env := range envelopes {
				if err := ValidateEnvelope(p, env); err != nil {
					t.Fatalf("invalid envelope for %q: %v", family, err)
				}
				if env.ByteCount > p.CarrierPolicy.MaxEnvelopeBytes {
					t.Fatalf("envelope exceeds profile limit: %d > %d", env.ByteCount, p.CarrierPolicy.MaxEnvelopeBytes)
				}
			}
			decoded, err := model.Decode(envelopes)
			if err != nil {
				t.Fatalf("Decode(%q) error = %v", family, err)
			}
			if !SemanticallyEquivalent(messages, decoded) {
				t.Fatalf("%q did not preserve semantics:\nwant=%#v\ngot=%#v", family, messages, decoded)
			}
		})
	}
}

func TestCarrierRejectsUnknownMalformedAndOversized(t *testing.T) {
	p, err := compiler.Generate(11002)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := NewModel(p, "real_http_carrier"); err == nil {
		t.Fatalf("unknown carrier family accepted")
	}
	model, err := NewModel(p, "stream_carrier")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := model.Decode([]Envelope{{CarrierFamily: "stream_carrier", Sequence: 1, Kind: "bad", ByteCount: -1}}); err == nil {
		t.Fatalf("malformed envelope accepted")
	}
	if err := ValidateEnvelope(p, Envelope{CarrierFamily: "stream_carrier", Sequence: 1, Kind: "data", ByteCount: p.CarrierPolicy.MaxEnvelopeBytes + 1}); err == nil {
		t.Fatalf("oversized envelope accepted")
	}
}

func TestCarrierPolicyVariationAcrossSeeds(t *testing.T) {
	families := map[string]bool{}
	encodings := map[string]bool{}
	flushes := map[string]bool{}
	for seed := int64(1); seed <= 64; seed++ {
		p, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		families[p.CarrierPolicy.CarrierFamily] = true
		encodings[p.CarrierPolicy.EnvelopeEncoding] = true
		flushes[p.CarrierPolicy.FlushPolicy] = true
	}
	if len(families) < 6 || len(encodings) < 4 || len(flushes) < 4 {
		t.Fatalf("carrier policy diversity too low: families=%d encodings=%d flushes=%d", len(families), len(encodings), len(flushes))
	}
}
