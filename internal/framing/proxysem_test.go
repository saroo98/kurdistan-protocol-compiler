// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package framing

import (
	"testing"

	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
)

func TestProxySemanticEncodeDecodeRoundTrip(t *testing.T) {
	p, err := compiler.Generate(222)
	if err != nil {
		t.Fatal(err)
	}
	tests := []Operation{
		{Semantic: ir.SemanticOpenRelay, StreamID: 1, RelayIntentID: 7, TargetClass: "echo", RequestClass: "interactive", ResponseMode: "immediate"},
		{Semantic: ir.SemanticTargetDescriptor, StreamID: 1, RelayIntentID: 7, TargetClass: "fixed_response", TargetVariant: "small", RequestClass: "bulk"},
		{Semantic: ir.SemanticTargetData, StreamID: 1, RelayIntentID: 7, PayloadByteCount: 1024, Payload: make([]byte, 64)},
		{Semantic: ir.SemanticTargetResponse, StreamID: 1, RelayIntentID: 7, ResponseByteCount: 2048, ResponseChunkIndex: 2, Payload: make([]byte, 32)},
		{Semantic: ir.SemanticTargetError, StreamID: 1, RelayIntentID: 7, TargetErrorCode: "synthetic_error"},
		{Semantic: ir.SemanticTargetClose, StreamID: 1, RelayIntentID: 7, TargetCloseReason: "complete", EndStream: true},
		{Semantic: ir.SemanticTargetReset, StreamID: 1, RelayIntentID: 7, TargetResetReason: "reset_midstream"},
		{Semantic: ir.SemanticTargetMetadata, StreamID: 1, RelayIntentID: 7, MetadataClass: "slow_tick"},
	}
	for _, op := range tests {
		t.Run(op.Semantic, func(t *testing.T) {
			frames, err := EncodeOperation(p, op, 9)
			if err != nil {
				t.Fatal(err)
			}
			decoded, _, err := DecodeFrames(p, frames)
			if err != nil {
				t.Fatal(err)
			}
			if decoded.Semantic != op.Semantic || decoded.StreamID != op.StreamID || decoded.RelayIntentID != op.RelayIntentID {
				t.Fatalf("decoded identity mismatch: %+v", decoded)
			}
			if decoded.TargetClass != op.TargetClass || decoded.TargetErrorCode != op.TargetErrorCode || decoded.ResponseChunkIndex != op.ResponseChunkIndex {
				t.Fatalf("decoded proxy metadata mismatch: %+v", decoded)
			}
		})
	}
}

func TestProxySemanticEncodingDiffersAcrossProfiles(t *testing.T) {
	a, err := compiler.Generate(301)
	if err != nil {
		t.Fatal(err)
	}
	b, err := compiler.Generate(302)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Semantic: ir.SemanticOpenRelay, StreamID: 1, RelayIntentID: 9, TargetClass: "echo", RequestClass: "interactive", ResponseMode: "immediate"}
	framesA, err := EncodeOperation(a, op, 1)
	if err != nil {
		t.Fatal(err)
	}
	framesB, err := EncodeOperation(b, op, 1)
	if err != nil {
		t.Fatal(err)
	}
	if string(framesA[0]) == string(framesB[0]) {
		t.Fatalf("same proxy semantic encoded identically across profiles")
	}
	decoded, _, err := DecodeFrames(b, framesA)
	if err == nil && decoded.Semantic == op.Semantic && decoded.TargetClass == op.TargetClass {
		t.Fatalf("profile B accepted profile A proxy frame as equivalent")
	}
}

func TestProxySemanticOversizedMetadataRejected(t *testing.T) {
	p, err := compiler.Generate(333)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Semantic: ir.SemanticTargetResponse, StreamID: 1, RelayIntentID: 1, ResponseByteCount: p.ProxySemantics.MaxResponseBytes + 1}
	if _, err := EncodeOperation(p, op, 1); err == nil {
		t.Fatalf("expected oversized proxy response to be rejected")
	}
}
