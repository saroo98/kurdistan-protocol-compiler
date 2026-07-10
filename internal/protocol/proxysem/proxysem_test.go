// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

import (
	"encoding/json"
	"testing"
)

func TestRelayIntentValidationRejectsUnsafeDescriptor(t *testing.T) {
	intent := RelayIntent{
		StreamID:         1,
		Target:           TargetDescriptor{Class: "external", Variant: "real-host", Parameters: map[string]string{"host": "example.com"}},
		RequestClass:     RequestInteractive,
		PriorityClass:    PriorityInteractive,
		ResponseMode:     ResponseImmediate,
		MaxRequestBytes:  1024,
		MaxResponseBytes: 2048,
	}
	if err := ValidateRelayIntent(intent); err == nil {
		t.Fatalf("expected unsafe descriptor to be rejected")
	}
}

func TestSyntheticTargets(t *testing.T) {
	tests := []struct {
		name          string
		descriptor    TargetDescriptor
		requestBytes  int
		wantResponse  int
		wantChunks    int
		wantError     bool
		wantReset     bool
		wantBackpress bool
	}{
		{name: "echo", descriptor: TargetDescriptor{Class: TargetEcho}, requestBytes: 777, wantResponse: 777, wantChunks: 1},
		{name: "discard", descriptor: TargetDescriptor{Class: TargetDiscard}, requestBytes: 777, wantResponse: 0, wantChunks: 0},
		{name: "fixed", descriptor: TargetDescriptor{Class: TargetFixedResponse, Parameters: map[string]string{"bytes": "4096"}}, requestBytes: 12, wantResponse: 4096, wantChunks: 1},
		{name: "slow", descriptor: TargetDescriptor{Class: TargetSlowResponse, Parameters: map[string]string{"bytes": "2048", "ticks": "3"}}, requestBytes: 12, wantResponse: 2048, wantChunks: 3, wantBackpress: true},
		{name: "chunked", descriptor: TargetDescriptor{Class: TargetChunkedResponse, Parameters: map[string]string{"bytes": "3000", "chunks": "3"}}, requestBytes: 12, wantResponse: 3000, wantChunks: 3},
		{name: "large", descriptor: TargetDescriptor{Class: TargetLargeObject, Parameters: map[string]string{"bytes": "131072"}}, requestBytes: 12, wantResponse: 131072},
		{name: "error", descriptor: TargetDescriptor{Class: TargetErrorResponse}, requestBytes: 12, wantError: true},
		{name: "reset", descriptor: TargetDescriptor{Class: TargetResetMidstream, Parameters: map[string]string{"partial": "128"}}, requestBytes: 12, wantResponse: 128, wantReset: true},
		{name: "drip", descriptor: TargetDescriptor{Class: TargetDripResponse, Parameters: map[string]string{"bytes": "512", "chunks": "8"}}, requestBytes: 12, wantResponse: 512, wantChunks: 8},
		{name: "jittery", descriptor: TargetDescriptor{Class: TargetJitteryResponse, Parameters: map[string]string{"bytes": "1024", "seed": "7"}}, requestBytes: 12, wantResponse: 1024},
	}
	registry := DefaultRegistry()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chunks, result, err := registry.Run(tt.descriptor, TargetRequest{StreamID: 3, Bytes: tt.requestBytes, Class: RequestInteractive}, 99)
			if tt.wantError {
				if err == nil && result.ErrorCode == "" {
					t.Fatalf("expected target error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.ResponseBytes != tt.wantResponse {
				t.Fatalf("response bytes = %d, want %d", result.ResponseBytes, tt.wantResponse)
			}
			if tt.wantChunks > 0 && result.ChunkCount != tt.wantChunks {
				t.Fatalf("chunk count = %d, want %d", result.ChunkCount, tt.wantChunks)
			}
			if result.Reset != tt.wantReset {
				t.Fatalf("reset = %v, want %v", result.Reset, tt.wantReset)
			}
			if tt.wantBackpress && !chunksHaveBackpressure(chunks) {
				t.Fatalf("expected target-induced backpressure chunk")
			}
			raw, err := json.Marshal(chunks)
			if err != nil {
				t.Fatal(err)
			}
			if containsPayloadMarker(raw) {
				t.Fatalf("target chunks leaked payload-like marker")
			}
		})
	}
}

func TestRegistryRejectsUnknownAndOversizedTargets(t *testing.T) {
	registry := DefaultRegistry()
	if err := registry.Validate(TargetDescriptor{Class: "unknown"}); err == nil {
		t.Fatalf("expected unknown target class to be rejected")
	}
	if err := registry.Validate(TargetDescriptor{Class: TargetFixedResponse, Parameters: map[string]string{"bytes": "999999999"}}); err == nil {
		t.Fatalf("expected oversized target parameter to be rejected")
	}
}

func chunksHaveBackpressure(chunks []TargetChunk) bool {
	for _, chunk := range chunks {
		if chunk.Backpressure {
			return true
		}
	}
	return false
}

func containsPayloadMarker(raw []byte) bool {
	for _, marker := range [][]byte{[]byte("request-body"), []byte("payload"), []byte("secret")} {
		if json.Valid(marker) && string(marker) == string(raw) {
			return true
		}
	}
	return false
}
