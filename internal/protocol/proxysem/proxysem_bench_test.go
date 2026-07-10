// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

import "testing"

func BenchmarkRegistryLookup(b *testing.B) {
	registry := DefaultRegistry()
	for i := 0; i < b.N; i++ {
		if _, ok := registry.Lookup(TargetEcho); !ok {
			b.Fatal("missing echo target")
		}
	}
}

func BenchmarkEchoTarget(b *testing.B) {
	benchmarkTarget(b, TargetDescriptor{Class: TargetEcho}, TargetRequest{StreamID: 1, Bytes: 1024, Class: RequestInteractive})
}

func BenchmarkFixedResponseTarget(b *testing.B) {
	benchmarkTarget(b, TargetDescriptor{Class: TargetFixedResponse, Parameters: map[string]string{"bytes": "8192"}}, TargetRequest{StreamID: 1, Bytes: 128, Class: RequestBulk})
}

func BenchmarkChunkedResponseTarget(b *testing.B) {
	benchmarkTarget(b, TargetDescriptor{Class: TargetChunkedResponse, Parameters: map[string]string{"bytes": "32768", "chunks": "8"}}, TargetRequest{StreamID: 1, Bytes: 128, Class: RequestBulk})
}

func BenchmarkLargeObjectTarget(b *testing.B) {
	benchmarkTarget(b, TargetDescriptor{Class: TargetLargeObject, Parameters: map[string]string{"bytes": "262144"}}, TargetRequest{StreamID: 1, Bytes: 128, Class: RequestBulk})
}

func benchmarkTarget(b *testing.B, desc TargetDescriptor, req TargetRequest) {
	b.Helper()
	registry := DefaultRegistry()
	for i := 0; i < b.N; i++ {
		if _, _, err := registry.Run(desc, req, int64(i)); err != nil {
			b.Fatal(err)
		}
	}
}
