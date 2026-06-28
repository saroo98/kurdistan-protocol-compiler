// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import (
	"testing"

	"kurdistan/internal/compiler"
)

func BenchmarkCarrierRegistryLookup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		if !Lookup(FamilyStream) {
			b.Fatal("missing family")
		}
	}
}

func BenchmarkStreamCarrierRoundTrip(b *testing.B) {
	benchmarkRoundTrip(b, FamilyStream)
}

func BenchmarkMessageCarrierRoundTrip(b *testing.B) {
	benchmarkRoundTrip(b, FamilyMessage)
}

func BenchmarkChunkedCarrierLargeResponse(b *testing.B) {
	benchmarkRoundTrip(b, FamilyChunked)
}

func BenchmarkBatchCarrierManySmallMessages(b *testing.B) {
	benchmarkRoundTrip(b, FamilyBatch)
}

func BenchmarkLongPollCarrierQueueCycle(b *testing.B) {
	benchmarkRoundTrip(b, FamilyLongPollStyle)
}

func BenchmarkLossyReorderedCarrierRecovery(b *testing.B) {
	benchmarkRoundTrip(b, FamilyLossyReordered)
}

func benchmarkRoundTrip(b *testing.B, family string) {
	p, err := compiler.Generate(12001)
	if err != nil {
		b.Fatal(err)
	}
	messages := make([]SemanticMessage, 32)
	for i := range messages {
		messages[i] = SemanticMessage{StreamID: uint64(i%4 + 1), Semantic: "target_response", ByteCount: 2048 + i, PriorityClass: "bulk"}
	}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := RoundTrip(p, family, messages); err != nil {
			b.Fatal(err)
		}
	}
}
