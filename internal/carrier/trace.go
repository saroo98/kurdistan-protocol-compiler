// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import (
	"strings"

	ktrace "kurdistan/internal/trace"
)

func TraceEvents(profileID, scenario string, envelopes []Envelope, reconstructed bool) []ktrace.Event {
	events := make([]ktrace.Event, 0, len(envelopes))
	for _, env := range envelopes {
		events = append(events, ktrace.Event{
			ProfileID:             profileID,
			EventType:             "carrier_envelope",
			StreamLabel:           streamLabel(env.StreamID),
			CarrierFamilyBucket:   env.CarrierFamily,
			CarrierEnvelopeKind:   env.Kind,
			CarrierEnvelopeCount:  bucket(env.MessageCount),
			CarrierSemanticCount:  bucket(env.MessageCount),
			CarrierChunkCount:     bucket(env.ChunkIndex + 1),
			CarrierBatchCount:     bucket(env.MessageCount),
			CarrierFlushClass:     env.FlushClass,
			CarrierRetryCount:     bucket(env.Reliability.RetryCount),
			CarrierReordered:      env.Reliability.Reordered,
			CarrierDropped:        env.Reliability.Dropped,
			CarrierBackpressure:   env.Backpressure,
			CarrierQueueDepth:     bucket(env.QueueDepth),
			CarrierReconstruction: reconstructionBucket(reconstructed),
			CarrierScenario:       scenario,
			Backpressure:          env.Backpressure,
			Note:                  policyNote(env),
		})
	}
	return events
}

func policyNote(env Envelope) string {
	return strings.Join([]string{
		"carrier_envelope_encoding=" + env.EncodingClass,
		"carrier_flush_policy=" + env.FlushClass,
		"carrier_batch_policy=" + env.BatchClass,
		"carrier_chunking_policy=" + env.ChunkingClass,
		"carrier_priority_mapping=" + env.PriorityClass,
		"carrier_error_reset=preserved",
	}, ";")
}

func streamLabel(id uint64) string {
	return "carrier_stream_bucket_" + bucket(int(id%8))
}

func bucket(value int) string {
	switch {
	case value <= 0:
		return "none"
	case value == 1:
		return "one"
	case value <= 3:
		return "few"
	case value <= 8:
		return "some"
	default:
		return "many"
	}
}

func reconstructionBucket(ok bool) string {
	if ok {
		return "equivalent"
	}
	return "failed"
}
