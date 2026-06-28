// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import (
	"fmt"

	"kurdistan/internal/ir"
)

type Envelope struct {
	CarrierFamily string              `json:"carrier_family"`
	Sequence      uint64              `json:"sequence"`
	Kind          string              `json:"kind"`
	StreamID      uint64              `json:"stream_id,omitempty"`
	MessageCount  int                 `json:"message_count"`
	ByteCount     int                 `json:"byte_count"`
	ChunkIndex    int                 `json:"chunk_index,omitempty"`
	FinalChunk    bool                `json:"final_chunk,omitempty"`
	FlushClass    string              `json:"flush_class,omitempty"`
	PaddingClass  string              `json:"padding_class,omitempty"`
	TimingBucket  string              `json:"timing_bucket,omitempty"`
	EncodingClass string              `json:"encoding_class,omitempty"`
	BatchClass    string              `json:"batch_class,omitempty"`
	ChunkingClass string              `json:"chunking_class,omitempty"`
	PriorityClass string              `json:"priority_class,omitempty"`
	Reliability   ReliabilityMetadata `json:"reliability"`
	Backpressure  bool                `json:"backpressure,omitempty"`
	QueueDepth    int                 `json:"queue_depth,omitempty"`
	Messages      []SemanticMessage   `json:"messages,omitempty"`
}

type ReliabilityMetadata struct {
	AckRequired bool   `json:"ack_required,omitempty"`
	AckSequence uint64 `json:"ack_sequence,omitempty"`
	RetryCount  int    `json:"retry_count,omitempty"`
	Dropped     bool   `json:"dropped,omitempty"`
	Reordered   bool   `json:"reordered,omitempty"`
}

func ValidateEnvelope(p *ir.Profile, env Envelope) error {
	if p == nil {
		return fmt.Errorf("profile is nil")
	}
	if !familyAllowed(env.CarrierFamily) {
		return fmt.Errorf("unknown carrier family %q", env.CarrierFamily)
	}
	if env.Sequence == 0 {
		return fmt.Errorf("envelope sequence is required")
	}
	if !kindAllowed(env.Kind) {
		return fmt.Errorf("invalid envelope kind %q", env.Kind)
	}
	if env.ByteCount < 0 || env.ByteCount > p.CarrierPolicy.MaxEnvelopeBytes {
		return fmt.Errorf("invalid envelope byte count")
	}
	if env.MessageCount < 0 || env.MessageCount > p.CarrierPolicy.MaxMessagesPerEnvelope {
		return fmt.Errorf("invalid envelope message count")
	}
	if env.Reliability.RetryCount < 0 || env.Reliability.RetryCount > p.CarrierPolicy.MaxRetryCount+1 {
		return fmt.Errorf("invalid retry count")
	}
	for _, msg := range env.Messages {
		if msg.Semantic == "" || msg.ByteCount < 0 {
			return fmt.Errorf("invalid semantic message in envelope")
		}
	}
	return nil
}

func familyAllowed(value string) bool {
	for _, family := range RequiredFamilies() {
		if value == family {
			return true
		}
	}
	return false
}

func kindAllowed(value string) bool {
	switch value {
	case "data", "coalesced", "chunk", "batch", "poll_request", "poll_response", "datagram", "retry":
		return true
	default:
		return false
	}
}
