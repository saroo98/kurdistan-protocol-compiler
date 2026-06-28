// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrier

import "kurdistan/internal/ir"

const (
	FamilyStream         = "stream_carrier"
	FamilyMessage        = "message_carrier"
	FamilyDatagramLike   = "datagram_like_carrier"
	FamilyChunked        = "chunked_carrier"
	FamilyBatch          = "batch_carrier"
	FamilyInteractive    = "interactive_carrier"
	FamilyLongPollStyle  = "long_poll_style_carrier"
	FamilyLossyReordered = "lossy_reordered_carrier"
)

type SemanticMessage struct {
	StreamID      uint64 `json:"stream_id"`
	Semantic      string `json:"semantic"`
	ByteCount     int    `json:"byte_count"`
	PriorityClass string `json:"priority_class,omitempty"`
	MetadataClass string `json:"metadata_class,omitempty"`
	OriginalIndex int    `json:"original_index,omitempty"`
}

type Model interface {
	Name() string
	Encode([]SemanticMessage) ([]Envelope, error)
	Decode([]Envelope) ([]SemanticMessage, error)
	Validate() error
}

func RequiredFamilies() []string {
	return ir.CarrierFamilies()
}
