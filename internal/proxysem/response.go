// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxysem

type TargetChunk struct {
	StreamID      uint64 `json:"stream_id"`
	ChunkIndex    int    `json:"chunk_index"`
	Bytes         int    `json:"bytes"`
	Final         bool   `json:"final"`
	ErrorCode     string `json:"error_code,omitempty"`
	Reset         bool   `json:"reset,omitempty"`
	Backpressure  bool   `json:"backpressure,omitempty"`
	MetadataClass string `json:"metadata_class,omitempty"`
	Tick          int    `json:"tick,omitempty"`
}

type TargetResult struct {
	StreamID      uint64 `json:"stream_id"`
	ResponseBytes int    `json:"response_bytes"`
	ChunkCount    int    `json:"chunk_count"`
	ErrorCode     string `json:"error_code,omitempty"`
	Closed        bool   `json:"closed"`
	Reset         bool   `json:"reset,omitempty"`
}
