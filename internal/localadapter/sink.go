// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"fmt"

	"kurdistan/internal/adapter"
)

type LocalSinkChunk struct {
	FlowID        adapter.FlowID `json:"flow_id"`
	Sequence      uint64         `json:"sequence"`
	ByteCount     int            `json:"byte_count"`
	Final         bool           `json:"final"`
	Reset         bool           `json:"reset"`
	MetadataClass string         `json:"metadata_class"`
}

type LocalSink struct {
	cfg      LocalAdapterConfig
	lastSeq  map[adapter.FlowID]uint64
	closed   map[adapter.FlowID]bool
	reset    map[adapter.FlowID]bool
	chunks   int
	bytes    int
	rejected int
}

func NewSink(cfg LocalAdapterConfig) (*LocalSink, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	return &LocalSink{
		cfg:     cfg,
		lastSeq: map[adapter.FlowID]uint64{},
		closed:  map[adapter.FlowID]bool{},
		reset:   map[adapter.FlowID]bool{},
	}, nil
}

func (s *LocalSink) Write(chunk LocalSinkChunk) error {
	if s == nil {
		return fmt.Errorf("%w: nil sink", adapter.ErrInvalidConfig)
	}
	if chunk.FlowID == "" || chunk.Sequence == 0 || chunk.ByteCount < 0 || chunk.ByteCount > s.cfg.MaxChunkBytes {
		s.rejected++
		return fmt.Errorf("%w: sink chunk", ErrInvalidSourceChunk)
	}
	if s.closed[chunk.FlowID] || s.reset[chunk.FlowID] {
		s.rejected++
		return ErrClosedSink
	}
	if last := s.lastSeq[chunk.FlowID]; last != 0 && chunk.Sequence <= last {
		s.rejected++
		return ErrInvalidSequence
	}
	s.lastSeq[chunk.FlowID] = chunk.Sequence
	s.chunks++
	s.bytes += chunk.ByteCount
	if chunk.Final {
		s.closed[chunk.FlowID] = true
	}
	if chunk.Reset {
		s.reset[chunk.FlowID] = true
	}
	return nil
}

func (s *LocalSink) Summary() (chunks, bytes, rejected int) {
	if s == nil {
		return 0, 0, 0
	}
	return s.chunks, s.bytes, s.rejected
}
