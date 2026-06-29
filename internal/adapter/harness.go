// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import "fmt"

type Harness struct {
	cfg      AdapterConfig
	caps     AdapterCapabilities
	flows    map[FlowID]*Flow
	buffered int
	seq      uint64
	events   int
	summary  AdapterHarnessSummary
}

func NewHarness(cfg AdapterConfig, caps AdapterCapabilities) (*Harness, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	return &Harness{
		cfg:   cfg,
		caps:  caps,
		flows: map[FlowID]*Flow{},
		summary: AdapterHarnessSummary{
			AdapterName:   cfg.Name,
			PayloadLogged: false,
			SecretLogged:  false,
		},
	}, nil
}

func (h *Harness) Name() string {
	if h == nil {
		return ""
	}
	return h.cfg.Name
}

func (h *Harness) ValidateConfig(cfg AdapterConfig) error {
	return ValidateConfig(cfg)
}

func (h *Harness) OpenFlow(desc FlowDescriptor) error {
	if h == nil {
		return fmt.Errorf("%w: nil harness", ErrInvalidConfig)
	}
	if len(h.flows) >= h.cfg.MaxFlows {
		return fmt.Errorf("%w: max flows", ErrResourceLimit)
	}
	if _, ok := h.flows[desc.ID]; ok {
		return ErrFlowExists
	}
	flow, err := NewFlow(desc)
	if err != nil {
		return err
	}
	if err := flow.Open(h.caps); err != nil {
		return err
	}
	h.flows[desc.ID] = flow
	h.summary.FlowsOpened++
	h.summary.RuntimeStreamsOpened++
	return h.recordEvent()
}

func (h *Harness) ReadFlow(id FlowID, n int) (AdapterChunk, error) {
	flow, err := h.flow(id)
	if err != nil {
		return AdapterChunk{}, err
	}
	if n > h.cfg.MaxFlowBytes {
		return AdapterChunk{}, fmt.Errorf("%w: read too large", ErrResourceLimit)
	}
	if err := flow.RecordRead(n); err != nil {
		return AdapterChunk{}, err
	}
	h.seq++
	h.summary.ChunksRead++
	h.summary.BytesIn += n
	h.buffered += n
	chunk := AdapterChunk{FlowID: id, Sequence: h.seq, ByteCount: n, MetadataClass: "byte_count"}
	if h.buffered > h.cfg.MaxBufferedBytes {
		chunk.Backpressure = true
		h.summary.BackpressureEvents++
		return chunk, ErrBackpressure
	}
	return chunk, h.recordEvent()
}

func (h *Harness) WriteFlow(id FlowID, chunk AdapterChunk) error {
	flow, err := h.flow(id)
	if err != nil {
		return err
	}
	if err := ValidateChunk(chunk, h.cfg.MaxFlowBytes); err != nil {
		return err
	}
	if err := flow.RecordWrite(chunk.ByteCount); err != nil {
		return err
	}
	h.summary.ChunksWritten++
	h.summary.BytesOut += chunk.ByteCount
	h.buffered -= chunk.ByteCount
	if h.buffered < 0 {
		h.buffered = 0
	}
	if chunk.Backpressure {
		h.summary.BackpressureEvents++
	}
	return h.recordEvent()
}

func (h *Harness) CloseFlow(id FlowID) error {
	flow, err := h.flow(id)
	if err != nil {
		return err
	}
	wasClosed := flow.State == FlowClosed
	if err := flow.Close(h.caps); err != nil {
		return err
	}
	if !wasClosed && flow.State == FlowClosed {
		h.summary.FlowsClosed++
		h.summary.RuntimeStreamsClosed++
	}
	return h.recordEvent()
}

func (h *Harness) ResetFlow(id FlowID, reason string) error {
	flow, err := h.flow(id)
	if err != nil {
		return err
	}
	wasReset := flow.State == FlowReset
	if err := flow.Reset(h.caps, reason); err != nil {
		return err
	}
	if !wasReset && flow.State == FlowReset {
		h.summary.FlowsReset++
		h.summary.RuntimeStreamsClosed++
	}
	return h.recordEvent()
}

func (h *Harness) HalfCloseFlow(id FlowID) error {
	flow, err := h.flow(id)
	if err != nil {
		return err
	}
	return flow.Transition(FlowHalfClosed, h.caps)
}

func (h *Harness) Summary() AdapterSummary {
	s := h.summary
	return AdapterSummary{
		AdapterName:        s.AdapterName,
		AdapterKind:        string(h.cfg.Kind),
		FlowsOpened:        s.FlowsOpened,
		FlowsClosed:        s.FlowsClosed,
		FlowsReset:         s.FlowsReset,
		ChunksRead:         s.ChunksRead,
		ChunksWritten:      s.ChunksWritten,
		BytesIn:            s.BytesIn,
		BytesOut:           s.BytesOut,
		BackpressureEvents: s.BackpressureEvents,
		PayloadLogged:      s.PayloadLogged,
		SecretLogged:       s.SecretLogged,
	}
}

func (h *Harness) HarnessSummary() AdapterHarnessSummary {
	return h.summary
}

func (h *Harness) flow(id FlowID) (*Flow, error) {
	if h == nil {
		return nil, fmt.Errorf("%w: nil harness", ErrInvalidConfig)
	}
	flow, ok := h.flows[id]
	if !ok {
		return nil, ErrFlowNotFound
	}
	return flow, nil
}

func (h *Harness) recordEvent() error {
	h.events++
	if h.events > h.cfg.MaxEvents {
		return fmt.Errorf("%w: max events", ErrResourceLimit)
	}
	return nil
}
