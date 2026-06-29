// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"fmt"

	"kurdistan/internal/adapter"
)

type MemoryIngressAdapter struct {
	harness *adapter.Harness
	cfg     LocalAdapterConfig
	summary LocalAdapterSummary
}

type MemoryEgressAdapter struct {
	harness *adapter.Harness
	sink    *LocalSink
	cfg     LocalAdapterConfig
	summary LocalAdapterSummary
}

func NewMemoryIngress(cfg LocalAdapterConfig) (*MemoryIngressAdapter, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	h, err := adapter.NewHarness(AdapterConfig(cfg, adapter.AdapterKindIngress), adapter.DefaultCapabilities())
	if err != nil {
		return nil, err
	}
	return &MemoryIngressAdapter{harness: h, cfg: cfg, summary: LocalAdapterSummary{Name: cfg.Name, PayloadLogged: false, SecretLogged: false}}, nil
}

func NewMemoryEgress(cfg LocalAdapterConfig) (*MemoryEgressAdapter, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	h, err := adapter.NewHarness(AdapterConfig(cfg, adapter.AdapterKindEgress), adapter.DefaultCapabilities())
	if err != nil {
		return nil, err
	}
	sink, err := NewSink(cfg)
	if err != nil {
		return nil, err
	}
	return &MemoryEgressAdapter{harness: h, sink: sink, cfg: cfg, summary: LocalAdapterSummary{Name: cfg.Name, SinkModel: "memory_sink", PayloadLogged: false, SecretLogged: false}}, nil
}

func (m *MemoryIngressAdapter) OpenFlow(desc adapter.FlowDescriptor) error {
	if m == nil {
		return fmt.Errorf("%w: nil ingress", adapter.ErrInvalidConfig)
	}
	if err := m.harness.OpenFlow(desc); err != nil {
		return err
	}
	m.summary.FlowsOpened++
	return nil
}

func (m *MemoryIngressAdapter) ReadSource(chunk LocalSourceChunk) (adapter.AdapterChunk, error) {
	if m == nil {
		return adapter.AdapterChunk{}, fmt.Errorf("%w: nil ingress", adapter.ErrInvalidConfig)
	}
	if err := ValidateSourceChunk(chunk, m.cfg); err != nil {
		m.summary.SequenceRejected++
		return adapter.AdapterChunk{}, err
	}
	out, err := m.harness.ReadFlow(chunk.FlowID, chunk.ByteCount)
	if err != nil && err != adapter.ErrBackpressure {
		return out, err
	}
	m.summary.SourceChunks++
	m.summary.SourceBytes += chunk.ByteCount
	if err == adapter.ErrBackpressure || out.Backpressure {
		m.summary.BackpressureEvents++
		return out, ErrLocalBackpressure
	}
	return out, nil
}

func (m *MemoryIngressAdapter) CloseFlow(id adapter.FlowID) error {
	if m == nil {
		return fmt.Errorf("%w: nil ingress", adapter.ErrInvalidConfig)
	}
	if err := m.harness.CloseFlow(id); err != nil {
		return err
	}
	m.summary.FlowsClosed++
	return nil
}

func (m *MemoryIngressAdapter) ResetFlow(id adapter.FlowID, reason string) error {
	if m == nil {
		return fmt.Errorf("%w: nil ingress", adapter.ErrInvalidConfig)
	}
	if err := m.harness.ResetFlow(id, reason); err != nil {
		return err
	}
	m.summary.FlowsReset++
	return nil
}

func (m *MemoryIngressAdapter) Summary() LocalAdapterSummary {
	if m == nil {
		return LocalAdapterSummary{}
	}
	sum := m.summary
	hs := m.harness.HarnessSummary()
	sum.RuntimeStreamsOpened = hs.RuntimeStreamsOpened
	sum.RuntimeStreamsClosed = hs.RuntimeStreamsClosed
	return sum
}

func (m *MemoryEgressAdapter) OpenFlow(desc adapter.FlowDescriptor) error {
	if m == nil {
		return fmt.Errorf("%w: nil egress", adapter.ErrInvalidConfig)
	}
	if err := m.harness.OpenFlow(desc); err != nil {
		return err
	}
	m.summary.FlowsOpened++
	return nil
}

func (m *MemoryEgressAdapter) WriteSink(chunk LocalSinkChunk) error {
	if m == nil {
		return fmt.Errorf("%w: nil egress", adapter.ErrInvalidConfig)
	}
	if err := m.sink.Write(chunk); err != nil {
		if err == ErrClosedSink {
			m.summary.PostCloseRejected++
		} else {
			m.summary.SequenceRejected++
		}
		return err
	}
	if err := m.harness.WriteFlow(chunk.FlowID, adapter.AdapterChunk{FlowID: chunk.FlowID, Sequence: chunk.Sequence, ByteCount: chunk.ByteCount, Final: chunk.Final, Reset: chunk.Reset, MetadataClass: chunk.MetadataClass}); err != nil {
		return err
	}
	m.summary.SinkChunks++
	m.summary.SinkBytes += chunk.ByteCount
	if chunk.Final {
		m.summary.FlowsClosed++
	}
	if chunk.Reset {
		m.summary.FlowsReset++
	}
	return nil
}

func (m *MemoryEgressAdapter) Summary() LocalAdapterSummary {
	if m == nil {
		return LocalAdapterSummary{}
	}
	sum := m.summary
	hs := m.harness.HarnessSummary()
	sum.RuntimeStreamsOpened = hs.RuntimeStreamsOpened
	sum.RuntimeStreamsClosed = hs.RuntimeStreamsClosed
	return sum
}
