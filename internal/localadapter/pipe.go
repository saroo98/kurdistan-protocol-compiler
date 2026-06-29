// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

type MemoryPipeAdapter struct {
	Ingress *MemoryIngressAdapter
	Egress  *MemoryEgressAdapter
}

func NewMemoryPipe(cfg LocalAdapterConfig) (*MemoryPipeAdapter, error) {
	in, err := NewMemoryIngress(cfg)
	if err != nil {
		return nil, err
	}
	eg, err := NewMemoryEgress(cfg)
	if err != nil {
		return nil, err
	}
	return &MemoryPipeAdapter{Ingress: in, Egress: eg}, nil
}

func (p *MemoryPipeAdapter) Summary() LocalAdapterSummary {
	if p == nil {
		return LocalAdapterSummary{}
	}
	in := p.Ingress.Summary()
	eg := p.Egress.Summary()
	in.SinkModel = eg.SinkModel
	in.SinkChunks = eg.SinkChunks
	in.SinkBytes = eg.SinkBytes
	in.FlowsClosed += eg.FlowsClosed
	in.FlowsReset += eg.FlowsReset
	in.SequenceRejected += eg.SequenceRejected
	in.PostCloseRejected += eg.PostCloseRejected
	in.RuntimeStreamsOpened += eg.RuntimeStreamsOpened
	in.RuntimeStreamsClosed += eg.RuntimeStreamsClosed
	in.Completed = in.SourceChunks > 0 && eg.SinkChunks > 0 && !in.PayloadLogged && !in.SecretLogged
	return in
}
