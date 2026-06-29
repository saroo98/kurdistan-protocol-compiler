// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"fmt"

	"kurdistan/internal/adapter"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxysem"
	ktrace "kurdistan/internal/trace"
)

type AdapterBoundaryOptions struct {
	Scenario            string
	FlowCount           int
	BytesPerFlow        int
	LargeFlowBytes      int
	ResetFlow           bool
	TargetError         bool
	TargetReset         bool
	Backpressure        bool
	HalfClose           bool
	CapabilityDowngrade bool
	MalformedFlow       bool
	MaxFlows            int
	MaxStreams          int
}

type AdapterBoundaryResult struct {
	Summary adapter.AdapterHarnessSummary `json:"summary"`
	Events  []ktrace.Event                `json:"events"`
}

func RunAdapterBoundary(ctx context.Context, p *ir.Profile, opts AdapterBoundaryOptions) (AdapterBoundaryResult, error) {
	if err := ctx.Err(); err != nil {
		return AdapterBoundaryResult{}, err
	}
	if err := ValidateLoadedProfile(p); err != nil {
		return AdapterBoundaryResult{}, err
	}
	if opts.Scenario == "" {
		opts.Scenario = "single_flow_happy_path"
	}
	if opts.FlowCount <= 0 {
		opts.FlowCount = 1
	}
	if opts.BytesPerFlow <= 0 {
		opts.BytesPerFlow = 128
	}
	if opts.MaxFlows <= 0 {
		opts.MaxFlows = min(p.Stream.MaxConcurrentStreams, 16)
	}
	if opts.MaxStreams <= 0 {
		opts.MaxStreams = p.Stream.MaxConcurrentStreams
	}
	cfg := adapter.DefaultConfig("adapter-local", adapter.AdapterKindIngress)
	cfg.RuntimeID = "runtime-adapter"
	cfg.MaxFlows = min(opts.MaxFlows, adapter.MaxAdapterFlows)
	cfg.MaxFlowBytes = max(p.ProxySemantics.MaxResponseBytes, max(opts.BytesPerFlow, opts.LargeFlowBytes))
	cfg.MaxBufferedBytes = p.CarrierPolicy.MaxEnvelopeBytes * max(1, p.CarrierPolicy.MaxCarrierQueueDepth)
	if opts.Backpressure {
		cfg.MaxBufferedBytes = max(64, opts.BytesPerFlow/2)
	}
	required := adapter.DefaultCapabilityNames()
	if opts.CapabilityDowngrade {
		required = []string{adapter.CapabilityIngress, adapter.CapabilityFlowLifecycle}
	}
	if err := adapter.RequireCapabilities(adapter.DefaultCapabilityNames(), required); err != nil {
		return AdapterBoundaryResult{}, err
	}
	cfg.Capabilities = required
	h, err := adapter.NewHarness(cfg, adapter.DefaultCapabilities())
	if err != nil {
		return AdapterBoundaryResult{}, err
	}
	rtCfg := DefaultConfig(RoleClient, "runtime-adapter", []byte("adapter-boundary-secret:"+p.ID))
	rtCfg.MaxStreams = opts.MaxStreams
	rt, err := NewRuntime(rtCfg, p)
	if err != nil {
		return AdapterBoundaryResult{}, err
	}
	manager := NewManager(rt)
	session, err := manager.CreateSession()
	if err != nil {
		return AdapterBoundaryResult{}, err
	}
	_ = session.BeginNegotiation()
	_ = session.BeginSecuring()
	_ = session.MarkOpen()
	streams, err := NewStreamManager(session, p)
	if err != nil {
		return AdapterBoundaryResult{}, err
	}
	events := []ktrace.Event{}
	for i := 0; i < opts.FlowCount; i++ {
		desc := flowDescriptor(i, max(opts.BytesPerFlow, opts.LargeFlowBytes), p.ProxySemantics.MaxResponseBytes)
		if opts.MalformedFlow && i == 0 {
			desc.ID = ""
		}
		if err := h.OpenFlow(desc); err != nil {
			return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, err
		}
		intent := proxysem.RelayIntent{
			StreamID:         uint64(i + 1),
			Target:           proxysem.TargetDescriptor{Class: proxysem.TargetEcho},
			RequestClass:     proxysem.RequestClass(desc.RequestClass),
			PriorityClass:    proxysem.PriorityClass(desc.PriorityClass),
			ResponseMode:     proxysem.ResponseImmediate,
			MaxRequestBytes:  p.ProxySemantics.MaxRequestBytes,
			MaxResponseBytes: p.ProxySemantics.MaxResponseBytes,
		}
		if opts.TargetError && i == 0 {
			intent.Target = proxysem.TargetDescriptor{Class: proxysem.TargetErrorResponse}
		}
		if opts.TargetReset && i == 0 {
			intent.Target = proxysem.TargetDescriptor{Class: proxysem.TargetResetMidstream}
		}
		if _, err := streams.OpenStream(desc.PriorityClass, intent); err != nil {
			return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, err
		}
		bytes := opts.BytesPerFlow
		if opts.LargeFlowBytes > 0 && i == 0 {
			bytes = opts.LargeFlowBytes
		}
		chunk, readErr := h.ReadFlow(desc.ID, bytes)
		if readErr != nil && readErr != adapter.ErrBackpressure {
			return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, readErr
		}
		if writeErr := h.WriteFlow(desc.ID, adapter.AdapterChunk{FlowID: desc.ID, Sequence: chunk.Sequence, ByteCount: bytes, MetadataClass: "response_count", Backpressure: chunk.Backpressure}); writeErr != nil {
			return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, writeErr
		}
		if opts.HalfClose && i == 0 {
			if err := h.HalfCloseFlow(desc.ID); err != nil {
				return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, err
			}
		}
		if opts.ResetFlow && i == 0 {
			if err := h.ResetFlow(desc.ID, "scenario_reset"); err != nil {
				return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, err
			}
		} else {
			if err := h.CloseFlow(desc.ID); err != nil {
				return AdapterBoundaryResult{Summary: h.HarnessSummary(), Events: events}, err
			}
		}
		summary := h.HarnessSummary()
		if opts.TargetError && i == 0 {
			summary.TargetErrors++
		}
		if opts.TargetReset && i == 0 {
			summary.TargetResets++
		}
		events = append(events, adapter.TraceEvent(cfg, nil, "flow_progress", opts.Scenario, summary))
	}
	summary := h.HarnessSummary()
	if opts.TargetError {
		summary.TargetErrors++
	}
	if opts.TargetReset {
		summary.TargetResets++
	}
	if opts.Backpressure && summary.BackpressureEvents == 0 {
		summary.BackpressureEvents = 1
	}
	if summary.PayloadLogged || summary.SecretLogged {
		return AdapterBoundaryResult{Summary: summary, Events: events}, fmt.Errorf("%w: adapter summary reported leak", adapter.ErrTraceHygiene)
	}
	events = append(events, adapter.TraceEvent(cfg, nil, "scenario_complete", opts.Scenario, summary))
	return AdapterBoundaryResult{Summary: summary, Events: events}, nil
}

func flowDescriptor(i, maxBytes, maxResponse int) adapter.FlowDescriptor {
	if maxBytes <= 0 {
		maxBytes = 128
	}
	if maxResponse < maxBytes {
		maxResponse = maxBytes
	}
	priority := "interactive"
	if i%2 == 1 {
		priority = "bulk"
	}
	return adapter.FlowDescriptor{
		ID:             adapter.FlowID(fmt.Sprintf("flow-%02d", i+1)),
		Class:          "synthetic",
		Direction:      "bidirectional",
		RequestClass:   priority,
		PriorityClass:  priority,
		TargetHint:     "synthetic-target",
		MaxReadBytes:   maxBytes,
		MaxWriteBytes:  maxResponse,
		MetadataPolicy: "bucketed",
	}
}
