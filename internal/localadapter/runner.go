// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

import (
	"context"
	"fmt"

	"kurdistan/internal/adapter"
	"kurdistan/internal/ir"
	kruntime "kurdistan/internal/runtime"
	ktrace "kurdistan/internal/trace"
)

type RunResult struct {
	Summary LocalAdapterSummary `json:"summary"`
	Events  []ktrace.Event      `json:"events,omitempty"`
}

func RunScenario(ctx context.Context, p *ir.Profile, scenario Scenario, cfg LocalAdapterConfig) (RunResult, error) {
	if err := ctx.Err(); err != nil {
		return RunResult{}, err
	}
	if err := kruntime.ValidateLoadedProfile(p); err != nil {
		return RunResult{}, err
	}
	if cfg.Name == "" {
		cfg = DefaultConfig("local-adapter")
	}
	cfg.MaxFlows = minPositive(cfg.MaxFlows, min(p.AdapterPolicy.MaxFlows, p.Stream.MaxConcurrentStreams))
	if cfg.MaxFlows <= 0 {
		cfg.MaxFlows = min(p.AdapterPolicy.MaxFlows, p.Stream.MaxConcurrentStreams)
	}
	if cfg.MaxChunkBytes <= 0 || cfg.MaxChunkBytes > p.AdapterPolicy.MaxFlowBytes {
		cfg.MaxChunkBytes = min(p.AdapterPolicy.MaxFlowBytes, MaxLocalChunkBytes)
	}
	if scenario.ExpectBackpressure || scenario.Name == ScenarioQueuePressure {
		cfg.MaxBufferedBytes = max(64, cfg.MaxChunkBytes/4)
	}
	if err := ValidateConfig(cfg); err != nil {
		return RunResult{}, err
	}
	flowCount := scenario.FlowCount
	if flowCount <= 0 {
		flowCount = 1
	}
	if flowCount > cfg.MaxFlows {
		flowCount = cfg.MaxFlows
	}
	plan, err := GenerateSourcePlan(scenario.SourceModel, flowCount, cfg)
	if err != nil {
		return RunResult{}, err
	}
	if scenario.Name == ScenarioMalformedSource && len(plan.Chunks) > 0 {
		plan.Chunks[0].Sequence = 0
	}
	pipe, err := NewMemoryPipe(cfg)
	if err != nil {
		return RunResult{}, err
	}
	opened := map[adapter.FlowID]bool{}
	events := []ktrace.Event{}
	backpressure := 0
	for _, chunk := range plan.Chunks {
		if !opened[chunk.FlowID] {
			desc := FlowDescriptor(chunk.FlowID, max(cfg.MaxChunkBytes, totalBytes(plan)))
			if err := pipe.Ingress.OpenFlow(desc); err != nil {
				return RunResult{Summary: pipe.Summary(), Events: events}, err
			}
			if err := pipe.Egress.OpenFlow(desc); err != nil {
				return RunResult{Summary: pipe.Summary(), Events: events}, err
			}
			opened[chunk.FlowID] = true
		}
		inChunk, readErr := pipe.Ingress.ReadSource(chunk)
		if readErr != nil && readErr != ErrLocalBackpressure {
			sum := pipe.Summary()
			sum.SequenceRejected++
			sum.Scenario = scenario.Name
			sum.SourceModel = scenario.SourceModel
			return RunResult{Summary: sum, Events: events}, readErr
		}
		if readErr == ErrLocalBackpressure || inChunk.Backpressure {
			backpressure++
		}
		sinkChunk := LocalSinkChunk{FlowID: chunk.FlowID, Sequence: chunk.Sequence, ByteCount: chunk.ByteCount, Final: chunk.Final, Reset: chunk.Reset, MetadataClass: chunk.MetadataClass}
		if err := pipe.Egress.WriteSink(sinkChunk); err != nil {
			sum := pipe.Summary()
			sum.Scenario = scenario.Name
			sum.SourceModel = scenario.SourceModel
			return RunResult{Summary: sum, Events: events}, err
		}
		if chunk.Reset {
			_ = pipe.Ingress.ResetFlow(chunk.FlowID, "local_reset")
		} else if chunk.Final {
			_ = pipe.Ingress.CloseFlow(chunk.FlowID)
		}
		events = append(events, TraceEvent(p, cfg, "local_chunk", scenario.Name, pipe.Summary()))
	}
	boundary, err := kruntime.RunAdapterBoundary(ctx, p, kruntime.AdapterBoundaryOptions{
		Scenario:     scenario.Name,
		FlowCount:    flowCount,
		BytesPerFlow: max(64, totalBytes(plan)/max(1, len(plan.Chunks))),
		Backpressure: scenario.ExpectBackpressure,
		ResetFlow:    scenario.ExpectReset,
		TargetError:  scenario.ExpectTargetError,
		TargetReset:  scenario.ExpectTargetReset,
		HalfClose:    scenario.HalfClose,
	})
	if err != nil {
		return RunResult{Summary: pipe.Summary(), Events: events}, err
	}
	sum := pipe.Summary()
	sum.Scenario = scenario.Name
	sum.SourceModel = scenario.SourceModel
	sum.BackpressureEvents += boundary.Summary.BackpressureEvents + backpressure
	sum.RuntimeStreamsOpened = boundary.Summary.RuntimeStreamsOpened
	sum.RuntimeStreamsClosed = boundary.Summary.RuntimeStreamsClosed
	sum.TargetErrors = boundary.Summary.TargetErrors
	sum.TargetResets = boundary.Summary.TargetResets
	sum.PayloadLogged = sum.PayloadLogged || boundary.Summary.PayloadLogged
	sum.SecretLogged = sum.SecretLogged || boundary.Summary.SecretLogged
	sum.Completed = !sum.PayloadLogged && !sum.SecretLogged && sum.SourceChunks > 0 && (sum.SinkChunks > 0 || scenario.ExpectFailure)
	if scenario.ExpectBackpressure && sum.BackpressureEvents == 0 {
		return RunResult{Summary: sum, Events: events}, fmt.Errorf("%w: expected local backpressure", ErrLocalBackpressure)
	}
	events = append(events, boundary.Events...)
	events = append(events, TraceEvent(p, cfg, "local_complete", scenario.Name, sum))
	return RunResult{Summary: sum, Events: events}, nil
}

func totalBytes(plan SourcePlan) int {
	total := 0
	for _, chunk := range plan.Chunks {
		total += chunk.ByteCount
	}
	return total
}

func minPositive(a, b int) int {
	if a <= 0 {
		return b
	}
	if b <= 0 {
		return a
	}
	if a < b {
		return a
	}
	return b
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
