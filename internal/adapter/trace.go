// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import ktrace "kurdistan/internal/trace"

func TraceEvent(cfg AdapterConfig, flow *Flow, event, scenario string, summary AdapterHarnessSummary) ktrace.Event {
	state := ""
	if flow != nil {
		state = string(flow.State)
	}
	return ktrace.Event{
		Role:                       "adapter",
		EventType:                  "adapter",
		AdapterNameBucket:          cfg.Name,
		AdapterKind:                string(cfg.Kind),
		FlowState:                  state,
		FlowEvent:                  event,
		FlowCountBucket:            CountBucket(summary.FlowsOpened),
		AdapterChunkCountBucket:    CountBucket(summary.ChunksRead + summary.ChunksWritten),
		AdapterByteCountBucket:     ByteBucket(summary.BytesIn + summary.BytesOut),
		AdapterBackpressureCount:   summary.BackpressureEvents,
		AdapterResetCount:          summary.FlowsReset,
		AdapterCloseCount:          summary.FlowsClosed,
		RuntimeStreamMappingResult: "mapped",
		AdapterScenario:            scenario,
		PayloadHygiene:             !summary.PayloadLogged,
		SecretHygiene:              !summary.SecretLogged,
	}
}
