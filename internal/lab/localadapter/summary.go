// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localadapter

type LocalAdapterSummary struct {
	Name                 string `json:"name"`
	Scenario             string `json:"scenario"`
	SourceModel          string `json:"source_model"`
	SinkModel            string `json:"sink_model"`
	FlowsOpened          int    `json:"flows_opened"`
	FlowsClosed          int    `json:"flows_closed"`
	FlowsReset           int    `json:"flows_reset"`
	SourceChunks         int    `json:"source_chunks"`
	SinkChunks           int    `json:"sink_chunks"`
	SourceBytes          int    `json:"source_bytes"`
	SinkBytes            int    `json:"sink_bytes"`
	BackpressureEvents   int    `json:"backpressure_events"`
	QueuePressureEvents  int    `json:"queue_pressure_events"`
	RuntimeStreamsOpened int    `json:"runtime_streams_opened"`
	RuntimeStreamsClosed int    `json:"runtime_streams_closed"`
	TargetErrors         int    `json:"target_errors"`
	TargetResets         int    `json:"target_resets"`
	SequenceRejected     int    `json:"sequence_rejected"`
	PostCloseRejected    int    `json:"post_close_rejected"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
	Completed            bool   `json:"completed"`
}
