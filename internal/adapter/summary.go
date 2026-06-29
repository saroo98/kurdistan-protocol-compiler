// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

type AdapterSummary struct {
	AdapterName        string `json:"adapter_name"`
	AdapterKind        string `json:"adapter_kind"`
	FlowsOpened        int    `json:"flows_opened"`
	FlowsClosed        int    `json:"flows_closed"`
	FlowsReset         int    `json:"flows_reset"`
	ChunksRead         int    `json:"chunks_read"`
	ChunksWritten      int    `json:"chunks_written"`
	BytesIn            int    `json:"bytes_in"`
	BytesOut           int    `json:"bytes_out"`
	BackpressureEvents int    `json:"backpressure_events"`
	PayloadLogged      bool   `json:"payload_logged"`
	SecretLogged       bool   `json:"secret_logged"`
}

type AdapterHarnessSummary struct {
	AdapterName          string `json:"adapter_name"`
	FlowsOpened          int    `json:"flows_opened"`
	FlowsClosed          int    `json:"flows_closed"`
	FlowsReset           int    `json:"flows_reset"`
	ChunksRead           int    `json:"chunks_read"`
	ChunksWritten        int    `json:"chunks_written"`
	BytesIn              int    `json:"bytes_in"`
	BytesOut             int    `json:"bytes_out"`
	BackpressureEvents   int    `json:"backpressure_events"`
	RuntimeStreamsOpened int    `json:"runtime_streams_opened"`
	RuntimeStreamsClosed int    `json:"runtime_streams_closed"`
	TargetErrors         int    `json:"target_errors"`
	TargetResets         int    `json:"target_resets"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
}
