// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package bytetransport

type ByteTransportSummary struct {
	Scenario             string `json:"scenario,omitempty"`
	FramesEncoded        int    `json:"frames_encoded"`
	FramesDecoded        int    `json:"frames_decoded"`
	FragmentsCreated     int    `json:"fragments_created"`
	FragmentsReassembled int    `json:"fragments_reassembled"`
	BytesWritten         int    `json:"bytes_written"`
	BytesRead            int    `json:"bytes_read"`
	BackpressureEvents   int    `json:"backpressure_events"`
	MalformedRejected    int    `json:"malformed_rejected"`
	SequenceRejected     int    `json:"sequence_rejected"`
	ReassemblyRejected   int    `json:"reassembly_rejected"`
	CorruptionRejected   int    `json:"corruption_rejected"`
	ReplayRejected       int    `json:"replay_rejected"`
	RuntimeStreamsMapped int    `json:"runtime_streams_mapped"`
	TargetErrors         int    `json:"target_errors"`
	TargetResets         int    `json:"target_resets"`
	PayloadLogged        bool   `json:"payload_logged"`
	SecretLogged         bool   `json:"secret_logged"`
	Completed            bool   `json:"completed"`
}
