// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import "kurdistan/internal/proxyingress"

type SyntheticIngressEvent struct {
	EventID         string                        `json:"event_id"`
	RequestID       string                        `json:"request_id"`
	Kind            RequestEventKind              `json:"kind"`
	Target          proxyingress.TargetDescriptor `json:"target"`
	ByteCountBucket string                        `json:"byte_count_bucket"`
	ChunkClass      string                        `json:"chunk_class"`
	FlowClass       string                        `json:"flow_class"`
	ErrorClass      string                        `json:"error_class"`
	ResetClass      string                        `json:"reset_class"`
	LogicalTick     int                           `json:"logical_tick"`
	PayloadLogged   bool                          `json:"payload_logged"`
	SecretLogged    bool                          `json:"secret_logged"`
}

func validEventKind(kind RequestEventKind) bool {
	switch kind {
	case RequestEventOpen, RequestEventData, RequestEventClose, RequestEventReset, RequestEventTargetErr, RequestEventBackpress:
		return true
	default:
		return false
	}
}
