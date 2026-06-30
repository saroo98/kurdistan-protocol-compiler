// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import "kurdistan/internal/proxyingress"

const Version LocalProxyIngressVersion = "localproxyingress-v1"

type LocalProxyIngressVersion string
type RequestEventKind string

const (
	RequestEventOpen      RequestEventKind = "open"
	RequestEventData      RequestEventKind = "data"
	RequestEventClose     RequestEventKind = "close"
	RequestEventReset     RequestEventKind = "reset"
	RequestEventTargetErr RequestEventKind = "target_error"
	RequestEventBackpress RequestEventKind = "backpressure"
)

type LocalProxyIngressConfig struct {
	Version                 string `json:"version"`
	ContractID              string `json:"contract_id"`
	MaxConcurrentRequests   int    `json:"max_concurrent_requests"`
	MaxQueuedEvents         int    `json:"max_queued_events"`
	MaxEventsPerRequest     int    `json:"max_events_per_request"`
	MaxSyntheticBytesBucket string `json:"max_synthetic_bytes_bucket"`
	EnableBackpressure      bool   `json:"enable_backpressure"`
	EnableReset             bool   `json:"enable_reset"`
	EnableTargetErrors      bool   `json:"enable_target_errors"`
	TraceSafeSummaries      bool   `json:"trace_safe_summaries"`
}

func DefaultConfig() LocalProxyIngressConfig {
	contract := proxyingress.DefaultContract()
	return LocalProxyIngressConfig{
		Version:                 string(Version),
		ContractID:              contract.ContractID,
		MaxConcurrentRequests:   contract.Limits.MaxConcurrentRequests,
		MaxQueuedEvents:         96,
		MaxEventsPerRequest:     24,
		MaxSyntheticBytesBucket: "bucket_64k",
		EnableBackpressure:      true,
		EnableReset:             true,
		EnableTargetErrors:      true,
		TraceSafeSummaries:      true,
	}
}

func Contract() proxyingress.ProxyIngressContract {
	return proxyingress.DefaultContract()
}
