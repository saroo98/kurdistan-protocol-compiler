// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

type LocalProxyIngressResult struct {
	RequestID             string `json:"request_id"`
	Accepted              bool   `json:"accepted"`
	Rejected              bool   `json:"rejected"`
	FinalState            string `json:"final_state"`
	StreamClass           string `json:"stream_class"`
	TargetDescriptorClass string `json:"target_descriptor_class"`
	EventsProcessed       int    `json:"events_processed"`
	DataEvents            int    `json:"data_events"`
	CloseEvents           int    `json:"close_events"`
	ResetEvents           int    `json:"reset_events"`
	ErrorEvents           int    `json:"error_events"`
	BackpressureEvents    int    `json:"backpressure_events"`
	RuntimeMappingHash    string `json:"runtime_mapping_hash"`
	ProxySemIntentHash    string `json:"proxysem_intent_hash"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	Conclusion            string `json:"conclusion"`
}

type LocalProxyIngressSummary struct {
	Version             string                    `json:"version"`
	Scenario            string                    `json:"scenario"`
	ContractID          string                    `json:"contract_id"`
	RequestCount        int                       `json:"request_count"`
	AcceptedRequests    int                       `json:"accepted_requests"`
	RejectedRequests    int                       `json:"rejected_requests"`
	EventsProcessed     int                       `json:"events_processed"`
	StreamMappings      int                       `json:"stream_mappings"`
	TargetBindings      int                       `json:"target_bindings"`
	BackpressureEvents  int                       `json:"backpressure_events"`
	ResetEvents         int                       `json:"reset_events"`
	TargetErrorEvents   int                       `json:"target_error_events"`
	LifecycleViolations int                       `json:"lifecycle_violations"`
	QueueStats          IngressQueueStats         `json:"queue_stats"`
	Results             []LocalProxyIngressResult `json:"results"`
	PayloadLogged       bool                      `json:"payload_logged"`
	SecretLogged        bool                      `json:"secret_logged"`
	SummaryHash         string                    `json:"summary_hash"`
}
