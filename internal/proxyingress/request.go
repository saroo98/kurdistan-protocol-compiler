// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

type SyntheticProxyRequest struct {
	RequestID            string              `json:"request_id"`
	IngressKind          IngressKind         `json:"ingress_kind"`
	Target               TargetDescriptor    `json:"target"`
	ClientFlowID         string              `json:"client_flow_id"`
	RequestState         IngressRequestState `json:"request_state"`
	RequestedStreamClass string              `json:"requested_stream_class"`
	RequestedPolicyClass string              `json:"requested_policy_class"`
	ByteBudgetBucket     string              `json:"byte_budget_bucket"`
	DeadlineBucket       string              `json:"deadline_bucket"`
	BackpressureClass    string              `json:"backpressure_class"`
	PayloadLogged        bool                `json:"payload_logged"`
	SecretLogged         bool                `json:"secret_logged"`
}

func ValidRequests() []SyntheticProxyRequest {
	return []SyntheticProxyRequest{
		{
			RequestID:            "req_connect_alpha",
			IngressKind:          IngressKindSyntheticConnect,
			Target:               TargetDescriptor{TargetKind: TargetKindSyntheticName, DescriptorID: "target_alpha", ServiceClass: "service_echo", PortClass: "port_class_small", NameClass: "name_alpha", AddressClass: "loopback_class", MetadataClass: "meta_basic", OpaqueHash: safeHash("target_alpha")},
			ClientFlowID:         "flow_alpha",
			RequestState:         RequestCreated,
			RequestedStreamClass: "interactive",
			RequestedPolicyClass: "policy_low_latency",
			ByteBudgetBucket:     "bucket_4k",
			DeadlineBucket:       "deadline_short",
			BackpressureClass:    "pressure_runtime",
		},
		{
			RequestID:            "req_assoc_beta",
			IngressKind:          IngressKindSyntheticAssociate,
			Target:               TargetDescriptor{TargetKind: TargetKindSyntheticService, DescriptorID: "service_echo", ServiceClass: "service_echo", PortClass: "port_class_medium", NameClass: "name_beta", AddressClass: "private_lab_class", MetadataClass: "meta_control", OpaqueHash: safeHash("service_echo")},
			ClientFlowID:         "flow_beta",
			RequestState:         RequestCreated,
			RequestedStreamClass: "bulk",
			RequestedPolicyClass: "policy_bulk",
			ByteBudgetBucket:     "bucket_64k",
			DeadlineBucket:       "deadline_medium",
			BackpressureClass:    "pressure_adapter",
		},
		{
			RequestID:            "req_opaque_gamma",
			IngressKind:          IngressKindSyntheticBind,
			Target:               TargetDescriptor{TargetKind: TargetKindOpaqueDescriptor, DescriptorID: "opaque_target_001", ServiceClass: "service_opaque", PortClass: "port_class_control", NameClass: "name_gamma", AddressClass: "opaque_descriptor", MetadataClass: "meta_opaque", OpaqueHash: safeHash("opaque_target_001")},
			ClientFlowID:         "flow_gamma",
			RequestState:         RequestCreated,
			RequestedStreamClass: "control",
			RequestedPolicyClass: "policy_control",
			ByteBudgetBucket:     "bucket_16k",
			DeadlineBucket:       "deadline_long",
			BackpressureClass:    "pressure_carrier",
		},
	}
}

func InvalidRequests() []SyntheticProxyRequest {
	requests := ValidRequests()
	badTarget := requests[0]
	badTarget.RequestID = "req_invalid_target"
	badTarget.Target.DescriptorID = "127.0.0.1"
	badKind := requests[0]
	badKind.RequestID = "req_bad_kind"
	badKind.IngressKind = "real_listener"
	badLeak := requests[0]
	badLeak.RequestID = "req_leak_flag"
	badLeak.PayloadLogged = true
	return []SyntheticProxyRequest{badTarget, badKind, badLeak}
}
