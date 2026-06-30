// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

const Version ProxyIngressVersion = "proxyingress-v1"

type ProxyIngressVersion string
type IngressKind string
type TargetKind string
type IngressRequestState string

const (
	IngressKindSyntheticConnect   IngressKind = "synthetic_connect"
	IngressKindSyntheticAssociate IngressKind = "synthetic_associate"
	IngressKindSyntheticBind      IngressKind = "synthetic_bind"

	TargetKindSyntheticName    TargetKind = "synthetic_name"
	TargetKindSyntheticService TargetKind = "synthetic_service"
	TargetKindOpaqueDescriptor TargetKind = "opaque_descriptor"

	RequestCreated   IngressRequestState = "created"
	RequestValidated IngressRequestState = "validated"
	RequestMapped    IngressRequestState = "mapped"
	RequestAccepted  IngressRequestState = "accepted"
	RequestRejected  IngressRequestState = "rejected"
	RequestClosed    IngressRequestState = "closed"
	RequestFailed    IngressRequestState = "failed"
)

type ProxyIngressContract struct {
	Version              string             `json:"version"`
	ContractID           string             `json:"contract_id"`
	SupportedKinds       []IngressKind      `json:"supported_kinds"`
	SupportedTargetKinds []TargetKind       `json:"supported_target_kinds"`
	Limits               ProxyIngressLimits `json:"limits"`
	RequiredCapabilities []string           `json:"required_capabilities"`
	ForbiddenBehaviors   []string           `json:"forbidden_behaviors"`
	ContractHash         string             `json:"contract_hash"`
	PayloadLogged        bool               `json:"payload_logged"`
	SecretLogged         bool               `json:"secret_logged"`
}

type ProxyIngressLimits struct {
	MaxConcurrentRequests    int    `json:"max_concurrent_requests"`
	MaxRequestBytesBucket    string `json:"max_request_bytes_bucket"`
	MaxTargetDescriptorBytes int    `json:"max_target_descriptor_bytes"`
	MaxMetadataFields        int    `json:"max_metadata_fields"`
	MaxPendingStreams        int    `json:"max_pending_streams"`
	MaxFailureRecords        int    `json:"max_failure_records"`
}

func DefaultLimits() ProxyIngressLimits {
	return ProxyIngressLimits{
		MaxConcurrentRequests:    16,
		MaxRequestBytesBucket:    "bucket_64k",
		MaxTargetDescriptorBytes: 256,
		MaxMetadataFields:        8,
		MaxPendingStreams:        16,
		MaxFailureRecords:        64,
	}
}

func DefaultContract() ProxyIngressContract {
	contract := ProxyIngressContract{
		Version:              string(Version),
		ContractID:           "proxyingress_contract_v1",
		SupportedKinds:       []IngressKind{IngressKindSyntheticConnect, IngressKindSyntheticAssociate, IngressKindSyntheticBind},
		SupportedTargetKinds: []TargetKind{TargetKindSyntheticName, TargetKindSyntheticService, TargetKindOpaqueDescriptor},
		Limits:               DefaultLimits(),
		RequiredCapabilities: DefaultRequiredCapabilities(),
		ForbiddenBehaviors: []string{
			"network_address_rejected",
			"lookup_rejected",
			"listener_rejected",
			"raw_content_rejected",
			"sensitive_material_rejected",
			"provider_metadata_rejected",
		},
	}
	contract.ContractHash = ContractHash(contract)
	return contract
}

func SupportedIngressKinds() []IngressKind {
	return []IngressKind{IngressKindSyntheticConnect, IngressKindSyntheticAssociate, IngressKindSyntheticBind}
}

func SupportedTargetKinds() []TargetKind {
	return []TargetKind{TargetKindSyntheticName, TargetKindSyntheticService, TargetKindOpaqueDescriptor}
}

func DefaultRequiredCapabilities() []string {
	return []string{
		"stream_open",
		"stream_data",
		"stream_close",
		"stream_reset",
		"backpressure",
		"target_descriptor",
		"target_error",
		"target_reset",
		"target_close",
		"secure_context_required",
		"replay_rejection_required",
		"trace_hygiene_required",
		"bounded_queue_required",
	}
}
