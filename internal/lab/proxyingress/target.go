// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

type TargetDescriptor struct {
	TargetKind    TargetKind `json:"target_kind"`
	DescriptorID  string     `json:"descriptor_id"`
	ServiceClass  string     `json:"service_class"`
	PortClass     string     `json:"port_class"`
	NameClass     string     `json:"name_class"`
	AddressClass  string     `json:"address_class"`
	MetadataClass string     `json:"metadata_class"`
	OpaqueHash    string     `json:"opaque_hash"`
	PayloadLogged bool       `json:"payload_logged"`
	SecretLogged  bool       `json:"secret_logged"`
}

func ValidTargetDescriptors() []TargetDescriptor {
	requests := ValidRequests()
	out := make([]TargetDescriptor, 0, len(requests))
	for _, request := range requests {
		out = append(out, request.Target)
	}
	return out
}

func InvalidTargetDescriptors() []TargetDescriptor {
	return []TargetDescriptor{
		{TargetKind: TargetKindSyntheticName, DescriptorID: "127.0.0.1", ServiceClass: "service_echo", AddressClass: "loopback_class"},
		{TargetKind: TargetKindSyntheticName, DescriptorID: "example.invalid", ServiceClass: "service_echo", AddressClass: "loopback_class"},
		{TargetKind: TargetKindSyntheticName, DescriptorID: "synthetic://target", ServiceClass: "service_echo", AddressClass: "loopback_class"},
		{TargetKind: TargetKindSyntheticService, DescriptorID: "service_echo", ServiceClass: "service_echo", AddressClass: "host_header"},
		{TargetKind: TargetKindOpaqueDescriptor, DescriptorID: "opaque_target_oversized_" + longString(300), ServiceClass: "service_opaque", AddressClass: "opaque_descriptor"},
		{TargetKind: TargetKindSyntheticName, DescriptorID: "target_secret", ServiceClass: "credential", AddressClass: "loopback_class"},
	}
}
