// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import "kurdistan/internal/proxyingress"

type TargetBinding struct {
	RequestID     string `json:"request_id"`
	DescriptorID  string `json:"descriptor_id"`
	TargetKind    string `json:"target_kind"`
	ServiceClass  string `json:"service_class"`
	PortClass     string `json:"port_class"`
	NameClass     string `json:"name_class"`
	BindingHash   string `json:"binding_hash"`
	PayloadLogged bool   `json:"payload_logged"`
	SecretLogged  bool   `json:"secret_logged"`
}

func BindTarget(requestID string, target proxyingress.TargetDescriptor, contract proxyingress.ProxyIngressContract) (TargetBinding, error) {
	if err := proxyingress.ValidateTargetDescriptor(target, contract.Limits); err != nil {
		return TargetBinding{}, err
	}
	binding := TargetBinding{
		RequestID:    requestID,
		DescriptorID: target.DescriptorID,
		TargetKind:   string(target.TargetKind),
		ServiceClass: target.ServiceClass,
		PortClass:    target.PortClass,
		NameClass:    target.NameClass,
	}
	binding.BindingHash = HashValue(binding)
	return binding, nil
}
