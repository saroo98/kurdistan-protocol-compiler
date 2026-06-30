// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingress

import "sort"

type IngressCapabilityMapping struct {
	ContractID            string   `json:"contract_id"`
	RequiredCapabilities  []string `json:"required_capabilities"`
	AdapterCapabilities   []string `json:"adapter_capabilities"`
	RuntimeCapabilities   []string `json:"runtime_capabilities"`
	ProxySemCapabilities  []string `json:"proxysem_capabilities"`
	SecurityPreconditions []string `json:"security_preconditions"`
	MissingCapabilities   []string `json:"missing_capabilities,omitempty"`
	UnsupportedBehaviors  []string `json:"unsupported_behaviors,omitempty"`
	Conclusion            string   `json:"conclusion"`
	PayloadLogged         bool     `json:"payload_logged"`
	SecretLogged          bool     `json:"secret_logged"`
}

func MapCapabilities(contract ProxyIngressContract, available []string) IngressCapabilityMapping {
	availableSet := map[string]bool{}
	for _, capability := range available {
		availableSet[capability] = true
	}
	mapping := IngressCapabilityMapping{
		ContractID:            contract.ContractID,
		RequiredCapabilities:  append([]string(nil), contract.RequiredCapabilities...),
		AdapterCapabilities:   []string{"adapter_ingress", "flow_lifecycle", "flow_reset", "flow_backpressure", "flow_metadata_only"},
		RuntimeCapabilities:   []string{"runtime_stream_mapping", "session_lifecycle", "stream_reset", "stream_close", "bounded_queue"},
		ProxySemCapabilities:  []string{"target_descriptor", "target_error", "target_reset", "target_close"},
		SecurityPreconditions: []string{"secure_context_required", "replay_rejection_required", "trace_hygiene_required"},
		Conclusion:            "passed",
	}
	for _, required := range contract.RequiredCapabilities {
		if !availableSet[required] {
			mapping.MissingCapabilities = append(mapping.MissingCapabilities, required)
		}
	}
	if len(mapping.MissingCapabilities) > 0 {
		sort.Strings(mapping.MissingCapabilities)
		mapping.Conclusion = "failed"
	}
	return mapping
}

func DefaultAvailableCapabilities() []string {
	return append([]string(nil), DefaultRequiredCapabilities()...)
}
