// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

const (
	CapabilityIngress          = "adapter_ingress"
	CapabilityEgress           = "adapter_egress"
	CapabilityFlowLifecycle    = "flow_lifecycle"
	CapabilityFlowReset        = "flow_reset"
	CapabilityFlowHalfClose    = "flow_half_close"
	CapabilityFlowBackpressure = "flow_backpressure"
	CapabilityFlowPriority     = "flow_priority"
	CapabilityMetadataOnly     = "flow_metadata_only"
	CapabilityRuntimeMapping   = "runtime_stream_mapping"
	CapabilityTraceSafeSummary = "trace_safe_adapter_summary"
)

func KnownCapabilities() []string {
	return []string{
		CapabilityIngress,
		CapabilityEgress,
		CapabilityFlowLifecycle,
		CapabilityFlowReset,
		CapabilityFlowHalfClose,
		CapabilityFlowBackpressure,
		CapabilityFlowPriority,
		CapabilityMetadataOnly,
		CapabilityRuntimeMapping,
		CapabilityTraceSafeSummary,
	}
}

func DefaultCapabilityNames() []string {
	return KnownCapabilities()
}

func CanonicalCapabilities(values []string) ([]string, error) {
	if err := ValidateCapabilityNames(values); err != nil {
		return nil, err
	}
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out, nil
}

func CapabilityHash(values []string) (string, error) {
	canonical, err := CanonicalCapabilities(values)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func ValidateCapabilityNames(values []string) error {
	known := map[string]bool{}
	for _, capability := range KnownCapabilities() {
		known[capability] = true
	}
	seen := map[string]bool{}
	for _, value := range values {
		if !known[value] {
			return fmt.Errorf("%w: unsupported capability", ErrCapabilityMismatch)
		}
		if seen[value] {
			return fmt.Errorf("%w: duplicate capability", ErrCapabilityMismatch)
		}
		seen[value] = true
	}
	return nil
}

func RequireCapabilities(required, offered []string) error {
	if err := ValidateCapabilityNames(required); err != nil {
		return err
	}
	if err := ValidateCapabilityNames(offered); err != nil {
		return err
	}
	have := map[string]bool{}
	for _, value := range offered {
		have[value] = true
	}
	for _, value := range required {
		if !have[value] {
			return fmt.Errorf("%w: required adapter capability missing", ErrCapabilityMismatch)
		}
	}
	return nil
}
