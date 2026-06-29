// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

import (
	"fmt"
	"strings"
)

func ValidateConfig(cfg AdapterConfig) error {
	if cfg.Name == "" {
		return fmt.Errorf("%w: name required", ErrInvalidConfig)
	}
	if containsSensitiveMarker(cfg.Name) || containsSensitiveMarker(cfg.RuntimeID) {
		return fmt.Errorf("%w: secret-like adapter config value rejected", ErrInvalidConfig)
	}
	if cfg.Kind != AdapterKindIngress && cfg.Kind != AdapterKindEgress && cfg.Kind != AdapterKindCarrier {
		return fmt.Errorf("%w: unsupported kind", ErrInvalidConfig)
	}
	if cfg.RuntimeID == "" {
		return fmt.Errorf("%w: runtime id required", ErrInvalidConfig)
	}
	if cfg.MaxFlows <= 0 || cfg.MaxFlows > MaxAdapterFlows {
		return fmt.Errorf("%w: max flows out of bounds", ErrInvalidConfig)
	}
	if cfg.MaxFlowBytes <= 0 || cfg.MaxFlowBytes > MaxAdapterFlowBytes {
		return fmt.Errorf("%w: max flow bytes out of bounds", ErrInvalidConfig)
	}
	if cfg.MaxBufferedBytes <= 0 || cfg.MaxBufferedBytes > MaxAdapterBufferedBytes {
		return fmt.Errorf("%w: max buffered bytes out of bounds", ErrInvalidConfig)
	}
	if cfg.MaxEvents <= 0 || cfg.MaxEvents > MaxAdapterEvents {
		return fmt.Errorf("%w: max events out of bounds", ErrInvalidConfig)
	}
	if err := ValidateCapabilityNames(cfg.Capabilities); err != nil {
		return err
	}
	for _, capability := range cfg.Capabilities {
		if containsSensitiveMarker(capability) {
			return fmt.Errorf("%w: secret-like adapter capability rejected", ErrInvalidConfig)
		}
	}
	return nil
}

func RedactConfig(cfg AdapterConfig) AdapterConfig {
	if containsSensitiveMarker(cfg.Name) {
		cfg.Name = "redacted"
	}
	if containsSensitiveMarker(cfg.RuntimeID) {
		cfg.RuntimeID = "redacted"
	}
	return cfg
}

func containsSensitiveMarker(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"secret", "token", "password", "private", "credential", "key=", "raw_secret"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
