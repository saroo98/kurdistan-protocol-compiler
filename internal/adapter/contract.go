// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adapter

func ValidateContract(cfg AdapterConfig, required []string) error {
	if err := ValidateConfig(cfg); err != nil {
		return err
	}
	return RequireCapabilities(required, cfg.Capabilities)
}
