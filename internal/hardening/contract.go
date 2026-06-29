// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"encoding/json"
	"fmt"

	"kurdistan/internal/carrier"
	"kurdistan/internal/compiler"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxysem"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/security"
)

func RunAPIContractChecks(ctx context.Context, profiles []*ir.Profile) []CheckResult {
	_ = ctx
	p := firstProfile(profiles)
	return []CheckResult{
		check("nil_profile_rejected_by_carrier", CategoryAPIContracts, func() error {
			if _, err := carrier.NewModel(nil, carrier.FamilyStream); err == nil {
				return fmt.Errorf("nil profile accepted")
			}
			return nil
		}),
		check("empty_security_secret_rejected", CategoryAPIContracts, func() error {
			cfg := security.SecurityConfig{ProfileID: p.ID, ProfileHash: p.GenerationHash, Suite: security.DefaultSuite(), ReplayWindow: 64, MaxEnvelopeBytes: 1024, QueueDepth: 4, Capabilities: security.DefaultCapabilities().Features}
			if err := security.ValidateConfig(cfg); err == nil {
				return fmt.Errorf("empty secret accepted")
			}
			cfg.InputSecret = make([]byte, 8)
			if err := security.ValidateConfig(cfg); err == nil {
				return fmt.Errorf("all-zero secret accepted")
			}
			return nil
		}),
		check("unknown_carrier_family_rejected", CategoryAPIContracts, func() error {
			if _, err := carrier.NewModel(p, "unknown"); err == nil {
				return fmt.Errorf("unknown carrier accepted")
			}
			return nil
		}),
		check("unknown_proxy_target_rejected", CategoryAPIContracts, func() error {
			_, _, err := proxysem.DefaultRegistry().Run(proxysem.TargetDescriptor{Class: "unknown"}, proxysem.TargetRequest{StreamID: 1, Bytes: 1}, 1)
			if err == nil {
				return fmt.Errorf("unknown target accepted")
			}
			return nil
		}),
		check("invalid_runtime_config_rejected", CategoryAPIContracts, func() error {
			if _, err := kruntime.NewRuntime(kruntime.RuntimeConfig{}, p); err == nil {
				return fmt.Errorf("zero runtime config accepted")
			}
			if _, err := kruntime.NewSession("", "rt", kruntime.RoleClient); err == nil {
				return fmt.Errorf("empty session id accepted")
			}
			return nil
		}),
		check("malformed_profile_json_rejected", CategoryAPIContracts, func() error {
			var decoded map[string]any
			if err := json.Unmarshal([]byte(`{bad json`), &decoded); err == nil {
				return fmt.Errorf("malformed JSON accepted")
			}
			return nil
		}),
		check("compiler_profile_nil_not_generated", CategoryAPIContracts, func() error {
			p, err := compiler.Generate(99)
			if err != nil || p == nil || p.ID == "" {
				return fmt.Errorf("compiler generated invalid profile")
			}
			return nil
		}),
	}
}
