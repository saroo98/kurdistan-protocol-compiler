// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"fmt"

	"kurdistan/internal/compiler"
	"kurdistan/internal/framing"
	"kurdistan/internal/ir"
	"kurdistan/internal/proxysem"
	kstream "kurdistan/internal/stream"
)

func RunInvariantRegistry(profiles []*ir.Profile) []CheckResult {
	p := firstProfile(profiles)
	results := []CheckResult{}
	results = append(results, check("generated_profiles_validate", CategoryInvariants, func() error {
		for _, p := range profiles {
			if err := ir.Validate(p); err != nil {
				return err
			}
		}
		return nil
	}))
	results = append(results, check("profile_id_stable_for_seed", CategoryInvariants, func() error {
		a, err := compiler.Generate(44)
		if err != nil {
			return err
		}
		b, err := compiler.Generate(44)
		if err != nil {
			return err
		}
		if a.ID != b.ID || a.GenerationHash != b.GenerationHash {
			return fmt.Errorf("seed not stable")
		}
		return nil
	}))
	results = append(results, check("profile_hash_changes_on_policy_change", CategoryInvariants, func() error {
		cp := *p
		cp.GenerationHash = ""
		cp.Scheduler.Mode = "mutated_mode"
		hash, err := ir.CanonicalHash(&cp)
		if err != nil {
			return err
		}
		if hash == p.GenerationHash {
			return fmt.Errorf("hash did not change")
		}
		return nil
	}))
	results = append(results, check("semantic_mappings_unique_and_present", CategoryInvariants, func() error {
		seen := map[string]bool{}
		for _, msg := range p.Messages {
			if msg.Semantic == "" || msg.WireSymbol == "" {
				return fmt.Errorf("empty semantic mapping")
			}
			if seen[msg.WireSymbol] {
				return fmt.Errorf("duplicate wire symbol")
			}
			seen[msg.WireSymbol] = true
		}
		return nil
	}))
	results = append(results, check("unsupported_policy_rejected", CategoryInvariants, func() error {
		cp := *p
		cp.GenerationHash = ""
		cp.FrameGrammar.LengthMode = "unsupported"
		if err := ir.Validate(&cp); err == nil {
			return fmt.Errorf("unsupported policy accepted")
		}
		return nil
	}))
	results = append(results, check("frame_round_trip_and_cross_profile_reject", CategoryInvariants, func() error {
		frames, err := framing.EncodeOperation(p, framing.Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hardening")}, p.Seed)
		if err != nil {
			return err
		}
		op, _, err := framing.DecodeFrames(p, frames)
		if err != nil {
			return err
		}
		if string(op.Payload) != "hardening" {
			return fmt.Errorf("frame round trip mismatch")
		}
		if len(profiles) > 1 {
			if other := profiles[1]; other != nil && other.ID != p.ID {
				if op2, _, err := framing.DecodeFrames(other, frames); err == nil && op2.Semantic == op.Semantic && string(op2.Payload) == string(op.Payload) {
					return fmt.Errorf("cross-profile frame silently equivalent")
				}
			}
		}
		return nil
	}))
	results = append(results, check("stream_limits_and_terminal_writes_rejected", CategoryInvariants, func() error {
		s, err := kstream.NewSession(kstream.Config{MaxConcurrentStreams: 1, InitialStreamWindowBytes: 8, InitialSessionWindowBytes: 8})
		if err != nil {
			return err
		}
		id, err := s.OpenStream("interactive")
		if err != nil {
			return err
		}
		if _, err := s.OpenStream("bulk"); err == nil {
			return fmt.Errorf("max stream limit ignored")
		}
		if _, err := s.WriteData(id, make([]byte, 9)); err == nil {
			return fmt.Errorf("backpressure not surfaced")
		}
		if err := s.Reset(id, "test"); err != nil {
			return err
		}
		if _, err := s.WriteData(id, []byte("x")); err == nil {
			return fmt.Errorf("reset stream accepted write")
		}
		return nil
	}))
	results = append(results, check("proxy_unknown_target_rejected", CategoryInvariants, func() error {
		if err := proxysem.DefaultRegistry().Validate(proxysem.TargetDescriptor{Class: "unknown"}); err == nil {
			return fmt.Errorf("unknown target accepted")
		}
		return nil
	}))
	return results
}

func check(name, category string, fn func() error) CheckResult {
	if err := fn(); err != nil {
		return fail(name, category, err.Error(), nil)
	}
	return pass(name, category, "checked", nil)
}
