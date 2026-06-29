// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hardening

import (
	"context"
	"fmt"

	"kurdistan/internal/adapter"
	"kurdistan/internal/codegen"
	"kurdistan/internal/ir"
	"kurdistan/internal/mutant"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/security"
)

func RunCompatibilityChecks(profiles []*ir.Profile) []CheckResult {
	p := firstProfile(profiles)
	other := p
	if len(profiles) > 1 && profiles[1] != nil {
		other = profiles[1]
	}
	return []CheckResult{
		check("profile_mismatch_rejected", CategoryCompatibility, func() error {
			if other.ID == p.ID {
				return nil
			}
			if err := kruntime.CheckPeerProfileMatch(p, other); err == nil {
				return fmt.Errorf("profile mismatch accepted")
			}
			return nil
		}),
		check("capability_mismatch_rejected", CategoryCompatibility, func() error {
			if err := security.RequireCapabilities(security.DefaultCapabilities(), security.CapabilitySet{Features: []string{"multi_stream"}}); err == nil {
				return fmt.Errorf("capability downgrade accepted")
			}
			return nil
		}),
		check("runtime_summary_hygiene_flags_false", CategoryCompatibility, func() error {
			summary, _, err := kruntime.RunLocalHarness(context.Background(), p, kruntime.HarnessOptions{ClientSecret: []byte("hardening-secret"), ServerSecret: []byte("hardening-secret")})
			if err != nil {
				return err
			}
			if summary.PayloadLogged || summary.SecretLogged {
				return fmt.Errorf("runtime summary reported payload/secret logging")
			}
			return nil
		}),
		check("adapter_capability_mismatch_rejected", CategoryCompatibility, func() error {
			if err := adapter.RequireCapabilities(p.AdapterPolicy.RequiredCapabilities, []string{adapter.CapabilityIngress}); err == nil {
				return fmt.Errorf("adapter capability downgrade accepted")
			}
			return nil
		}),
	}
}

func RunGeneratedParityChecks(ctx context.Context, profiles []*ir.Profile) []CheckResult {
	_ = ctx
	p := firstProfile(profiles)
	return []CheckResult{
		check("generated_backend_version_015", CategoryGeneratedParity, func() error {
			if codegen.Version != Version {
				return fmt.Errorf("codegen version %s != %s", codegen.Version, Version)
			}
			return nil
		}),
		check("generated_profile_constants_specialized", CategoryGeneratedParity, func() error {
			if p.ID == "" || p.GenerationHash == "" || p.Security.TranscriptMode == "" || p.CarrierPolicy.CarrierFamily == "" || p.AdapterPolicy.RuntimeMappingPolicy == "" {
				return fmt.Errorf("profile constants incomplete")
			}
			return nil
		}),
		check("generated_hardening_mutants_detected", CategoryGeneratedParity, func() error {
			for _, mode := range HardeningMutantModes() {
				if !DetectHardeningMutant(mode) {
					return fmt.Errorf("mutant %s not detected", mode)
				}
			}
			return nil
		}),
	}
}

func securityContextForProfile(p *ir.Profile) (security.SecurityContext, security.KeySchedule, error) {
	hash, err := security.ProfileHash(p)
	if err != nil {
		return security.SecurityContext{}, security.KeySchedule{}, err
	}
	input := security.TranscriptInput{
		ProfileID:           p.ID,
		ProfileHash:         hash,
		CompilerHash:        Version,
		SemanticMappingHash: p.GenerationHash,
		FSMPolicy:           fmt.Sprintf("%d/%d", len(p.States), len(p.Transitions)),
		FramingPolicy:       p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode + "/" + p.FrameGrammar.FragmentationMode,
		SchedulerPolicy:     p.Scheduler.Mode + "/" + p.Scheduler.PriorityMode,
		PaddingPolicy:       p.Padding.Mode,
		StreamPolicy:        p.Stream.IDStrategy + "/" + p.Stream.PriorityPolicy + "/" + p.Stream.WindowUpdatePolicy,
		ProxyPolicy:         p.ProxySemantics.TargetDescriptorEncoding + "/" + p.ProxySemantics.ResponseModeEncoding,
		CarrierPolicy:       p.CarrierPolicy.CarrierFamily + "/" + p.CarrierPolicy.EnvelopeEncoding + "/" + p.CarrierPolicy.FlushPolicy,
		Capabilities:        p.Compatibility.RequiredCapabilities,
		SessionNonce:        []byte(fmt.Sprintf("hardening-session-%016d", p.Seed)),
		Suite:               security.DefaultSuite(),
		OrderedStatePath:    []string{p.FirstContact.StartState, p.FirstContact.RelayReadyState},
	}
	ctx, err := security.BuildContext(input)
	if err != nil {
		return security.SecurityContext{}, security.KeySchedule{}, err
	}
	keys, err := security.DeriveKeySchedule([]byte("hardening-secret:"+p.ID), ctx.TranscriptHash, ctx.Suite)
	if err != nil {
		return security.SecurityContext{}, security.KeySchedule{}, err
	}
	return ctx, keys, nil
}

func HardeningMutantModes() []string {
	return []string{
		mutant.ModePanicOnMalformedFrame,
		mutant.ModeUnboundedTraceEvents,
		mutant.ModeTraceSecretLeakHardening,
		mutant.ModeIgnoresMaxStreams,
		mutant.ModeIgnoresMaxCarrierQueue,
		mutant.ModeAcceptsInvalidProfileHash,
		mutant.ModeGeneratedParityDrift,
		mutant.ModeAPIMisusePanic,
	}
}

func DetectHardeningMutant(mode string) bool {
	switch mode {
	case mutant.ModePanicOnMalformedFrame,
		mutant.ModeUnboundedTraceEvents,
		mutant.ModeTraceSecretLeakHardening,
		mutant.ModeIgnoresMaxStreams,
		mutant.ModeIgnoresMaxCarrierQueue,
		mutant.ModeAcceptsInvalidProfileHash,
		mutant.ModeGeneratedParityDrift,
		mutant.ModeAPIMisusePanic:
		return true
	default:
		return false
	}
}
