// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/ir"
	"kurdistan/internal/security"
)

type SecureChannel struct {
	Context security.SecurityContext
	Keys    security.KeySchedule
	Out     *security.EnvelopeCodec
	In      *security.EnvelopeCodec
}

func BuildSecurityContext(p *ir.Profile, caps security.CapabilitySet, secret []byte) (security.SecurityContext, security.KeySchedule, error) {
	input, err := TranscriptInputForProfile(p, caps)
	if err != nil {
		return security.SecurityContext{}, security.KeySchedule{}, err
	}
	ctx, err := security.BuildContext(input)
	if err != nil {
		return security.SecurityContext{}, security.KeySchedule{}, err
	}
	keys, err := security.DeriveKeySchedule(secret, ctx.TranscriptHash, ctx.Suite)
	if err != nil {
		return security.SecurityContext{}, security.KeySchedule{}, err
	}
	return ctx, keys, nil
}

func NewSecureChannel(ctx security.SecurityContext, keys security.KeySchedule, role Role) (*SecureChannel, error) {
	out, err := security.NewEnvelopeCodec(ctx, keys, string(role))
	if err != nil {
		return nil, err
	}
	in, err := security.NewEnvelopeCodec(ctx, keys, string(oppositeRole(role)))
	if err != nil {
		return nil, err
	}
	return &SecureChannel{Context: ctx, Keys: keys, Out: out, In: in}, nil
}

func (c *SecureChannel) Seal(meta security.EnvelopeMetadata, payload []byte) (security.SecureEnvelope, error) {
	if c == nil || c.Out == nil {
		return security.SecureEnvelope{}, fmt.Errorf("%w: nil outbound channel", ErrSecureChannel)
	}
	return c.Out.Seal(meta, payload)
}

func (c *SecureChannel) Open(env security.SecureEnvelope) ([]byte, error) {
	if c == nil || c.In == nil {
		return nil, fmt.Errorf("%w: nil inbound channel", ErrSecureChannel)
	}
	return c.In.Open(env)
}

func TranscriptInputForProfile(p *ir.Profile, caps security.CapabilitySet) (security.TranscriptInput, error) {
	if p == nil {
		return security.TranscriptInput{}, fmt.Errorf("%w: nil profile", ErrCompatibility)
	}
	hash, err := security.ProfileHash(p)
	if err != nil {
		return security.TranscriptInput{}, err
	}
	return security.TranscriptInput{
		ProfileID:           p.ID,
		ProfileHash:         hash,
		CompilerHash:        "runtime-0.13.0-lab",
		SemanticMappingHash: p.GenerationHash,
		FSMPolicy:           fmt.Sprintf("%d/%d", len(p.States), len(p.Transitions)),
		FramingPolicy:       p.FrameGrammar.LengthMode + "/" + p.FrameGrammar.TypeMode + "/" + p.FrameGrammar.FragmentationMode,
		SchedulerPolicy:     p.Scheduler.Mode + "/" + p.Scheduler.PriorityMode,
		PaddingPolicy:       p.Padding.Mode,
		StreamPolicy:        p.Stream.IDStrategy + "/" + p.Stream.PriorityPolicy + "/" + p.Stream.WindowUpdatePolicy,
		ProxyPolicy:         p.ProxySemantics.TargetDescriptorEncoding + "/" + p.ProxySemantics.ResponseModeEncoding,
		CarrierPolicy:       p.CarrierPolicy.CarrierFamily + "/" + p.CarrierPolicy.EnvelopeEncoding + "/" + p.CarrierPolicy.FlushPolicy,
		Capabilities:        caps.Features,
		SessionNonce:        []byte("runtime-session:" + p.ID),
		Suite:               security.DefaultSuite(),
		OrderedStatePath:    []string{p.FirstContact.StartState, p.FirstContact.RelayReadyState},
	}, nil
}
