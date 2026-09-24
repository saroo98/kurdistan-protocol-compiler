// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package security

import (
	"reflect"
	"strings"
	"unsafe"

	"kurdistan/internal/protocol/ir"
)

// This is live owned capacity, not allocator classes, garbage, GC arenas or RSS.
// Go 1.26.6 standard AES-GCM: two retained GCMs, two construction AES blocks
// and two key clones fit 2560 bytes on supported amd64/arm64 paths. The 4096
// reserve includes slack, checked by construction regression tests. Review it
// when changing the toolchain/backend. No private crypto representation is used.
const boundedAESAllowanceV3 uint64 = 4096

// Seal and authenticate have separate fixed nonce/AAD scratch. Count both even
// though the concrete duplex serializes calls; compiler escape does not change
// logical owned capacity (allocator size-class rounding is outside this model).
const boundedEnvelopeScratchV3 = uint64(2*222+nonceBytesV1) + uint64(unsafe.Sizeof(NonceAllocationV1{}))

func nonceDomainsV3(mode string) int {
	if mode == NonceModeStreamPartitionedCounterV1 {
		return 65536
	}
	return 1
}

// EnvelopeOwnedBytesV3 bounds fixed owned capacity for a serialized bounded
// consumer with one live replay grant. Policy text is capped at 256 bytes and
// each of the three capability lists at 32 entries of at most 96 bytes. Text
// and descriptors are detached on construction; input backing is not retained.
func EnvelopeOwnedBytesV3(context EnvelopeContextV1) (uint64, error) {
	if err := validateEnvelopeContextV1(context); err != nil {
		return 0, err
	}
	return EnvelopeStorageOwnedBytesV3(context.EffectivePolicy)
}

// EnvelopeStorageOwnedBytesV3 calculates bounded policy storage only. It cannot
// validate an authenticated context or construct an envelope codec.
func EnvelopeStorageOwnedBytesV3(policy ir.EffectiveSecurityPolicy) (uint64, error) {
	if err := validateEnvelopePolicyV1(policy); err != nil {
		return 0, err
	}
	var descriptors uint64
	fields := reflect.ValueOf(policy)
	for i := 0; i < fields.NumField(); i++ {
		v := fields.Field(i)
		if v.Kind() == reflect.String {
			if v.Len() > 256 {
				return 0, ErrInvalidConfig
			}
			descriptors += uint64(v.Len())
		}
	}
	for _, values := range [][]string{policy.ClientMandatoryCapabilities, policy.ServerMandatoryCapabilities, policy.SelectedCapabilities} {
		if len(values) > 32 {
			return 0, ErrInvalidConfig
		}
		for _, value := range values {
			if len(value) > 96 {
				return 0, ErrInvalidConfig
			}
			descriptors += uint64(len(value))
		}
		descriptors += uint64(len(values)) * uint64(unsafe.Sizeof(""))
	}
	// Each bound method retains a code pointer and a receiver pointer, separate
	// from its function field. The receiver itself is charged only once.
	type capture struct {
		code     uintptr
		receiver unsafe.Pointer
	}
	d := uint64(nonceDomainsV3(policy.NonceMode))
	j := (uint64(policy.ReplayWindowSize) + 63) / 64
	fixed := uint64(unsafe.Sizeof(EnvelopeCodecV1{})) + uint64(unsafe.Sizeof(strictEnvelopeStateV1{})) + uint64(unsafe.Sizeof(ClientNonceOwnerV1{})) + uint64(unsafe.Sizeof(nonceDirectionStateV1{})) + uint64(unsafe.Sizeof(authenticatedReplayAuthorityV1{})) + 4*uint64(unsafe.Sizeof(capture{})) + uint64(unsafe.Sizeof(authenticatedReplayStateV1{})) + uint64(unsafe.Sizeof(authenticatedReplayGrantV1{})) + boundedAESAllowanceV3 + boundedEnvelopeScratchV3 + descriptors
	per := uint64(unsafe.Sizeof(nonceSequenceStateV1{})) + uint64(unsafe.Sizeof(ReplayWindowV1{})) + uint64(unsafe.Sizeof(replayWindowStateV1{})) + j*uint64(unsafe.Sizeof(uint64(0)))
	if d > (^uint64(0)-fixed)/per {
		return 0, ErrInvalidConfig
	}
	return fixed + d*per, nil
}

// Bounded constructors choose final storage on fresh owners only. They do not
// grant signed service authority or generic concurrent precheck scheduling parity.
func NewClientEnvelopeBoundedV3(schedule KeySchedule, context EnvelopeContextV1) (*EnvelopeCodecV1, error) {
	return newRoleEnvelopeV1(schedule, context, true, true)
}
func NewRelayEnvelopeBoundedV3(schedule KeySchedule, context EnvelopeContextV1) (*EnvelopeCodecV1, error) {
	return newRoleEnvelopeV1(schedule, context, false, true)
}

func cloneBoundedPolicyTextV3(p *ir.EffectiveSecurityPolicy) {
	fields := reflect.ValueOf(p).Elem()
	for i := 0; i < fields.NumField(); i++ {
		v := fields.Field(i)
		if v.Kind() == reflect.String {
			v.SetString(strings.Clone(v.String()))
		}
	}
	for _, list := range [][]string{p.ClientMandatoryCapabilities, p.ServerMandatoryCapabilities, p.SelectedCapabilities} {
		for i := range list {
			list[i] = strings.Clone(list[i])
		}
	}
}

func newReplayArenaV3(context EnvelopeContextV1) []ReplayWindowV1 {
	d := nonceDomainsV3(context.EffectivePolicy.NonceMode)
	j := (context.EffectivePolicy.ReplayWindowSize + 63) / 64
	windows := make([]ReplayWindowV1, d)
	states := make([]replayWindowStateV1, d)
	arena := make([]uint64, d*j)
	for i := range windows {
		windows[i].state = &states[i]
		states[i].policy = context.EffectivePolicy.ReplayPolicy
		states[i].window = uint64(context.EffectivePolicy.ReplayWindowSize)
		states[i].bitmap = arena[i*j : (i+1)*j : (i+1)*j]
	}
	return windows
}

// DestroyBoundedV3 requires all external users, including copied codec and
// capability users, to have joined. It invalidates shared authority without
// resetting identities or used mutexes. This is not secure erasure of opaque
// standard AES objects or caller-retained copies of nonsecret context.
func (c *EnvelopeCodecV1) DestroyBoundedV3() error {
	if c == nil || c.state == nil || !c.state.bounded {
		return ErrInvalidConfig
	}
	s := c.state
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.destroyed {
		s.destroyed = true
		s.replayAuthority = nil
		var direction *nonceDirectionStateV1
		if s.boundedClient != nil {
			direction = s.boundedClient.outbound
			s.boundedClient.inbound = nonceDirectionConfigV1{}
		}
		if s.boundedRelay != nil {
			direction = s.boundedRelay.outbound
			s.boundedRelay.inbound = nonceDirectionConfigV1{}
		}
		if direction != nil {
			direction.config = nonceDirectionConfigV1{}
			clear(direction.fixed)
			direction.fixed = nil
		}
		for i := range s.windows {
			r := s.windows[i].state
			clear(r.bitmap)
			r.bitmap = nil
			r.policy = ""
			r.window = 0
			r.highest = 0
			r.initialized = false
			s.windows[i].state = nil
		}
		s.windows = nil
		s.nonces = envelopeNonceOwnerV1{}
		s.boundedClient = nil
		s.boundedRelay = nil
		s.sealFail = nil
	}
	clear(c.context.EffectivePolicy.ClientMandatoryCapabilities)
	clear(c.context.EffectivePolicy.ServerMandatoryCapabilities)
	clear(c.context.EffectivePolicy.SelectedCapabilities)
	c.context = EnvelopeContextV1{}
	c.outbound = nil
	c.inbound = nil
	c.epoch = 0
	return nil
}
