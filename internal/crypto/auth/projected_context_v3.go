// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package auth

import (
	"bytes"
	"reflect"
	"strings"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/liveprogram"
)

// ProjectedContextValidationBytesV3 is a separate, lifetime-reserved construction
// allowance, not the framing codec's reserve. Input guards below bound all text
// and descriptor storage before existing canonical encoders or cloning run.
// This covers the retained snapshot and nested canonical/projector scratch;
// it is not an RSS/allocator/GC bound. Toolchain changes require remeasurement.
// Conservative live-capacity derivation, with U=32768: input backing <=16384
// bounds all list text plus descriptors. LP list prefixes consume at most a
// quarter of descriptor bytes, and fixed hashes/scalars/LP fields fit 4096,
// so each canonical policy/compatibility/config/mode block fits U. ContextHash
// retains <=4U component bytes; nested component encoding and its aggregate
// buffer growth are charged 16U together. Existing liveprogram/IR validation
// narrows policy lists to ten known capabilities before policy JSON hashing.
// Its text is at most eighteen 256-byte fields; escaping at six bytes/byte
// plus keys/lists fits U. Each program JSON projection is smaller (two 255-byte
// base64 tags, two messages, four header names, or one 256-byte priority text).
// Charge 8U for these sequential JSON/projector buffers and growth, even though
// they do not overlap ContextHash scratch; 2U for retained snapshot/backing,
// and 2U for fixed value copies/reflect frames/descriptor maps. 28U=917504,
// leaving 4U slack in this 1MiB reserve. This is deliberately a live ownership
// bound, not a promise about collection of earlier unreachable temporaries.
const ProjectedContextValidationBytesV3 uint64 = 1 << 20

// ProjectedContextSnapshotV3 validates the still-owned result under its lock,
// before cloning or consuming any channel secret. It confers no service grant.
func (result *ProcessHandshakeResultV1) ProjectedContextSnapshotV3(program liveprogram.ProgramV1, carrierFamily string, budgetBytes uint64) (AuthenticatedContextSnapshotV1, error) {
	if result == nil || budgetBytes < ProjectedContextValidationBytesV3 {
		return AuthenticatedContextSnapshotV1{}, fail(FailureInternalLimit)
	}
	result.mu.Lock()
	defer result.mu.Unlock()
	if result.closed || len(result.secret) == 0 || isZero32(result.context.ContextHash) {
		return AuthenticatedContextSnapshotV1{}, fail(FailureOutOfOrder)
	}
	if err := ValidateProjectedProcessContextV3(result.context, program, carrierFamily); err != nil {
		return AuthenticatedContextSnapshotV1{}, err
	}
	return cloneProjectedContextV3(result.context), nil
}

// ValidateProjectedProcessContextV3 compares the existing security-relevant
// projection, not an invented whole-program hash. Snapshot values alone are not
// provenance; the runtime obtains them only through the success-owned result.
func ValidateProjectedProcessContextV3(snapshot AuthenticatedContextSnapshotV1, program liveprogram.ProgramV1, carrierFamily string) error {
	if !boundedProjectionInputV3(snapshot, program) {
		return fail(FailureInternalLimit)
	}
	if carrierFamily != "tls13-tcp" || liveprogram.ValidateV1(program) != nil {
		return fail(FailureProfileMismatch)
	}
	policy, err := projectedEffectivePolicyV1(program)
	if err != nil {
		return fail(FailureProfileMismatch)
	}
	binding, err := projectedModeBindingV1(program, policy, carrierFamily)
	if err != nil {
		return fail(FailureProfileMismatch)
	}
	// First contact adds the offered-minus-required projection after constructing
	// the program binding. Reuse that same operation rather than compare the
	// pre-negotiation empty optional lists to the authenticated result.
	binding.ClientOptional = optionalCapabilities(program.Security.SelectedCapabilities, program.Security.ClientMandatoryCapabilities)
	binding.ServerOptional = optionalCapabilities(program.Security.SelectedCapabilities, program.Security.RelayMandatoryCapabilities)
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil || policyHash != snapshot.EffectivePolicyHash {
		return fail(FailureProfileMismatch)
	}
	capHash, err := security.SelectedCapabilityHashV1(policy.SelectedCapabilities)
	if err != nil || capHash != snapshot.SelectedCapabilityHash || snapshot.ClientProfileHash != program.SourceGenerationHash || snapshot.ServerProfileHash != program.SourceGenerationHash || !contextSnapshotBindingsMatch(snapshot) {
		return fail(FailureProfileMismatch)
	}
	actualHash, err := security.ContextHashV1(contextHashInputFromSnapshot(snapshot))
	if err != nil || actualHash != snapshot.ContextHash {
		return fail(FailureProfileMismatch)
	}
	expected, err := security.CanonicalAuthenticatedModeBindingV1(policy.TranscriptMode, binding)
	if err != nil {
		return fail(FailureProfileMismatch)
	}
	for _, role := range []security.HandshakeModeBinding{snapshot.ClientModeBinding, snapshot.ServerModeBinding} {
		actual, err := security.CanonicalAuthenticatedModeBindingV1(policy.TranscriptMode, role)
		if err != nil || !bytes.Equal(expected, actual) {
			return fail(FailureProfileMismatch)
		}
	}
	return nil
}

// A bounded traversal of these two fixed public Go types checks sizes only;
// protocol interpretation remains in the existing validators/projectors. No
// caller callbacks, serialization, slice growth, or string copies occur here.
// At most 64 elements per descriptor list, 256 bytes per text, 510 per byte
// slice and 16 KiB aggregate logical backing precede all canonical allocations.
func boundedProjectionInputV3(snapshot AuthenticatedContextSnapshotV1, program liveprogram.ProgramV1) bool {
	return boundedProjectionValuesV3(reflect.ValueOf(snapshot), reflect.ValueOf(program))
}

func boundedProgramInputV3(program liveprogram.ProgramV1) bool {
	return boundedProjectionValuesV3(reflect.ValueOf(program))
}

func boundedProjectionValuesV3(values ...reflect.Value) bool {
	remaining := 16384
	var visit func(reflect.Value) bool
	visit = func(v reflect.Value) bool {
		switch v.Kind() {
		case reflect.String:
			if v.Len() > 256 {
				return false
			}
			remaining -= v.Len()
		case reflect.Slice:
			if v.Type().Elem().Kind() == reflect.Uint8 {
				if v.Len() > 510 {
					return false
				}
				remaining -= v.Len()
				break
			}
			if v.Len() > 64 {
				return false
			}
			remaining -= v.Len() * int(v.Type().Elem().Size())
			for i := 0; i < v.Len(); i++ {
				if !visit(v.Index(i)) {
					return false
				}
			}
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				if !visit(v.Field(i)) {
					return false
				}
			}
		}
		return remaining >= 0
	}
	for _, value := range values {
		if !visit(value) {
			return false
		}
	}
	return true
}

func cloneProjectedContextV3(s AuthenticatedContextSnapshotV1) AuthenticatedContextSnapshotV1 {
	clone := func(v []string) []string { out := make([]string, len(v)); copy(out, v); return out }
	s.EffectivePolicy.ClientMandatoryCapabilities = clone(s.EffectivePolicy.ClientMandatoryCapabilities)
	s.EffectivePolicy.ServerMandatoryCapabilities = clone(s.EffectivePolicy.ServerMandatoryCapabilities)
	s.EffectivePolicy.SelectedCapabilities = clone(s.EffectivePolicy.SelectedCapabilities)
	compat := func(v security.CompatibilityBlockV1) security.CompatibilityBlockV1 {
		v.SupportedSecuritySuites = clone(v.SupportedSecuritySuites)
		v.RequiredCapabilities = clone(v.RequiredCapabilities)
		v.SupportedCarrierFamilies = clone(v.SupportedCarrierFamilies)
		v.SupportedProxyFeatures = clone(v.SupportedProxyFeatures)
		v.SupportedStreamFeatures = clone(v.SupportedStreamFeatures)
		return v
	}
	s.ClientCompatibilityBlock = compat(s.ClientCompatibilityBlock)
	s.ServerCompatibilityBlock = compat(s.ServerCompatibilityBlock)
	mode := func(v security.HandshakeModeBinding) security.HandshakeModeBinding {
		v.ClientOptional = clone(v.ClientOptional)
		v.ServerOptional = clone(v.ServerOptional)
		v.FeatureVectors = clone(v.FeatureVectors)
		v.CompatibilityBlock = compat(v.CompatibilityBlock)
		return v
	}
	s.ClientModeBinding = mode(s.ClientModeBinding)
	s.ServerModeBinding = mode(s.ServerModeBinding)
	// Slice descriptors now belong to s. Detach text so a short substring
	// cannot retain unmeasured backing from a locally constructed context.
	var text func(reflect.Value)
	text = func(v reflect.Value) {
		switch v.Kind() {
		case reflect.String:
			v.SetString(strings.Clone(v.String()))
		case reflect.Struct:
			for i := 0; i < v.NumField(); i++ {
				text(v.Field(i))
			}
		case reflect.Slice:
			for i := 0; i < v.Len(); i++ {
				text(v.Index(i))
			}
		}
	}
	text(reflect.ValueOf(&s).Elem())
	return s
}
