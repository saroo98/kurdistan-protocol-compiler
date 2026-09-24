// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package main

/*
#include <stdint.h>
*/
import "C"

import (
	"encoding/binary"
	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/selfhost"
	"time"
	"unsafe"
)

type bootstrapSpanV1 struct {
	pointer unsafe.Pointer
	length  uint32
}

func (s bootstrapSpanV1) valid() bool {
	return s.pointer != nil && s.length > 0 && uintptr(s.length) <= ^uintptr(0)-uintptr(s.pointer)
}
func (s bootstrapSpanV1) bytes() []byte { return unsafe.Slice((*byte)(s.pointer), int(s.length)) }
func bootstrapSpansDisjointV1(spans []bootstrapSpanV1) bool {
	for i, s := range spans {
		if !s.valid() {
			return false
		}
		for _, other := range spans[:i] {
			if uintptr(s.pointer) < uintptr(other.pointer)+uintptr(other.length) && uintptr(other.pointer) < uintptr(s.pointer)+uintptr(s.length) {
				return false
			}
		}
	}
	return true
}
func bootstrapInputsStatusV1(inputs [5]bootstrapSpanV1, production bool) int32 {
	maxima := [5]uint32{1405996, 1118299, 512, 128, 16777}
	if production {
		maxima[4] = 196608
	}
	for i, s := range inputs {
		if !s.valid() {
			return 2
		}
		if s.length > maxima[i] {
			return 4
		}
	}
	return 0
}
func bootstrapOwnedInputsV1(inputs [5]bootstrapSpanV1, owned *[5][]byte) {
	for i, s := range inputs {
		owned[i] = make([]byte, int(s.length))
		copy(owned[i], s.bytes())
	}
}
func bootstrapMaterialV1(owned [5][]byte) androidbridge.MaintenanceCurrentInputV1 {
	return androidbridge.MaintenanceCurrentInputV1{VerifyRequest: owned[0], ActivationRecord: owned[1], RecipientRequest: owned[2], RecipientPrivate: owned[3]}
}
func bootstrapLimitsV1() selfhost.LiveMaintenanceLimits {
	return selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}
}
func bootstrapLegacyBindingV1(inputs [5]bootstrapSpanV1, output bootstrapSpanV1) (result int32) {
	return bootstrapLegacyBindingAtV1(inputs, output, selfHostedBridgeEnvironment{}, time.Now().UTC())
}

// Production always supplies the actual environment and one captured time.
// This private call seam also exercises anomalies without replacing ownership.
func bootstrapLegacyBindingAtV1(inputs [5]bootstrapSpanV1, output bootstrapSpanV1, environment androidbridge.RecipientVerificationEnvironmentAt, now time.Time) (result int32) {
	result = int32(androidbridge.CodeInternalFailure)
	defer func() {
		if recover() != nil {
			result = int32(androidbridge.CodeInternalFailure)
		}
	}()
	if !output.valid() {
		return int32(androidbridge.CodeInvalidArgument)
	}
	if output.length < 41 {
		return int32(androidbridge.CodeSizeLimit)
	}
	if s := bootstrapInputsStatusV1(inputs, false); s != 0 {
		if s == 4 {
			return int32(androidbridge.CodeSizeLimit)
		}
		return int32(androidbridge.CodeInvalidArgument)
	}
	spans := append(inputs[:], output)
	if !bootstrapSpansDisjointV1(spans) {
		return int32(androidbridge.CodeInvalidArgument)
	}
	var owned [5][]byte
	defer func() {
		for _, p := range owned {
			clear(p)
		}
	}()
	bootstrapOwnedInputsV1(inputs, &owned)
	policy, err := androidbridge.DecodeLegacyBootstrapPolicyV1(owned[4])
	if err != nil {
		return int32(androidbridge.CodeInvalidArgument)
	}
	facts, code := androidbridge.ReadLegacyRuntimeBootstrapBindingV1(bootstrapMaterialV1(owned), policy, environment, now, bootstrapLimitsV1())
	if code != androidbridge.CodeOK {
		return int32(code)
	}
	var wire [41]byte
	defer clear(wire[:])
	binary.BigEndian.PutUint64(wire[:8], facts.Generation)
	copy(wire[8:40], facts.PlanDigest[:])
	wire[40] = facts.SignedRetryMaximum
	facts = androidbridge.RuntimeBootstrapBindingV1{}
	copy(output.bytes()[:41], wire[:])
	return 0
}
func bootstrapProductionBindingV1(inputs [5]bootstrapSpanV1, output, active bootstrapSpanV1, activeWritten *uint32,
	disconnected bootstrapSpanV1, disconnectedWritten *uint32) (result int32) {
	result = 18
	defer func() {
		if recover() != nil {
			result = 18
		}
	}()
	if activeWritten == nil || disconnectedWritten == nil || uintptr(unsafe.Pointer(activeWritten))%4 != 0 || uintptr(unsafe.Pointer(disconnectedWritten))%4 != 0 {
		return 2
	}
	metadata := [2]bootstrapSpanV1{{unsafe.Pointer(activeWritten), 4}, {unsafe.Pointer(disconnectedWritten), 4}}
	outputs := []bootstrapSpanV1{output, active, disconnected, metadata[0], metadata[1]}
	if !bootstrapSpansDisjointV1(outputs) {
		return 2
	}
	if output.length < 44 || active.length < 512 || disconnected.length < 512 {
		return 4
	}
	// Do not zero metadata until every alias against the input spans is rejected.
	spans := append(inputs[:], outputs...)
	if s := bootstrapInputsStatusV1(inputs, true); s != 0 {
		return s
	}
	if !bootstrapSpansDisjointV1(spans) {
		return 2
	}
	*activeWritten = 0
	*disconnectedWritten = 0
	var owned [5][]byte
	defer func() {
		for _, p := range owned {
			clear(p)
		}
	}()
	bootstrapOwnedInputsV1(inputs, &owned)
	var activeStaging, disconnectedStaging [512]byte
	defer clear(activeStaging[:])
	defer clear(disconnectedStaging[:])
	facts, a, d, status := androidbridge.ReadProductionRuntimeBootstrapBindingV1(bootstrapMaterialV1(owned), owned[4], selfHostedBridgeEnvironment{}, time.Now().UTC(), bootstrapLimitsV1(), activeStaging[:], disconnectedStaging[:])
	if status != 0 {
		return status
	}
	if a < 54 || a > 512 || d < 54 || d > 512 {
		return 18
	}
	var wire [44]byte
	defer clear(wire[:])
	binary.BigEndian.PutUint64(wire[:8], facts.Generation)
	copy(wire[8:40], facts.PlanDigest[:])
	binary.BigEndian.PutUint16(wire[40:42], facts.EffectiveMTU)
	wire[42] = facts.SignedRetryMaximum
	wire[43] = facts.EffectiveAutomaticReconnectMaximum
	facts = androidbridge.ProductionBootstrapFactsV1{}
	copy(output.bytes()[:44], wire[:])
	copy(active.bytes()[:a], activeStaging[:a])
	copy(disconnected.bytes()[:d], disconnectedStaging[:d])
	*activeWritten = uint32(a)
	*disconnectedWritten = uint32(d)
	return 0
}

//export kvpn_bootstrap_legacy_binding_v1
func kvpn_bootstrap_legacy_binding_v1(v *C.uint8_t, vn C.uint32_t, a *C.uint8_t, an C.uint32_t, r *C.uint8_t, rn C.uint32_t, p *C.uint8_t, pn C.uint32_t, s *C.uint8_t, sn C.uint32_t, o *C.uint8_t, on C.uint32_t) C.int32_t {
	return C.int32_t(bootstrapLegacyBindingV1([5]bootstrapSpanV1{{unsafe.Pointer(v), uint32(vn)}, {unsafe.Pointer(a), uint32(an)}, {unsafe.Pointer(r), uint32(rn)}, {unsafe.Pointer(p), uint32(pn)}, {unsafe.Pointer(s), uint32(sn)}}, bootstrapSpanV1{unsafe.Pointer(o), uint32(on)}))
}

//export kvpn_bootstrap_production_binding_v1
func kvpn_bootstrap_production_binding_v1(v *C.uint8_t, vn C.uint32_t, a *C.uint8_t, an C.uint32_t, r *C.uint8_t, rn C.uint32_t, p *C.uint8_t, pn C.uint32_t, s *C.uint8_t, sn C.uint32_t, o *C.uint8_t, on C.uint32_t, ac *C.uint8_t, acn C.uint32_t, aw *C.uint32_t, dc *C.uint8_t, dcn C.uint32_t, dw *C.uint32_t) C.int32_t {
	return C.int32_t(bootstrapProductionBindingV1([5]bootstrapSpanV1{{unsafe.Pointer(v), uint32(vn)}, {unsafe.Pointer(a), uint32(an)}, {unsafe.Pointer(r), uint32(rn)}, {unsafe.Pointer(p), uint32(pn)}, {unsafe.Pointer(s), uint32(sn)}}, bootstrapSpanV1{unsafe.Pointer(o), uint32(on)}, bootstrapSpanV1{unsafe.Pointer(ac), uint32(acn)}, (*uint32)(unsafe.Pointer(aw)), bootstrapSpanV1{unsafe.Pointer(dc), uint32(dcn)}, (*uint32)(unsafe.Pointer(dw))))
}
