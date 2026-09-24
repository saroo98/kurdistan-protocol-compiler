// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package sessionplan

import (
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/liveprogram"
	"math"
	"unsafe"
)

// AdmittedCalculationBounds describes named source holders around one decoder
// invocation. Caller-retained verified material and input copies are additional.
type AdmittedCalculationBounds struct {
	DecoderBytes, PolicyBytes, PlanBytes, ProgramBytes, SelectionBytes uint64
	BuildBytes, ReturnBytes, SuffixBytes                               uint64
}

func AdmittedCalculationBoundsV2(profileBytes uint32) (AdmittedCalculationBounds, bool) {
	d, ok := runtimepolicy.AdmittedCodecWorkspaceV1(profileBytes)
	if !ok {
		return AdmittedCalculationBounds{}, false
	}
	clone := func(n uint64) uint64 {
		if n == 0 {
			return 0
		}
		return 2*n + 8
	}
	r, g := uint64(runtimepolicy.MaxEncodedBytes), uint64(runtimepolicy.MaxLiveProgramBytes)
	arrayView := uint64(2*2048*24 + 50*64*96)
	policy := uint64(unsafe.Sizeof(runtimepolicy.PolicyV2{})) + 2*r + 8*2048 + arrayView +
		uint64(unsafe.Sizeof(runtimepolicy.ServicesV1{})) + uint64(unsafe.Sizeof(runtimepolicy.ProxyV1{})) +
		uint64(unsafe.Sizeof(runtimepolicy.ProbesV1{})) + uint64(unsafe.Sizeof(runtimepolicy.UpdateV1{}))
	plan := uint64(unsafe.Sizeof(PlanV2{})) + clone(r) + clone(4*uint64(unsafe.Sizeof(runtimepolicy.EndpointV2{}))) + 4*clone(16) +
		clone(2*uint64(unsafe.Sizeof(runtimepolicy.PrefixV2{}))) + 2*clone(16) + clone(4*uint64(unsafe.Sizeof(runtimepolicy.PayloadProtocolV2(""))))
	program := uint64(unsafe.Sizeof(liveprogram.ProgramV1{})) + 2*g + 8*512 + arrayView
	// Includes both historical selection views, two DNS projection sets, four
	// indexes/protocols and the existing bounded hash/codec frame allowance.
	network := 2*clone(2*uint64(unsafe.Sizeof(runtimepolicy.PrefixV2{}))) + 2*clone(2*uint64(unsafe.Sizeof([]byte{}))) +
		8*clone(16) + clone(4) + clone(4*uint64(unsafe.Sizeof(runtimepolicy.PayloadProtocolV2("")))) + 32*1024
	add := func(values ...uint64) (uint64, bool) {
		var n uint64
		for _, v := range values {
			if v > math.MaxUint64-n {
				return 0, false
			}
			n += v
		}
		return n, true
	}
	build, ok := add(policy, clone(r), plan, d, network)
	if !ok {
		return AdmittedCalculationBounds{}, false
	}
	returned, ok := add(policy, clone(r), plan, plan, network)
	if !ok {
		return AdmittedCalculationBounds{}, false
	}
	return AdmittedCalculationBounds{d, policy, plan, program, network, build, returned, max(d, build, returned)}, true
}
