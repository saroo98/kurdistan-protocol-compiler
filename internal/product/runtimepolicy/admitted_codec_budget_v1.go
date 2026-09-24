// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtimepolicy

import (
	"kurdistan/internal/product/envelope"
	"math"
	"unsafe"
)

// AdmittedCodecWorkspaceV1 reserves the existing typed/map/array/canonical
// decoder envelope after bounded cryptographic and resource-shape admission.
// It is not admission for arbitrary typed graphs or an allocator/RSS ceiling.
func AdmittedCodecWorkspaceV1(profileBytes uint32) (uint64, bool) {
	if unsafe.Sizeof(uintptr(0)) != 8 || profileBytes == 0 || profileBytes > envelope.MaxPayloadBytes {
		return 0, false
	}
	p, r, g := uint64(profileBytes), uint64(MaxEncodedBytes), uint64(MaxLiveProgramBytes)
	clone := func(n uint64) uint64 { return 2*n + 8 }
	typed := 3*(2*p+8*4096) + 7*(2*r+8*2048) + 3*(2*g+8*512)
	maps := uint64(4 * 128 * ((256+128)*65 + 512))
	arrays := uint64(3*(2*2048*24+50*64*96) + 2048*24)
	canonical := 2*clone(r) + 2*clone(g)
	// Existing exact <=4096 DER/crypto qualification and bounded codec slots.
	fixed := uint64(1703936 + 4141 + 4140 + 32*1024)
	var total uint64
	for _, term := range []uint64{typed, maps, arrays, canonical, fixed} {
		if term > math.MaxUint64-total {
			return 0, false
		}
		total += term
	}
	return total, true
}
