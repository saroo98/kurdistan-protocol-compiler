// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package livecarrier

import (
	"time"

	"kurdistan/internal/product/runtimepolicy"
)

const liveALPNV2 = "kurd/1"

// LiveAuthorityV2 is the closed mapping from signed runtime policy to the
// first network-capable Kurd carrier. It contains no endpoint material.
type LiveAuthorityV2 struct {
	CarrierFamily string
	ALPN          string
	EndpointCount int
	Networked     bool
}

// ResolveV2 validates the complete signed runtime policy before authorizing a
// networked implementation. A carrier label alone is never authority.
func ResolveV2(policy runtimepolicy.PolicyV2) (LiveAuthorityV2, error) {
	return ResolveV2At(policy, time.Now())
}

// ResolveV2At lets callers bind carrier authorization to the same trusted-time
// decision used for profile and policy validation.
func ResolveV2At(policy runtimepolicy.PolicyV2, now time.Time) (LiveAuthorityV2, error) {
	if err := runtimepolicy.ValidateV2At(policy, now); err != nil ||
		policy.WireProtocol != runtimepolicy.WireProtocolV1 ||
		policy.CarrierFamily != runtimepolicy.CarrierFamilyTLS13TCP {
		return LiveAuthorityV2{}, ErrNotAuthorized
	}
	return LiveAuthorityV2{
		CarrierFamily: policy.CarrierFamily,
		ALPN:          liveALPNV2,
		EndpointCount: len(policy.Endpoints),
		Networked:     true,
	}, nil
}
