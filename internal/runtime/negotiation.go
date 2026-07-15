// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"

	"kurdistan/internal/crypto/security"
)

type NegotiationResult struct {
	Selected       security.CapabilitySet `json:"selected"`
	CapabilityHash string                 `json:"capability_hash"`
	TraceBucket    string                 `json:"trace_bucket"`
}

type BilateralNegotiationInput struct {
	LocalOffer                  security.CapabilitySet
	PeerOffer                   security.CapabilitySet
	LocalFloor                  security.CapabilitySet
	PeerFloor                   security.CapabilitySet
	CapabilityNegotiationPolicy string
	DowngradePolicy             string
	LocalSuite                  security.Suite
	PeerSuite                   security.Suite
	LocalTranscriptMode         string
	PeerTranscriptMode          string
}

func LocalCapabilities(required []string) security.CapabilitySet {
	if len(required) == 0 {
		return security.DefaultCapabilities()
	}
	return security.CapabilitySet{Features: append([]string(nil), required...)}
}

func NegotiateCapabilities(local, peer, required security.CapabilitySet) (NegotiationResult, error) {
	return NegotiateBilateralCapabilities(BilateralNegotiationInput{
		LocalOffer:                  local,
		PeerOffer:                   peer,
		LocalFloor:                  required,
		PeerFloor:                   required,
		CapabilityNegotiationPolicy: "intersection_with_required",
		DowngradePolicy:             "strict_capabilities",
		LocalSuite:                  security.DefaultSuite(),
		PeerSuite:                   security.DefaultSuite(),
		LocalTranscriptMode:         "canonical_v1",
		PeerTranscriptMode:          "canonical_v1",
	})
}

func NegotiateBilateralCapabilities(input BilateralNegotiationInput) (NegotiationResult, error) {
	selectedSet, err := security.SelectBilateralCapabilities(security.BilateralCapabilityInput{
		LocalOffer:                  input.LocalOffer,
		PeerOffer:                   input.PeerOffer,
		LocalFloor:                  input.LocalFloor,
		PeerFloor:                   input.PeerFloor,
		CapabilityNegotiationPolicy: input.CapabilityNegotiationPolicy,
		DowngradePolicy:             input.DowngradePolicy,
		LocalSuite:                  input.LocalSuite,
		PeerSuite:                   input.PeerSuite,
		LocalTranscriptMode:         input.LocalTranscriptMode,
		PeerTranscriptMode:          input.PeerTranscriptMode,
	})
	if err != nil {
		return NegotiationResult{}, fmt.Errorf("%w: %v", ErrNegotiation, err)
	}
	hash, err := selectedSet.Hash()
	if err != nil {
		return NegotiationResult{}, err
	}
	return NegotiationResult{Selected: selectedSet, CapabilityHash: hash, TraceBucket: shortHash(hash)}, nil
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
