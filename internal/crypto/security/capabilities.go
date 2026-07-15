// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
)

type BilateralCapabilityInput struct {
	LocalOffer                  CapabilitySet
	PeerOffer                   CapabilitySet
	LocalFloor                  CapabilitySet
	PeerFloor                   CapabilitySet
	CapabilityNegotiationPolicy string
	DowngradePolicy             string
	LocalSuite                  Suite
	PeerSuite                   Suite
	LocalTranscriptMode         string
	PeerTranscriptMode          string
}

type CapabilitySet struct {
	Features []string `json:"features"`
}

func DefaultCapabilities() CapabilitySet {
	return CapabilitySet{Features: []string{
		"multi_stream",
		"proxy_semantics",
		"carrier_abstraction",
		"adapter_interface",
		"carrier_loss_recovery",
		"carrier_backpressure",
		"generated_backend",
		"transcript_binding",
		"replay_window",
		"nonce_schedule",
	}}
}

func KnownCapabilities() []string {
	return DefaultCapabilities().Features
}

func (c CapabilitySet) Hash() (string, error) {
	caps, err := canonicalCapabilities(c.Features)
	if err != nil {
		return "", err
	}
	raw, err := json.Marshal(struct {
		Domain string   `json:"domain"`
		Items  []string `json:"items"`
	}{Domain: "kurdistan-capabilities-v1", Items: caps})
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func RequireCapabilities(required, selected CapabilitySet) error {
	selectedSet := map[string]bool{}
	for _, feature := range selected.Features {
		selectedSet[feature] = true
	}
	for _, feature := range required.Features {
		if !selectedSet[feature] {
			return fmt.Errorf("%w: missing %s", ErrDowngrade, feature)
		}
	}
	return nil
}

func SelectBilateralCapabilities(input BilateralCapabilityInput) (CapabilitySet, error) {
	if err := validateBilateralDowngrade(input); err != nil {
		return CapabilitySet{}, err
	}
	localOffer, err := canonicalUniqueCapabilities(input.LocalOffer.Features)
	if err != nil {
		return CapabilitySet{}, err
	}
	peerOffer, err := canonicalUniqueCapabilities(input.PeerOffer.Features)
	if err != nil {
		return CapabilitySet{}, err
	}
	localFloor, err := canonicalUniqueCapabilities(input.LocalFloor.Features)
	if err != nil {
		return CapabilitySet{}, err
	}
	peerFloor, err := canonicalUniqueCapabilities(input.PeerFloor.Features)
	if err != nil {
		return CapabilitySet{}, err
	}
	if len(localOffer) == 0 || len(peerOffer) == 0 || len(localFloor) == 0 || len(peerFloor) == 0 {
		return CapabilitySet{}, fmt.Errorf("%w: empty offer or mandatory floor", ErrDowngrade)
	}
	floorSet := map[string]bool{}
	for _, floor := range [][]string{localFloor, peerFloor} {
		for _, capability := range floor {
			floorSet[capability] = true
		}
	}
	for _, offer := range [][]string{localOffer, peerOffer} {
		offerSet := setCapabilities(offer)
		for capability := range floorSet {
			if !offerSet[capability] {
				return CapabilitySet{}, fmt.Errorf("%w: offer below bilateral floor", ErrDowngrade)
			}
		}
	}

	selected := make([]string, 0)
	switch input.CapabilityNegotiationPolicy {
	case "strict_required":
		for capability := range floorSet {
			selected = append(selected, capability)
		}
	case "intersection_with_required", "profile_declared_required":
		peerSet := setCapabilities(peerOffer)
		for _, capability := range localOffer {
			if peerSet[capability] {
				selected = append(selected, capability)
			}
		}
	default:
		return CapabilitySet{}, fmt.Errorf("%w: unknown capability negotiation policy", ErrDowngrade)
	}
	sort.Strings(selected)
	return CapabilitySet{Features: selected}, nil
}

func DetectSuiteDowngrade(expected, selected Suite, transcriptHash string) error {
	if expected != selected {
		return fmt.Errorf("%w: suite mismatch", ErrDowngrade)
	}
	return nil
}

func canonicalCapabilities(features []string) ([]string, error) {
	known := map[string]bool{}
	for _, item := range KnownCapabilities() {
		known[item] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(features))
	for _, feature := range features {
		if !known[feature] {
			return nil, fmt.Errorf("%w: unknown capability %q", ErrInvalidConfig, feature)
		}
		if !seen[feature] {
			seen[feature] = true
			out = append(out, feature)
		}
	}
	sort.Strings(out)
	return out, nil
}

func canonicalUniqueCapabilities(features []string) ([]string, error) {
	known := map[string]bool{}
	for _, item := range KnownCapabilities() {
		known[item] = true
	}
	seen := map[string]bool{}
	out := make([]string, 0, len(features))
	for _, feature := range features {
		if !known[feature] {
			return nil, fmt.Errorf("%w: unknown capability", ErrInvalidConfig)
		}
		if seen[feature] {
			return nil, fmt.Errorf("%w: duplicate capability", ErrInvalidConfig)
		}
		seen[feature] = true
		out = append(out, feature)
	}
	sort.Strings(out)
	return out, nil
}

func setCapabilities(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, value := range values {
		out[value] = true
	}
	return out
}
