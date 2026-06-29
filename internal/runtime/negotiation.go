// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"fmt"
	"sort"

	"kurdistan/internal/security"
)

type NegotiationResult struct {
	Selected       security.CapabilitySet `json:"selected"`
	CapabilityHash string                 `json:"capability_hash"`
	TraceBucket    string                 `json:"trace_bucket"`
}

func LocalCapabilities(required []string) security.CapabilitySet {
	if len(required) == 0 {
		return security.DefaultCapabilities()
	}
	return security.CapabilitySet{Features: append([]string(nil), required...)}
}

func NegotiateCapabilities(local, peer, required security.CapabilitySet) (NegotiationResult, error) {
	localSet := set(local.Features)
	peerSet := set(peer.Features)
	selected := []string{}
	for feature := range localSet {
		if peerSet[feature] {
			selected = append(selected, feature)
		}
	}
	sort.Strings(selected)
	selectedSet := security.CapabilitySet{Features: selected}
	if err := security.RequireCapabilities(required, selectedSet); err != nil {
		return NegotiationResult{}, fmt.Errorf("%w: %v", ErrNegotiation, err)
	}
	hash, err := selectedSet.Hash()
	if err != nil {
		return NegotiationResult{}, err
	}
	return NegotiationResult{Selected: selectedSet, CapabilityHash: hash, TraceBucket: shortHash(hash)}, nil
}

func set(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		out[value] = true
	}
	return out
}

func shortHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
