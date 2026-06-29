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

type CapabilitySet struct {
	Features []string `json:"features"`
}

func DefaultCapabilities() CapabilitySet {
	return CapabilitySet{Features: []string{
		"multi_stream",
		"proxy_semantics",
		"carrier_abstraction",
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
