// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
)

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func uniqueSorted(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func fixtureHashInput(set RelayBridgeFixtureSet) RelayBridgeFixtureSet {
	set.GeneratedAt = ""
	set.FixtureHash = ""
	return set
}
