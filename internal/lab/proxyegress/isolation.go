// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

func IsolationPreserved(mappings []EgressMappingPlan) bool {
	seen := map[string]bool{}
	for _, mapping := range mappings {
		if mapping.StreamID == "" || seen[mapping.StreamID] || mapping.IsolationClass != "per_stream_isolated" {
			return false
		}
		seen[mapping.StreamID] = true
	}
	return true
}
