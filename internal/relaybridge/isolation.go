// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func IsolationViolations(streams []RelayBridgeStream) int {
	seen := map[string]bool{}
	violations := 0
	for _, stream := range streams {
		if stream.StreamID == "" || seen[stream.StreamID] {
			violations++
		}
		seen[stream.StreamID] = true
	}
	return violations
}
