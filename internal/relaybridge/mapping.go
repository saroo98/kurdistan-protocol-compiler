// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func MappingPreserved(sessions []RelayBridgeSession, streams []RelayBridgeStream) bool {
	sessionByBridge := map[string]bool{}
	for _, session := range sessions {
		sessionByBridge[session.BridgeID] = true
	}
	seenStreams := map[string]bool{}
	for _, stream := range streams {
		if !sessionByBridge[stream.BridgeID] || seenStreams[stream.StreamID] {
			return false
		}
		seenStreams[stream.StreamID] = true
	}
	return len(streams) > 0
}
