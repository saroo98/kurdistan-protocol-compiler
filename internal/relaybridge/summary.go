// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relaybridge

func Summary(set RelayBridgeFixtureSet) map[string]any {
	return map[string]any{
		"version":          set.Version,
		"scenario_count":   len(set.Scenarios),
		"session_count":    len(set.Sessions),
		"stream_count":     len(set.Streams),
		"payload_logged":   set.PayloadLogged,
		"secret_logged":    set.SecretLogged,
		"conclusion":       set.Conclusion,
		"recommended_next": RecommendedNextMilestone,
	}
}
