// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

func Summary(set EgressFixtureSet) map[string]any {
	return map[string]any{
		"version":          set.Version,
		"scenario_count":   len(set.Scenarios),
		"request_count":    len(set.Requests),
		"target_count":     len(set.Targets),
		"mapping_count":    len(set.Mappings),
		"payload_logged":   set.PayloadLogged,
		"secret_logged":    set.SecretLogged,
		"conclusion":       set.Conclusion,
		"recommended_next": RecommendedNextMilestone,
	}
}
