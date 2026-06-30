// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

type WirePolicyPlanSummary struct {
	CandidateCount         int    `json:"candidate_count"`
	UniqueWirePolicyHashes int    `json:"unique_wire_policy_hashes"`
	Conclusion             string `json:"conclusion"`
}
