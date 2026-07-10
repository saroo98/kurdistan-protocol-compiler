// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

type ProfilePlanSummary struct {
	CandidateCount     int    `json:"candidate_count"`
	UniqueProfileSeeds int    `json:"unique_profile_seeds"`
	Conclusion         string `json:"conclusion"`
}
