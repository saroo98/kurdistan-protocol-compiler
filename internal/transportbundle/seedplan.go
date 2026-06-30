// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "fmt"

type BundleSeedPlan struct {
	BundleSeed         int              `json:"bundle_seed"`
	CandidateSeeds     []int            `json:"candidate_seeds"`
	ProfileSeeds       []int            `json:"profile_seeds"`
	FamilySeedMap      map[string][]int `json:"family_seed_map"`
	UniqueProfileSeeds int              `json:"unique_profile_seeds"`
	SeedPlanHash       string           `json:"seed_plan_hash"`
	PayloadLogged      bool             `json:"payload_logged"`
	SecretLogged       bool             `json:"secret_logged"`
}

func BuildSeedPlan(policy TransportBundlePolicy, families []string) BundleSeedPlan {
	plan := BundleSeedPlan{
		BundleSeed:     policy.BundleSeed,
		FamilySeedMap:  map[string][]int{},
		CandidateSeeds: make([]int, 0, policy.CandidateCount),
		ProfileSeeds:   make([]int, 0, policy.CandidateCount),
	}
	unique := map[int]bool{}
	for i := 0; i < policy.CandidateCount; i++ {
		seed := policy.BundleSeed*1000 + 101 + i*17
		profileSeed := seed + 7
		if policy.Mode == BundleModeControlCollapsed {
			profileSeed = policy.BundleSeed
		}
		family := families[i%len(families)]
		plan.CandidateSeeds = append(plan.CandidateSeeds, seed)
		plan.ProfileSeeds = append(plan.ProfileSeeds, profileSeed)
		plan.FamilySeedMap[family] = append(plan.FamilySeedMap[family], profileSeed)
		unique[profileSeed] = true
	}
	plan.UniqueProfileSeeds = len(unique)
	plan.SeedPlanHash = HashValue(seedPlanHashInput(plan))
	return plan
}

func seedPlanHashInput(plan BundleSeedPlan) BundleSeedPlan {
	plan.SeedPlanHash = ""
	return plan
}

func candidateID(mode BundleMode, family string, seed int, index int) string {
	return fmt.Sprintf("bundle_candidate_%s_%02d_%s_%05d", mode, index+1, family, seed%100000)
}
