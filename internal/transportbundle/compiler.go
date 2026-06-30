// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"context"
	"fmt"
	"sort"

	"kurdistan/internal/adaptivepath"
	"kurdistan/internal/compiler"
	"kurdistan/internal/protocorpus"
	"kurdistan/internal/wiregen"
)

func Compile(ctx context.Context, policy TransportBundlePolicy) (CompiledBundle, error) {
	_ = ctx
	policy = normalizePolicy(policy)
	if err := ValidatePolicy(policy); err != nil {
		return CompiledBundle{}, err
	}
	families := expandFamilies(policy)
	seedPlan := BuildSeedPlan(policy, families)
	candidates := make([]TransportBundleCandidate, 0, policy.CandidateCount)
	corpus := protocorpus.DefaultCorpus()
	for i := 0; i < policy.CandidateCount; i++ {
		family := adaptivepath.CandidateFamily(families[i%len(families)])
		profileSeed := seedPlan.ProfileSeeds[i]
		profile, err := compiler.Generate(int64(profileSeed))
		if err != nil {
			return CompiledBundle{}, err
		}
		wirePolicy, err := wiregen.SamplePolicy(int64(seedPlan.CandidateSeeds[i]), corpus)
		if err != nil {
			return CompiledBundle{}, err
		}
		if policy.Mode == BundleModeControlCollapsed {
			wirePolicy.PolicyHash = "collapsed_wire_policy"
		}
		desc, _ := adaptivepath.FamilyDescriptor(family)
		c := TransportBundleCandidate{
			CandidateID:         candidateID(policy.Mode, string(family), seedPlan.CandidateSeeds[i], i),
			Role:                roleForFamily(family),
			Family:              family,
			ProfileID:           profile.ID,
			ProfileSeed:         profileSeed,
			WirePolicyHash:      wirePolicy.PolicyHash,
			SelectedCorpusEntry: wirePolicy.SelectedCorpusEntry,
			RelayID:             fmt.Sprintf("relay_bucket_%02d", (i%7)+1),
			SyntheticHostID:     fmt.Sprintf("synthetic_host_%02d", (i%5)+1),
			RelayRiskBucket:     relayRiskBucket(family, i),
			HostRiskBucket:      hostRiskBucket(i),
			BurnRiskClass:       burnRiskClass(family, i),
			MetadataRiskBucket:  desc.MetadataRiskBucket,
			FreshnessTTLClass:   desc.DefaultTTLClass,
			FallbackClass:       fallbackClassForFamily(family),
			HighRisk:            desc.HighRisk,
			Experimental:        desc.Experimental,
			Gated:               desc.Gated,
		}
		if policy.Mode == BundleModeControlCollapsed {
			c.Family = adaptivepath.CandidateCollapsedControl
			c.Role = CandidateRoleControl
			c.WirePolicyHash = "collapsed_wire_policy"
			c.ProfileSeed = policy.BundleSeed
			c.ProfileID = "profile_collapsed_control"
		}
		c.CandidateHash = HashValue(candidateHashInput(c))
		candidates = append(candidates, c)
	}
	manifest := buildManifest(policy, candidates)
	adaptiveCandidates := MapToAdaptivePath(manifest.Candidates)
	relayBinding := BindRelayMetadata(manifest)
	fallbacks := BuildFallbackHints(manifest.Candidates)
	collapse := ScanCollapse(manifest)
	control := CollapsedControl(manifest)
	parity := CompareGeneratedInterpreted(manifest)
	out := CompiledBundle{
		Policy:                 policy,
		SeedPlan:               seedPlan,
		Manifest:               manifest,
		AdaptivePathCandidates: adaptiveCandidates,
		RelayBinding:           relayBinding,
		FallbackHints:          fallbacks,
		CollapseReport:         collapse,
		ControlCollapseReport:  control,
		Parity:                 parity,
		Conclusion:             "passed",
	}
	if policy.Mode == BundleModeControlCollapsed || collapse.Conclusion != "passed" || parity.Conclusion != "passed" {
		out.Conclusion = "failed"
	}
	return out, nil
}

func normalizePolicy(policy TransportBundlePolicy) TransportBundlePolicy {
	if policy.Version == "" {
		policy.Version = string(Version)
	}
	if policy.PolicyID == "" {
		policy.PolicyID = fmt.Sprintf("bundle_policy_%s_%05d", policy.Mode, policy.BundleSeed)
	}
	if policy.CandidateCount == 0 {
		policy.CandidateCount = max(4, len(policy.RequiredFamilies))
	}
	if policy.MaxCandidatesPerFamily == 0 {
		policy.MaxCandidatesPerFamily = 2
	}
	if policy.MinUniqueProfileSeeds == 0 {
		policy.MinUniqueProfileSeeds = min(3, policy.CandidateCount)
	}
	if policy.MinUniqueWirePolicyHashes == 0 {
		policy.MinUniqueWirePolicyHashes = min(3, policy.CandidateCount)
	}
	if !policy.RequireRelayRiskMetadata && !policy.RequireFreshnessMetadata && !policy.RequireFallbackHints {
		policy.RequireRelayRiskMetadata = true
		policy.RequireFreshnessMetadata = true
		policy.RequireFallbackHints = true
	}
	if policy.PolicyHash == "" {
		policy.PolicyHash = HashValue(policyHashInput(policy))
	}
	return policy
}

func expandFamilies(policy TransportBundlePolicy) []string {
	families := []string{}
	for _, family := range policy.RequiredFamilies {
		families = append(families, string(family))
	}
	for _, family := range policy.OptionalFamilies {
		families = append(families, string(family))
	}
	if len(families) == 0 {
		families = append(families, string(adaptivepath.CandidateHTTPSLikeTCP))
	}
	sort.Strings(families)
	if policy.Mode == BundleModeBalancedAdaptive {
		families = []string{
			string(adaptivepath.CandidateHTTPSLikeTCP),
			string(adaptivepath.CandidateDNSSurvival),
			string(adaptivepath.CandidateExperimentalUDP),
			string(adaptivepath.CandidateRelayRotation),
			string(adaptivepath.CandidateBaselineControl),
		}
	}
	return families
}

func buildManifest(policy TransportBundlePolicy, candidates []TransportBundleCandidate) TransportBundleManifest {
	manifest := TransportBundleManifest{
		Version:      string(Version),
		BundleID:     fmt.Sprintf("bundle_%s_%05d", policy.Mode, policy.BundleSeed),
		BundleSeed:   policy.BundleSeed,
		PolicyID:     policy.PolicyID,
		Mode:         policy.Mode,
		Candidates:   candidates,
		FamilyCounts: map[string]int{},
		RoleCounts:   map[string]int{},
	}
	for _, c := range candidates {
		manifest.FamilyCounts[string(c.Family)]++
		manifest.RoleCounts[string(c.Role)]++
	}
	manifest.FallbackPlan = BuildFallbackPlan(candidates)
	manifest.BundleHash = HashValue(manifestHashInput(manifest))
	return manifest
}

func manifestHashInput(manifest TransportBundleManifest) TransportBundleManifest {
	manifest.BundleHash = ""
	return manifest
}

func candidateHashInput(c TransportBundleCandidate) TransportBundleCandidate {
	c.CandidateHash = ""
	return c
}
