// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"fmt"

	"kurdistan/internal/adaptivepath"
)

func RequiredBundleModes() []BundleMode {
	return []BundleMode{
		BundleModeBalancedAdaptive,
		BundleModeConservativeTCP,
		BundleModeSurvivalDNS,
		BundleModeExperimentalMix,
		BundleModeHighRiskReview,
		BundleModeControlCollapsed,
	}
}

func DefaultPolicy(seed int, mode BundleMode) TransportBundlePolicy {
	p := TransportBundlePolicy{
		Version:                   string(Version),
		PolicyID:                  fmt.Sprintf("bundle_policy_%s_%05d", mode, seed),
		Mode:                      mode,
		BundleSeed:                seed,
		MaxCandidatesPerFamily:    2,
		MinUniqueProfileSeeds:     3,
		MinUniqueWirePolicyHashes: 3,
		RequireRelayRiskMetadata:  true,
		RequireFreshnessMetadata:  true,
		RequireFallbackHints:      true,
	}
	switch mode {
	case BundleModeBalancedAdaptive:
		p.CandidateCount = 6
		p.RequiredFamilies = []adaptivepath.CandidateFamily{
			adaptivepath.CandidateHTTPSLikeTCP,
			adaptivepath.CandidateDNSSurvival,
			adaptivepath.CandidateExperimentalUDP,
			adaptivepath.CandidateRelayRotation,
		}
		p.OptionalFamilies = []adaptivepath.CandidateFamily{adaptivepath.CandidateBaselineControl}
		p.AllowExperimentalCandidates = true
	case BundleModeConservativeTCP:
		p.CandidateCount = 5
		p.RequiredFamilies = []adaptivepath.CandidateFamily{
			adaptivepath.CandidateHTTPSLikeTCP,
			adaptivepath.CandidateRelayRotation,
		}
		p.OptionalFamilies = []adaptivepath.CandidateFamily{adaptivepath.CandidateBaselineControl}
	case BundleModeSurvivalDNS:
		p.CandidateCount = 5
		p.RequiredFamilies = []adaptivepath.CandidateFamily{
			adaptivepath.CandidateDNSSurvival,
			adaptivepath.CandidateHTTPSLikeTCP,
			adaptivepath.CandidateRelayRotation,
		}
	case BundleModeExperimentalMix:
		p.CandidateCount = 5
		p.RequiredFamilies = []adaptivepath.CandidateFamily{
			adaptivepath.CandidateExperimentalUDP,
			adaptivepath.CandidateHTTPSLikeTCP,
			adaptivepath.CandidateRelayRotation,
		}
		p.AllowExperimentalCandidates = true
	case BundleModeHighRiskReview:
		p.CandidateCount = 4
		p.RequiredFamilies = []adaptivepath.CandidateFamily{
			adaptivepath.CandidateDomesticMediaRisk,
			adaptivepath.CandidateHTTPSLikeTCP,
		}
		p.AllowHighRiskCandidates = true
	case BundleModeControlCollapsed:
		p.CandidateCount = 5
		p.RequiredFamilies = []adaptivepath.CandidateFamily{adaptivepath.CandidateCollapsedControl}
		p.MaxCandidatesPerFamily = 99
		p.MinUniqueProfileSeeds = 1
		p.MinUniqueWirePolicyHashes = 1
	default:
		p.CandidateCount = 4
		p.RequiredFamilies = []adaptivepath.CandidateFamily{adaptivepath.CandidateHTTPSLikeTCP}
	}
	p.PolicyHash = HashValue(policyHashInput(p))
	return p
}

func policyHashInput(p TransportBundlePolicy) TransportBundlePolicy {
	p.PolicyHash = ""
	return p
}
