// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "kurdistan/internal/adaptivepath"

type TransportBundleVersion string
type BundleID string
type BundleMode string
type BundleCandidateRole string

const (
	Version TransportBundleVersion = "transportbundle-v1"
)

const (
	BundleModeBalancedAdaptive BundleMode = "balanced_adaptive"
	BundleModeConservativeTCP  BundleMode = "conservative_tcp"
	BundleModeSurvivalDNS      BundleMode = "survival_dns"
	BundleModeExperimentalMix  BundleMode = "experimental_mix"
	BundleModeHighRiskReview   BundleMode = "high_risk_review"
	BundleModeControlCollapsed BundleMode = "control_collapsed"
)

const (
	CandidateRolePrimaryEligible BundleCandidateRole = "primary_eligible"
	CandidateRoleFallback        BundleCandidateRole = "fallback"
	CandidateRoleSurvival        BundleCandidateRole = "survival"
	CandidateRoleExperimental    BundleCandidateRole = "experimental"
	CandidateRoleHighRiskGated   BundleCandidateRole = "high_risk_gated"
	CandidateRoleControl         BundleCandidateRole = "control"
	CandidateRoleRejected        BundleCandidateRole = "rejected"
)

type TransportBundlePolicy struct {
	Version                     string                         `json:"version"`
	PolicyID                    string                         `json:"policy_id"`
	Mode                        BundleMode                     `json:"mode"`
	BundleSeed                  int                            `json:"bundle_seed"`
	CandidateCount              int                            `json:"candidate_count"`
	RequiredFamilies            []adaptivepath.CandidateFamily `json:"required_families"`
	OptionalFamilies            []adaptivepath.CandidateFamily `json:"optional_families,omitempty"`
	MaxCandidatesPerFamily      int                            `json:"max_candidates_per_family"`
	MinUniqueProfileSeeds       int                            `json:"min_unique_profile_seeds"`
	MinUniqueWirePolicyHashes   int                            `json:"min_unique_wire_policy_hashes"`
	AllowHighRiskCandidates     bool                           `json:"allow_high_risk_candidates"`
	AllowExperimentalCandidates bool                           `json:"allow_experimental_candidates"`
	RequireRelayRiskMetadata    bool                           `json:"require_relay_risk_metadata"`
	RequireFreshnessMetadata    bool                           `json:"require_freshness_metadata"`
	RequireFallbackHints        bool                           `json:"require_fallback_hints"`
	PolicyHash                  string                         `json:"policy_hash"`
	PayloadLogged               bool                           `json:"payload_logged"`
	SecretLogged                bool                           `json:"secret_logged"`
}

type TransportBundleCandidate struct {
	CandidateID         string                       `json:"candidate_id"`
	Role                BundleCandidateRole          `json:"role"`
	Family              adaptivepath.CandidateFamily `json:"family"`
	ProfileID           string                       `json:"profile_id"`
	ProfileSeed         int                          `json:"profile_seed"`
	WirePolicyHash      string                       `json:"wire_policy_hash"`
	SelectedCorpusEntry string                       `json:"selected_corpus_entry"`
	RelayID             string                       `json:"relay_id"`
	SyntheticHostID     string                       `json:"synthetic_host_id"`
	RelayRiskBucket     string                       `json:"relay_risk_bucket"`
	HostRiskBucket      string                       `json:"host_risk_bucket"`
	BurnRiskClass       string                       `json:"burn_risk_class"`
	MetadataRiskBucket  string                       `json:"metadata_risk_bucket"`
	FreshnessTTLClass   string                       `json:"freshness_ttl_class"`
	FallbackClass       string                       `json:"fallback_class"`
	HighRisk            bool                         `json:"high_risk"`
	Experimental        bool                         `json:"experimental"`
	Gated               bool                         `json:"gated"`
	CandidateHash       string                       `json:"candidate_hash"`
	PayloadLogged       bool                         `json:"payload_logged"`
	SecretLogged        bool                         `json:"secret_logged"`
}

type TransportBundleManifest struct {
	Version       string                     `json:"version"`
	BundleID      string                     `json:"bundle_id"`
	BundleSeed    int                        `json:"bundle_seed"`
	PolicyID      string                     `json:"policy_id"`
	Mode          BundleMode                 `json:"mode"`
	Candidates    []TransportBundleCandidate `json:"candidates"`
	FamilyCounts  map[string]int             `json:"family_counts"`
	RoleCounts    map[string]int             `json:"role_counts"`
	FallbackPlan  FallbackPlan               `json:"fallback_plan"`
	BundleHash    string                     `json:"bundle_hash"`
	PayloadLogged bool                       `json:"payload_logged"`
	SecretLogged  bool                       `json:"secret_logged"`
}

type CompiledBundle struct {
	Policy                 TransportBundlePolicy        `json:"policy"`
	SeedPlan               BundleSeedPlan               `json:"seed_plan"`
	Manifest               TransportBundleManifest      `json:"manifest"`
	AdaptivePathCandidates []adaptivepath.PathCandidate `json:"adaptivepath_candidates"`
	RelayBinding           BundleRelayBindingReport     `json:"relay_binding"`
	FallbackHints          []BundleFallbackHint         `json:"fallback_hints"`
	CollapseReport         BundleCollapseReport         `json:"collapse_report"`
	ControlCollapseReport  BundleCollapseReport         `json:"control_collapse_report"`
	Parity                 TransportBundleParityReport  `json:"parity"`
	PayloadLogged          bool                         `json:"payload_logged"`
	SecretLogged           bool                         `json:"secret_logged"`
	Conclusion             string                       `json:"conclusion"`
}
