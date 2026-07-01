// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package carrierreview

const Version = "carrierreview-v1"

const (
	FamilyHTTPSLikeTCP        = "https_like_tcp"
	FamilyDNSSurvival         = "dns_survival"
	FamilyExperimentalUDPQUIC = "experimental_udp_quic"
	FamilyDomesticMediaRisk   = "domestic_media_risk"
	FamilyRelayBridgeRotation = "relay_bridge_rotation"
	FamilyUnsafeControl       = "unsafe_control"
)

const (
	ReadinessReadySynthetic    = "ready_for_synthetic_prototype"
	ReadinessGatedSurvival     = "gated_survival_design_only"
	ReadinessExperimentalGated = "experimental_gated_design_only"
	ReadinessManualReviewOnly  = "manual_review_only"
	ReadinessBlockedByRisk     = "blocked_by_risk"
	RecommendedNextMilestone   = "M32 safe measurement-client design and privacy review"
)

type CarrierFamilyDescriptor struct {
	Family                  string   `json:"family"`
	ReviewClass             string   `json:"review_class"`
	RiskClass               string   `json:"risk_class"`
	Readiness               string   `json:"readiness"`
	AllowedPrototypeScope   string   `json:"allowed_prototype_scope"`
	ManualReviewRequired    bool     `json:"manual_review_required"`
	DefaultEligible         bool     `json:"default_eligible"`
	SyntheticOnly           bool     `json:"synthetic_only"`
	RequiredPreconditions   []string `json:"required_preconditions"`
	ForbiddenClaims         []string `json:"forbidden_claims"`
	ForbiddenImplementation []string `json:"forbidden_implementation"`
	Notes                   []string `json:"notes"`
	PayloadLogged           bool     `json:"payload_logged"`
	SecretLogged            bool     `json:"secret_logged"`
}

func DefaultDescriptors() []CarrierFamilyDescriptor {
	return []CarrierFamilyDescriptor{
		{
			Family: FamilyHTTPSLikeTCP, ReviewClass: "baseline_tcp_shape", RiskClass: "medium", Readiness: ReadinessReadySynthetic,
			AllowedPrototypeScope: "synthetic_metadata_model", DefaultEligible: true, SyntheticOnly: true,
			RequiredPreconditions:   []string{"trace_hygiene", "security_context", "generated_parity", "pathhealth_hooks"},
			ForbiddenClaims:         []string{"tls_mimicry", "http_compatibility", "sni_behavior", "host_header_behavior", "guaranteed_bypass"},
			ForbiddenImplementation: []string{"real_tls", "real_http", "sockets", "external_targets"},
			Notes:                   []string{"TCP-like shape review only; no TLS or HTTP carrier is implemented."},
		},
		{
			Family: FamilyDNSSurvival, ReviewClass: "survival_fallback", RiskClass: "high", Readiness: ReadinessGatedSurvival,
			AllowedPrototypeScope: "design_only_or_synthetic_metadata_model", ManualReviewRequired: true, SyntheticOnly: true,
			RequiredPreconditions:   []string{"manual_review", "trace_hygiene", "privacy_review", "pathhealth_hooks"},
			ForbiddenClaims:         []string{"dns_tunneling_ready", "resolver_compatibility", "reliable_bypass", "real_dns_query"},
			ForbiddenImplementation: []string{"resolver_testing", "dns_queries", "external_targets"},
			Notes:                   []string{"DNS-survival remains a gated design review; no resolver or query behavior is implemented."},
		},
		{
			Family: FamilyExperimentalUDPQUIC, ReviewClass: "experimental", RiskClass: "high", Readiness: ReadinessExperimentalGated,
			AllowedPrototypeScope: "synthetic_metadata_model", ManualReviewRequired: true, SyntheticOnly: true,
			RequiredPreconditions:   []string{"experimental_gate", "trace_hygiene", "privacy_review", "loss_reorder_review"},
			ForbiddenClaims:         []string{"quic_compatibility", "udp_reachability", "default_transport"},
			ForbiddenImplementation: []string{"real_udp", "real_quic", "external_targets"},
			Notes:                   []string{"UDP/QUIC-like behavior is an experimental metadata model, not a QUIC implementation."},
		},
		{
			Family: FamilyDomesticMediaRisk, ReviewClass: "high_risk_sensitive", RiskClass: "critical", Readiness: ReadinessManualReviewOnly,
			AllowedPrototypeScope: "manual_review_only", ManualReviewRequired: true, SyntheticOnly: true,
			RequiredPreconditions:   []string{"explicit_manual_review", "privacy_review", "risk_acceptance", "trace_hygiene"},
			ForbiddenClaims:         []string{"default_transport", "safe_for_high_risk_users", "real_platform_support"},
			ForbiddenImplementation: []string{"service_names", "provider_names", "account_metadata", "app_identifiers"},
			Notes:                   []string{"Domestic/media-shaped risk is tracked only as a high-risk review class."},
		},
		{
			Family: FamilyRelayBridgeRotation, ReviewClass: "relay_lifecycle", RiskClass: "medium", Readiness: ReadinessReadySynthetic,
			AllowedPrototypeScope: "synthetic_relay_lifecycle_model", DefaultEligible: true, SyntheticOnly: true,
			RequiredPreconditions:   []string{"relayfleet_hooks", "hostdetect_hooks", "pathhealth_hooks", "trace_hygiene"},
			ForbiddenClaims:         []string{"real_bridge_discovery", "endpoint_rotation_ready", "relay_deployment_ready"},
			ForbiddenImplementation: []string{"real_bridge_endpoints", "relay_provisioning", "external_targets"},
			Notes:                   []string{"Relay rotation review ties synthetic burn/quarantine metadata to fleet and pathhealth gates."},
		},
	}
}
