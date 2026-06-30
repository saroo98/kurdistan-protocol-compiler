// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

type PathObservationKind string

const (
	ObservationHandshakeOK          PathObservationKind = "handshake_ok"
	ObservationHandshakeFailed      PathObservationKind = "handshake_failed"
	ObservationFirstUsefulByteOK    PathObservationKind = "first_useful_byte_ok"
	ObservationStallAfterHandshake  PathObservationKind = "stall_after_handshake"
	ObservationStallAfterData       PathObservationKind = "stall_after_data"
	ObservationResetLikeFailure     PathObservationKind = "reset_like_failure"
	ObservationBlackholeLikeFailure PathObservationKind = "blackhole_like_failure"
	ObservationPoisoningLikeSignal  PathObservationKind = "poisoning_like_signal"
	ObservationTruncationLikeSignal PathObservationKind = "truncation_like_signal"
	ObservationRelayBurnRisk        PathObservationKind = "relay_burn_risk"
	ObservationShortSuccess         PathObservationKind = "short_success"
	ObservationShortFailure         PathObservationKind = "short_failure"
)

type CandidateFamilyDescriptor struct {
	Family             CandidateFamily       `json:"family"`
	Role               string                `json:"role"`
	CarrierClass       string                `json:"carrier_class"`
	ExpectedSignals    []PathObservationKind `json:"expected_signals"`
	ExpectedFailures   []string              `json:"expected_failures"`
	MetadataRiskBucket string                `json:"metadata_risk_bucket"`
	DefaultTTLClass    string                `json:"default_ttl_class"`
	DefaultEligible    bool                  `json:"default_eligible"`
	HighRisk           bool                  `json:"high_risk"`
	Gated              bool                  `json:"gated"`
	Experimental       bool                  `json:"experimental"`
	Notes              []string              `json:"notes"`
	DescriptorHash     string                `json:"descriptor_hash"`
}

func FamilyDescriptors() []CandidateFamilyDescriptor {
	out := []CandidateFamilyDescriptor{
		{
			Family: CandidateHTTPSLikeTCP, Role: "baseline stream-shaped candidate", CarrierClass: "ordered_stream_shape",
			ExpectedSignals:  []PathObservationKind{ObservationHandshakeOK, ObservationFirstUsefulByteOK, ObservationBlackholeLikeFailure},
			ExpectedFailures: []string{"blackhole_like_failure", "stall_after_handshake"}, MetadataRiskBucket: "medium_metadata_risk",
			DefaultTTLClass: TTLShortSession, DefaultEligible: true, Notes: []string{"default eligible only when fresh and not degraded"},
		},
		{
			Family: CandidateDNSSurvival, Role: "survival-class name-service-shaped candidate", CarrierClass: "message_survival_shape",
			ExpectedSignals:  []PathObservationKind{ObservationShortSuccess, ObservationPoisoningLikeSignal, ObservationTruncationLikeSignal},
			ExpectedFailures: []string{"poisoning_like_signal", "truncation_like_signal", "rate_limited_signal"}, MetadataRiskBucket: "high_metadata_risk",
			DefaultTTLClass: TTLOneMinute, Gated: true, Notes: []string{"gated survival model only; no real name-service queries"},
		},
		{
			Family: CandidateExperimentalUDP, Role: "experimental datagram-shaped candidate", CarrierClass: "datagram_experimental_shape",
			ExpectedSignals:  []PathObservationKind{ObservationShortSuccess, ObservationShortFailure, ObservationResetLikeFailure},
			ExpectedFailures: []string{"udp_blocked", "udp_throttled", "udp_unstable"}, MetadataRiskBucket: "medium_metadata_risk",
			DefaultTTLClass: TTLOneMinute, Gated: true, Experimental: true, Notes: []string{"deterministic model only; no UDP probing"},
		},
		{
			Family: CandidateDomesticMediaRisk, Role: "high-risk domestic media-shaped control", CarrierClass: "domestic_media_synthetic_shape",
			ExpectedSignals:  []PathObservationKind{ObservationShortSuccess, ObservationShortFailure, ObservationRelayBurnRisk},
			ExpectedFailures: []string{"metadata_risk_high", "relay_burn_risk"}, MetadataRiskBucket: "critical_metadata_risk",
			DefaultTTLClass: TTLExpired, HighRisk: true, Gated: true, Notes: []string{"cannot be default winner"},
		},
		{
			Family: CandidateRelayRotation, Role: "supporting relay lifecycle candidate", CarrierClass: "relay_rotation_support_shape",
			ExpectedSignals: []PathObservationKind{ObservationRelayBurnRisk, ObservationShortSuccess}, ExpectedFailures: []string{"relay_burned"},
			MetadataRiskBucket: "low_metadata_risk", DefaultTTLClass: TTLFiveMinutes, Gated: true, Notes: []string{"supporting infrastructure model"},
		},
		{
			Family: CandidateBaselineControl, Role: "healthy control candidate", CarrierClass: "baseline_control_shape",
			ExpectedSignals: []PathObservationKind{ObservationHandshakeOK, ObservationFirstUsefulByteOK}, ExpectedFailures: []string{"none"},
			MetadataRiskBucket: "low_metadata_risk", DefaultTTLClass: TTLFiveMinutes, DefaultEligible: true, Notes: []string{"control fixture"},
		},
		{
			Family: CandidateCollapsedControl, Role: "collapsed control candidate", CarrierClass: "collapsed_control_shape",
			ExpectedSignals: []PathObservationKind{ObservationShortFailure}, ExpectedFailures: []string{"collapse_control"},
			MetadataRiskBucket: "medium_metadata_risk", DefaultTTLClass: TTLExpired, Notes: []string{"must be detected by misuse scanner"},
		},
	}
	for i := range out {
		out[i].DescriptorHash = HashValue(familyHashInput(out[i]))
	}
	return out
}

func FamilyDescriptor(f CandidateFamily) (CandidateFamilyDescriptor, bool) {
	for _, desc := range FamilyDescriptors() {
		if desc.Family == f {
			return desc, true
		}
	}
	return CandidateFamilyDescriptor{}, false
}

func familyHashInput(d CandidateFamilyDescriptor) CandidateFamilyDescriptor {
	d.DescriptorHash = ""
	return d
}
