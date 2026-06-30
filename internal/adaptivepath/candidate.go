// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adaptivepath

import "fmt"

type AdaptivePathVersion string
type CandidateID string
type CandidateFamily string
type CandidateState string

const (
	Version AdaptivePathVersion = "adaptivepath-v1"
)

const (
	CandidateHTTPSLikeTCP      CandidateFamily = "https_like_tcp"
	CandidateDNSSurvival       CandidateFamily = "dns_survival"
	CandidateExperimentalUDP   CandidateFamily = "experimental_udp_quic"
	CandidateDomesticMediaRisk CandidateFamily = "domestic_media_risk"
	CandidateRelayRotation     CandidateFamily = "relay_rotation"
	CandidateBaselineControl   CandidateFamily = "baseline_control"
	CandidateCollapsedControl  CandidateFamily = "collapsed_control"
)

const (
	CandidateUnknown      CandidateState = "unknown"
	CandidateLikelyUsable CandidateState = "likely_usable"
	CandidateDegraded     CandidateState = "degraded"
	CandidateUnstable     CandidateState = "unstable"
	CandidateBlocked      CandidateState = "blocked"
	CandidateBurned       CandidateState = "burned"
	CandidateQuarantined  CandidateState = "quarantined"
	CandidateRejected     CandidateState = "rejected"
)

type PathCandidate struct {
	CandidateID        CandidateID     `json:"candidate_id"`
	Family             CandidateFamily `json:"family"`
	ProfileID          string          `json:"profile_id"`
	ProfileSeed        int             `json:"profile_seed"`
	WirePolicyHash     string          `json:"wire_policy_hash"`
	RelayID            string          `json:"relay_id"`
	SyntheticHostID    string          `json:"synthetic_host_id"`
	CarrierClass       string          `json:"carrier_class"`
	NameServiceClass   string          `json:"name_service_class"`
	RouteClass         string          `json:"route_class"`
	RelayRiskBucket    string          `json:"relay_risk_bucket"`
	MetadataRiskBucket string          `json:"metadata_risk_bucket"`
	DefaultTTLClass    string          `json:"default_ttl_class"`
	CandidateHash      string          `json:"candidate_hash"`
	PayloadLogged      bool            `json:"payload_logged"`
	SecretLogged       bool            `json:"secret_logged"`
}

func DefaultCandidates() []PathCandidate {
	families := []CandidateFamily{
		CandidateHTTPSLikeTCP,
		CandidateDNSSurvival,
		CandidateExperimentalUDP,
		CandidateDomesticMediaRisk,
		CandidateRelayRotation,
		CandidateBaselineControl,
		CandidateCollapsedControl,
	}
	out := make([]PathCandidate, 0, len(families))
	for i, family := range families {
		desc, _ := FamilyDescriptor(family)
		c := PathCandidate{
			CandidateID:        CandidateID(fmt.Sprintf("candidate_%02d_%s", i+1, family)),
			Family:             family,
			ProfileID:          fmt.Sprintf("profile_synthetic_%05d", 12345+i),
			ProfileSeed:        12345 + i,
			WirePolicyHash:     fmt.Sprintf("wire_policy_bucket_%02d", i+1),
			RelayID:            fmt.Sprintf("relay_bucket_%02d", i+1),
			SyntheticHostID:    fmt.Sprintf("synthetic_host_%02d", i+1),
			CarrierClass:       desc.CarrierClass,
			NameServiceClass:   nameServiceClassForFamily(family),
			RouteClass:         routeClassForFamily(family),
			RelayRiskBucket:    relayRiskForFamily(family),
			MetadataRiskBucket: desc.MetadataRiskBucket,
			DefaultTTLClass:    desc.DefaultTTLClass,
		}
		c.CandidateHash = HashValue(candidateHashInput(c))
		out = append(out, c)
	}
	return out
}

func candidateHashInput(c PathCandidate) PathCandidate {
	c.CandidateHash = ""
	return c
}

func nameServiceClassForFamily(f CandidateFamily) string {
	switch f {
	case CandidateDNSSurvival:
		return "name_service_survival_class"
	case CandidateBaselineControl, CandidateCollapsedControl:
		return "name_service_control_class"
	default:
		return "name_service_none"
	}
}

func routeClassForFamily(f CandidateFamily) string {
	switch f {
	case CandidateDomesticMediaRisk:
		return "domestic_media_route_class"
	case CandidateRelayRotation:
		return "relay_rotation_support_class"
	default:
		return "synthetic_route_class"
	}
}
