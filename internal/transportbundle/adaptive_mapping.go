// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import "kurdistan/internal/adaptivepath"

func MapToAdaptivePath(candidates []TransportBundleCandidate) []adaptivepath.PathCandidate {
	out := make([]adaptivepath.PathCandidate, 0, len(candidates))
	for _, c := range candidates {
		desc, _ := adaptivepath.FamilyDescriptor(c.Family)
		mapped := adaptivepath.PathCandidate{
			CandidateID:        adaptivepath.CandidateID(c.CandidateID),
			Family:             c.Family,
			ProfileID:          c.ProfileID,
			ProfileSeed:        c.ProfileSeed,
			WirePolicyHash:     c.WirePolicyHash,
			RelayID:            c.RelayID,
			SyntheticHostID:    c.SyntheticHostID,
			CarrierClass:       desc.CarrierClass,
			NameServiceClass:   "name_service_bundle_class",
			RouteClass:         "bundle_route_class",
			RelayRiskBucket:    c.RelayRiskBucket,
			MetadataRiskBucket: c.MetadataRiskBucket,
			DefaultTTLClass:    c.FreshnessTTLClass,
		}
		mapped.CandidateHash = adaptivepath.HashValue(mapped)
		out = append(out, mapped)
	}
	return out
}
