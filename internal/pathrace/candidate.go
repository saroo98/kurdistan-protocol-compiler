// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import "kurdistan/internal/transportbundle"

func CandidatesFromBundle(manifest transportbundle.TransportBundleManifest) []RaceCandidate {
	out := make([]RaceCandidate, 0, len(manifest.Candidates))
	for _, c := range manifest.Candidates {
		out = append(out, RaceCandidate{
			CandidateID:        c.CandidateID,
			Family:             c.Family,
			Role:               string(c.Role),
			BundleID:           manifest.BundleID,
			ProfileSeed:        c.ProfileSeed,
			WirePolicyHash:     c.WirePolicyHash,
			RelayRiskBucket:    c.RelayRiskBucket,
			MetadataRiskBucket: c.MetadataRiskBucket,
			FreshnessTTLClass:  c.FreshnessTTLClass,
			Gated:              c.Gated,
			HighRisk:           c.HighRisk,
			Experimental:       c.Experimental,
			PayloadLogged:      c.PayloadLogged,
			SecretLogged:       c.SecretLogged,
		})
	}
	return out
}
