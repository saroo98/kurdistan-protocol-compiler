// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

type BundleRelayBindingReport struct {
	CandidateCount        int    `json:"candidate_count"`
	SyntheticRelays       int    `json:"synthetic_relays"`
	SyntheticHosts        int    `json:"synthetic_hosts"`
	LowRiskCandidates     int    `json:"low_risk_candidates"`
	MediumRiskCandidates  int    `json:"medium_risk_candidates"`
	HighRiskCandidates    int    `json:"high_risk_candidates"`
	BurnedCandidates      int    `json:"burned_candidates"`
	QuarantinedCandidates int    `json:"quarantined_candidates"`
	PrimaryEligible       int    `json:"primary_eligible"`
	PayloadLogged         bool   `json:"payload_logged"`
	SecretLogged          bool   `json:"secret_logged"`
	Conclusion            string `json:"conclusion"`
}

func BindRelayMetadata(manifest TransportBundleManifest) BundleRelayBindingReport {
	report := BundleRelayBindingReport{CandidateCount: len(manifest.Candidates), Conclusion: "passed"}
	relays := map[string]bool{}
	hosts := map[string]bool{}
	for _, c := range manifest.Candidates {
		relays[c.RelayID] = true
		hosts[c.SyntheticHostID] = true
		switch c.RelayRiskBucket {
		case "low":
			report.LowRiskCandidates++
		case "medium":
			report.MediumRiskCandidates++
		case "high", "critical":
			report.HighRiskCandidates++
		}
		if c.BurnRiskClass == "burned" {
			report.BurnedCandidates++
			if c.Role == CandidateRolePrimaryEligible {
				report.Conclusion = "failed"
			}
		}
		if c.BurnRiskClass == "quarantined" {
			report.QuarantinedCandidates++
			if c.Role == CandidateRolePrimaryEligible {
				report.Conclusion = "failed"
			}
		}
		if c.Role == CandidateRolePrimaryEligible {
			report.PrimaryEligible++
		}
	}
	report.SyntheticRelays = len(relays)
	report.SyntheticHosts = len(hosts)
	return report
}
