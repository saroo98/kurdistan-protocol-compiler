// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import (
	"sort"

	"kurdistan/internal/protocorpus"
)

type CorpusComparisonReport struct {
	CorpusVersion     string         `json:"corpus_version"`
	ProfileCount      int            `json:"profile_count"`
	ScenarioCount     int            `json:"scenario_count"`
	CorpusEntries     int            `json:"corpus_entries"`
	MatchedFamilies   []string       `json:"matched_families"`
	UnmatchedProfiles []string       `json:"unmatched_profiles,omitempty"`
	OverfitProfiles   []string       `json:"overfit_profiles,omitempty"`
	FeatureCoverage   map[string]int `json:"feature_coverage"`
	DiversityScore    float64        `json:"diversity_score"`
	PayloadLogged     bool           `json:"payload_logged"`
	SecretLogged      bool           `json:"secret_logged"`
	Conclusion        string         `json:"conclusion"`
}

func CompareToCorpus(vectors []WireFeatureVector, corpus protocorpus.CorpusManifest) CorpusComparisonReport {
	report := CorpusComparisonReport{
		CorpusVersion:   string(corpus.Version),
		CorpusEntries:   len(corpus.Entries),
		FeatureCoverage: map[string]int{},
		Conclusion:      "passed",
	}
	profiles := map[string]bool{}
	scenarios := map[string]bool{}
	families := map[string]bool{}
	firstN := map[string]int{}
	for _, vector := range vectors {
		profiles[vector.ProfileID] = true
		scenarios[vector.Scenario] = true
		report.PayloadLogged = report.PayloadLogged || vector.PayloadLogged
		report.SecretLogged = report.SecretLogged || vector.SecretLogged
		family := matchFamily(vector, corpus)
		if family == "" {
			report.UnmatchedProfiles = append(report.UnmatchedProfiles, vector.ProfileID+"/"+vector.Scenario)
			continue
		}
		families[family] = true
		report.FeatureCoverage[family]++
		firstN[vector.FirstNPacketShape]++
	}
	for family := range families {
		report.MatchedFamilies = append(report.MatchedFamilies, family)
	}
	sort.Strings(report.MatchedFamilies)
	report.ProfileCount = len(profiles)
	report.ScenarioCount = len(scenarios)
	if len(vectors) > 0 {
		report.DiversityScore = float64(len(families)+len(firstN)) / float64(len(vectors)+1)
	}
	if len(report.UnmatchedProfiles) > 0 || len(report.MatchedFamilies) < 2 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
}

func matchFamily(vector WireFeatureVector, corpus protocorpus.CorpusManifest) string {
	for _, entry := range corpus.Entries {
		if entry.MetadataExposure == vector.MetadataExposure {
			return string(entry.Family)
		}
		if entry.ControlRichness == vector.ControlRichness {
			return string(entry.Family)
		}
		for _, bucket := range entry.FrameSizeBuckets {
			for _, vectorBucket := range vector.FrameSizeBuckets {
				if bucket == vectorBucket {
					return string(entry.Family)
				}
			}
		}
	}
	return ""
}
