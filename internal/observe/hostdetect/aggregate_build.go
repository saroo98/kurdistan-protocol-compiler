// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import "sort"

func Aggregate(observations []HostObservation) []HostAggregate {
	byHost := map[SyntheticHostID][]HostObservation{}
	for _, observation := range observations {
		byHost[observation.SyntheticHostID] = append(byHost[observation.SyntheticHostID], observation)
	}
	hosts := make([]string, 0, len(byHost))
	for host := range byHost {
		hosts = append(hosts, string(host))
	}
	sort.Strings(hosts)
	out := make([]HostAggregate, 0, len(hosts))
	for _, hostValue := range hosts {
		host := SyntheticHostID(hostValue)
		items := byHost[host]
		agg := HostAggregate{SyntheticHostID: host, HostClass: items[0].HostClass, ObservationCount: len(items)}
		profiles := map[int]bool{}
		features := map[string]int{}
		firstN := map[string]int{}
		families := map[string]int{}
		metadata := map[string]int{}
		fragments := map[string]int{}
		for _, item := range items {
			profiles[item.ProfileSeed] = true
			features[item.FeatureHash]++
			firstN[item.FirstNShapeHash]++
			families[item.SelectedFamily]++
			metadata[item.MetadataExposure]++
			fragments[item.FragmentRhythm]++
			agg.PayloadLogged = agg.PayloadLogged || item.PayloadLogged
			agg.SecretLogged = agg.SecretLogged || item.SecretLogged
			if hostClassRank(item.HostClass) > hostClassRank(agg.HostClass) {
				agg.HostClass = item.HostClass
			}
		}
		agg.UniqueProfileSeeds = len(profiles)
		agg.UniqueFeatureHashes = len(features)
		agg.UniqueFirstNShapes = len(firstN)
		agg.UniqueFamilies = len(families)
		agg.UniqueMetadataClasses = len(metadata)
		agg.UniqueFragmentRhythms = len(fragments)
		agg.DominantFeatureShare = dominantShare(features, len(items))
		agg.DominantFirstNShare = dominantShare(firstN, len(items))
		agg.DominantFamilyShare = dominantShare(families, len(items))
		agg.ConsistencyScore = (agg.DominantFeatureShare + agg.DominantFirstNShare + agg.DominantFamilyShare + dominantShare(metadata, len(items)) + dominantShare(fragments, len(items))) / 5
		agg.RotationScore = 1 - agg.ConsistencyScore
		agg.RiskBucket = RiskBucket(agg.ConsistencyScore, agg.ObservationCount)
		out = append(out, agg)
	}
	return out
}

func hostClassRank(class HostClass) int {
	switch class {
	case HostClassControlFixed:
		return 5
	case HostClassControlPadding:
		return 4
	case HostClassControlNoise:
		return 3
	case HostClassCorpusBaseline:
		return 2
	default:
		return 1
	}
}

func dominantShare(values map[string]int, total int) float64 {
	if total <= 0 {
		return 0
	}
	max := 0
	for _, count := range values {
		if count > max {
			max = count
		}
	}
	return float64(max) / float64(total)
}
