// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package adversary

import (
	"fmt"
	"sort"
)

const DefaultClusterThreshold = 0.18

type ClusterGroup struct {
	ID            int      `json:"id"`
	Size          int      `json:"size"`
	TraceIDs      []string `json:"trace_ids"`
	ProfileIDs    []string `json:"profile_ids"`
	Labels        []string `json:"labels"`
	DominantLabel string   `json:"dominant_label,omitempty"`
}

type PairwiseStats struct {
	PairCount                       int     `json:"pair_count"`
	MinDistance                     float64 `json:"min_distance"`
	MaxDistance                     float64 `json:"max_distance"`
	AverageDistance                 float64 `json:"average_distance"`
	SameProfilePairs                int     `json:"same_profile_pairs"`
	SameProfileAverageDistance      float64 `json:"same_profile_average_distance"`
	DifferentProfilePairs           int     `json:"different_profile_pairs"`
	DifferentProfileAverageDistance float64 `json:"different_profile_average_distance"`
}

type ClusterReport struct {
	VectorCount         int            `json:"vector_count"`
	Threshold           float64        `json:"threshold"`
	ClusterCount        int            `json:"cluster_count"`
	LargestClusterSize  int            `json:"largest_cluster_size"`
	LargestClusterRatio float64        `json:"largest_cluster_ratio"`
	Clusters            []ClusterGroup `json:"clusters"`
	PairwiseStats       PairwiseStats  `json:"pairwise_stats"`
	Conclusion          string         `json:"conclusion"`
}

func ClusterVectors(vectors []FeatureVector, threshold float64) ClusterReport {
	return Cluster(vectors, threshold)
}

func Cluster(vectors []FeatureVector, threshold float64) ClusterReport {
	if threshold <= 0 {
		threshold = DefaultClusterThreshold
	}
	report := ClusterReport{VectorCount: len(vectors), Threshold: threshold}
	if len(vectors) == 0 {
		report.Conclusion = "no vectors"
		return report
	}
	parent := make([]int, len(vectors))
	for i := range parent {
		parent[i] = i
	}
	stats := PairwiseStats{MinDistance: 1}
	var totalDistance, sameDistance, differentDistance float64
	for i := 0; i < len(vectors); i++ {
		for j := i + 1; j < len(vectors); j++ {
			distance := Distance(vectors[i], vectors[j])
			stats.PairCount++
			totalDistance += distance
			if distance < stats.MinDistance {
				stats.MinDistance = distance
			}
			if distance > stats.MaxDistance {
				stats.MaxDistance = distance
			}
			if sameProfile(vectors[i], vectors[j]) {
				stats.SameProfilePairs++
				sameDistance += distance
			} else {
				stats.DifferentProfilePairs++
				differentDistance += distance
			}
			if distance <= threshold {
				union(parent, i, j)
			}
		}
	}
	if stats.PairCount == 0 {
		stats.MinDistance = 0
	} else {
		stats.AverageDistance = totalDistance / float64(stats.PairCount)
	}
	if stats.SameProfilePairs > 0 {
		stats.SameProfileAverageDistance = sameDistance / float64(stats.SameProfilePairs)
	}
	if stats.DifferentProfilePairs > 0 {
		stats.DifferentProfileAverageDistance = differentDistance / float64(stats.DifferentProfilePairs)
	}
	report.PairwiseStats = stats

	grouped := map[int][]FeatureVector{}
	for i, vector := range vectors {
		root := find(parent, i)
		grouped[root] = append(grouped[root], vector)
	}
	clusters := make([]ClusterGroup, 0, len(grouped))
	for _, members := range grouped {
		clusters = append(clusters, clusterFromMembers(len(clusters), members))
	}
	sort.Slice(clusters, func(i, j int) bool {
		if clusters[i].Size == clusters[j].Size {
			return fmt.Sprint(clusters[i].TraceIDs) < fmt.Sprint(clusters[j].TraceIDs)
		}
		return clusters[i].Size > clusters[j].Size
	})
	for i := range clusters {
		clusters[i].ID = i
	}
	report.Clusters = clusters
	report.ClusterCount = len(clusters)
	if len(clusters) > 0 {
		report.LargestClusterSize = clusters[0].Size
		report.LargestClusterRatio = float64(clusters[0].Size) / float64(len(vectors))
	}
	switch {
	case report.ClusterCount == 1:
		report.Conclusion = "single cluster"
	case report.LargestClusterRatio >= 0.80:
		report.Conclusion = "dominant cluster"
	default:
		report.Conclusion = "multiple clusters"
	}
	return report
}

func clusterFromMembers(id int, members []FeatureVector) ClusterGroup {
	traceIDs := make([]string, 0, len(members))
	profileSet := map[string]bool{}
	labelSet := map[string]bool{}
	labelCounts := map[string]int{}
	for _, member := range members {
		traceIDs = append(traceIDs, member.TraceID)
		if member.ProfileID != "" {
			profileSet[member.ProfileID] = true
		}
		if member.Label != "" {
			labelSet[member.Label] = true
			labelCounts[member.Label]++
		}
	}
	sort.Strings(traceIDs)
	cluster := ClusterGroup{
		ID:         id,
		Size:       len(members),
		TraceIDs:   traceIDs,
		ProfileIDs: sortedSet(profileSet),
		Labels:     sortedSet(labelSet),
	}
	dominantCount := 0
	for label, count := range labelCounts {
		if count > dominantCount || (count == dominantCount && label < cluster.DominantLabel) {
			cluster.DominantLabel = label
			dominantCount = count
		}
	}
	return cluster
}

func sortedSet(set map[string]bool) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func sameProfile(a, b FeatureVector) bool {
	return a.ProfileID != "" && a.ProfileID == b.ProfileID
}

func find(parent []int, i int) int {
	for parent[i] != i {
		parent[i] = parent[parent[i]]
		i = parent[i]
	}
	return i
}

func union(parent []int, a, b int) {
	ra := find(parent, a)
	rb := find(parent, b)
	if ra != rb {
		parent[rb] = ra
	}
}
