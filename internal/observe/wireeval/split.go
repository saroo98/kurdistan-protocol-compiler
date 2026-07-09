// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import "sort"

const (
	SplitModeProfileHoldout      = "profile_holdout"
	SplitModeScenarioHoldout     = "scenario_holdout"
	SplitModeFamilyHoldout       = "family_holdout"
	SplitModeMixedHoldout        = "mixed_holdout"
	SplitModeOODGeneratedProfile = "ood_generated_profiles"
)

func DefaultSplitMode() string { return SplitModeProfileHoldout }

func SplitForRecord(index int, record WireEvalRecord, mode string) DatasetSplit {
	switch mode {
	case "", SplitModeProfileHoldout, SplitModeOODGeneratedProfile:
		switch record.ProfileSeed % 4 {
		case 0:
			return SplitOOD
		case 1:
			return SplitTest
		case 2:
			return SplitHoldout
		default:
			return SplitTrain
		}
	case SplitModeScenarioHoldout:
		switch index % 5 {
		case 0:
			return SplitOOD
		case 1:
			return SplitTest
		default:
			return SplitTrain
		}
	case SplitModeFamilyHoldout:
		if record.SelectedFamily == "message_like" || record.SelectedFamily == "long_poll_like" {
			return SplitOOD
		}
		if record.SelectedFamily == "datagram_like" {
			return SplitTest
		}
		return SplitTrain
	case SplitModeMixedHoldout:
		if record.ProfileSeed%5 == 0 || record.SelectedFamily == "long_poll_like" {
			return SplitOOD
		}
		if index%3 == 0 {
			return SplitTest
		}
		return SplitTrain
	default:
		return SplitTrain
	}
}

func BuildSplitManifest(records []WireEvalRecord, mode string) SplitManifest {
	m := SplitManifest{
		Mode:         mode,
		SplitCounts:  map[string]int{},
		ProfileSets:  map[string][]int{},
		ScenarioSets: map[string][]string{},
		FamilySets:   map[string][]string{},
		Passed:       true,
		Conclusion:   "passed",
	}
	profiles := map[string]map[int]bool{}
	scenarios := map[string]map[string]bool{}
	families := map[string]map[string]bool{}
	for _, split := range []DatasetSplit{SplitTrain, SplitTest, SplitOOD, SplitHoldout} {
		key := string(split)
		profiles[key] = map[int]bool{}
		scenarios[key] = map[string]bool{}
		families[key] = map[string]bool{}
	}
	for _, record := range records {
		key := string(record.Split)
		m.SplitCounts[key]++
		profiles[key][record.ProfileSeed] = true
		scenarios[key][record.Scenario] = true
		families[key][record.SelectedFamily] = true
	}
	for key := range profiles {
		m.ProfileSets[key] = sortedInts(profiles[key])
		m.ScenarioSets[key] = sortedStrings(scenarios[key])
		m.FamilySets[key] = sortedStrings(families[key])
	}
	if len(records) == 0 || m.SplitCounts[string(SplitTrain)] == 0 || m.SplitCounts[string(SplitTest)] == 0 || m.SplitCounts[string(SplitOOD)] == 0 {
		m.Passed = false
		m.Conclusion = "failed"
	}
	return m
}

func sortedInts(values map[int]bool) []int {
	out := make([]int, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Ints(out)
	return out
}

func sortedStrings(values map[string]bool) []string {
	out := make([]string, 0, len(values))
	for value := range values {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}
