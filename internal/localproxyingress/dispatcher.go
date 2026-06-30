// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingress

import "sort"

func GroupByRequest(events []SyntheticIngressEvent) map[string][]SyntheticIngressEvent {
	grouped := map[string][]SyntheticIngressEvent{}
	for _, event := range events {
		grouped[event.RequestID] = append(grouped[event.RequestID], event)
	}
	for key := range grouped {
		sort.SliceStable(grouped[key], func(i, j int) bool {
			return grouped[key][i].LogicalTick < grouped[key][j].LogicalTick
		})
	}
	return grouped
}

func orderedRequestIDs(grouped map[string][]SyntheticIngressEvent) []string {
	ids := make([]string, 0, len(grouped))
	for id := range grouped {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}
