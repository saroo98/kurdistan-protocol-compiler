// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyingressreview

func DefaultChecklist() []ReviewChecklistItem {
	categories := []string{
		"contract_completeness",
		"target_descriptor_safety",
		"capability_mapping",
		"runtime_mapping",
		"security_preconditions",
		"resource_limits",
		"trace_hygiene",
		"failure_modes",
		"generated_backend_readiness",
		"documentation_readiness",
		"implementation_go_no_go",
	}
	items := make([]ReviewChecklistItem, 0, len(categories))
	for i, category := range categories {
		items = append(items, ReviewChecklistItem{
			ID:       category,
			Category: category,
			Status:   "passed",
			Evidence: "deterministic_review_check",
			Blocking: i < 9,
		})
	}
	return items
}

func failItem(items []ReviewChecklistItem, id, evidence string) []ReviewChecklistItem {
	for i := range items {
		if items[i].ID == id {
			items[i].Status = "failed"
			items[i].Evidence = evidence
		}
	}
	return items
}
