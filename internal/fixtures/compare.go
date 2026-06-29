// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"fmt"
	"sort"
)

type CompareReport struct {
	OldFixtureSet  string   `json:"old_fixture_set"`
	NewFixtureSet  string   `json:"new_fixture_set"`
	Added          []string `json:"added,omitempty"`
	Removed        []string `json:"removed,omitempty"`
	Changed        []string `json:"changed,omitempty"`
	SemanticDrift  []string `json:"semantic_drift,omitempty"`
	ByteShapeDrift []string `json:"byte_shape_drift,omitempty"`
	PayloadLogged  bool     `json:"payload_logged"`
	SecretLogged   bool     `json:"secret_logged"`
	Compared       int      `json:"compared"`
	Passed         bool     `json:"passed"`
	Conclusion     string   `json:"conclusion"`
}

func CompareManifests(oldManifest, newManifest FixtureManifest) CompareReport {
	oldManifest.Normalize()
	newManifest.Normalize()
	report := CompareReport{
		OldFixtureSet: oldManifest.FixtureSet,
		NewFixtureSet: newManifest.FixtureSet,
		PayloadLogged: oldManifest.PayloadLogged || newManifest.PayloadLogged,
		SecretLogged:  oldManifest.SecretLogged || newManifest.SecretLogged,
	}
	oldEntries := map[string]FixtureEntry{}
	newEntries := map[string]FixtureEntry{}
	for _, entry := range oldManifest.Entries {
		oldEntries[entry.Name] = entry
	}
	for _, entry := range newManifest.Entries {
		newEntries[entry.Name] = entry
	}
	for name, oldEntry := range oldEntries {
		newEntry, ok := newEntries[name]
		if !ok {
			report.Removed = append(report.Removed, name)
			continue
		}
		report.Compared++
		if oldEntry.SummaryHash != newEntry.SummaryHash {
			report.Changed = append(report.Changed, name)
			report.SemanticDrift = append(report.SemanticDrift, name)
			continue
		}
		if oldEntry.ByteShapeHash != newEntry.ByteShapeHash {
			report.Changed = append(report.Changed, name)
			report.ByteShapeDrift = append(report.ByteShapeDrift, name)
		}
	}
	for name := range newEntries {
		if _, ok := oldEntries[name]; !ok {
			report.Added = append(report.Added, name)
		}
	}
	sort.Strings(report.Added)
	sort.Strings(report.Removed)
	sort.Strings(report.Changed)
	sort.Strings(report.SemanticDrift)
	sort.Strings(report.ByteShapeDrift)
	report.Passed = len(report.Added) == 0 &&
		len(report.Removed) == 0 &&
		len(report.Changed) == 0 &&
		!report.PayloadLogged &&
		!report.SecretLogged
	report.Conclusion = "passed"
	if !report.Passed {
		report.Conclusion = "failed"
	}
	return report
}

func (r CompareReport) HumanSummary() string {
	status := "PASS"
	if !r.Passed {
		status = "FAIL"
	}
	return fmt.Sprintf("[%s] fixture compare: compared=%d added=%d removed=%d changed=%d conclusion=%s\n", status, r.Compared, len(r.Added), len(r.Removed), len(r.Changed), r.Conclusion)
}
