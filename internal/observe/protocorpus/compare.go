// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

type CompareReport struct {
	OldEntries    int      `json:"old_entries"`
	NewEntries    int      `json:"new_entries"`
	Added         []string `json:"added,omitempty"`
	Removed       []string `json:"removed,omitempty"`
	Changed       []string `json:"changed,omitempty"`
	PayloadLogged bool     `json:"payload_logged"`
	SecretLogged  bool     `json:"secret_logged"`
	Conclusion    string   `json:"conclusion"`
	Passed        bool     `json:"passed"`
}

func CompareManifests(oldManifest, newManifest CorpusManifest) CompareReport {
	oldMap := entryMap(oldManifest)
	newMap := entryMap(newManifest)
	report := CompareReport{OldEntries: len(oldManifest.Entries), NewEntries: len(newManifest.Entries), Passed: true, Conclusion: "passed"}
	for name, oldEntry := range oldMap {
		newEntry, ok := newMap[name]
		if !ok {
			report.Removed = append(report.Removed, name)
			continue
		}
		oldHash, _ := HashValue(oldEntry)
		newHash, _ := HashValue(newEntry)
		if oldHash != newHash {
			report.Changed = append(report.Changed, name)
		}
	}
	for name := range newMap {
		if _, ok := oldMap[name]; !ok {
			report.Added = append(report.Added, name)
		}
	}
	report.PayloadLogged = oldManifest.PayloadLogged || newManifest.PayloadLogged
	report.SecretLogged = oldManifest.SecretLogged || newManifest.SecretLogged
	if len(report.Added)+len(report.Removed)+len(report.Changed) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Passed = false
		report.Conclusion = "failed"
	}
	return report
}

func entryMap(manifest CorpusManifest) map[string]ProtocolShapeEntry {
	out := map[string]ProtocolShapeEntry{}
	for _, entry := range manifest.Entries {
		out[entry.Name] = entry
	}
	return out
}
