// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import "fmt"

func ValidateManifest(manifest FixtureManifest) error {
	if manifest.Version != SchemaVersion {
		return fmt.Errorf("%w: version", ErrFixtureInvalid)
	}
	if manifest.FixtureSet == "" || manifest.GeneratedAt == "" || manifest.BackendVersion == "" {
		return fmt.Errorf("%w: metadata", ErrFixtureInvalid)
	}
	if manifest.PayloadLogged || manifest.SecretLogged {
		return ErrTraceLeak
	}
	if len(manifest.ProfileSeeds) == 0 || len(manifest.ScenarioNames) == 0 {
		return fmt.Errorf("%w: missing seeds or scenarios", ErrFixtureInvalid)
	}
	if manifest.FixtureCount != len(manifest.Entries) {
		return fmt.Errorf("%w: fixture count", ErrFixtureInvalid)
	}
	if len(manifest.Entries) == 0 {
		return fmt.Errorf("%w: no entries", ErrFixtureInvalid)
	}
	summaryByName := map[string]BytePathFixtureSummary{}
	for _, summary := range manifest.Summaries {
		summaryByName[summaryKey(summary)] = summary
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if entry.Name == "" || entry.Kind == "" || entry.ExpectedResult == "" {
			return fmt.Errorf("%w: entry metadata", ErrFixtureInvalid)
		}
		if entry.PayloadLogged || entry.SecretLogged {
			return ErrTraceLeak
		}
		if seen[entry.Name] {
			return fmt.Errorf("%w: duplicate entry %s", ErrFixtureInvalid, entry.Name)
		}
		seen[entry.Name] = true
		summary, ok := summaryByName[entryKey(entry)]
		if !ok {
			return fmt.Errorf("%w: missing summary for %s", ErrFixtureInvalid, entry.Name)
		}
		expected, err := EntryForSummary(summary)
		if err != nil {
			return err
		}
		if entry.SummaryHash != expected.SummaryHash || entry.TraceHash != expected.TraceHash || entry.ByteShapeHash != expected.ByteShapeHash {
			return fmt.Errorf("%w: hash mismatch for %s", ErrFixtureInvalid, entry.Name)
		}
	}
	if report := ValidateRedaction(manifest); !report.Passed {
		return fmt.Errorf("%w: %v", ErrTraceLeak, report.Findings)
	}
	if len(manifest.MalformedCases) > 0 {
		if err := ValidateMalformedCorpus(manifest.MalformedCases); err != nil {
			return err
		}
	}
	if manifest.Performance != nil {
		if err := ValidatePerformanceBaseline(*manifest.Performance); err != nil {
			return err
		}
	}
	return nil
}

func summaryKey(summary BytePathFixtureSummary) string {
	return fmt.Sprintf("%s|%d|%s|%s", summary.Backend, summary.ProfileSeed, summary.ProfileID, summary.Scenario)
}

func entryKey(entry FixtureEntry) string {
	return fmt.Sprintf("%s|%d|%s|%s", entry.Backend, entry.ProfileSeed, entry.ProfileID, entry.Scenario)
}
