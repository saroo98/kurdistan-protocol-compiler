// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathrace

import (
	"encoding/json"
	"os"
)

func LoadFixtureSet(path string) (PathRaceFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PathRaceFixtureSet{}, err
	}
	var set PathRaceFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return PathRaceFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func LoadReport(path string) (PathRaceReport, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PathRaceReport{}, err
	}
	var report PathRaceReport
	if err := json.Unmarshal(raw, &report); err != nil {
		return PathRaceReport{}, err
	}
	return report, ValidateSingleReport(report)
}

func ValidateSingleReport(report PathRaceReport) error {
	if report.Version != string(Version) || report.RaceID == "" || report.ReportHash == "" {
		return ErrInvalidRace
	}
	if report.ReportHash != HashValue(reportHashInput(report)) {
		return ErrInvalidRace
	}
	return ScanForLeak(report)
}
