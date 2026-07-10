// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package pathhealth

import (
	"encoding/json"
	"os"
)

func LoadFixtureSet(path string) (PathHealthFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return PathHealthFixtureSet{}, err
	}
	var set PathHealthFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return PathHealthFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}
