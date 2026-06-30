// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"encoding/json"
	"os"
)

func LoadObservationSet(path string) (HostObservationSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return HostObservationSet{}, err
	}
	var set HostObservationSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return HostObservationSet{}, err
	}
	return set, ValidateObservationSet(set)
}
