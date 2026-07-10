// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"encoding/json"
	"os"
)

func LoadFixtureSet(path string) (TransportBundleFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return TransportBundleFixtureSet{}, err
	}
	var set TransportBundleFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return TransportBundleFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func ValidateManifestJSON(raw []byte) error {
	var manifest TransportBundleManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	if err := ScanForLeak(manifest); err != nil {
		return err
	}
	if manifest.Version == string(Version) {
		return ValidateManifest(manifest)
	}
	return nil
}
