// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func HashValue(value any) (string, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func FeatureHash(vector WireFeatureVector) (string, error) {
	vector.FeatureHash = ""
	return HashValue(vector)
}
