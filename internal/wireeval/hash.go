// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

func HashValue(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func StableJSON(value any) ([]byte, error) {
	raw, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func DatasetHash(records []WireEvalRecord) string {
	type safeRecord struct {
		RecordID        string `json:"record_id"`
		FeatureHash     string `json:"feature_hash"`
		ByteShapeHash   string `json:"byte_shape_hash"`
		Split           string `json:"split"`
		Label           string `json:"label"`
		FirstNShapeHash string `json:"first_n_shape_hash"`
	}
	safe := make([]safeRecord, 0, len(records))
	for _, record := range records {
		safe = append(safe, safeRecord{
			RecordID:        record.RecordID,
			FeatureHash:     record.FeatureHash,
			ByteShapeHash:   record.ByteShapeHash,
			Split:           string(record.Split),
			Label:           string(record.Label),
			FirstNShapeHash: record.FirstNShapeHash,
		})
	}
	raw, _ := json.Marshal(safe)
	return HashValue(string(raw))
}
