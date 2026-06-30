// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

func HashValue(value any) string {
	raw, _ := json.Marshal(value)
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func ObservationID(recordID string, host SyntheticHostID, logicalTime int) string {
	return "obs_" + HashValue(fmt.Sprintf("%s:%s:%d", recordID, host, logicalTime))[:16]
}

func ObservationSetHash(observations []HostObservation) string {
	return HashValue(observations)
}
