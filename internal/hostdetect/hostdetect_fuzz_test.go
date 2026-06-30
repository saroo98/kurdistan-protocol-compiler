// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"encoding/json"
	"testing"
)

func FuzzHostObservationValidation(f *testing.F) {
	seed := HostObservation{Version: string(Version), ObservationID: "obs_seed", SyntheticHostID: "host_0001", DatasetRecordID: "rec_seed", FeatureHash: "h", FirstNShapeHash: "f", ByteShapeHash: "b"}
	raw, _ := json.Marshal(seed)
	f.Add(raw)
	f.Add([]byte(`{"synthetic_host_id":"127.0.0.1","raw_payload":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			t.Skip()
		}
		var observation HostObservation
		if err := json.Unmarshal(raw, &observation); err != nil {
			return
		}
		_ = ValidateObservation(observation)
	})
}

func FuzzHostLeakScanner(f *testing.F) {
	f.Add([]byte(`{"synthetic_host_id":"host_0001"}`))
	f.Add([]byte(`{"endpoint":"127.0.0.1"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 8192 {
			t.Skip()
		}
		var value any
		if err := json.Unmarshal(raw, &value); err != nil {
			return
		}
		_ = ScanForLeak(value)
	})
}
