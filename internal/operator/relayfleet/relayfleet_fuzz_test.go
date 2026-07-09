// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"encoding/json"
	"testing"
)

func FuzzRelayFleetValidateRelay(f *testing.F) {
	f.Add("relay_0001", string(RelayActive), "host_0001")
	f.Add("bad", "burned", "host_0001")
	f.Fuzz(func(t *testing.T, id, state, host string) {
		relay := SyntheticRelay{RelayID: RelayID(id), RelayClass: RelayClassGenerated, State: RelayState(state), ProfileID: "profile", ProfileSeed: 1, WirePolicyHash: "hash", SelectedFamily: "family", SyntheticHostID: host, BurnRiskBucket: RiskLow}
		_ = ValidateRelay(relay)
	})
}

func FuzzRelayFleetLeakScanner(f *testing.F) {
	f.Add(`{"relay_id":"relay_0001"}`)
	f.Add(`{"endpoint":"x"}`)
	f.Add(`{"cloud_provider":"x"}`)
	f.Fuzz(func(t *testing.T, raw string) {
		if len(raw) > 4096 {
			t.Skip()
		}
		var value any
		if err := json.Unmarshal([]byte(raw), &value); err != nil {
			return
		}
		_ = ScanForLeak(value)
	})
}
