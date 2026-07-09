// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wireeval

import "testing"

func FuzzDatasetParser(f *testing.F) {
	dataset, _ := GenerateGoldenDataset(nil)
	raw, _ := StableJSON(dataset)
	f.Add(raw)
	f.Add([]byte(`{"dataset_version":"bad"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 64*1024 {
			t.Skip()
		}
		_, _ = ParseDataset(raw)
	})
}

func FuzzLeakageScanner(f *testing.F) {
	f.Add("safe_feature_hash")
	f.Add("raw_payload")
	f.Fuzz(func(t *testing.T, value string) {
		if len(value) > 4096 {
			t.Skip()
		}
		_ = ScanForLeak(map[string]string{"value": value})
	})
}
