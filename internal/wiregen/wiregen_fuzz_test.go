// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"encoding/json"
	"testing"

	"kurdistan/internal/protocorpus"
)

func FuzzWireShapePolicyValidator(f *testing.F) {
	corpus := protocorpus.DefaultCorpus()
	policy, err := SamplePolicy(12345, corpus)
	if err != nil {
		f.Fatal(err)
	}
	raw, err := json.Marshal(policy)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(raw)
	f.Add([]byte(`{"version":"wiregen-policy-v1"}`))
	f.Add([]byte(`not-json`))
	f.Fuzz(func(t *testing.T, data []byte) {
		if len(data) > 32*1024 {
			t.Skip()
		}
		var candidate WireShapePolicy
		if err := json.Unmarshal(data, &candidate); err != nil {
			return
		}
		_ = ValidatePolicy(candidate, corpus)
	})
}
