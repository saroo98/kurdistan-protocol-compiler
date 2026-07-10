// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import "testing"

func FuzzFixtureManifestParser(f *testing.F) {
	f.Add([]byte(`{"version":"bytepath-fixture-v1","fixture_set":"x"}`))
	f.Add([]byte(`{"raw_payload":"x"}`))
	f.Fuzz(func(t *testing.T, raw []byte) {
		if len(raw) > 4096 {
			raw = raw[:4096]
		}
		_ = ScanFixtureJSON(raw)
	})
}

func FuzzMalformedCaseParser(f *testing.F) {
	f.Add("empty_input")
	f.Add("sequence_replay")
	f.Add("raw_bytes")
	f.Fuzz(func(t *testing.T, name string) {
		if len(name) > 128 {
			name = name[:128]
		}
		tc := MalformedByteCase{Name: name, InputClass: name, ExpectedReject: true, RejectBucket: "rejected"}
		_ = RunMalformedCase(tc)
	})
}
