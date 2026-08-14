// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17evidence

import (
	"bytes"
	"testing"
)

func FuzzOwnedVPSEvidenceDispatch(f *testing.F) {
	v2 := validOwnedVPSEvidence(f)
	v3, err := MarshalOwnedVPSRawV3(validOwnedVPSV3(f, "Functional"))
	if err != nil {
		f.Fatal(err)
	}
	sanitized, err := SanitizeOwnedVPSV3(v3)
	if err != nil {
		f.Fatal(err)
	}
	f.Add(uint8(0), v2)
	f.Add(uint8(1), v3)
	f.Add(uint8(2), sanitized)
	f.Add(uint8(1), []byte(`{"schema":"kurdistan-phase17-owned-vps-raw-v3"}`))
	f.Fuzz(func(t *testing.T, kind uint8, raw []byte) {
		_ = ContainsSensitiveFieldEvidence(raw)
		switch kind % 3 {
		case 0:
			value, err := DecodeOwnedVPS(raw)
			if err == nil && (value.Schema != OwnedVPSSchema || value.Result != "PASS") {
				t.Fatalf("v2 decoder accepted wrong identity: %+v", value)
			}
		case 1:
			value, err := DecodeOwnedVPSRawV3(raw)
			if err != nil {
				return
			}
			canonical, err := MarshalOwnedVPSRawV3(value)
			if err != nil || !bytes.Equal(raw, canonical) {
				t.Fatalf("successful raw v3 decode was not canonical: %v", err)
			}
		case 2:
			value, err := DecodeOwnedVPSSanitizedV3(raw)
			if err != nil {
				return
			}
			canonical, err := MarshalOwnedVPSSanitizedV3(value)
			if err != nil || !bytes.Equal(raw, canonical) {
				t.Fatalf("successful sanitized v3 decode was not canonical: %v", err)
			}
		}
	})
}

func FuzzSanitizeOwnedVPSV3(f *testing.F) {
	valid, err := MarshalOwnedVPSRawV3(validOwnedVPSV3(f, "Functional"))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte("not-json"))
	f.Fuzz(func(t *testing.T, raw []byte) {
		sanitized, err := SanitizeOwnedVPSV3(raw)
		if err != nil {
			return
		}
		source, err := DecodeOwnedVPSRawV3(raw)
		if err != nil || source.Outcome != "PASS" {
			t.Fatalf("sanitizer accepted invalid source: %v", err)
		}
		value, err := DecodeOwnedVPSSanitizedV3(sanitized)
		if err != nil || value.Schema != OwnedVPSSchemaV3 || value.Attempt.AttemptID != source.Attempt.AttemptID {
			t.Fatalf("sanitized evidence mismatch: %v", err)
		}
	})
}
