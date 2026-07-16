// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"testing"
	"time"
)

func validEnvelope() Envelope {
	return Envelope{
		Issuer:        "lab-issuer",
		ProfileRef:    "profile-ref-abc123",
		Expiry:        time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC).Unix(),
		RevocationID:  "rev-001",
		CompatVersion: "kurd-runtime-0.1",
		SealMode:      SealModeUnsealedContract,
	}
}

func TestFormatParseRoundTrip(t *testing.T) {
	e := validEnvelope()
	link, err := Format(e)
	if err != nil {
		t.Fatalf("Format: %v", err)
	}
	got, err := Parse(link)
	if err != nil {
		t.Fatalf("Parse(%q): %v", link, err)
	}
	if got != e {
		t.Fatalf("round trip mismatch:\n got %+v\nwant %+v", got, e)
	}
}

func TestValidateRejectsUnsafeOrIncomplete(t *testing.T) {
	cases := map[string]func(*Envelope){
		"missing issuer":      func(e *Envelope) { e.Issuer = "" },
		"missing profile_ref": func(e *Envelope) { e.ProfileRef = "" },
		"no expiry":           func(e *Envelope) { e.Expiry = 0 },
		"missing revocation":  func(e *Envelope) { e.RevocationID = "" },
		"missing compat":      func(e *Envelope) { e.CompatVersion = "" },
		"unknown seal mode":   func(e *Envelope) { e.SealMode = "aead_sealed" },
		"payload embedded":    func(e *Envelope) { e.PayloadEmbedded = true },
		"secret-looking ref":  func(e *Envelope) { e.ProfileRef = "-----BEGIN PRIVATE KEY-----" },
		"payload-looking ref": func(e *Envelope) { e.ProfileRef = "payload:rawbytes" },
	}
	for name, mutate := range cases {
		e := validEnvelope()
		mutate(&e)
		if err := Validate(e); err == nil {
			t.Errorf("Validate accepted invalid envelope (%s)", name)
		}
	}
}

func TestSealingIsUnavailable(t *testing.T) {
	var s Sealer = UnavailableSealer{}
	if _, err := s.Seal("ref", []byte("x")); err != ErrSealingUnavailable {
		t.Fatalf("Seal err = %v, want ErrSealingUnavailable", err)
	}
	if _, err := s.Open([]byte("x")); err != ErrSealingUnavailable {
		t.Fatalf("Open err = %v, want ErrSealingUnavailable", err)
	}
}

func TestExpired(t *testing.T) {
	e := validEnvelope()
	e.Expiry = time.Date(2020, 1, 1, 0, 0, 0, 0, time.UTC).Unix()
	if !e.Expired(time.Now()) {
		t.Fatal("past-dated envelope should be expired")
	}
}

func TestNeutralMetadataContainsNoProfileMaterial(t *testing.T) {
	m, err := NeutralMetadata(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if m.Issuer != "lab-issuer" || m.ProfileRef != "profile-ref-abc123" || m.RevocationID != "rev-001" {
		t.Fatalf("unexpected metadata: %+v", m)
	}
}
