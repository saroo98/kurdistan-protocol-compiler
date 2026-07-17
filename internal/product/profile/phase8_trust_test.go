// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
)

func validArtifactTrust(c Candidate) ArtifactTrust {
	return ArtifactTrust{
		Artifact:            envelope.ArtifactMetadata{Class: envelope.ArtifactSignedPublic, AudienceClass: envelope.AudiencePublic},
		ContentID:           "content-2",
		LineageID:           "lineage-1",
		ProviderID:          "provider-1",
		ProfileID:           c.ProfileID,
		ContractVersion:     c.ContractVersion,
		RevocationScope:     c.RevocationScope,
		SnapshotMode:        SnapshotFull,
		UpdateKind:          UpdateInitial,
		Generation:          c.Generation,
		RequiredSafetyFloor: c.RequiredSafetyFloor,
		ValidFrom:           c.ValidFrom,
		ValidUntil:          c.ValidUntil,
		Authority:           c.Authority,
		Envelope:            c.Envelope,
		RootEpoch:           1,
		RevocationEpoch:     1,
	}
}

func TestValidateArtifactTrust(t *testing.T) {
	n := time.Unix(2000000000, 0)
	c := valid(n)
	if err := ValidateArtifactTrust(c, validArtifactTrust(c)); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*ArtifactTrust){
		"class audience mismatch": func(a *ArtifactTrust) { a.Artifact.AudienceClass = envelope.AudienceProvisionedDevice },
		"not full snapshot":       func(a *ArtifactTrust) { a.SnapshotMode = "delta" },
		"generation mismatch":     func(a *ArtifactTrust) { a.Generation++ },
		"profile mismatch":        func(a *ArtifactTrust) { a.ProfileID = "profile-other" },
		"revocation mismatch":     func(a *ArtifactTrust) { a.RevocationScope = "scope-other" },
		"contract mismatch":       func(a *ArtifactTrust) { a.ContractVersion = "contract-other" },
		"safety floor mismatch":   func(a *ArtifactTrust) { a.RequiredSafetyFloor++ },
		"validity mismatch":       func(a *ArtifactTrust) { a.ValidUntil++ },
		"authority mismatch":      func(a *ArtifactTrust) { a.Authority.Issuer = "issuer-other" },
		"envelope mismatch":       func(a *ArtifactTrust) { a.Envelope.ProfileRef = "profile-other" },
		"missing root epoch":      func(a *ArtifactTrust) { a.RootEpoch = 0 },
		"missing revocation epoch": func(a *ArtifactTrust) {
			a.RevocationEpoch = 0
		},
		"replacement without predecessor": func(a *ArtifactTrust) { a.UpdateKind = UpdateReplace },
		"removal reuses content": func(a *ArtifactTrust) {
			a.UpdateKind, a.PreviousContentID = UpdateRemove, a.ContentID
		},
		"migration without prior provider": func(a *ArtifactTrust) {
			a.UpdateKind, a.PreviousContentID = UpdateMigrate, "content-1"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			a := validArtifactTrust(c)
			mutate(&a)
			if err := ValidateArtifactTrust(c, a); err == nil {
				t.Fatal("accepted invalid artifact trust metadata")
			}
		})
	}
}

func TestFullSnapshotUpdateSemantics(t *testing.T) {
	n := time.Unix(2000000000, 0)
	c := valid(n)
	for _, kind := range []string{UpdateReplace, UpdateRemove} {
		a := validArtifactTrust(c)
		a.UpdateKind, a.PreviousContentID = kind, "content-1"
		if err := ValidateArtifactTrust(c, a); err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
	}
	migration := validArtifactTrust(c)
	migration.UpdateKind = UpdateMigrate
	migration.PreviousContentID = "content-1"
	migration.PreviousProviderID = "provider-0"
	if err := ValidateArtifactTrust(c, migration); err != nil {
		t.Fatal(err)
	}
}

func TestArtifactTrustCannotBeReusedAcrossCandidates(t *testing.T) {
	n := time.Unix(2000000000, 0)
	original := valid(n)
	trust := validArtifactTrust(original)
	mutations := map[string]func(*Candidate){
		"profile ID":          func(c *Candidate) { c.ProfileID = "profile-other" },
		"revocation scope":    func(c *Candidate) { c.RevocationScope = "scope-other" },
		"contract version":    func(c *Candidate) { c.ContractVersion = "contract-other" },
		"generation":          func(c *Candidate) { c.Generation++ },
		"safety floor":        func(c *Candidate) { c.RequiredSafetyFloor++ },
		"valid from":          func(c *Candidate) { c.ValidFrom++ },
		"valid until":         func(c *Candidate) { c.ValidUntil++ },
		"authority issuer":    func(c *Candidate) { c.Authority.Issuer = "issuer-other" },
		"authority kind":      func(c *Candidate) { c.Authority.Kind = "authority-other" },
		"authority subject":   func(c *Candidate) { c.Authority.Subject = "profile-other" },
		"authority reference": func(c *Candidate) { c.Authority.Reference = "evidence-other" },
		"authority version":   func(c *Candidate) { c.Authority.Version++ },
		"authority issued at": func(c *Candidate) { c.Authority.IssuedAt++ },
		"authority expires":   func(c *Candidate) { c.Authority.ExpiresAt++ },
		"envelope issuer":     func(c *Candidate) { c.Envelope.Issuer = "issuer-other" },
		"envelope profile":    func(c *Candidate) { c.Envelope.ProfileRef = "profile-other" },
		"envelope expiry":     func(c *Candidate) { c.Envelope.Expiry++ },
		"envelope revocation": func(c *Candidate) { c.Envelope.RevocationID = "scope-other" },
		"envelope compatibility": func(c *Candidate) {
			c.Envelope.CompatVersion = "contract-other"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			other := original
			mutate(&other)
			if err := ValidateArtifactTrust(other, trust); err == nil {
				t.Fatal("artifact trust validated a materially different candidate")
			}
		})
	}
}

func TestEqualGenerationRequiresIdenticalAuthenticatedIdentity(t *testing.T) {
	n := time.Unix(2000000000, 0)
	c := valid(n)
	a := validArtifactTrust(c)
	if !SameGenerationIdentity(a, a) {
		t.Fatal("identical artifact was not idempotent")
	}
	mutations := []func(*ArtifactTrust){
		func(b *ArtifactTrust) { b.ContentID = "content-conflict" },
		func(b *ArtifactTrust) { b.LineageID = "lineage-conflict" },
		func(b *ArtifactTrust) { b.RootEpoch++ },
		func(b *ArtifactTrust) { b.RevocationEpoch++ },
		func(b *ArtifactTrust) { b.ProviderID = "provider-conflict" },
		func(b *ArtifactTrust) { b.ProfileID = "profile-conflict" },
		func(b *ArtifactTrust) { b.RevocationScope = "scope-conflict" },
		func(b *ArtifactTrust) { b.ContractVersion = "contract-conflict" },
		func(b *ArtifactTrust) { b.RequiredSafetyFloor++ },
		func(b *ArtifactTrust) { b.ValidFrom++ },
		func(b *ArtifactTrust) { b.ValidUntil++ },
		func(b *ArtifactTrust) { b.Authority.Reference = "evidence-conflict" },
		func(b *ArtifactTrust) { b.Envelope.Expiry++ },
		func(b *ArtifactTrust) { b.Artifact.Class = envelope.ArtifactDeviceRecipient },
		func(b *ArtifactTrust) { b.Artifact.AudienceClass = envelope.AudienceProvisionedDevice },
		func(b *ArtifactTrust) { b.Artifact.RecipientEpoch++ },
		func(b *ArtifactTrust) { b.PreviousContentID = "predecessor-conflict" },
		func(b *ArtifactTrust) { b.UpdateKind = UpdateReplace },
	}
	for _, mutate := range mutations {
		b := a
		mutate(&b)
		if SameGenerationIdentity(a, b) {
			t.Fatalf("conflicting equal-generation metadata treated as identical: %+v", b)
		}
	}
}

func TestEqualGenerationRejectsDifferentRecipientEpoch(t *testing.T) {
	n := time.Unix(2000000000, 0)
	c := valid(n)
	current := validArtifactTrust(c)
	current.Artifact = envelope.ArtifactMetadata{
		Class:          envelope.ArtifactDeviceRecipient,
		AudienceClass:  envelope.AudienceProvisionedDevice,
		RecipientHint:  "rotating_hint_02",
		RecipientEpoch: 2,
	}
	stale := current
	stale.Artifact.RecipientEpoch = 1
	if err := ValidateArtifactTrust(c, current); err != nil {
		t.Fatalf("current recipient epoch: %v", err)
	}
	if err := ValidateArtifactTrust(c, stale); err != nil {
		t.Fatalf("stale recipient epoch shape: %v", err)
	}
	if SameGenerationIdentity(current, stale) {
		t.Fatal("different recipient epochs were treated as equal-generation identity")
	}
}
