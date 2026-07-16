package m3profilesdk

import (
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
)

func TestSupportedContractSurvivesRejectedFutureVersion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	e := envelope.Envelope{Issuer: "issuer", ProfileRef: "p1", Expiry: now.Add(2 * time.Hour).Unix(), RevocationID: "r1", CompatVersion: profile.Version, SealMode: envelope.SealModeUnsealedContract}
	m, err := envelope.NeutralMetadata(e)
	if err != nil {
		t.Fatal(err)
	}
	c := profile.Candidate{ProfileID: "p1", ContractVersion: profile.Version, RevocationScope: "r1", Generation: 1, RequiredSafetyFloor: profile.SafetyFloor, ValidFrom: now.Add(-time.Minute).Unix(), ValidUntil: now.Add(time.Hour).Unix(), Authority: profile.AuthorityEvidence{Issuer: "issuer", Kind: profile.AuthorityKind, Version: profile.AuthorityVersion, Subject: "p1", IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix(), Reference: "e1"}, Envelope: m}
	if err := profile.Validate(c, profile.Context{Now: now, ExpectedRevocationScope: "r1"}); err != nil {
		t.Fatal(err)
	}
	s, err := lifecycle.Apply(lifecycle.State{}, lifecycle.Decision{Action: lifecycle.Admit, ProfileID: "p1", Scope: "r1", Generation: 1, EvidenceReference: "e1"})
	if err != nil {
		t.Fatal(err)
	}
	future := c
	future.ContractVersion = "product-profile-admission-v2"
	if profile.Validate(future, profile.Context{Now: now, MinimumGeneration: s.Generation, ExpectedRevocationScope: "r1"}) == nil {
		t.Fatal("future incompatible version accepted")
	}
	if s.Status != lifecycle.Admitted || s.Generation != 1 {
		t.Fatalf("last safe state changed: %+v", s)
	}
}
