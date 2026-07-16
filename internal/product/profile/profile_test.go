// SPDX-License-Identifier: AGPL-3.0-or-later
package profile

import (
	"kurdistan/internal/product/envelope"
	"strings"
	"testing"
	"time"
)

func valid(now time.Time) Candidate {
	return Candidate{ProfileID: "p-1", ContractVersion: Version, RevocationScope: "r-1", Generation: 2, RequiredSafetyFloor: SafetyFloor, ValidFrom: now.Add(-time.Minute).Unix(), ValidUntil: now.Add(time.Hour).Unix(), Authority: AuthorityEvidence{Issuer: "issuer-1", Kind: AuthorityKind, Version: AuthorityVersion, Subject: "p-1", IssuedAt: now.Add(-time.Minute).Unix(), ExpiresAt: now.Add(2 * time.Hour).Unix(), Reference: "e-1"}, Envelope: envelope.Metadata{Issuer: "issuer-1", ProfileRef: "p-1", Expiry: now.Add(2 * time.Hour).Unix(), RevocationID: "r-1", CompatVersion: Version}}
}

func TestValidateAdmission(t *testing.T) {
	n := time.Unix(2000000000, 0)
	if err := Validate(valid(n), Context{Now: n, MinimumGeneration: 2, ExpectedRevocationScope: "r-1"}); err != nil {
		t.Fatal(err)
	}
}

func TestRejectsInvalidAdmission(t *testing.T) {
	n := time.Unix(2000000000, 0)
	cases := map[string]func(*Candidate, *Context){
		"missing": func(c *Candidate, _ *Context) { c.Authority.Reference = "" }, "expired": func(c *Candidate, _ *Context) { c.ValidUntil = n.Unix() }, "future": func(c *Candidate, _ *Context) { c.Authority.IssuedAt = n.Add(time.Minute).Unix() }, "rollback": func(c *Candidate, x *Context) { x.MinimumGeneration = 3 }, "incompatible": func(c *Candidate, _ *Context) { c.ContractVersion = "v2" }, "weak": func(c *Candidate, _ *Context) { c.RequiredSafetyFloor = 0 }, "mismatch": func(c *Candidate, _ *Context) { c.Authority.Subject = "other" }, "partial": func(c *Candidate, _ *Context) { c.Envelope.RevocationID = "" }, "replayed": func(c *Candidate, x *Context) { x.SeenEvidenceReferences = map[string]struct{}{"e-1": {}} }, "over-scoped": func(c *Candidate, _ *Context) { c.RevocationScope, c.Envelope.RevocationID = "global", "global" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := valid(n)
			x := Context{Now: n, MinimumGeneration: 2, ExpectedRevocationScope: "r-1"}
			mutate(&c, &x)
			if err := Validate(c, x); err == nil {
				t.Fatal("accepted invalid candidate")
			}
		})
	}
}

func TestRejectsSecretLikeOrUnboundedIdentifiers(t *testing.T) {
	n := time.Unix(2000000000, 0)
	c := valid(n)
	c.ProfileID = strings.Repeat("x", 129)
	if Validate(c, Context{Now: n, ExpectedRevocationScope: "r-1"}) == nil {
		t.Fatal("accepted unbounded id")
	}
}
