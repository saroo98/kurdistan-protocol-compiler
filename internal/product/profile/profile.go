// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package profile defines deterministic offline profile-admission contracts.
// AuthorityEvidence is metadata about an upstream authorization decision. This
// package validates its shape and binding; it does not verify signatures.
package profile

import (
	"errors"
	"fmt"
	"strings"
	"time"

	"kurdistan/internal/product/envelope"
)

const (
	Version          = "product-profile-admission-v1"
	AuthorityKind    = "signed-profile-authority-metadata"
	AuthorityVersion = 1
	SafetyFloor      = 1
)

type AuthorityEvidence struct {
	Issuer, Kind, Subject, Reference string
	Version                          int
	IssuedAt, ExpiresAt              int64
}

type Candidate struct {
	ProfileID, ContractVersion, RevocationScope string
	Generation, RequiredSafetyFloor             uint64
	ValidFrom, ValidUntil                       int64
	Authority                                   AuthorityEvidence
	Envelope                                    envelope.Metadata
}

type Context struct {
	Now                     time.Time
	MinimumGeneration       uint64
	ExpectedRevocationScope string
	SeenEvidenceReferences  map[string]struct{}
}

func Validate(c Candidate, ctx Context) error {
	if ctx.Now.IsZero() {
		return errors.New("profile: validation time is required")
	}
	if !boundedID(ctx.ExpectedRevocationScope) {
		return errors.New("profile: expected revocation scope is missing or invalid")
	}
	for name, value := range map[string]string{"profile_id": c.ProfileID, "revocation_scope": c.RevocationScope, "authority issuer": c.Authority.Issuer, "authority subject": c.Authority.Subject, "authority reference": c.Authority.Reference} {
		if !boundedID(value) {
			return fmt.Errorf("profile: %s is missing or invalid", name)
		}
	}
	if c.ContractVersion != Version {
		return fmt.Errorf("profile: unsupported contract version %q", c.ContractVersion)
	}
	if c.Generation == 0 || c.Generation < ctx.MinimumGeneration {
		return errors.New("profile: stale or rollback generation")
	}
	if c.RequiredSafetyFloor < SafetyFloor || c.RequiredSafetyFloor > SafetyFloor {
		return errors.New("profile: incompatible safety floor")
	}
	now := ctx.Now.Unix()
	if c.ValidFrom <= 0 || c.ValidUntil <= c.ValidFrom || now < c.ValidFrom || now >= c.ValidUntil {
		return errors.New("profile: candidate is not currently valid")
	}
	if c.Authority.Kind != AuthorityKind || c.Authority.Version != AuthorityVersion {
		return errors.New("profile: unknown or incompatible authority evidence")
	}
	if c.Authority.IssuedAt <= 0 || c.Authority.ExpiresAt <= c.Authority.IssuedAt || c.Authority.IssuedAt > now || now >= c.Authority.ExpiresAt {
		return errors.New("profile: authority evidence is future, expired, or malformed")
	}
	if _, replayed := ctx.SeenEvidenceReferences[c.Authority.Reference]; replayed {
		return errors.New("profile: replayed authority evidence")
	}
	if !boundedID(c.Envelope.Issuer) || !boundedID(c.Envelope.ProfileRef) || !boundedID(c.Envelope.RevocationID) || c.Envelope.Expiry <= 0 || c.Envelope.CompatVersion == "" {
		return errors.New("profile: partial envelope metadata")
	}
	if c.Envelope.Issuer != c.Authority.Issuer || c.Envelope.ProfileRef != c.ProfileID || c.Authority.Subject != c.ProfileID || c.Envelope.RevocationID != c.RevocationScope {
		return errors.New("profile: authority or envelope binding mismatch")
	}
	if c.RevocationScope != ctx.ExpectedRevocationScope {
		return errors.New("profile: revocation scope is not authorized by context")
	}
	if c.Envelope.CompatVersion != Version || c.Envelope.Expiry < c.ValidUntil || c.Authority.ExpiresAt < c.ValidUntil {
		return errors.New("profile: incompatible or insufficient validity binding")
	}
	return nil
}

func boundedID(v string) bool {
	if v != strings.TrimSpace(v) || len(v) < 1 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		if !(r == '-' || r == '_' || r == '.' || r == ':' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
