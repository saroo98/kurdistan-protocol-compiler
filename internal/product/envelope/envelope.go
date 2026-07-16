// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package envelope is the kurd:// profile-envelope DESIGN CONTRACT (Stage 8).
//
// LOOM: contract. This is a contract-only surface: it parses, formats, and
// validates the metadata shape of a kurd:// profile-distribution link. It does
// NOT seal, encrypt, or transport anything. Real sealing is production
// cryptography and is gated on external review (D-003); the Sealer interface has
// no implementation here on purpose. The kurd:// link carries metadata and an
// opaque profile reference only — never payloads, secrets, keys, or raw profile
// material. Nothing in the live runtime imports this package (enforced by
// internal/testkit/importrules).
package envelope

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
	"time"
)

const (
	// Version identifies the kurd:// envelope contract revision.
	Version = "kurd-envelope-v1"
	// Scheme is the URL scheme for a profile-distribution link.
	Scheme = "kurd"

	// SealModeUnsealedContract is the only seal mode this contract admits: a
	// metadata-only link whose profile reference is opaque and unsealed. Real
	// sealed modes await the D-003 crypto suite.
	SealModeUnsealedContract = "unsealed_contract"
)

// ErrSealingUnavailable is returned by every Sealer method in this package.
// Real sealing is production cryptography gated on external review (D-003).
var ErrSealingUnavailable = errors.New("kurd:// sealing is unavailable: production cryptography is gated on external review (D-003)")

// Envelope is the metadata contract for a kurd:// profile-distribution link.
// It references a profile; it never contains the profile material itself.
type Envelope struct {
	Issuer        string `json:"issuer"`         // opaque issuer identifier
	ProfileRef    string `json:"profile_ref"`    // opaque reference to a profile (not the profile)
	Expiry        int64  `json:"expiry"`         // unix seconds; must be > 0 (envelopes must expire)
	RevocationID  string `json:"revocation_id"`  // identifier used for revocation checks
	CompatVersion string `json:"compat_version"` // minimum compatible runtime/profile version
	SealMode      string `json:"seal_mode"`      // must be SealModeUnsealedContract in this contract

	// PayloadEmbedded MUST be false. It exists only so a misuse control can
	// prove the contract rejects any attempt to embed profile/payload material
	// in the link.
	PayloadEmbedded bool `json:"payload_embedded"`
}

// Metadata is the neutral, profile-material-free subset consumed by offline
// admission contracts. It deliberately contains no proof, key, payload, or
// transport data.
type Metadata struct {
	Issuer        string
	ProfileRef    string
	Expiry        int64
	RevocationID  string
	CompatVersion string
}

// NeutralMetadata validates e and returns its neutral metadata projection.
// Consumers must perform their own policy and authority-evidence checks.
func NeutralMetadata(e Envelope) (Metadata, error) {
	if err := Validate(e); err != nil {
		return Metadata{}, err
	}
	return Metadata{Issuer: e.Issuer, ProfileRef: e.ProfileRef, Expiry: e.Expiry, RevocationID: e.RevocationID, CompatVersion: e.CompatVersion}, nil
}

// Sealer seals and opens the profile material referenced by an Envelope. There
// is deliberately NO implementation: real sealing is production cryptography,
// gated on external review (D-003). UnavailableSealer is the only provided
// value and returns ErrSealingUnavailable from both methods.
type Sealer interface {
	Seal(profileRef string, material []byte) ([]byte, error)
	Open(sealed []byte) ([]byte, error)
}

// UnavailableSealer implements Sealer by refusing: sealing is D-003-gated.
type UnavailableSealer struct{}

func (UnavailableSealer) Seal(string, []byte) ([]byte, error) { return nil, ErrSealingUnavailable }
func (UnavailableSealer) Open([]byte) ([]byte, error)         { return nil, ErrSealingUnavailable }

// Validate reports whether e is a well-formed, safe kurd:// envelope contract.
// It enforces the safety invariants (must expire, opaque reference only, no
// embedded payload) as well as the required-field contract.
func Validate(e Envelope) error {
	if strings.TrimSpace(e.Issuer) == "" {
		return errors.New("envelope: issuer is required")
	}
	if strings.TrimSpace(e.ProfileRef) == "" {
		return errors.New("envelope: profile_ref is required")
	}
	if e.PayloadEmbedded {
		return errors.New("envelope: payload_embedded must be false (kurd:// carries an opaque reference, never profile/payload material)")
	}
	if looksLikeEmbeddedMaterial(e.ProfileRef) {
		return errors.New("envelope: profile_ref must be an opaque reference, not embedded profile/secret material")
	}
	if e.Expiry <= 0 {
		return errors.New("envelope: expiry (unix seconds) is required and must be positive")
	}
	if strings.TrimSpace(e.RevocationID) == "" {
		return errors.New("envelope: revocation_id is required")
	}
	if strings.TrimSpace(e.CompatVersion) == "" {
		return errors.New("envelope: compat_version is required")
	}
	if e.SealMode != SealModeUnsealedContract {
		return fmt.Errorf("envelope: seal_mode %q is not admitted by this contract (only %q; sealed modes await D-003)", e.SealMode, SealModeUnsealedContract)
	}
	return nil
}

// Expired reports whether the envelope is expired at time now.
func (e Envelope) Expired(now time.Time) bool {
	return e.Expiry > 0 && now.Unix() >= e.Expiry
}

// Format renders a valid envelope as a kurd:// link. It fails if e is invalid so
// a malformed or unsafe envelope can never be serialized.
func Format(e Envelope) (string, error) {
	if err := Validate(e); err != nil {
		return "", err
	}
	q := url.Values{}
	q.Set("exp", fmt.Sprintf("%d", e.Expiry))
	q.Set("rev", e.RevocationID)
	q.Set("compat", e.CompatVersion)
	q.Set("seal", e.SealMode)
	u := url.URL{
		Scheme:   Scheme,
		Host:     url.PathEscape(e.Issuer),
		Path:     "/" + url.PathEscape(e.ProfileRef),
		RawQuery: encodeSorted(q),
	}
	return u.String(), nil
}

// Parse parses a kurd:// link into an Envelope and validates it. A malformed or
// unsafe link is rejected rather than partially accepted.
func Parse(link string) (Envelope, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: parse: %w", err)
	}
	if u.Scheme != Scheme {
		return Envelope{}, fmt.Errorf("envelope: scheme %q is not %q", u.Scheme, Scheme)
	}
	issuer, err := url.PathUnescape(u.Host)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: issuer: %w", err)
	}
	ref, err := url.PathUnescape(strings.TrimPrefix(u.Path, "/"))
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: profile_ref: %w", err)
	}
	q := u.Query()
	var exp int64
	if _, err := fmt.Sscanf(q.Get("exp"), "%d", &exp); err != nil {
		return Envelope{}, fmt.Errorf("envelope: exp must be a unix timestamp: %w", err)
	}
	e := Envelope{
		Issuer:        issuer,
		ProfileRef:    ref,
		Expiry:        exp,
		RevocationID:  q.Get("rev"),
		CompatVersion: q.Get("compat"),
		SealMode:      q.Get("seal"),
	}
	if err := Validate(e); err != nil {
		return Envelope{}, err
	}
	return e, nil
}

// looksLikeEmbeddedMaterial is a conservative guard: a profile reference should
// be a short opaque token, not a base64 blob or a key/secret-looking string.
func looksLikeEmbeddedMaterial(ref string) bool {
	if len(ref) > 256 {
		return true
	}
	lower := strings.ToLower(ref)
	for _, marker := range []string{"begin", "private", "secret", "-----", "payload"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func encodeSorted(q url.Values) string {
	keys := make([]string, 0, len(q))
	for k := range q {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, url.QueryEscape(k)+"="+url.QueryEscape(q.Get(k)))
	}
	return strings.Join(parts, "&")
}
