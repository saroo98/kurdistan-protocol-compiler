// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profilemigration

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"unicode/utf8"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/ir"
)

var (
	ErrMigrationAuthorizationSerialization = errors.New("profile migration authorization serialization rejected")
	ErrMigrationAuthorizationInvalid       = errors.New("profile migration authorization invalid")
	ErrMigrationNotRequired                = errors.New("profile migration not required")
	ErrMigrationSourceMismatch             = errors.New("profile migration source mismatch")
	ErrMigrationFailed                     = errors.New("profile migration failed")
)

type AuthorizationRequestV1 struct {
	SourceProfileID   string
	SourceProfileHash [32]byte
	ClientIdentityID  string
	RelayIdentityID   string
}

type MigrationAuthorizationV1 struct {
	request             AuthorizationRequestV1
	clientPublicKeyHash [32]byte
	relayPublicKeyHash  [32]byte
	seal                [32]byte
}

type MigrationReportV1 struct {
	Version                  string
	SourceClass              string
	TargetClass              string
	VersionFieldsChanged     uint32
	GenerationHashRecomputed bool
}

func NewMigrationAuthorizationV1(req AuthorizationRequestV1, clientDeps, relayDeps auth.Dependencies) (MigrationAuthorizationV1, error) {
	var out MigrationAuthorizationV1
	if !validText(req.SourceProfileID) || !validText(req.ClientIdentityID) || !validText(req.RelayIdentityID) || req.SourceProfileHash == ([32]byte{}) || clientDeps.Identity == nil || clientDeps.Trust == nil || relayDeps.Identity == nil || relayDeps.Trust == nil {
		return out, ErrMigrationAuthorizationInvalid
	}
	clientPrivate, err := clientDeps.Identity.Local(req.ClientIdentityID)
	if err != nil {
		return out, ErrMigrationAuthorizationInvalid
	}
	defer wipe(clientPrivate)
	relayPrivate, err := relayDeps.Identity.Local(req.RelayIdentityID)
	if err != nil {
		return out, ErrMigrationAuthorizationInvalid
	}
	defer wipe(relayPrivate)
	if len(clientPrivate) != ed25519.PrivateKeySize || len(relayPrivate) != ed25519.PrivateKeySize {
		return out, ErrMigrationAuthorizationInvalid
	}
	clientPublic := append(ed25519.PublicKey(nil), clientPrivate[32:]...)
	relayPublic := append(ed25519.PublicKey(nil), relayPrivate[32:]...)
	trustedRelay, err := clientDeps.Trust.Peer(req.RelayIdentityID)
	if err != nil || subtle.ConstantTimeCompare(trustedRelay, relayPublic) != 1 {
		return out, ErrMigrationAuthorizationInvalid
	}
	trustedClient, err := relayDeps.Trust.Peer(req.ClientIdentityID)
	if err != nil || subtle.ConstantTimeCompare(trustedClient, clientPublic) != 1 {
		return out, ErrMigrationAuthorizationInvalid
	}
	out.request = req
	out.clientPublicKeyHash = sha256.Sum256(clientPublic)
	out.relayPublicKeyHash = sha256.Sum256(relayPublic)
	out.seal = sha256.Sum256(out.canonical())
	return out, nil
}

func validText(v string) bool {
	if v == "" || !utf8.ValidString(v) {
		return false
	}
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

func wipe(v []byte) {
	for i := range v {
		v[i] = 0
	}
}

func (a MigrationAuthorizationV1) canonical() []byte {
	parts := []string{"kurdistan/profile-migration/authorization/v1", "0.1.0-lab", "0.12.0-lab", "0.2.0-lab", "0.13.0-lab", "kurdistan-handshake-v1", "policy-v1", "record-v1", a.request.SourceProfileID}
	b := make([]byte, 0, 256)
	for _, part := range parts {
		b = appendLP(b, []byte(part))
	}
	b = append(b, a.request.SourceProfileHash[:]...)
	b = appendLP(b, []byte(a.request.ClientIdentityID))
	b = append(b, a.clientPublicKeyHash[:]...)
	b = appendLP(b, []byte(a.request.RelayIdentityID))
	b = append(b, a.relayPublicKeyHash[:]...)
	return b
}

func appendLP(dst, value []byte) []byte {
	var size [4]byte
	binary.BigEndian.PutUint32(size[:], uint32(len(value)))
	dst = append(dst, size[:]...)
	return append(dst, value...)
}

func (a MigrationAuthorizationV1) valid() bool {
	if !validText(a.request.SourceProfileID) || !validText(a.request.ClientIdentityID) || !validText(a.request.RelayIdentityID) || a.request.SourceProfileHash == ([32]byte{}) || a.clientPublicKeyHash == ([32]byte{}) || a.relayPublicKeyHash == ([32]byte{}) || a.seal == ([32]byte{}) {
		return false
	}
	want := sha256.Sum256(a.canonical())
	return subtle.ConstantTimeCompare(a.seal[:], want[:]) == 1
}

func (MigrationAuthorizationV1) Format(state fmt.State, verb rune) {
	_, _ = io.WriteString(state, "migration-authorization-redacted")
}
func (MigrationAuthorizationV1) MarshalJSON() ([]byte, error) {
	return nil, ErrMigrationAuthorizationSerialization
}
func (a *MigrationAuthorizationV1) UnmarshalJSON([]byte) error {
	*a = MigrationAuthorizationV1{}
	return ErrMigrationAuthorizationSerialization
}
func (MigrationAuthorizationV1) MarshalText() ([]byte, error) {
	return nil, ErrMigrationAuthorizationSerialization
}
func (a *MigrationAuthorizationV1) UnmarshalText([]byte) error {
	*a = MigrationAuthorizationV1{}
	return ErrMigrationAuthorizationSerialization
}
func (MigrationAuthorizationV1) MarshalBinary() ([]byte, error) {
	return nil, ErrMigrationAuthorizationSerialization
}
func (a *MigrationAuthorizationV1) UnmarshalBinary([]byte) error {
	*a = MigrationAuthorizationV1{}
	return ErrMigrationAuthorizationSerialization
}
func (MigrationAuthorizationV1) GobEncode() ([]byte, error) {
	return nil, ErrMigrationAuthorizationSerialization
}
func (a *MigrationAuthorizationV1) GobDecode([]byte) error {
	*a = MigrationAuthorizationV1{}
	return ErrMigrationAuthorizationSerialization
}

type migrationFailure struct{ cause error }

var revalidateMigratedV1 = ir.Validate

func (migrationFailure) Error() string     { return ErrMigrationFailed.Error() }
func (e migrationFailure) Unwrap() []error { return []error{ErrMigrationFailed, e.cause} }

func MigrateProfileV1(raw []byte, token MigrationAuthorizationV1) (*ir.Profile, MigrationReportV1, error) {
	var report MigrationReportV1
	if !token.valid() {
		return nil, report, ErrMigrationAuthorizationInvalid
	}
	current, err := ir.DecodeProfileV1(raw)
	if err == nil && current != nil {
		return nil, report, ErrMigrationNotRequired
	}
	if !errors.Is(err, ir.ErrMigrationRequired) {
		return nil, report, migrationFailure{cause: normalizedIRCause(err)}
	}
	legacy, err := ir.DecodeLegacyProfileForMigrationV1(raw)
	if err != nil {
		return nil, report, migrationFailure{cause: normalizedIRCause(err)}
	}
	sourceHash, err := decodeHash(legacy.GenerationHash)
	if err != nil || legacy.ID != token.request.SourceProfileID || subtle.ConstantTimeCompare(sourceHash[:], token.request.SourceProfileHash[:]) != 1 {
		return nil, report, ErrMigrationSourceMismatch
	}
	migrated, err := clone(legacy)
	if err != nil {
		return nil, report, migrationFailure{cause: ir.ErrProfileInvalid}
	}
	migrated.Version = ir.SupportedVersion
	migrated.Compatibility.SchemaVersion = ir.SupportedVersion
	migrated.Security.SecurityVersion = ir.SupportedSecurityVersion
	migrated.Compatibility.CompilerSecurityVersion = ir.SupportedSecurityVersion
	migrated.Compatibility.MinimumRuntimeVersion = ir.SupportedSecurityVersion
	migrated.GenerationHash = ""
	migrated.GenerationHash, err = ir.CanonicalHash(migrated)
	if err != nil || revalidateMigratedV1(migrated) != nil {
		return nil, report, migrationFailure{cause: ir.ErrProfileInvalid}
	}
	report = MigrationReportV1{"profile-migration-report-v1", "legacy", "current", 5, true}
	return migrated, report, nil
}

func normalizedIRCause(err error) error {
	for _, candidate := range []error{ir.ErrProfileMalformed, ir.ErrProfileVersionMismatch, ir.ErrProfileVersionUnsupported, ir.ErrProfileInvalid} {
		if errors.Is(err, candidate) {
			return candidate
		}
	}
	return ir.ErrProfileInvalid
}

func decodeHash(value string) ([32]byte, error) {
	var out [32]byte
	b, err := hex.DecodeString(value)
	if err != nil || len(b) != len(out) {
		return out, errors.New("invalid")
	}
	copy(out[:], b)
	return out, nil
}

func clone(profile *ir.Profile) (*ir.Profile, error) {
	raw, err := json.Marshal(profile)
	if err != nil {
		return nil, err
	}
	var out ir.Profile
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
