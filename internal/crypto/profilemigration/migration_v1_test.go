package profilemigration

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding"
	"encoding/binary"
	"encoding/gob"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

type identityV1 struct {
	id       string
	key      ed25519.PrivateKey
	returned *ed25519.PrivateKey
}

func (p identityV1) Local(id string) (ed25519.PrivateKey, error) {
	if id != p.id {
		return nil, errors.New("id")
	}
	out := append(ed25519.PrivateKey(nil), p.key...)
	if p.returned != nil {
		*p.returned = out
	}
	return out, nil
}

type trustV1 struct {
	id  string
	key ed25519.PublicKey
}

type failingIdentityV1 struct{}

func (failingIdentityV1) Local(string) (ed25519.PrivateKey, error) {
	return nil, errors.New("identity")
}

type failingTrustV1 struct{}

func (failingTrustV1) Peer(string) (ed25519.PublicKey, error) { return nil, errors.New("trust") }

type gobWireV1 []byte

func (g gobWireV1) GobEncode() ([]byte, error) { return []byte(g), nil }

func (p trustV1) Peer(id string) (ed25519.PublicKey, error) {
	if id != p.id {
		return nil, errors.New("id")
	}
	return append(ed25519.PublicKey(nil), p.key...), nil
}

func migrationFixture(t *testing.T) ([]byte, AuthorizationRequestV1, auth.Dependencies, auth.Dependencies, *ir.Profile) {
	t.Helper()
	p, err := compiler.Generate(38002)
	if err != nil {
		t.Fatal(err)
	}
	p.Version = ir.LegacySchemaVersionV1
	p.Compatibility.SchemaVersion = ir.LegacySchemaVersionV1
	p.Security.SecurityVersion = ir.LegacySecurityVersionV1
	p.Compatibility.CompilerSecurityVersion = ir.LegacySecurityVersionV1
	p.Compatibility.MinimumRuntimeVersion = ir.LegacySecurityVersionV1
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	hashBytes, err := hex.DecodeString(p.GenerationHash)
	if err != nil {
		t.Fatal(err)
	}
	var hash [32]byte
	copy(hash[:], hashBytes)
	client := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32))
	relay := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{2}, 32))
	req := AuthorizationRequestV1{p.ID, hash, "client", "relay"}
	cd := auth.Dependencies{Identity: identityV1{"client", client, nil}, Trust: trustV1{"relay", relay.Public().(ed25519.PublicKey)}}
	rd := auth.Dependencies{Identity: identityV1{"relay", relay, nil}, Trust: trustV1{"client", client.Public().(ed25519.PublicKey)}}
	return raw, req, cd, rd, p
}

func TestMigrationAuthorizationAPIV1(t *testing.T) {
	var _ func(AuthorizationRequestV1, auth.Dependencies, auth.Dependencies) (MigrationAuthorizationV1, error) = NewMigrationAuthorizationV1
	var _ func([]byte, MigrationAuthorizationV1) (*ir.Profile, MigrationReportV1, error) = MigrateProfileV1
	var _ encoding.TextMarshaler = MigrationAuthorizationV1{}
	var _ encoding.BinaryMarshaler = MigrationAuthorizationV1{}
	raw, req, cd, rd, _ := migrationFixture(t)
	_ = raw
	var returned ed25519.PrivateKey
	ci := cd.Identity.(identityV1)
	ci.returned = &returned
	cd.Identity = ci
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	if !token.valid() {
		t.Fatal("valid token rejected")
	}
	for _, b := range returned {
		if b != 0 {
			t.Fatal("private copy not wiped")
		}
	}
	copyToken := token
	if !copyToken.valid() {
		t.Fatal("value copy invalid")
	}
	want := sha256.Sum256(token.canonical())
	if token.seal != want {
		t.Fatal("canonical seal mismatch")
	}
	for _, format := range []string{"%v", "%+v", "%#v", "% v", "%-v", "%0v", "%20v", "%-20v", "%.5v", "%20.5v", "%s", "%q", "%x"} {
		if got := fmt.Sprintf(format, token); got != "migration-authorization-redacted" {
			t.Fatalf("format %s=%q", format, got)
		}
	}
	bad := token
	bad.request.SourceProfileID += "x"
	if bad.valid() {
		t.Fatal("mutation accepted")
	}
	if _, err := NewMigrationAuthorizationV1(AuthorizationRequestV1{}, cd, rd); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	wrong := rd
	wrong.Trust = trustV1{"client", bytes.Repeat([]byte{9}, 32)}
	if _, err := NewMigrationAuthorizationV1(req, cd, wrong); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
}

func TestMigrationAuthorizationV1ConstructorMatrix(t *testing.T) {
	_, req, cd, rd, _ := migrationFixture(t)
	badRequests := []AuthorizationRequestV1{
		{}, {SourceProfileID: req.SourceProfileID, SourceProfileHash: req.SourceProfileHash, ClientIdentityID: req.ClientIdentityID},
		{SourceProfileID: "\x00", SourceProfileHash: req.SourceProfileHash, ClientIdentityID: req.ClientIdentityID, RelayIdentityID: req.RelayIdentityID},
		{SourceProfileID: req.SourceProfileID, ClientIdentityID: req.ClientIdentityID, RelayIdentityID: req.RelayIdentityID},
		{SourceProfileID: req.SourceProfileID, SourceProfileHash: req.SourceProfileHash, ClientIdentityID: "", RelayIdentityID: req.RelayIdentityID},
		{SourceProfileID: req.SourceProfileID, SourceProfileHash: req.SourceProfileHash, ClientIdentityID: req.ClientIdentityID, RelayIdentityID: ""},
	}
	for i, bad := range badRequests {
		if _, err := NewMigrationAuthorizationV1(bad, cd, rd); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
			t.Fatalf("bad request %d: %v", i, err)
		}
	}
	depsCases := [][2]auth.Dependencies{{{}, rd}, {cd, {}}, {{Identity: failingIdentityV1{}, Trust: cd.Trust}, rd}, {cd, {Identity: failingIdentityV1{}, Trust: rd.Trust}}, {{Identity: cd.Identity, Trust: failingTrustV1{}}, rd}, {cd, {Identity: rd.Identity, Trust: failingTrustV1{}}}}
	for i, pair := range depsCases {
		if _, err := NewMigrationAuthorizationV1(req, pair[0], pair[1]); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
			t.Fatalf("deps %d: %v", i, err)
		}
	}
	shortCD := cd
	shortIdentity := shortCD.Identity.(identityV1)
	shortIdentity.key = ed25519.PrivateKey{1}
	shortCD.Identity = shortIdentity
	if _, err := NewMigrationAuthorizationV1(req, shortCD, rd); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	shortRD := rd
	shortRelay := shortRD.Identity.(identityV1)
	shortRelay.key = ed25519.PrivateKey{1}
	shortRD.Identity = shortRelay
	if _, err := NewMigrationAuthorizationV1(req, cd, shortRD); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	client := cd.Identity.(identityV1)
	client.id = "wrong"
	badCD := cd
	badCD.Identity = client
	if _, err := NewMigrationAuthorizationV1(req, badCD, rd); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	relay := rd.Identity.(identityV1)
	relay.id = "wrong"
	badRD := rd
	badRD.Identity = relay
	if _, err := NewMigrationAuthorizationV1(req, cd, badRD); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	ct := cd.Trust.(trustV1)
	ct.id = "wrong"
	badCD = cd
	badCD.Trust = ct
	if _, err := NewMigrationAuthorizationV1(req, badCD, rd); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	rt := rd.Trust.(trustV1)
	rt.id = "wrong"
	badRD = rd
	badRD.Trust = rt
	if _, err := NewMigrationAuthorizationV1(req, cd, badRD); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	badClientTrust := cd
	clientTrust := badClientTrust.Trust.(trustV1)
	clientTrust.key = bytes.Repeat([]byte{7}, ed25519.PublicKeySize)
	badClientTrust.Trust = clientTrust
	if _, err := NewMigrationAuthorizationV1(req, badClientTrust, rd); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	badRelayTrust := rd
	relayTrust := badRelayTrust.Trust.(trustV1)
	relayTrust.key = bytes.Repeat([]byte{8}, ed25519.PublicKeySize)
	badRelayTrust.Trust = relayTrust
	if _, err := NewMigrationAuthorizationV1(req, cd, badRelayTrust); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	var clientCopy, relayCopy ed25519.PrivateKey
	ci := cd.Identity.(identityV1)
	ci.returned = &clientCopy
	ri := rd.Identity.(identityV1)
	ri.returned = &relayCopy
	badRD = rd
	badRD.Identity = ri
	badRD.Trust = failingTrustV1{}
	badCD = cd
	badCD.Identity = ci
	_, _ = NewMigrationAuthorizationV1(req, badCD, badRD)
	for _, copy := range []ed25519.PrivateKey{clientCopy, relayCopy} {
		for _, b := range copy {
			if b != 0 {
				t.Fatal("failure path retained private copy")
			}
		}
	}
	var earlyClientCopy ed25519.PrivateKey
	early := cd.Identity.(identityV1)
	early.returned = &earlyClientCopy
	earlyCD := cd
	earlyCD.Identity = early
	earlyRD := rd
	earlyRD.Identity = failingIdentityV1{}
	_, _ = NewMigrationAuthorizationV1(req, earlyCD, earlyRD)
	for _, b := range earlyClientCopy {
		if b != 0 {
			t.Fatal("relay identity failure retained client private copy")
		}
	}
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	partials := []MigrationAuthorizationV1{{request: req}, {request: req, clientPublicKeyHash: token.clientPublicKeyHash, relayPublicKeyHash: token.relayPublicKeyHash}}
	for _, partial := range partials {
		if partial.valid() {
			t.Fatal("reconstructed partial token accepted")
		}
	}
	for i := 0; i < 4; i++ {
		mut := token
		switch i {
		case 0:
			mut.request.SourceProfileHash[0] ^= 1
		case 1:
			mut.clientPublicKeyHash[0] ^= 1
		case 2:
			mut.relayPublicKeyHash[0] ^= 1
		case 3:
			mut.seal[0] ^= 1
		}
		if mut.valid() {
			t.Fatalf("mutation %d accepted", i)
		}
	}
}

func independentCanonicalV1(a MigrationAuthorizationV1) []byte {
	var out []byte
	lp := func(v []byte) {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(v)))
		out = append(out, n[:]...)
		out = append(out, v...)
	}
	for _, v := range []string{"kurdistan/profile-migration/authorization/v1", "0.1.0-lab", "0.12.0-lab", "0.2.0-lab", "0.13.0-lab", "kurdistan-handshake-v1", "policy-v1", "record-v1", a.request.SourceProfileID} {
		lp([]byte(v))
	}
	out = append(out, a.request.SourceProfileHash[:]...)
	lp([]byte(a.request.ClientIdentityID))
	out = append(out, a.clientPublicKeyHash[:]...)
	lp([]byte(a.request.RelayIdentityID))
	out = append(out, a.relayPublicKeyHash[:]...)
	return out
}

func TestMigrationAuthorizationV1IndependentCanonicalVector(t *testing.T) {
	_, req, cd, rd, _ := migrationFixture(t)
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	vector := independentCanonicalV1(token)
	want := sha256.Sum256(vector)
	if token.seal != want {
		t.Fatalf("seal=%x want=%x", token.seal, want)
	}
	if bytes.Contains([]byte(fmt.Sprintf("%v", token)), vector) {
		t.Fatal("canonical bytes exposed")
	}
}

func TestMigrationAuthorizationV1Serialization(t *testing.T) {
	_, req, cd, rd, _ := migrationFixture(t)
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	encoders := []func() ([]byte, error){token.MarshalJSON, token.MarshalText, token.MarshalBinary, token.GobEncode}
	for _, encode := range encoders {
		b, err := encode()
		if b != nil || !errors.Is(err, ErrMigrationAuthorizationSerialization) || err.Error() != ErrMigrationAuthorizationSerialization.Error() {
			t.Fatalf("bytes=%v err=%v", b, err)
		}
	}
	decoders := []func(*MigrationAuthorizationV1) error{func(v *MigrationAuthorizationV1) error { return v.UnmarshalJSON([]byte("{}")) }, func(v *MigrationAuthorizationV1) error { return v.UnmarshalText([]byte("x")) }, func(v *MigrationAuthorizationV1) error { return v.UnmarshalBinary([]byte("x")) }, func(v *MigrationAuthorizationV1) error { return v.GobDecode([]byte("x")) }}
	for _, decode := range decoders {
		v := token
		err := decode(&v)
		if v != (MigrationAuthorizationV1{}) || !errors.Is(err, ErrMigrationAuthorizationSerialization) {
			t.Fatalf("value=%v err=%v", v, err)
		}
	}
	var buf bytes.Buffer
	if err := gob.NewEncoder(&buf).Encode(token); !errors.Is(err, ErrMigrationAuthorizationSerialization) {
		t.Fatalf("gob bytes=%d err=%v", buf.Len(), err)
	}
	// A real gob decoder reaches GobDecode when fed a custom-binary wire value.
	var wire bytes.Buffer
	if err := gob.NewEncoder(&wire).Encode(gobWireV1("x")); err != nil {
		t.Fatal(err)
	}
	v := token
	err = gob.NewDecoder(&wire).Decode(&v)
	if err == nil || v != (MigrationAuthorizationV1{}) {
		t.Fatalf("gob decoder err=%v value=%v", err, v)
	}
	for _, encode := range []func() ([]byte, error){func() ([]byte, error) { return json.Marshal(token) }, func() ([]byte, error) { return token.MarshalText() }, func() ([]byte, error) { return token.MarshalBinary() }} {
		b, err := encode()
		if b != nil || !errors.Is(err, ErrMigrationAuthorizationSerialization) {
			t.Fatalf("public encode bytes=%v err=%v", b, err)
		}
	}
	for _, decode := range []func(*MigrationAuthorizationV1) error{func(v *MigrationAuthorizationV1) error { return json.Unmarshal([]byte(`{}`), v) }, func(v *MigrationAuthorizationV1) error { return v.UnmarshalText([]byte("x")) }, func(v *MigrationAuthorizationV1) error { return v.UnmarshalBinary([]byte("x")) }} {
		v := token
		err := decode(&v)
		if v != (MigrationAuthorizationV1{}) || !errors.Is(err, ErrMigrationAuthorizationSerialization) {
			t.Fatalf("public decode value=%v err=%v", v, err)
		}
	}
}

func TestMigrateProfileV1AndMigrationReportV1(t *testing.T) {
	raw, req, cd, rd, legacy := migrationFixture(t)
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	migrated, report, err := MigrateProfileV1(raw, token)
	if err != nil {
		t.Fatal(err)
	}
	wantReport := MigrationReportV1{"profile-migration-report-v1", "legacy", "current", 5, true}
	if report != wantReport {
		t.Fatalf("report=%+v", report)
	}
	if err := ir.Validate(migrated); err != nil {
		t.Fatal(err)
	}
	if migrated.GenerationHash == legacy.GenerationHash {
		t.Fatal("hash not recomputed")
	}
	before := *legacy
	before.Version = migrated.Version
	before.Compatibility.SchemaVersion = migrated.Compatibility.SchemaVersion
	before.Compatibility.CompilerSecurityVersion = migrated.Compatibility.CompilerSecurityVersion
	before.Compatibility.MinimumRuntimeVersion = migrated.Compatibility.MinimumRuntimeVersion
	before.Security.SecurityVersion = migrated.Security.SecurityVersion
	before.GenerationHash = migrated.GenerationHash
	if !reflect.DeepEqual(&before, migrated) {
		t.Fatal("fields beyond frozen migration changed")
	}
	migrated.ID = "owned"
	if legacy.ID == migrated.ID {
		t.Fatal("migration aliased source")
	}
	if len(migrated.States) > 0 {
		old := legacy.States[0].ID
		migrated.States[0].ID = "nested-owned"
		if legacy.States[0].ID != old {
			t.Fatal("states slice aliased")
		}
	}
	if len(migrated.Messages) > 0 {
		old := legacy.Messages[0].Semantic
		migrated.Messages[0].Semantic = "nested-owned"
		if legacy.Messages[0].Semantic != old {
			t.Fatal("messages slice aliased")
		}
	}
	if !bytes.Equal(raw, mustJSON(t, legacy)) {
		t.Fatal("raw input mutated")
	}
}

func TestMigrationErrorIdentityV1(t *testing.T) {
	raw, req, cd, rd, _ := migrationFixture(t)
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := MigrateProfileV1(raw, MigrationAuthorizationV1{}); !errors.Is(err, ErrMigrationAuthorizationInvalid) {
		t.Fatal(err)
	}
	current, err := compiler.Generate(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := MigrateProfileV1(mustJSON(t, current), token); !errors.Is(err, ErrMigrationNotRequired) {
		t.Fatal(err)
	}
	cases := []struct {
		raw   []byte
		cause error
	}{{[]byte("{"), ir.ErrProfileMalformed}}
	legacyMixed := append([]byte(nil), raw...)
	legacyMixed = bytes.Replace(legacyMixed, []byte(`"version":"`+ir.LegacySchemaVersionV1+`"`), []byte(`"version":"`+ir.SupportedVersion+`"`), 1)
	cases = append(cases, struct {
		raw   []byte
		cause error
	}{legacyMixed, ir.ErrProfileVersionMismatch})
	for _, tc := range cases {
		_, _, err := MigrateProfileV1(tc.raw, token)
		if !errors.Is(err, ErrMigrationFailed) || !errors.Is(err, tc.cause) || err.Error() != ErrMigrationFailed.Error() {
			t.Fatalf("err=%v cause=%v", err, tc.cause)
		}
	}
	badReq := req
	badReq.SourceProfileID += "x"
	badToken, err := NewMigrationAuthorizationV1(badReq, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := MigrateProfileV1(raw, badToken); !errors.Is(err, ErrMigrationSourceMismatch) || errors.Is(err, ErrMigrationFailed) {
		t.Fatal(err)
	}
}

func TestMigrateProfileV1CompletePrecedenceAndAtomicity(t *testing.T) {
	raw, req, cd, rd, legacy := migrationFixture(t)
	token, err := NewMigrationAuthorizationV1(req, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	assertFailure := func(name string, input []byte, want error) {
		t.Helper()
		got, report, err := MigrateProfileV1(input, token)
		if got != nil || report != (MigrationReportV1{}) || !errors.Is(err, ErrMigrationFailed) || !errors.Is(err, want) || err.Error() != ErrMigrationFailed.Error() {
			t.Fatalf("%s got=%v report=%+v err=%v", name, got, report, err)
		}
	}
	assertFailure("malformed", []byte(`{`), ir.ErrProfileMalformed)
	future := *legacy
	future.Version = "99.0.0"
	future.Compatibility.SchemaVersion = "99.0.0"
	future.Security.SecurityVersion = "99.0.0"
	future.Compatibility.CompilerSecurityVersion = "99.0.0"
	future.Compatibility.MinimumRuntimeVersion = "99.0.0"
	assertFailure("future", mustJSON(t, &future), ir.ErrProfileVersionUnsupported)
	mixed := *legacy
	mixed.Version = ir.SupportedVersion
	assertFailure("mixed", mustJSON(t, &mixed), ir.ErrProfileVersionMismatch)
	current, err := compiler.Generate(9)
	if err != nil {
		t.Fatal(err)
	}
	current.ID = ""
	current.GenerationHash = ""
	assertFailure("current-invalid", mustJSON(t, current), ir.ErrProfileInvalid)
	legacyInvalid := *legacy
	legacyInvalid.GenerationHash = "bad"
	assertFailure("legacy-invalid", mustJSON(t, &legacyInvalid), ir.ErrProfileInvalid)
	if _, _, err := MigrateProfileV1([]byte(`{`), MigrationAuthorizationV1{}); !errors.Is(err, ErrMigrationAuthorizationInvalid) || errors.Is(err, ErrMigrationFailed) {
		t.Fatalf("invalid-token precedence: %v", err)
	}
	wrong := req
	wrong.SourceProfileHash[0] ^= 1
	wrongToken, err := NewMigrationAuthorizationV1(wrong, cd, rd)
	if err != nil {
		t.Fatal(err)
	}
	got, report, err := MigrateProfileV1(raw, wrongToken)
	if got != nil || report != (MigrationReportV1{}) || !errors.Is(err, ErrMigrationSourceMismatch) || errors.Is(err, ErrMigrationFailed) {
		t.Fatalf("source mismatch got=%v report=%+v err=%v", got, report, err)
	}
	if !bytes.Equal(raw, mustJSON(t, legacy)) {
		t.Fatal("failure paths mutated source bytes")
	}
	originalRevalidate := revalidateMigratedV1
	revalidateMigratedV1 = func(*ir.Profile) error { return errors.New("forced") }
	defer func() { revalidateMigratedV1 = originalRevalidate }()
	got, report, err = MigrateProfileV1(raw, token)
	if got != nil || report != (MigrationReportV1{}) || !errors.Is(err, ErrMigrationFailed) || !errors.Is(err, ir.ErrProfileInvalid) || err.Error() != ErrMigrationFailed.Error() {
		t.Fatalf("conversion failure got=%v report=%+v err=%v", got, report, err)
	}
}

func TestMigrationReportV1ExactPrivacyShape(t *testing.T) {
	typeOf := reflect.TypeOf(MigrationReportV1{})
	want := []struct{ name, typ string }{{"Version", "string"}, {"SourceClass", "string"}, {"TargetClass", "string"}, {"VersionFieldsChanged", "uint32"}, {"GenerationHashRecomputed", "bool"}}
	if typeOf.NumField() != len(want) {
		t.Fatalf("fields=%d", typeOf.NumField())
	}
	for i, w := range want {
		f := typeOf.Field(i)
		if f.Name != w.name || f.Type.String() != w.typ {
			t.Fatalf("field %d=%s %s", i, f.Name, f.Type)
		}
	}
	for _, forbidden := range []string{"ID", "Hash", "Key", "Path", "Seed", "Cause", "Time", "Credential"} {
		for i := 0; i < typeOf.NumField(); i++ {
			if typeOf.Field(i).Name != "GenerationHashRecomputed" && strings.Contains(typeOf.Field(i).Name, forbidden) {
				t.Fatalf("privacy field %s", typeOf.Field(i).Name)
			}
		}
	}
	report := MigrationReportV1{"profile-migration-report-v1", "legacy", "current", 5, true}
	raw, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var keys map[string]json.RawMessage
	if err := json.Unmarshal(raw, &keys); err != nil {
		t.Fatal(err)
	}
	wantKeys := []string{"Version", "SourceClass", "TargetClass", "VersionFieldsChanged", "GenerationHashRecomputed"}
	if len(keys) != 5 {
		t.Fatalf("json keys=%v", keys)
	}
	for _, key := range wantKeys {
		if _, ok := keys[key]; !ok {
			t.Fatalf("missing report key %s", key)
		}
	}
	lower := strings.ToLower(string(raw))
	for _, secret := range []string{"profileid", "identity", "keyhash", "credential", "cause", "timestamp", "path", "seed"} {
		if strings.Contains(lower, secret) {
			t.Fatalf("sensitive report json %q", secret)
		}
	}
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestMigrationAuthorizationV1LeafBoundary(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	for _, top := range []string{"internal/runtime", "internal/crypto/auth", "internal/crypto/security"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, e os.DirEntry, walkErr error) error {
			if walkErr != nil || e.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			b, err := os.ReadFile(path)
			if err == nil && (strings.Contains(string(b), "internal/crypto/profilemigration") || strings.Contains(string(b), "DecodeLegacyProfileForMigrationV1")) {
				t.Errorf("live path reaches migration: %s", path)
			}
			return err
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	irRaw, err := os.ReadFile(filepath.Join(root, "internal/protocol/ir/migration_v1.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(irRaw), "internal/crypto/auth") || strings.Contains(string(irRaw), "internal/runtime") {
		t.Fatal("IR reaches auth/runtime")
	}
	allowed := map[string]bool{"internal/crypto/profilemigration/migration_v1.go": true, "internal/protocol/ir/migration_v1.go": true}
	err = filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		rel = filepath.ToSlash(rel)
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if !allowed[rel] && (strings.Contains(string(body), "internal/crypto/profilemigration") || strings.Contains(string(body), "DecodeLegacyProfileForMigrationV1")) {
			t.Errorf("unauthorized production migration caller/import: %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
