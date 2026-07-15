package runtime

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

var _ func(string, string) (*ir.Profile, error) = LoadProfile

func runtimeProfileV1(t *testing.T) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(39001)
	if err != nil {
		t.Fatal(err)
	}
	return p
}
func writeRuntimeProfileV1(t *testing.T, raw []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "profile.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
func marshalRuntimeProfileV1(t *testing.T, p *ir.Profile) []byte {
	t.Helper()
	raw, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func assertProfileLoadV1(t *testing.T, err error, cause error) {
	t.Helper()
	if !errors.Is(err, ErrProfileLoad) || !errors.Is(err, cause) || err.Error() != ErrProfileLoad.Error() {
		t.Fatalf("err=%v cause=%v", err, cause)
	}
	for _, other := range []error{ir.ErrProfileMalformed, ir.ErrMigrationRequired, ir.ErrProfileVersionMismatch, ir.ErrProfileVersionUnsupported, ir.ErrProfileInvalid, ir.ErrProfileMismatch} {
		if other != cause && errors.Is(err, other) {
			t.Fatalf("err %v also matches unrelated %v", err, other)
		}
	}
}

func TestProfileLoaderV1StrictMatrix(t *testing.T) {
	p := runtimeProfileV1(t)
	raw := marshalRuntimeProfileV1(t, p)
	got, err := LoadProfile(writeRuntimeProfileV1(t, raw), p.ID)
	if err != nil || got == p {
		t.Fatalf("got=%v err=%v", got, err)
	}
	legacy := *p
	legacy.Version = ir.LegacySchemaVersionV1
	legacy.Compatibility.SchemaVersion = ir.LegacySchemaVersionV1
	legacy.Security.SecurityVersion = ir.LegacySecurityVersionV1
	legacy.Compatibility.CompilerSecurityVersion = ir.LegacySecurityVersionV1
	legacy.Compatibility.MinimumRuntimeVersion = ir.LegacySecurityVersionV1
	legacy.GenerationHash = ""
	legacy.GenerationHash, _ = ir.CanonicalHash(&legacy)
	mixed := legacy
	mixed.Version = ir.SupportedVersion
	future := *p
	future.Version = "99"
	invalid := *p
	invalid.ID = ""
	invalid.GenerationHash = ""
	badHash := *p
	badHash.GenerationHash = strings.Repeat("0", 64)
	cases := []struct {
		name  string
		raw   []byte
		cause error
	}{{"malformed", []byte(`{`), ir.ErrProfileMalformed}, {"legacy", marshalRuntimeProfileV1(t, &legacy), ir.ErrMigrationRequired}, {"mixed", marshalRuntimeProfileV1(t, &mixed), ir.ErrProfileVersionMismatch}, {"future", marshalRuntimeProfileV1(t, &future), ir.ErrProfileVersionUnsupported}, {"current-invalid", marshalRuntimeProfileV1(t, &invalid), ir.ErrProfileInvalid}, {"current-bad-hash", marshalRuntimeProfileV1(t, &badHash), ir.ErrProfileInvalid}}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := LoadProfile(writeRuntimeProfileV1(t, tc.raw), "")
			if got != nil {
				t.Fatal("non-nil profile")
			}
			assertProfileLoadV1(t, err, tc.cause)
		})
	}
	got, err = LoadProfile(writeRuntimeProfileV1(t, raw), "wrong-id")
	if got != nil {
		t.Fatal("non-nil")
	}
	assertProfileLoadV1(t, err, ir.ErrProfileMismatch)
}

func TestProfileLoaderV1BoundAndErrorIdentity(t *testing.T) {
	for _, path := range []string{"", filepath.Join(t.TempDir(), "missing-secret-name"), t.TempDir()} {
		_, err := LoadProfile(path, "")
		if !errors.Is(err, ErrProfileLoad) || err.Error() != ErrProfileLoad.Error() {
			t.Fatalf("err=%v", err)
		}
		for _, cause := range []error{ir.ErrProfileMalformed, ir.ErrMigrationRequired, ir.ErrProfileVersionMismatch, ir.ErrProfileVersionUnsupported, ir.ErrProfileInvalid, ir.ErrProfileMismatch} {
			if errors.Is(err, cause) {
				t.Fatalf("unexpected cause %v", cause)
			}
		}
	}
	p := runtimeProfileV1(t)
	raw := marshalRuntimeProfileV1(t, p)
	exact := append(raw, []byte(strings.Repeat(" ", (1<<20)-len(raw)))...)
	if _, err := LoadProfile(writeRuntimeProfileV1(t, exact), p.ID); err != nil {
		t.Fatal(err)
	}
	over := append(exact, ' ')
	_, err := LoadProfile(writeRuntimeProfileV1(t, over), "")
	assertProfileLoadV1(t, err, ir.ErrProfileMalformed)
}

func TestProfileLoadErrorIdentityCombinedFaultPrecedence(t *testing.T) {
	p := runtimeProfileV1(t)
	cfg := DefaultConfig(RoleClient, "runtime-secret-id", []byte("secret-operand"))
	cfg.ProfileID = "wrong-config-id"
	cfg.ProfileHash = strings.Repeat("1", 64)
	for _, raw := range [][]byte{[]byte(`{"secret-version":"rejected-operand"`), make([]byte, (1<<20)+1)} {
		cfg.ProfilePath = writeRuntimeProfileV1(t, raw)
		rt, err := NewRuntimeFromPath(cfg)
		if rt != nil {
			t.Fatal("non-nil runtime")
		}
		assertProfileLoadV1(t, err, ir.ErrProfileMalformed)
		for _, operand := range []string{cfg.ProfilePath, cfg.ProfileID, cfg.ProfileHash, "secret-version", "rejected-operand", "secret-operand"} {
			if strings.Contains(err.Error(), operand) {
				t.Fatalf("error leaked operand %q: %v", operand, err)
			}
		}
	}
	legacy := *p
	legacy.Version = ir.LegacySchemaVersionV1
	legacy.Compatibility.SchemaVersion = ir.LegacySchemaVersionV1
	legacy.Security.SecurityVersion = ir.LegacySecurityVersionV1
	legacy.Compatibility.CompilerSecurityVersion = ir.LegacySecurityVersionV1
	legacy.Compatibility.MinimumRuntimeVersion = ir.LegacySecurityVersionV1
	legacy.GenerationHash = ""
	legacy.GenerationHash, _ = ir.CanonicalHash(&legacy)
	cfg.ProfilePath = writeRuntimeProfileV1(t, marshalRuntimeProfileV1(t, &legacy))
	rt, err := NewRuntimeFromPath(cfg)
	if rt != nil {
		t.Fatal("non-nil")
	}
	assertProfileLoadV1(t, err, ir.ErrMigrationRequired)
	current := runtimeProfileV1(t)
	cfg.ProfilePath = writeRuntimeProfileV1(t, marshalRuntimeProfileV1(t, current))
	original := checkRuntimeProfileCompatibilityV1
	checkRuntimeProfileCompatibilityV1 = func(*ir.Profile, security.RuntimeCompatibility) error {
		return errors.New("nested-compatibility-operand")
	}
	defer func() { checkRuntimeProfileCompatibilityV1 = original }()
	cfg.ProfileID = "wrong-id"
	cfg.ProfileHash = current.GenerationHash
	rt, err = NewRuntimeFromPath(cfg)
	if rt != nil {
		t.Fatal("non-nil")
	}
	assertProfileLoadV1(t, err, ir.ErrProfileMismatch)
	if strings.Contains(err.Error(), "wrong-id") || strings.Contains(err.Error(), "nested-compatibility-operand") {
		t.Fatal("operand leak")
	}
	cfg.ProfileID = current.ID
	cfg.ProfileHash = strings.Repeat("1", 64)
	rt, err = NewRuntimeFromPath(cfg)
	if rt != nil {
		t.Fatal("non-nil")
	}
	assertProfileLoadV1(t, err, ir.ErrProfileMismatch)
}

func TestRuntimeProfileBindingAndProfileVersion(t *testing.T) {
	p := runtimeProfileV1(t)
	cfg := DefaultConfig(RoleClient, "runtime", []byte("secret"))
	cfg.ProfileID = p.ID
	cfg.ProfileHash = p.GenerationHash
	if _, err := NewRuntime(cfg, p); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*ir.Profile){func(v *ir.Profile) { v.Version = "x" }, func(v *ir.Profile) { v.Compatibility.SchemaVersion = "x" }, func(v *ir.Profile) { v.Security.SecurityVersion = "x" }, func(v *ir.Profile) { v.Compatibility.CompilerSecurityVersion = "x" }, func(v *ir.Profile) { v.Compatibility.MinimumRuntimeVersion = "x" }} {
		copy := *p
		mutate(&copy)
		rt, err := NewRuntime(cfg, &copy)
		if rt != nil {
			t.Fatal("non-nil runtime")
		}
		assertProfileLoadV1(t, err, ir.ErrProfileInvalid)
	}
	for _, mutate := range []func(*RuntimeConfig){func(v *RuntimeConfig) { v.ProfileID = "wrong" }, func(v *RuntimeConfig) { v.ProfileHash = strings.Repeat("1", 64) }} {
		bad := cfg
		mutate(&bad)
		rt, err := NewRuntime(bad, p)
		if rt != nil {
			t.Fatal("non-nil runtime")
		}
		assertProfileLoadV1(t, err, ir.ErrProfileMismatch)
	}
	cfg.ProfilePath = writeRuntimeProfileV1(t, marshalRuntimeProfileV1(t, p))
	if _, err := NewRuntimeFromPath(cfg); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeProfileBindingConfigHash(t *testing.T) {
	typ, ok := reflect.TypeOf(RuntimeConfig{}).FieldByName("ProfileHash")
	if !ok || typ.Type.Kind() != reflect.String || typ.Tag.Get("json") != "profile_hash,omitempty" {
		t.Fatalf("field=%v", typ)
	}
	base := DefaultConfig(RoleClient, "runtime", []byte("secret"))
	if err := ValidateConfig(base); err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{"x", strings.Repeat("A", 64), strings.Repeat("g", 64), strings.Repeat("0", 64)} {
		bad := base
		bad.ProfileHash = value
		if err := ValidateConfig(bad); !errors.Is(err, ErrInvalidConfig) || err.Error() != ErrInvalidConfig.Error() {
			t.Fatalf("hash=%q err=%v", value, err)
		}
	}
	p := runtimeProfileV1(t)
	features := security.DefaultCapabilities().Features
	policy, err := ir.BuildEffectiveSecurityPolicy(p, features, features, features)
	if err != nil {
		t.Fatal(err)
	}
	bound, err := BindEffectivePolicy(base, policy)
	if err != nil {
		t.Fatal(err)
	}
	if bound.Config().ProfileHash != policy.ProfileHash {
		t.Fatal("hash not bound")
	}
	copyCfg := bound.Config()
	copyCfg.ProfileHash = strings.Repeat("2", 64)
	if bound.Config().ProfileHash != policy.ProfileHash {
		t.Fatal("bound config alias/mutation")
	}
	exact := base
	exact.ProfileHash = policy.ProfileHash
	if _, err := BindEffectivePolicy(exact, policy); err != nil {
		t.Fatal(err)
	}
	wrong := exact
	wrong.ProfileHash = strings.Repeat("1", 64)
	if _, err := BindEffectivePolicy(wrong, policy); !errors.Is(err, ErrInvalidConfig) || err.Error() != ErrInvalidConfig.Error() || strings.Contains(err.Error(), wrong.ProfileHash) || strings.Contains(err.Error(), policy.ProfileHash) {
		t.Fatal(err)
	}
	redacted := RedactConfig(exact)
	if _, ok := redacted["profile_hash"]; ok || redacted["profile_hash_set"] != true || strings.Contains(fmt.Sprint(redacted), exact.ProfileHash) {
		t.Fatalf("redaction=%v", redacted)
	}
}

func TestRuntimeProfileBindingCompatibilityStage(t *testing.T) {
	p := runtimeProfileV1(t)
	original := checkRuntimeProfileCompatibilityV1
	checkRuntimeProfileCompatibilityV1 = func(*ir.Profile, security.RuntimeCompatibility) error { return errors.New("forced compatibility") }
	defer func() { checkRuntimeProfileCompatibilityV1 = original }()
	cfg := DefaultConfig(RoleClient, "runtime", []byte("secret"))
	cfg.ProfileID = p.ID
	cfg.ProfileHash = p.GenerationHash
	rt, err := NewRuntime(cfg, p)
	if rt != nil || !errors.Is(err, ErrCompatibility) || err.Error() != ErrCompatibility.Error() {
		t.Fatalf("rt=%v err=%v", rt, err)
	}
	for _, cause := range []error{ir.ErrProfileMalformed, ir.ErrMigrationRequired, ir.ErrProfileVersionMismatch, ir.ErrProfileVersionUnsupported, ir.ErrProfileInvalid, ir.ErrProfileMismatch} {
		if errors.Is(err, cause) {
			t.Fatalf("compatibility matched %v", cause)
		}
	}
}

func TestProfileLoadErrorIdentityRecurrenceGuard(t *testing.T) {
	for _, file := range []string{"profile_loader.go", "config.go", "manager.go"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if strings.Contains(text, "internal/crypto/profilemigration") || strings.Contains(text, "DecodeLegacyProfileForMigrationV1") || strings.Contains(text, "LegacySchemaVersionV1") {
			t.Fatalf("live migration edge in %s", file)
		}
	}
	raw, err := os.ReadFile("profile_loader.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"os.Open(", "io.LimitReader(", "ir.DecodeProfileV1("} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing strict loader primitive %s", required)
		}
	}
	for _, forbidden := range []string{"os.ReadFile(", "json.Unmarshal("} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("permissive loader primitive %s", forbidden)
		}
	}
}

func forbiddenLiveMigrationEdgeV1(source string) bool {
	return strings.Contains(source, "internal/crypto/profilemigration") || strings.Contains(source, "DecodeLegacyProfileForMigrationV1") || strings.Contains(source, "MigrateProfileV1(")
}

func TestProfileLoadErrorIdentityOwnerAndDeferredEntryInventory(t *testing.T) {
	for _, synthetic := range []string{`import "kurdistan/internal/crypto/profilemigration"`, `DecodeLegacyProfileForMigrationV1(raw)`, `MigrateProfileV1(raw, token)`} {
		if !forbiddenLiveMigrationEdgeV1(synthetic) {
			t.Fatalf("synthetic forbidden edge escaped: %s", synthetic)
		}
	}
	for _, file := range []string{"profile_loader.go", "config.go", "manager.go", "errors.go"} {
		raw, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if forbiddenLiveMigrationEdgeV1(string(raw)) {
			t.Fatalf("forbidden live edge: %s", file)
		}
	}
	errorsRaw, err := os.ReadFile("errors.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(errorsRaw), "type profileLoadFailureV1 struct") || !strings.Contains(string(errorsRaw), "func (profileLoadFailureV1) Error()") || !strings.Contains(string(errorsRaw), "func (e profileLoadFailureV1) Unwrap()") || !strings.Contains(string(errorsRaw), "func newProfileLoadFailureV1(") {
		t.Fatal("errors.go does not own profile-load wrapper construction")
	}
	loaderRaw, err := os.ReadFile("profile_loader.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, definition := range []string{"type profileLoadFailureV1 struct", "func (profileLoadFailureV1) Error()", "func (e profileLoadFailureV1) Unwrap()", "func newProfileLoadFailureV1("} {
		if strings.Contains(string(loaderRaw), definition) {
			t.Fatalf("profile_loader.go owns wrapper definition %q", definition)
		}
	}
	deferred := map[string]string{"../../cmd/kclient/main.go": "legacy non-evidentiary deferred", "../../cmd/kserver/main.go": "legacy non-evidentiary deferred", "../../cmd/kdc/main.go": "legacy non-evidentiary deferred"}
	for file, label := range deferred {
		raw, err := os.ReadFile(filepath.Clean(file))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(raw), "ir.LoadProfile(") {
			t.Fatalf("%s inventory drift: %s", label, file)
		}
		if strings.Contains(string(raw), "ir.DecodeProfileV1(") {
			t.Fatalf("%s incorrectly migrated: %s", label, file)
		}
	}
	kgenRaw, err := os.ReadFile(filepath.Clean("../../cmd/kgen/main.go"))
	if err != nil {
		t.Fatal(err)
	}
	kgenSource := string(kgenRaw)
	if strings.Contains(kgenSource, "ir.LoadProfile(") || !strings.Contains(kgenSource, "ir.DecodeProfileV1(") || !strings.Contains(kgenSource, "codegen.ParseAuthorizationCatalogV1(") || !strings.Contains(kgenSource, "codegen.GenerateStrict(") {
		t.Fatal("WO-041 kgen strict profile/catalog inventory drift")
	}
}
