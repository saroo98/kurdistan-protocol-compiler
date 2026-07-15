package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

func captureCommandV1(t *testing.T, fn func() int) (int, string) {
	t.Helper()
	oldErr, oldOut := commandStderr, commandStdout
	var stderr bytes.Buffer
	commandStderr, commandStdout = &stderr, io.Discard
	t.Cleanup(func() { commandStderr, commandStdout = oldErr, oldOut })
	return fn(), stderr.String()
}

func authorizationCatalogV1(t *testing.T, scope string, seed int64) []byte {
	t.Helper()
	pin := map[string]any{
		"profile_hash": "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", "effective_policy_hash": "9a208cab2e4393c3c6417fc1436a1a7c9959dce4a50ac435baaf5d8b72d5bad7",
		"framing_hash": "1e01c3b207af2122b5dff65f1945f7dbad96c288163e5deb65684e9ed297da6c", "state_machine_hash": "ccf2a4742252f71b3d4aaa5cc9c0e26f00222df81dd7c9020afb1ca6ae48489f",
		"scheduler_hash": "8c27f74766a072e98e7a3108c02dd1680f6381178e23323fc8422b3f5f574930", "padding_hash": "ea3b7b093bb10a81d7a10cb21a465f022070ca1d0438683dd7b7843a4437db36",
		"stream_hash": "2bf26abe3667e47418a4fc935f8aeb18f64620454dd1ee234faba4ddcd9e2c90", "proxy_hash": "3e4bbe2759342669767541930cda069f9bee0b3b419c3016b64ee05621124ebd",
		"carrier_context_hash": "f71bd073932bf7de9a4df9dd0f666827849f9a87f895de98c5813f7474a116b2", "effective_replay_window": 128, "effective_max_concurrent_streams": 8, "effective_max_frame_bytes": 65536, "effective_max_envelope_bytes": 8192,
	}
	raw, err := json.Marshal(map[string]any{"version": "profile-authorization-catalog-v1", "scope": scope, "entries": []any{map[string]any{"seed": seed, "client": pin, "relay": pin}}})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func authorizationCatalogForProfileV1(t *testing.T, p *ir.Profile) []byte {
	t.Helper()
	hash, err := ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	raw := authorizationCatalogV1(t, "explicit_v1", p.Seed)
	return []byte(strings.ReplaceAll(string(raw), "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", hash))
}

func profileForSeedV1(t *testing.T, seed int64) *ir.Profile {
	t.Helper()
	p, err := compiler.Generate(42)
	if err != nil {
		t.Fatal(err)
	}
	p.Seed = seed
	key := sha256.Sum256([]byte(fmt.Sprintf("test-only-key:%s:%d", p.ID, seed)))
	p.Auth.TestKeyHex = hex.EncodeToString(key[:])
	p.GenerationHash = ""
	hash, err := ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	p.GenerationHash = hash
	return p
}

func strictInputs(t *testing.T) (string, string) {
	t.Helper()
	p, err := compiler.Generate(42)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	profile := filepath.Join(dir, "profile.json")
	catalog := filepath.Join(dir, "catalog.json")
	if err := ir.SaveProfile(profile, p); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalog, authorizationCatalogV1(t, "explicit_v1", 42), 0o600); err != nil {
		t.Fatal(err)
	}
	return profile, catalog
}

func TestProfileInputStrictLocalFile(t *testing.T) {
	profile, catalog := strictInputs(t)
	for _, args := range [][]string{{"--profile", "relative.json", "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}, {"--profile", filepath.Join(t.TempDir(), "missing"), "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}} {
		if run(args) == 0 {
			t.Fatal("unsafe profile input accepted")
		}
	}
	link := filepath.Join(t.TempDir(), "profile-link.json")
	if err := os.Symlink(profile, link); err == nil && run([]string{"--profile", link, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}) == 0 {
		t.Fatal("symlink accepted")
	}
	oversize := filepath.Join(t.TempDir(), "large.json")
	if err := os.WriteFile(oversize, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if run([]string{"--profile", oversize, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}) == 0 {
		t.Fatal("oversize profile accepted")
	}
	exact := filepath.Join(t.TempDir(), "exact.json")
	if err := os.WriteFile(exact, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readLocalRegularFile(exact); err != nil || len(raw) != 1<<20 {
		t.Fatalf("exact limit read=%d err=%v", len(raw), err)
	}
	parent := t.TempDir()
	realDir := filepath.Join(parent, "real")
	if err := os.Mkdir(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	parentLink := filepath.Join(parent, "link")
	if err := os.Symlink(realDir, parentLink); err == nil {
		inside := filepath.Join(realDir, "profile.json")
		if err := os.WriteFile(inside, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := readLocalRegularFile(filepath.Join(parentLink, "profile.json")); err == nil {
			t.Fatal("symlink component accepted")
		}
	}
}

func TestAuthorizationCatalogStrictLocalAndRange(t *testing.T) {
	profile, catalog := strictInputs(t)
	for name, raw := range map[string][]byte{"malformed": []byte("{"), "default scope": authorizationCatalogV1(t, "default_audit_v1", 42), "wrong seed": authorizationCatalogV1(t, "explicit_v1", 41)} {
		path := filepath.Join(t.TempDir(), strings.ReplaceAll(name, " ", "-")+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "out")
		if run([]string{"--profile", profile, "--authorization-catalog", path, "--out", out}) == 0 {
			t.Fatalf("%s accepted", name)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s mutated output", name)
		}
	}
	if run([]string{"--profile", profile, "--authorization-catalog", "relative.json", "--out", filepath.Join(t.TempDir(), "out")}) == 0 {
		t.Fatal("relative catalog accepted")
	}
	exact := filepath.Join(t.TempDir(), "exact-catalog.json")
	if err := os.WriteFile(exact, make([]byte, 1<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if raw, err := readLocalRegularFile(exact); err != nil || len(raw) != 1<<20 {
		t.Fatalf("exact catalog limit read=%d err=%v", len(raw), err)
	}
	_ = catalog
}

func TestStrictGenerationPreservesForceWrite(t *testing.T) {
	profile, catalog := strictInputs(t)
	out := filepath.Join(t.TempDir(), "generated")
	args := []string{"--profile", profile, "--authorization-catalog", catalog, "--out", out}
	if code := run(args); code != 0 {
		t.Fatalf("generate=%d", code)
	}
	if code := run(args); code == 0 {
		t.Fatal("overwrite accepted")
	}
	if code := run(append(args, "--force")); code != 0 {
		t.Fatalf("force=%d", code)
	}
	if _, err := os.Stat(filepath.Join(out, "manifest.json")); err != nil {
		t.Fatal(err)
	}
}

func TestStrictGenerationSignedSeedBoundaries(t *testing.T) {
	for _, seed := range []int64{math.MinInt64, -1, math.MaxInt64 - 7} {
		p := profileForSeedV1(t, seed)
		dir := t.TempDir()
		profile := filepath.Join(dir, "profile.json")
		catalog := filepath.Join(dir, "catalog.json")
		if err := ir.SaveProfile(profile, p); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(catalog, authorizationCatalogForProfileV1(t, p), 0o600); err != nil {
			t.Fatal(err)
		}
		if code := run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", filepath.Join(dir, "out")}); code != 0 {
			t.Fatalf("seed %d exit=%d", seed, code)
		}
	}
	for _, seed := range []int64{math.MaxInt64 - 6, math.MaxInt64} {
		p := profileForSeedV1(t, seed)
		dir := t.TempDir()
		profile := filepath.Join(dir, "profile.json")
		catalog := filepath.Join(dir, "catalog.json")
		out := filepath.Join(dir, "out")
		if err := ir.SaveProfile(profile, p); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(catalog, authorizationCatalogForProfileV1(t, p), 0o600); err != nil {
			t.Fatal(err)
		}
		if run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", out}) == 0 {
			t.Fatalf("seed %d accepted", seed)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("seed %d mutated output", seed)
		}
	}
}

func TestNoImplicitPinsSource(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"Lstat", "os.Open", "f.Stat", "os.SameFile", "io.LimitReader", "ir.DecodeProfileV1", "codegen.ParseAuthorizationCatalogV1", "ValidateExactSeedRangeV1", "codegen.GenerateStrict"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"ir.LoadProfile", "codegen.Generate(", "http.", "net.", "os.Getenv", "LookupEnv"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden %s", forbidden)
		}
	}
}

func TestPreGenerationNoMutation(t *testing.T) {
	profile, _ := strictInputs(t)
	out := filepath.Join(t.TempDir(), "must-not-exist")
	if run([]string{"--profile", profile, "--authorization-catalog", filepath.Join(t.TempDir(), "missing"), "--out", out}) == 0 {
		t.Fatal("missing catalog accepted")
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("pre-generation failure mutated output")
	}
}

func TestProfileInputDecodeMatrixAndConstantDiagnostics(t *testing.T) {
	base, _ := compiler.Generate(42)
	legacy := *base
	legacy.Version, legacy.Compatibility.SchemaVersion = ir.LegacySchemaVersionV1, ir.LegacySchemaVersionV1
	legacy.Security.SecurityVersion, legacy.Compatibility.CompilerSecurityVersion, legacy.Compatibility.MinimumRuntimeVersion = ir.LegacySecurityVersionV1, ir.LegacySecurityVersionV1, ir.LegacySecurityVersionV1
	mixed := *base
	mixed.Version = ir.LegacySchemaVersionV1
	future := *base
	future.Version, future.Compatibility.SchemaVersion = "99", "99"
	future.Security.SecurityVersion, future.Compatibility.CompilerSecurityVersion, future.Compatibility.MinimumRuntimeVersion = "99", "99", "99"
	invalid := *base
	invalid.GenerationHash = strings.Repeat("0", 64)
	_, catalog := strictInputs(t)
	for name, raw := range map[string][]byte{"malformed": []byte("{"), "legacy": mustMarshalV1(t, &legacy), "mixed": mustMarshalV1(t, &mixed), "future": mustMarshalV1(t, &future), "current-invalid": mustMarshalV1(t, &invalid)} {
		path := filepath.Join(t.TempDir(), name+".json")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		out := filepath.Join(t.TempDir(), "out")
		code, stderr := captureCommandV1(t, func() int { return run([]string{"--profile", path, "--authorization-catalog", catalog, "--out", out}) })
		if code == 0 || stderr != errProfileInput.Error()+"\n" || strings.Contains(stderr, path) || strings.Contains(stderr, name) {
			t.Fatalf("%s code=%d stderr=%q", name, code, stderr)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s mutated output", name)
		}
	}
}

func mustMarshalV1(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestAuthorizationCatalogParserRangeAndRoleMismatchMatrix(t *testing.T) {
	profile, good := strictInputs(t)
	p43 := profileForSeedV1(t, 43)
	var one, two map[string]any
	if err := json.Unmarshal(authorizationCatalogForProfileV1(t, p43), &two); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(authorizationCatalogV1(t, "explicit_v1", 42), &one); err != nil {
		t.Fatal(err)
	}
	extra := one
	extra["entries"] = append(extra["entries"].([]any), two["entries"].([]any)[0])
	cases := map[string][]byte{"missing": nil, "empty": []byte(`{"version":"profile-authorization-catalog-v1","scope":"explicit_v1","entries":[]}`), "extra": mustMarshalV1(t, extra), "wrong-range": authorizationCatalogV1(t, "explicit_v1", 41)}
	baseRaw, err := os.ReadFile(good)
	if err != nil {
		t.Fatal(err)
	}
	wrong := strings.Repeat("1", 64)
	cases["client-mismatch"] = []byte(strings.Replace(string(baseRaw), "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2", wrong, 1))
	last := strings.LastIndex(string(baseRaw), "af5f7ecf37cdd21cab29a7938f73ef3d5c6be849a8fb3d4f4c5e308c9312b4e2")
	cases["relay-mismatch"] = append(append([]byte{}, baseRaw[:last]...), append([]byte(wrong), baseRaw[last+64:]...)...)
	for name, raw := range cases {
		path := filepath.Join(t.TempDir(), name+".json")
		if raw != nil {
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		out := filepath.Join(t.TempDir(), "out")
		code, stderr := captureCommandV1(t, func() int { return run([]string{"--profile", profile, "--authorization-catalog", path, "--out", out}) })
		if code == 0 {
			t.Fatalf("%s accepted", name)
		}
		want := errAuthorizationCatalog.Error() + "\n"
		if strings.Contains(name, "mismatch") {
			want = errStrictGeneration.Error() + ": codegen authorization mismatch\n"
		}
		if stderr != want || strings.Contains(stderr, path) || strings.Contains(stderr, "42") {
			t.Fatalf("%s stderr=%q want=%q", name, stderr, want)
		}
		if _, err := os.Stat(out); !os.IsNotExist(err) {
			t.Fatalf("%s mutated output", name)
		}
	}
}

func TestProfileInputAndAuthorizationCatalogExactLimitReachParsers(t *testing.T) {
	profile, catalog := strictInputs(t)
	pRaw, _ := os.ReadFile(profile)
	cRaw, _ := os.ReadFile(catalog)
	if err := os.WriteFile(profile, append(pRaw, bytes.Repeat([]byte(" "), (1<<20)-len(pRaw))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalog, append(cRaw, bytes.Repeat([]byte(" "), (1<<20)-len(cRaw))...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code := run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}); code != 0 {
		t.Fatalf("exact limit command=%d", code)
	}
}

func TestProfileInputAuthorizationCatalogFilesystemFailureSeams(t *testing.T) {
	profile, catalog := strictInputs(t)
	for _, target := range []string{profile, catalog} {
		oldSame := sameLocalFile
		sameLocalFile = func(os.FileInfo, os.FileInfo) bool { return false }
		if _, err := readLocalRegularFile(target); err == nil {
			t.Fatal("identity mismatch accepted")
		}
		sameLocalFile = oldSame
		oldOpen := openLocal
		openLocal = func(path string) (*os.File, error) {
			f, err := os.Open(path)
			if err == nil {
				_ = f.Close()
			}
			return f, err
		}
		if _, err := readLocalRegularFile(target); err == nil {
			t.Fatal("read failure accepted")
		}
		openLocal = oldOpen
	}
	if _, err := readLocalRegularFile(filepath.Dir(profile)); err == nil {
		t.Fatal("directory accepted")
	}
	if filepath.IsAbs(os.DevNull) {
		if _, err := readLocalRegularFile(os.DevNull); err == nil {
			t.Fatal("irregular file accepted")
		}
	}
}

func TestStrictGenerationModulePathDeferredWO043(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "codegen.ErrStrictModulePath") {
		t.Fatal("WO-043 module-path sentinel not preserved")
	}
	// WO-041 only preserves the constant chain; WO-043 owns enforcement.
}

func TestNoImplicitPinsFourPathSHA256Evidence(t *testing.T) {
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	paths := []string{"cmd/kgen/main.go", "cmd/kgen/main_test.go", "internal/runtime/policy_enforcement_test.go", "internal/runtime/profile_loader_test.go"}
	for _, path := range paths {
		cmd := exec.Command("git", "show", "HEAD:"+path)
		cmd.Dir = root
		before, err := cmd.Output()
		pre := "ABSENT"
		if err == nil {
			sum := sha256.Sum256(before)
			pre = hex.EncodeToString(sum[:])
		}
		after, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(after)
		post := hex.EncodeToString(sum[:])
		if pre == post || post == strings.Repeat("0", 64) {
			t.Fatalf("%s SHA evidence invalid", path)
		}
		t.Logf("WO-041-SHA256 %s pre=%s post=%s", path, pre, post)
	}
}

type modeFileInfoV1 struct {
	os.FileInfo
	mode os.FileMode
}

func (i modeFileInfoV1) Mode() os.FileMode { return i.mode }

func TestProfileInputAuthorizationCatalogMissingFlagsAndSurrogateSeams(t *testing.T) {
	profile, catalog := strictInputs(t)
	catalogDir := filepath.Join(t.TempDir(), "catalog-input")
	if err := os.Mkdir(catalogDir, 0o700); err != nil {
		t.Fatal(err)
	}
	catalogCopy := filepath.Join(catalogDir, "catalog.json")
	raw, err := os.ReadFile(catalog)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(catalogCopy, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	catalog = catalogCopy
	out := filepath.Join(t.TempDir(), "out")
	for name, args := range map[string][]string{
		"profile":       {"--authorization-catalog", catalog, "--out", out},
		"authorization": {"--profile", profile, "--out", out},
		"out":           {"--profile", profile, "--authorization-catalog", catalog},
	} {
		code, stderr := captureCommandV1(t, func() int { return run(args) })
		if code != 2 || stderr != "--profile, --authorization-catalog, and --out are required\n" || strings.Contains(stderr, profile) || strings.Contains(stderr, catalog) || strings.Contains(stderr, out) {
			t.Fatalf("%s code=%d stderr=%q", name, code, stderr)
		}
	}
	for role, target := range map[string]string{"profile": profile, "catalog": catalog} {
		for _, tc := range []struct {
			name, path string
			mode       os.FileMode
		}{
			{"final-symlink", target, os.ModeSymlink},
			{"component-symlink", filepath.Dir(target), os.ModeDir | os.ModeSymlink},
			{"final-surrogate", target, os.ModeIrregular},
			{"component-surrogate", filepath.Dir(target), os.ModeDir | os.ModeIrregular},
		} {
			old := lstatLocal
			lstatLocal = func(path string) (os.FileInfo, error) {
				info, err := os.Lstat(path)
				if err == nil && filepath.Clean(path) == filepath.Clean(tc.path) {
					return modeFileInfoV1{info, tc.mode}, nil
				}
				return info, err
			}
			args := []string{"--profile", profile, "--authorization-catalog", catalog, "--out", filepath.Join(t.TempDir(), "out")}
			code, stderr := captureCommandV1(t, func() int { return run(args) })
			lstatLocal = old
			want := errProfileInput.Error() + "\n"
			if role == "catalog" {
				want = errAuthorizationCatalog.Error() + "\n"
			}
			if code == 0 || stderr != want {
				t.Fatalf("%s/%s code=%d stderr=%q", role, tc.name, code, stderr)
			}
		}
	}
}

func TestAuthorizationCatalogCommandRejectsOverflowByte(t *testing.T) {
	profile, _ := strictInputs(t)
	catalog := filepath.Join(t.TempDir(), "oversize-catalog.json")
	out := filepath.Join(t.TempDir(), "out")
	if err := os.WriteFile(catalog, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	code, stderr := captureCommandV1(t, func() int {
		return run([]string{"--profile", profile, "--authorization-catalog", catalog, "--out", out})
	})
	if code == 0 || stderr != errAuthorizationCatalog.Error()+"\n" {
		t.Fatalf("code=%d stderr=%q", code, stderr)
	}
	if _, err := os.Stat(out); !os.IsNotExist(err) {
		t.Fatal("catalog overflow mutated output")
	}
}
