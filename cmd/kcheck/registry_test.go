package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"kurdistan/internal/codegen"
)

type registryModeInfoV1 struct {
	os.FileInfo
	mode os.FileMode
}

func (i registryModeInfoV1) Mode() os.FileMode { return i.mode }

// frozenCommands is the kcheck CLI contract: the exact set of subsystem
// subcommands (excluding the bare/no-arg audit fallthrough). Adding or removing
// a name here is a CLI-surface change and must be a deliberate, reviewed edit
// (see planning contracts.md §1). This test guards the registry against
// accidental drift during the architecture-realignment restructure.
var frozenCommands = []string{
	"compare", "adversary", "codegen", "streamadversary", "proxysem", "carrier",
	"security", "runtime", "hardening", "adapter", "localadapter", "bytetransport",
	"fixtures", "bytepath", "protocorpus", "wirefeatures", "wiregen", "wireeval",
	"hostdetect", "relayfleet", "proxyingress", "localproxyingress",
	"localproxyingressadv", "adaptivepath", "transportbundle", "pathrace",
	"pathhealth", "carrierreview", "measurementreview", "proxyegress", "relaybridge",
	"localpipeline", "productionreadiness", "concretelocaladapter",
	"localprotocoladapter", "loopbackrelay", "labegress", "carrierreadiness",
	"httpscarrierreview", "httpslikecarrier", "httpscarrieradversary",
	"constrainedcarrierreview", "constrainedcarrier", "multicarrierselect",
	"carriercollapse", "localproxyadapterreview", "localproxyadapter",
	"vpnsemantics", "localvpnadapter", "relayprocess", "keyexchangeplan",
	"relayauthplan", "operationalhardening", "androidruntime", "androidvpnservice",
	"androidcarrier", "androidreview",
}

func explicitCatalogFixtureV1(t *testing.T, count int) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Clean("../../testdata/codegen/profile-authorization-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	if err := json.Unmarshal(raw, &wire); err != nil {
		t.Fatal(err)
	}
	wire["scope"] = "explicit_v1"
	entries := wire["entries"].([]any)
	wire["entries"] = entries[:count]
	raw, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "explicit.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestCodegenRegistryAuthorizationFlagCoupling(t *testing.T) {
	catalog := explicitCatalogFixtureV1(t, 3)
	for name, args := range map[string][]string{
		"catalog-only":          {"--authorization-catalog", catalog},
		"start-only":            {"--start-seed", "1"},
		"profiles-only":         {"--profiles", "3"},
		"numeric-default-start": {"--start-seed", "0"},
		"numeric-default-count": {"--profiles", "0"},
	} {
		if code := runCodegen(args); code == 0 {
			t.Fatalf("%s accepted", name)
		}
	}
	if code := runCodegen([]string{"--start-seed", "1", "--profiles", "3", "--authorization-catalog", "relative.json"}); code == 0 {
		t.Fatal("relative catalog accepted")
	}
}

func TestArbitrarySeedCatalogLocalFileBoundary(t *testing.T) {
	path := explicitCatalogFixtureV1(t, 3)
	if raw, err := readKcheckCatalogV1(path); err != nil || len(raw) == 0 {
		t.Fatalf("read=%d err=%v", len(raw), err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	exact := filepath.Join(t.TempDir(), "exact.json")
	if err := os.WriteFile(exact, append(raw, bytes.Repeat([]byte(" "), (1<<20)-len(raw))...), 0o600); err != nil {
		t.Fatal(err)
	}
	parsed, err := readKcheckCatalogV1(exact)
	if err != nil || len(parsed) != 1<<20 {
		t.Fatalf("exact=%d err=%v", len(parsed), err)
	}
	if _, err := codegen.ParseAuthorizationCatalogV1(parsed); err != nil {
		t.Fatalf("exact parser: %v", err)
	}
	over := filepath.Join(t.TempDir(), "over.json")
	if err := os.WriteFile(over, make([]byte, (1<<20)+1), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := readKcheckCatalogV1(over); err == nil {
		t.Fatal("overflow accepted")
	}
	if _, err := readKcheckCatalogV1(filepath.Dir(path)); err == nil {
		t.Fatal("directory accepted")
	}
	old := kcheckSameFileV1
	kcheckSameFileV1 = func(os.FileInfo, os.FileInfo) bool { return false }
	if _, err := readKcheckCatalogV1(path); err == nil {
		t.Fatal("identity mismatch accepted")
	}
	kcheckSameFileV1 = old
	for _, mode := range []os.FileMode{os.ModeSymlink, os.ModeIrregular, os.ModeDevice, os.ModeNamedPipe} {
		oldLstat := kcheckLstatV1
		kcheckLstatV1 = func(name string) (os.FileInfo, error) {
			info, err := os.Lstat(name)
			if err == nil && filepath.Clean(name) == filepath.Clean(path) {
				return registryModeInfoV1{info, mode}, nil
			}
			return info, err
		}
		if _, err := readKcheckCatalogV1(path); err == nil {
			t.Fatalf("mode %v accepted", mode)
		}
		kcheckLstatV1 = oldLstat
	}
}

func TestCodegenAuthorizationCatalogSourceBoundary(t *testing.T) {
	raw, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	text := string(raw)
	for _, required := range []string{"flags.Visit", "readKcheckCatalogV1", "codegen.ParseAuthorizationCatalogV1", "audit.NewExplicitCodegenAuditConfig", "audit.DefaultCodegenAuditConfig"} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"http.Get", "net.Dial", "os.Getenv", "LookupEnv", "codegen.Generate("} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("forbidden %s", forbidden)
		}
	}
}

func TestCommandRegistryMatchesFrozenSurface(t *testing.T) {
	reg := commandRegistry()

	got := make([]string, 0, len(reg))
	for name, handler := range reg {
		if handler == nil {
			t.Errorf("command %q has a nil handler", name)
		}
		got = append(got, name)
	}
	sort.Strings(got)

	want := append([]string(nil), frozenCommands...)
	sort.Strings(want)

	if len(got) != len(want) {
		t.Fatalf("command-surface drift: registry has %d commands, frozen set has %d\n registry=%v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command-surface drift at index %d: registry=%q frozen=%q", i, got[i], want[i])
		}
	}
}
