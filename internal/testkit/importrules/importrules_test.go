// Package importrules enforces the architecture-realignment boundary: the
// product runtime and real libraries must never depend on quarantined
// model/contract code. Only the analysis/generation tooling (audit, codegen,
// kcheck) and contracts/product packages themselves may import
// internal/contracts/** or internal/product/**, except exact reviewed
// signed-policy runtime consumers recorded below.
//
// This is the executable form of the Stage 6 contract-import gate.
package importrules

// WO-053 freezes ExecuteRuntimeLabFaultV1 as the sole root-runtime lab facade;
// the existing recurrence scan below remains the owner of external reachability.

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/build"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"kurdistan/internal/testkit/committedevidence"
	"kurdistan/internal/testkit/evidenceoverlay"
)

const modulePath = "kurdistan"

func phase18SizeofTestImportAllowedV1(name string, file *ast.File) bool {
	if name != "internal/product/envelope/phase8_resource_preflight_test.go" && name != "internal/product/profile/phase8_admission_test.go" {
		return false
	}
	imports := 0
	for _, im := range file.Imports {
		if im.Path.Value == `"unsafe"` {
			if im.Name != nil {
				return false
			}
			imports++
		}
	}
	if imports != 1 {
		return false
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			if strings.Contains(comment.Text, "go:linkname") {
				return false
			}
		}
	}
	allowed := map[*ast.Ident]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok || len(call.Args) != 1 || call.Ellipsis.IsValid() {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sizeof" {
			return true
		}
		id, ok := sel.X.(*ast.Ident)
		if ok && id.Name == "unsafe" {
			allowed[id] = true
		}
		return true
	})
	valid := len(allowed) > 0
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && id.Name == "unsafe" && !allowed[id] {
			valid = false
		}
		return true
	})
	return valid
}

// Exact reviewed signed-policy consumers, never package-prefix permissions.
var phase18RuntimeProductImportAllowlistV1 = map[string]map[string]bool{
	"internal/net/boundeddns/resolver.go":                     {"kurdistan/internal/product/runtimepolicy": true},
	"internal/relay/node/server.go":                           {"kurdistan/internal/product/runtimepolicy": true},
	"internal/relay/node/server_services_v3.go":               {"kurdistan/internal/product/envelope": true, "kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/relay/node/server_services_v3_test.go":          {"kurdistan/internal/product/enrollment": true, "kurdistan/internal/product/envelope": true, "kurdistan/internal/product/lifecycle": true, "kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/relay/node/service_network_v3.go":               {"kurdistan/internal/product/runtimepolicy": true},
	"internal/relay/node/service_network_v3_test.go":          {"kurdistan/internal/product/runtimepolicy": true},
	"internal/relay/node/session_device_v3.go":                {"kurdistan/internal/product/runtimepolicy": true},
	"internal/relay/node/session_device_v3_test.go":           {"kurdistan/internal/product/runtimepolicy": true},
	"internal/runtime/production_client_recipe_v1.go":         {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/production_client_recipe_v1_test.go":    {"kurdistan/internal/product/envelope": true, "kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/production_packet_admission_v1.go":      {"kurdistan/internal/product/runtimepolicy": true},
	"internal/runtime/production_packet_admission_v1_test.go": {"kurdistan/internal/product/runtimepolicy": true},
	"internal/runtime/production_raw_packet_pump_v2.go":       {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/production_raw_packet_pump_v2_test.go":  {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/service_admission_v1.go":                {"kurdistan/internal/product/runtimepolicy": true},
	"internal/runtime/service_admission_v1_test.go":           {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/service_preparation_v1.go":              {"kurdistan/internal/product/sessionplan": true},
	"internal/runtime/service_preparation_v1_test.go":         {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/service_probe_v1.go":                    {"kurdistan/internal/product/envelope": true},
	"internal/runtime/service_probe_v1_test.go":               {"kurdistan/internal/product/envelope": true},
	"internal/runtime/service_pump_v1.go":                     {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/service_pump_v1_test.go":                {"kurdistan/internal/product/envelope": true, "kurdistan/internal/product/lifecycle": true, "kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
	"internal/runtime/service_record_v1.go":                   {"kurdistan/internal/product/runtimepolicy": true},
	"internal/runtime/service_stream_port_v1_test.go":         {"kurdistan/internal/product/runtimepolicy": true, "kurdistan/internal/product/sessionplan": true},
}

func TestPhase18SizeAccountingUnsafeIsNotPointerPermission(t *testing.T) {
	for _, name := range []string{"internal/product/envelope/phase8_resource_preflight_test.go", "internal/product/profile/phase8_admission_test.go"} {
		for _, tc := range []struct {
			body string
			want bool
		}{
			{"var n = unsafe.Sizeof(0)", true}, {"var n = unsafe.Alignof(0)", false},
			{"var n = unsafe.Pointer(nil)", false}, {"var n = unsafe.Add(nil,0)", false},
			{"var n = unsafe.Slice((*byte)(nil),0)", false}, {"var n = unsafe.String(nil,0)", false},
			{"var n = unsafe.Offsetof(x.f)", false}, {"var n = unsafe.Sizeof", false},
			{"var n = unsafe.Sizeof(0); var p = unsafe.Pointer(nil)", false},
			{"//go:linkname n x\nvar n = unsafe.Sizeof(0)", false}, {"var unsafe = 0", false},
		} {
			f, err := parser.ParseFile(token.NewFileSet(), name, "package p; import \"unsafe\"\n"+tc.body, parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			if got := phase18SizeofTestImportAllowedV1(name, f); got != tc.want {
				t.Fatalf("%s: %s allowed=%v", name, tc.body, got)
			}
		}
		for _, alias := range []string{"u", ".", "_"} {
			f, err := parser.ParseFile(token.NewFileSet(), name, "package p; import "+alias+" \"unsafe\"; var n=unsafe.Sizeof(0)", parser.ParseComments)
			if err != nil {
				t.Fatal(err)
			}
			if phase18SizeofTestImportAllowedV1(name, f) {
				t.Fatal("unsafe alias allowed")
			}
		}
		f, err := parser.ParseFile(token.NewFileSet(), filepath.Join(repoRoot(t), filepath.FromSlash(name)), nil, parser.ParseComments)
		if err != nil || !phase18SizeofTestImportAllowedV1(name, f) {
			t.Fatal("real size accounting rejected", err)
		}
		for _, other := range []string{"internal/product/envelope/envelope.go", "internal/product/envelope/other_test.go", "internal/product/other/phase8_admission_test.go"} {
			if phase18SizeofTestImportAllowedV1(other, f) {
				t.Fatal("sibling unsafe permission")
			}
		}
	}
}

func TestPhase18RuntimeImportsStayExact(t *testing.T) {
	expectedRows := []string{
		"internal/net/boundeddns/resolver.go runtimepolicy",
		"internal/relay/node/server.go runtimepolicy",
		"internal/relay/node/server_services_v3.go envelope runtimepolicy sessionplan",
		"internal/relay/node/server_services_v3_test.go enrollment envelope lifecycle runtimepolicy sessionplan",
		"internal/relay/node/service_network_v3.go runtimepolicy",
		"internal/relay/node/service_network_v3_test.go runtimepolicy",
		"internal/relay/node/session_device_v3.go runtimepolicy",
		"internal/relay/node/session_device_v3_test.go runtimepolicy",
		"internal/runtime/production_client_recipe_v1.go runtimepolicy sessionplan",
		"internal/runtime/production_client_recipe_v1_test.go envelope runtimepolicy sessionplan",
		"internal/runtime/production_packet_admission_v1.go runtimepolicy",
		"internal/runtime/production_packet_admission_v1_test.go runtimepolicy",
		"internal/runtime/production_raw_packet_pump_v2.go runtimepolicy sessionplan",
		"internal/runtime/production_raw_packet_pump_v2_test.go runtimepolicy sessionplan",
		"internal/runtime/service_admission_v1.go runtimepolicy",
		"internal/runtime/service_admission_v1_test.go runtimepolicy sessionplan",
		"internal/runtime/service_preparation_v1.go sessionplan",
		"internal/runtime/service_preparation_v1_test.go runtimepolicy sessionplan",
		"internal/runtime/service_probe_v1.go envelope",
		"internal/runtime/service_probe_v1_test.go envelope",
		"internal/runtime/service_pump_v1.go runtimepolicy sessionplan",
		"internal/runtime/service_pump_v1_test.go envelope lifecycle runtimepolicy sessionplan",
		"internal/runtime/service_record_v1.go runtimepolicy",
		"internal/runtime/service_stream_port_v1_test.go runtimepolicy sessionplan",
	}
	expected := map[string]map[string]bool{}
	for _, row := range expectedRows {
		fields := strings.Fields(row)
		expected[fields[0]] = map[string]bool{}
		for _, suffix := range fields[1:] {
			expected[fields[0]][modulePath+"/internal/product/"+suffix] = true
		}
	}
	match := func(candidate map[string]map[string]bool) bool {
		if len(candidate) != len(expected) {
			return false
		}
		for file, imports := range expected {
			if len(candidate[file]) != len(imports) {
				return false
			}
			for ip := range imports {
				if !candidate[file][ip] {
					return false
				}
			}
		}
		return true
	}
	if !match(phase18RuntimeProductImportAllowlistV1) {
		t.Fatal("reviewed edge set changed")
	}
	for _, mutation := range []string{"remove", "substitute", "add"} {
		candidate := map[string]map[string]bool{}
		for f, imports := range phase18RuntimeProductImportAllowlistV1 {
			candidate[f] = map[string]bool{}
			for ip, v := range imports {
				candidate[f][ip] = v
			}
		}
		file := "internal/runtime/service_admission_v1.go"
		ip := modulePath + "/internal/product/runtimepolicy"
		switch mutation {
		case "remove":
			delete(candidate[file], ip)
		case "substitute":
			delete(candidate[file], ip)
			candidate[file][modulePath+"/internal/product/profile"] = true
		case "add":
			candidate["internal/runtime/extra.go"] = map[string]bool{ip: true}
		}
		if match(candidate) {
			t.Fatal("permission mutation accepted", mutation)
		}
	}
	edges := 0
	for file, imports := range phase18RuntimeProductImportAllowlistV1 {
		actual, err := localImportsV1(filepath.Join(repoRoot(t), filepath.FromSlash(file)))
		if err != nil {
			t.Fatal(err)
		}
		for ip := range imports {
			edges++
			if !slices.Contains(actual, strings.TrimPrefix(ip, modulePath+"/")) {
				t.Fatalf("obsolete permission %s -> %s", file, ip)
			}
		}
	}
	if len(phase18RuntimeProductImportAllowlistV1) != 24 || edges != 42 {
		t.Fatal("unexpected permission count", edges)
	}
	for _, tc := range []struct {
		file, ip string
		allowed  bool
	}{
		{"internal/runtime/service_admission_v1.go", "internal/product/runtimepolicy", true},
		{"internal/runtime/adjacent.go", "internal/product/runtimepolicy", false},
		{"internal/runtime/service_admission_v1.go", "internal/product/profile", false},
		{"internal/runtime/service_admission_v1.go", "internal/contracts/runtime", false},
		{"internal/runtime/service_admission_v1.go", "internal/product/runtimepolicy/extra", false},
		{"internal/relay/node/server_services_v3.go", "internal/product/enrollment", false},
		{"internal/relay/node/server_services_v3_test.go", "internal/product/profile", false},
		{"internal/product/profile/mutant.go", "internal/operator", false},
		{"internal/product/profile/mutant.go", "internal/operator/controlplane", false},
	} {
		root := t.TempDir()
		for _, dir := range []string{"cmd", filepath.Dir(tc.file)} {
			if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(root, tc.file), []byte("package p; import _ \""+modulePath+"/"+tc.ip+"\""), 0600); err != nil {
			t.Fatal(err)
		}
		violations, err := contractImportViolationsV1(root)
		if err != nil || (len(violations) == 0) != tc.allowed {
			t.Fatalf("%s %s: %v %v", tc.file, tc.ip, violations, err)
		}
	}
}

func TestPhase18OrdinarySourceSelection(t *testing.T) {
	root := t.TempDir()
	for _, target := range ordinaryImportTargetsV1 {
		t.Run(target.name, func(t *testing.T) {
			for _, tc := range []struct {
				name, source string
				want         bool
			}{
				{"plain.go", "package p", true},
				{"fixture.go", "//go:build phase9internal\n\npackage p", false},
				{"comment.go", "// phase9internal\npackage p", true},
				{"fixture_internal.go", "package p", true},
				{"ordinary.go", "//go:build !phase9internal\n\npackage p", true},
				{"either.go", "//go:build phase9internal || android\n\npackage p", target.goos == "android"},
				{"eitherlinux.go", "//go:build phase9internal || linux\n\npackage p", target.goos == "android" || target.goos == "linux"},
				{"code_linux.go", "package p", target.goos == "linux" || target.goos == "android"},
				{"code_android.go", "package p", target.goos == "android"},
				{"code_windows.go", "package p", target.goos == "windows"},
				{"code_arm64.go", "package p", target.goarch == "arm64"},
				{"cgo.go", "package p; import \"C\"", target.cgo},
			} {
				path := filepath.Join(root, tc.name)
				if err := os.WriteFile(path, []byte(tc.source), 0600); err != nil {
					t.Fatal(err)
				}
				_, selected, err := selectedLocalImportsV1(path, target)
				if err != nil || selected != tc.want {
					t.Fatalf("%s: selected=%v want=%v error=%v", tc.name, selected, tc.want, err)
				}
			}
		})
	}
	path := filepath.Join(root, "bad.go")
	if err := os.WriteFile(path, []byte("//go:build (\n\npackage p"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := selectedLocalImportsV1(path, ordinaryImportTargetsV1[0]); err == nil {
		t.Fatal("malformed constraint accepted")
	}
}

func TestPhase18SelectedCompilerGraphCannotHideTransitiveEdges(t *testing.T) {
	for _, guard := range []string{"//go:build phase9internal\n\n", "", "// phase9internal\n", "//go:build phase9internal || android\n\n"} {
		root := t.TempDir()
		write := func(name, src string) {
			t.Helper()
			path := filepath.Join(root, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, []byte(src), 0600); err != nil {
				t.Fatal(err)
			}
		}
		write("cmd/kandroidbridge/main.go", "package main; import _ \"kurdistan/internal/helper\"")
		write("internal/helper/base.go", "package helper")
		write("internal/helper/fixture_internal.go", guard+"package helper; import _ \"kurdistan/internal/protocol/liveprogramcompile\"")
		write("internal/protocol/liveprogramcompile/base.go", "package liveprogramcompile")
		for _, target := range ordinaryImportTargetsV1 {
			graph, err := loadImportGraphForTargetV1(root, []string{"cmd"}, target)
			if err != nil {
				t.Fatal(err)
			}
			denied := validateLiveProgramConversionImportGraphV1(graph) != nil
			want := guard == "" || guard == "// phase9internal\n" || strings.Contains(guard, "||") && target.goos == "android"
			if denied != want {
				t.Fatalf("%s guard %q denied=%v", target.name, guard, denied)
			}
		}
		internal := ordinaryImportTargetsV1[0]
		internal.tags = []string{"phase9internal"}
		graph, err := loadImportGraphForTargetV1(root, []string{"cmd"}, internal)
		if err != nil || validateLiveProgramConversionImportGraphV1(graph) == nil {
			t.Fatal("internal compiler fixture was not selected", err)
		}
		write("internal/helper/base.go", "package helper; import _ \"kurdistan/internal/missing\"")
		if _, err := loadImportGraphForTargetV1(root, []string{"cmd"}, ordinaryImportTargetsV1[0]); err == nil {
			t.Fatal("missing imported package hidden")
		}
	}
}

type shortcutInventoryRowV1 struct {
	Category, Path, Symbol, Classification string
}

var shortcutInventoryV1 = []shortcutInventoryRowV1{
	{"fixed_or_profile_nonce", "internal/runtime/secure_channel.go", `SessionNonce:        []byte("runtime-session:" + p.ID)`, "exact legacy/model allowlist"},
	{"public_profile_key", "internal/protocol/compiler/generator.go", "TestKeyHex:   testKeyHex(seed, id)", "exact legacy/model allowlist"},
	{"default_secret_identity_trust", "internal/runtime/config.go", "func DefaultConfig(role Role, runtimeID string, secret []byte)", "exact legacy/model allowlist"},
	{"replay_reset", "internal/crypto/security/envelope.go", "replay, err = NewReplayWindowV1", "strict-candidate safe"},
	{"lab_token_mint", "internal/crypto/auth/lab_fault.go", "func NewAuthLabFaultTokenV1", "owner/test-only"},
	{"lab_token_mint", "internal/runtime/labfault/token.go", "func NewTokenV1", "owner/test-only"},
	{"lab_token_consumer", "internal/runtime/lab_executor.go", "labfault.NewTokenV1", "owner/test-only"},
	{"lab_token_consumer", "internal/testkit/mutant/fault.go", "NewAuthLabFaultTokenV1", "owner/test-only"},
	{"lab_token_consumer", "internal/runtime/protected_channel.go", "labfault.NewTokenV1", "owner/test-only"},
	{"lab_token_consumer", "internal/runtime/loopback_pair.go", "labfault.NewTokenV1", "owner/test-only"},
	{"lab_token_consumer", "internal/runtime/link.go", "labfault.NewTokenV1", "owner/test-only"},
	{"lab_token_consumer", "internal/runtime/trace.go", "labfault.NewTokenV1", "owner/test-only"},
}

type legacyCompatibilityRowV1 struct {
	Path, Kind, Name, Status, Evidence string
}

var legacyCompatibilityInventoryV1 = []legacyCompatibilityRowV1{
	{"internal/runtime/secure_channel.go", "func", "BuildSecurityContext", "exact legacy/model allowlist", "profile-derived model transcript compatibility"},
	{"internal/runtime/secure_channel.go", "func", "NewSecureChannel", "exact legacy/model allowlist", "legacy envelope compatibility"},
	{"internal/runtime/config.go", "func", "DefaultConfig", "exact legacy/model allowlist", "caller-supplied legacy secret constructor"},
	{"internal/runtime/manager.go", "type", "Runtime", "exact legacy/model allowlist", "legacy runtime surface"},
	{"internal/runtime/manager.go", "type", "Manager", "exact legacy/model allowlist", "legacy manager surface"},
	{"internal/runtime/manager.go", "func", "NewRuntime", "exact legacy/model allowlist", "legacy runtime constructor"},
	{"internal/runtime/manager.go", "func", "NewRuntimeFromPath", "exact legacy/model allowlist", "legacy path-loading runtime constructor"},
	{"internal/runtime/manager.go", "func", "NewManager", "exact legacy/model allowlist", "legacy manager constructor"},
	{"internal/runtime/session.go", "type", "Session", "exact legacy/model allowlist", "legacy session surface"},
	{"internal/runtime/session.go", "func", "NewSession", "exact legacy/model allowlist", "legacy session constructor"},
	{"internal/runtime/stream_manager.go", "type", "StreamManager", "exact legacy/model allowlist", "legacy stream manager surface"},
	{"internal/runtime/stream_manager.go", "func", "NewStreamManager", "exact legacy/model allowlist", "legacy stream manager constructor"},
	{"internal/runtime/adapter_boundary.go", "func", "RunAdapterBoundary", "exact legacy/model allowlist", "legacy adapter boundary"},
	{"internal/relay/relay.go", "func", "ServeEcho", "exact legacy/model allowlist", "legacy TCP relay"},
	{"internal/relay/relay.go", "func", "Serve", "exact legacy/model allowlist", "legacy TCP relay"},
	{"internal/relay/relay.go", "func", "HandleServerConn", "exact legacy/model allowlist", "legacy TCP relay"},
	{"internal/relay/relay.go", "func", "ClientRoundTrip", "exact legacy/model allowlist", "legacy TCP client"},
	{"internal/relay/relay.go", "func", "ClientHandshake", "exact legacy/model allowlist", "legacy protocol handshake"},
	{"internal/relay/relay.go", "func", "ServerHandshake", "exact legacy/model allowlist", "legacy protocol handshake"},
	{"cmd/kclient/main.go", "package", "main", "exact legacy/model allowlist", "legacy protocol command"},
	{"cmd/kserver/main.go", "package", "main", "exact legacy/model allowlist", "legacy protocol command"},
	{"cmd/kecho/main.go", "package", "main", "exact legacy/model allowlist", "legacy protocol command"},
	{"cmd/ktrace/main.go", "package", "main", "exact legacy/model allowlist", "legacy protocol command"},
	{"internal/codegen/generator_templates.go", "const-series", "genTmpl001..genTmpl210", "exact legacy/model allowlist", "generated compatibility templates"},
}

func TestShortcutInventoryCurrentSourceV1(t *testing.T) {
	root := repoRoot(t)
	categories := map[string]bool{"fixed_or_profile_nonce": true, "public_profile_key": true, "default_secret_identity_trust": true, "replay_reset": true, "lab_token_mint": true, "lab_token_consumer": true, "model_only_path": true}
	classifications := map[string]bool{"strict-candidate safe": true, "owner/test-only": true, "exact legacy/model allowlist": true, "rejected": true}
	seen := map[string]bool{}
	for _, row := range shortcutInventoryV1 {
		if !categories[row.Category] || !classifications[row.Classification] || row.Path == "" || row.Symbol == "" {
			t.Fatalf("invalid shortcut inventory row: %+v", row)
		}
		key := row.Category + "|" + row.Path + "|" + row.Symbol
		if seen[key] {
			t.Fatalf("duplicate shortcut inventory row: %s", key)
		}
		seen[key] = true
		if strings.HasSuffix(row.Path, "/") {
			if info, err := os.Stat(filepath.Join(root, filepath.FromSlash(row.Path))); err != nil || !info.IsDir() {
				t.Fatalf("inventory model path missing: %s", row.Path)
			}
			continue
		}
		raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(row.Path)))
		if err != nil || !strings.Contains(string(raw), row.Symbol) {
			t.Fatalf("inventory source drift %s symbol=%q err=%v", row.Path, row.Symbol, err)
		}
	}
	if len(seen) != 12 {
		t.Fatalf("shortcut inventory rows=%d want=12", len(seen))
	}
}

func TestProductPathBoundaryV1(t *testing.T) {
	root := repoRoot(t)
	forbiddenProduct := []string{"internal/runtime/labfault", "NewAuthLabFaultTokenV1", "NewTokenV1", "TestKeyHex", "runtime-session:", "test-only-"}
	err := filepath.WalkDir(filepath.Join(root, "internal", "product"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range forbiddenProduct {
			if strings.Contains(string(raw), forbidden) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("contracts-only product path %s reaches shortcut %q", filepath.ToSlash(rel), forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, generatedRoot := range []string{"internal/protocol/compiler", "internal/codegen"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(generatedRoot)), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			for _, forbidden := range []string{"internal/testkit", "internal/runtime/labfault", "NewAuthLabFaultTokenV1", "labfault.NewTokenV1"} {
				if strings.Contains(string(raw), forbidden) {
					t.Errorf("generated compiler path %s reaches lab shortcut %q", filepath.ToSlash(rel), forbidden)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestLiveProgramReleaseImportBoundariesV1(t *testing.T) {
	root := repoRoot(t)
	forbiddenCompiler := modulePath + "/internal/protocol/liveprogramcompile"
	for _, target := range ordinaryImportTargetsV1 {
		for _, releaseRoot := range []string{"internal/androidbridge", "internal/product", "internal/runtime", "cmd/kandroidbridge"} {
			violations, err := selectedImportViolationsV1(root, releaseRoot, forbiddenCompiler, target)
			if err != nil || len(violations) != 0 {
				t.Fatalf("%s: %v %v", target.name, violations, err)
			}
		}
		for _, forbidden := range []string{
			modulePath + "/internal/protocol/ir",
			modulePath + "/internal/protocol/compiler",
			modulePath + "/internal/testkit",
			modulePath + "/internal/lab",
		} {
			violations, err := selectedImportViolationsV1(root, "internal/protocol/liveprogram", forbidden, target)
			if err != nil || len(violations) != 0 {
				t.Fatalf("%s: %v %v", target.name, violations, err)
			}
		}
	}
}

func TestLiveProgramConversionImportGraphV1(t *testing.T) {
	root := repoRoot(t)
	var graph map[string][]string
	var err error
	for _, target := range ordinaryImportTargetsV1 {
		graph, err = loadImportGraphForTargetV1(root, []string{"cmd", "internal"}, target)
		if err != nil {
			t.Fatalf("%s: %v", target.name, err)
		}
		if err := validateLiveProgramConversionImportGraphV1(graph); err != nil {
			t.Fatalf("%s: %v", target.name, err)
		}
	}
	clone := func() map[string][]string {
		copy := make(map[string][]string, len(graph)+2)
		for path, imports := range graph {
			copy[path] = append([]string(nil), imports...)
		}
		return copy
	}
	for name, mutate := range map[string]func(map[string][]string){
		"release-product-direct": func(candidate map[string][]string) {
			candidate["internal/product/release"] = []string{"internal/protocol/liveprogramcompile"}
		},
		"release-product-transitive": func(candidate map[string][]string) {
			candidate["internal/product/release"] = []string{"internal/liveadapter"}
			candidate["internal/liveadapter"] = []string{"internal/protocol/liveprogramcompile"}
		},
		"live-program-transitive-lab": func(candidate map[string][]string) {
			candidate["internal/protocol/liveprogram"] = append(candidate["internal/protocol/liveprogram"], "internal/liveadapter")
			candidate["internal/liveadapter"] = []string{"internal/lab/runtimeadversary"}
		},
		"unlisted-owner-importer": func(candidate map[string][]string) {
			candidate["internal/ownerhelper"] = []string{"internal/protocol/liveprogramcompile"}
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateLiveProgramConversionImportGraphV1(func() map[string][]string { candidate := clone(); mutate(candidate); return candidate }()); err == nil {
				t.Fatal("live-program ownership boundary violation was accepted")
			}
		})
	}
	t.Run("listed-owner-importers", func(t *testing.T) {
		candidate := clone()
		candidate["cmd/kurdctl"] = append(candidate["cmd/kurdctl"], "internal/protocol/liveprogramcompile")
		if err := validateLiveProgramConversionImportGraphV1(candidate); err != nil {
			t.Fatalf("listed owner importer rejected: %v", err)
		}
	})
}

func TestLoadImportGraphV1IncludesTransitivePackagesOutsideSeedRoots(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		"internal/product/root.go": `package product

import _ "kurdistan/internal/transitive"
`,
		"internal/transitive/transitive.go": `package transitive

import _ "kurdistan/internal/protocol/liveprogramcompile"
`,
		"internal/protocol/liveprogramcompile/compile.go": "package liveprogramcompile\n",
	}
	for rel, contents := range files {
		path := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(contents), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	graph, err := loadImportGraphForTargetV1(root, []string{"internal/product"}, ordinaryImportTargetsV1[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := graph["internal/transitive"]; !ok {
		t.Fatal("transitive package outside seed root was omitted from import graph")
	}
	if !slices.Contains(graph["internal/transitive"], "internal/protocol/liveprogramcompile") {
		t.Fatal("transitive owner-boundary violation was not represented in import graph")
	}
}

type importTargetV1 struct {
	name, goos, goarch string
	cgo                bool
	tags               []string
}

var ordinaryImportTargetsV1 = []importTargetV1{
	{"android-arm64", "android", "arm64", true, nil}, {"android-amd64", "android", "amd64", true, nil},
	{"linux-amd64-pure", "linux", "amd64", false, nil}, {"linux-amd64-cgo", "linux", "amd64", true, nil},
	{"windows-amd64-pure", "windows", "amd64", false, nil}, {"windows-amd64-cgo", "windows", "amd64", true, nil},
}

func selectedLocalImportsV1(path string, target importTargetV1) ([]string, bool, error) {
	if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
		return nil, false, nil
	}
	ctx := build.Default
	ctx.GOOS = target.goos
	ctx.GOARCH = target.goarch
	ctx.CgoEnabled = target.cgo
	ctx.Compiler = "gc"
	ctx.UseAllFiles = false
	ctx.BuildTags = append([]string(nil), target.tags...)
	selected, err := ctx.MatchFile(filepath.Dir(path), filepath.Base(path))
	if err != nil || !selected {
		return nil, false, err
	}
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, false, err
	}
	var imports []string
	for _, im := range f.Imports {
		ip := strings.Trim(im.Path.Value, `"`)
		if ip == "C" && !target.cgo {
			return nil, false, nil
		}
		if strings.HasPrefix(ip, modulePath+"/") {
			imports = append(imports, strings.TrimPrefix(ip, modulePath+"/"))
		}
	}
	return imports, true, nil
}

func selectedImportViolationsV1(root, sourceRoot, forbidden string, target importTargetV1) ([]string, error) {
	var violations []string
	err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(sourceRoot)), func(path string, e os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if e.IsDir() {
			return nil
		}
		imports, selected, err := selectedLocalImportsV1(path, target)
		if err != nil {
			return err
		}
		if !selected {
			return nil
		}
		for _, ip := range imports {
			full := modulePath + "/" + ip
			if full == forbidden || strings.HasPrefix(full, forbidden+"/") {
				rel, _ := filepath.Rel(root, path)
				violations = append(violations, filepath.ToSlash(rel)+": "+full)
			}
		}
		return nil
	})
	sort.Strings(violations)
	return violations, err
}

func loadImportGraphForTargetV1(root string, sourceRoots []string, target importTargetV1) (map[string][]string, error) {
	graph := map[string][]string{}
	for _, sourceRoot := range sourceRoots {
		base := filepath.Join(root, filepath.FromSlash(sourceRoot))
		err := filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			rel, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			packagePath := filepath.ToSlash(filepath.Dir(rel))
			imports, selected, err := selectedLocalImportsV1(path, target)
			if err != nil {
				return err
			}
			if !selected {
				return nil
			}
			graph[packagePath] = append(graph[packagePath], imports...)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}

	// Expand every repository-local import discovered from the seed trees. A
	// narrow filesystem walk is not a transitive import graph: a release root
	// could otherwise reach an owner-only package through an intermediate
	// package located outside the seed directories.
	for {
		pending := make([]string, 0)
		for _, imports := range graph {
			for _, imported := range imports {
				if _, loaded := graph[imported]; !loaded {
					pending = append(pending, imported)
				}
			}
		}
		sort.Strings(pending)
		pending = slices.Compact(pending)
		if len(pending) == 0 {
			break
		}
		for _, packagePath := range pending {
			base := filepath.Join(root, filepath.FromSlash(packagePath))
			entries, err := os.ReadDir(base)
			if err != nil {
				return nil, fmt.Errorf("load import package %s: %w", packagePath, err)
			}
			// Mark the package loaded even when it has no local imports so the
			// closure terminates deterministically.
			selectedPackage := false
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				imports, selected, err := selectedLocalImportsV1(filepath.Join(base, entry.Name()), target)
				if err != nil {
					return nil, err
				}
				if !selected {
					continue
				}
				selectedPackage = true
				graph[packagePath] = append(graph[packagePath], imports...)
			}
			if !selectedPackage {
				return nil, fmt.Errorf("target %s: imported package %s has no selected source", target.name, packagePath)
			}
		}
	}
	for path := range graph {
		sort.Strings(graph[path])
		graph[path] = slices.Compact(graph[path])
	}
	return graph, nil
}

func localImportsV1(path string) ([]string, error) {
	file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
	if err != nil {
		return nil, err
	}
	imports := make([]string, 0, len(file.Imports))
	for _, imported := range file.Imports {
		importPath := strings.Trim(imported.Path.Value, `"`)
		if strings.HasPrefix(importPath, modulePath+"/") {
			imports = append(imports, strings.TrimPrefix(importPath, modulePath+"/"))
		}
	}
	return imports, nil
}

func validateLiveProgramConversionImportGraphV1(graph map[string][]string) error {
	const compilerBoundary = "internal/protocol/liveprogramcompile"
	releaseRoots := []string{"internal/androidbridge", "internal/product", "internal/runtime", "cmd/kandroidbridge"}
	for source := range graph {
		if !packageWithinAnyV1(source, releaseRoots) {
			continue
		}
		if path := importReachabilityV1(graph, source, func(imported string) bool { return imported == compilerBoundary }); len(path) != 0 {
			return fmt.Errorf("live-program release root %s reaches owner compiler through %s", source, strings.Join(path, " -> "))
		}
	}

	for source, imports := range graph {
		if !slices.Contains(imports, compilerBoundary) {
			continue
		}
		// Keep the compiler at the final owner CLI boundary. internal/selfhost
		// is also linked by the Android bridge, so allowing it here would make
		// the release-path transitive guard depend on package topology.
		if source != "cmd/kurdctl" {
			return fmt.Errorf("live-program compiler importer %s is not owner tooling", source)
		}
	}

	forbiddenLiveDependencies := []string{"internal/protocol/ir", "internal/protocol/compiler", "internal/testkit", "internal/lab"}
	if path := importReachabilityV1(graph, "internal/protocol/liveprogram", func(imported string) bool {
		return packageWithinAnyV1(imported, forbiddenLiveDependencies)
	}); len(path) != 0 {
		return fmt.Errorf("live-program runtime package reaches forbidden dependency through %s", strings.Join(path, " -> "))
	}
	return nil
}

func packageWithinAnyV1(packagePath string, roots []string) bool {
	for _, root := range roots {
		if packagePath == root || strings.HasPrefix(packagePath, root+"/") {
			return true
		}
	}
	return false
}

func importReachabilityV1(graph map[string][]string, source string, forbidden func(string) bool) []string {
	type route struct{ path []string }
	queue := []route{{path: []string{source}}}
	seen := map[string]bool{source: true}
	for len(queue) != 0 {
		current := queue[0]
		queue = queue[1:]
		last := current.path[len(current.path)-1]
		for _, imported := range graph[last] {
			next := append(append([]string(nil), current.path...), imported)
			if forbidden(imported) {
				return next
			}
			if !seen[imported] {
				seen[imported] = true
				queue = append(queue, route{path: next})
			}
		}
	}
	return nil
}

func assertNoImportV1(t *testing.T, root, sourceRoot, forbidden string) {
	t.Helper()
	base := filepath.Join(root, filepath.FromSlash(sourceRoot))
	err := filepath.WalkDir(base, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if importPath == forbidden || strings.HasPrefix(importPath, forbidden+"/") {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("release boundary %s imports owner-only dependency %s", filepath.ToSlash(rel), importPath)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestPhase17QualificationScannerAndConverterBoundariesV1(t *testing.T) {
	root := repoRoot(t)
	for _, sourceRoot := range []string{"cmd/phase17scan", "internal/phase17privacy/scannera"} {
		assertNoImportV1(t, root, sourceRoot, modulePath+"/internal/phase17evidence")
		assertNoImportV1(t, root, sourceRoot, modulePath+"/internal/phase17qualification")
	}

	runnerRoot := filepath.Join(root, "cmd", "phase17field")
	err := filepath.WalkDir(runnerRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, forbidden := range []string{
			modulePath + "/cmd/phase17evidence",
			"phase17evidence.exe",
			"./cmd/phase17evidence",
		} {
			if bytes.Contains(raw, []byte(forbidden)) {
				relative, _ := filepath.Rel(root, path)
				t.Errorf("active Phase 17 runner %s reaches offline evidence converter %q", filepath.ToSlash(relative), forbidden)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedStrictBoundaryDiscoveredStrictPathsV1(t *testing.T) {
	root := repoRoot(t)
	strictDeclarations := 0
	const ownerSeamPath = "internal/runtime/protected_channel.go"
	const ownerSeamName = "newStrictProtectedChannelWithLabFaultV1"
	const ownerSeamSignature = "func newStrictProtectedChannelWithLabFaultV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, token labfault.Token) (*strictProtectedChannelV1, error)"
	wantOwnerMints := map[string]int{"reused_nonce": 1, "accepts_replay": 1, "runtime_accepts_replay": 1, "runtime_no_state_validation": 1}
	ownerSeamDeclarations := 0
	err := filepath.WalkDir(filepath.Join(root, "internal", "runtime"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			if strings.Contains(strings.Trim(imp.Path.Value, `"`), "/internal/testkit") {
				t.Errorf("runtime production file imports testkit: %s", path)
			}
		}
		for _, declaration := range file.Decls {
			name := ""
			var body ast.Node
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				name, body = value.Name.Name, value.Body
				if name == ownerSeamName {
					rel, _ := filepath.Rel(root, path)
					if filepath.ToSlash(rel) != ownerSeamPath {
						t.Errorf("strict owner seam moved or duplicated at %s", filepath.ToSlash(rel))
					}
					ownerSeamDeclarations++
					raw, readErr := os.ReadFile(path)
					if readErr != nil || !strings.Contains(string(raw), ownerSeamSignature+" {") {
						t.Errorf("strict owner seam signature drift: %v", readErr)
					}
					foundMints := map[string]int{}
					ast.Inspect(value.Body, func(node ast.Node) bool {
						call, ok := node.(*ast.CallExpr)
						if !ok || len(call.Args) != 1 {
							return true
						}
						selector, ok := call.Fun.(*ast.SelectorExpr)
						literal, literalOK := call.Args[0].(*ast.BasicLit)
						if ok && literalOK && selector.Sel.Name == "NewTokenV1" && literal.Kind == token.STRING {
							foundMints[strings.Trim(literal.Value, `"`)]++
						}
						return true
					})
					if len(foundMints) != len(wantOwnerMints) {
						t.Errorf("strict owner seam mint set drift: got=%v want=%v", foundMints, wantOwnerMints)
					}
					for mint, count := range wantOwnerMints {
						if foundMints[mint] != count {
							t.Errorf("strict owner seam mint %q count=%d want=%d", mint, foundMints[mint], count)
						}
					}
				}
			case *ast.GenDecl:
				for _, spec := range value.Specs {
					if typeSpec, ok := spec.(*ast.TypeSpec); ok && strings.Contains(strings.ToLower(typeSpec.Name.Name), "strict") {
						strictDeclarations++
					}
				}
				continue
			}
			if !strings.Contains(strings.ToLower(name), "strict") || body == nil {
				continue
			}
			strictDeclarations++
			ast.Inspect(body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && (selector.Sel.Name == "NewTokenV1" || selector.Sel.Name == "NewAuthLabFaultTokenV1") && name != ownerSeamName {
					t.Errorf("discovered strict path %s reaches lab mint %s", name, selector.Sel.Name)
				}
				literal, ok := node.(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					text := strings.ToLower(literal.Value)
					if strings.Contains(text, "runtime-session:") || strings.Contains(text, "testkeyhex") || strings.Contains(text, "default_secret") {
						t.Errorf("discovered strict path %s embeds unsafe shortcut %s", name, literal.Value)
					}
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strictDeclarations < 20 {
		t.Fatalf("strict discovery indexed only %d declarations", strictDeclarations)
	}
	if ownerSeamDeclarations != 1 {
		t.Fatalf("strict owner seam declarations=%d want=1", ownerSeamDeclarations)
	}
}

func TestLegacyModelAllowlistV1(t *testing.T) {
	root := repoRoot(t)
	want := map[string]bool{
		"internal/runtime/secure_channel.go|func|BuildSecurityContext": true, "internal/runtime/secure_channel.go|func|NewSecureChannel": true,
		"internal/runtime/config.go|func|DefaultConfig": true, "internal/runtime/manager.go|type|Runtime": true,
		"internal/runtime/manager.go|type|Manager": true, "internal/runtime/manager.go|func|NewRuntime": true,
		"internal/runtime/manager.go|func|NewRuntimeFromPath": true, "internal/runtime/manager.go|func|NewManager": true,
		"internal/runtime/session.go|type|Session": true, "internal/runtime/session.go|func|NewSession": true,
		"internal/runtime/stream_manager.go|type|StreamManager": true, "internal/runtime/stream_manager.go|func|NewStreamManager": true,
		"internal/runtime/adapter_boundary.go|func|RunAdapterBoundary": true, "internal/relay/relay.go|func|ServeEcho": true,
		"internal/relay/relay.go|func|Serve": true, "internal/relay/relay.go|func|HandleServerConn": true,
		"internal/relay/relay.go|func|ClientRoundTrip": true, "internal/relay/relay.go|func|ClientHandshake": true,
		"internal/relay/relay.go|func|ServerHandshake": true, "cmd/kclient/main.go|package|main": true,
		"cmd/kserver/main.go|package|main": true, "cmd/kecho/main.go|package|main": true,
		"cmd/ktrace/main.go|package|main": true, "internal/codegen/generator_templates.go|const-series|genTmpl001..genTmpl210": true,
	}
	seen := map[string]bool{}
	for _, row := range legacyCompatibilityInventoryV1 {
		key := row.Path + "|" + row.Kind + "|" + row.Name
		if !want[key] || seen[key] || row.Status != "exact legacy/model allowlist" || row.Evidence == "" {
			t.Fatalf("invalid legacy compatibility row: %+v", row)
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join(root, filepath.FromSlash(row.Path)), nil, 0)
		if err != nil {
			t.Fatalf("legacy compatibility parse %s: %v", key, err)
		}
		matches := 0
		series := map[string]bool{}
		if row.Kind == "package" && file.Name.Name == row.Name {
			matches++
		}
		for _, declaration := range file.Decls {
			switch value := declaration.(type) {
			case *ast.FuncDecl:
				if row.Kind == "func" && value.Recv == nil && value.Name.Name == row.Name {
					matches++
				}
			case *ast.GenDecl:
				for _, spec := range value.Specs {
					switch item := spec.(type) {
					case *ast.TypeSpec:
						if row.Kind == "type" && item.Name.Name == row.Name {
							matches++
						}
					case *ast.ValueSpec:
						for _, name := range item.Names {
							if row.Kind == "const" && value.Tok == token.CONST && name.Name == row.Name {
								matches++
							}
							if row.Kind == "const-series" && value.Tok == token.CONST {
								series[name.Name] = true
							}
						}
					}
				}
			}
		}
		if row.Kind == "const-series" {
			matches = 0
			for index := 1; index <= 210; index++ {
				name := fmt.Sprintf("genTmpl%03d", index)
				if series[name] {
					matches++
				}
			}
			if len(series) != 210 {
				t.Fatalf("legacy compatibility template series broadened: declarations=%d want=210", len(series))
			}
			if matches == 210 {
				matches = 1
			}
		}
		if matches != 1 {
			t.Fatalf("legacy compatibility exact declaration drift %s matches=%d", key, matches)
		}
		seen[key] = true
	}
	if len(seen) != len(want) {
		t.Fatalf("legacy compatibility membership seen=%v want=%v", seen, want)
	}
}

func TestNoLabShortcutInventoryCoverageV1(t *testing.T) {
	root := repoRoot(t)
	want := map[string]bool{}
	for _, row := range shortcutInventoryV1 {
		if row.Category == "lab_token_mint" || row.Category == "lab_token_consumer" {
			want[row.Path] = true
		}
	}
	found := map[string]bool{}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		text := string(raw)
		if strings.Contains(text, "func NewAuthLabFaultTokenV1") || strings.Contains(text, "func NewTokenV1") || strings.Contains(text, "NewAuthLabFaultTokenV1(") || strings.Contains(text, "labfault.NewTokenV1(") {
			rel, _ := filepath.Rel(root, path)
			found[filepath.ToSlash(rel)] = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(found) != len(want) {
		t.Fatalf("lab shortcut inventory found=%v want=%v", found, want)
	}
	for path := range found {
		if !want[path] {
			t.Fatalf("unclassified lab shortcut: %s", path)
		}
	}
}

func TestLabReachabilityRecurrenceV1(t *testing.T) {
	TestRealMutantCorpusMintAllowlistV1(t)
	TestRuntimeLabExecutorAllowlistV1(t)
}

// forbiddenImportPrefixes are import paths the runtime must not depend on.
var forbiddenImportPrefixes = []string{
	modulePath + "/internal/contracts/",
	modulePath + "/internal/operator/",
	modulePath + "/internal/product/",
}

func hasForbiddenImportPrefixV1(importPath string) bool {
	for _, prefix := range forbiddenImportPrefixes {
		if importPath == strings.TrimSuffix(prefix, "/") || strings.HasPrefix(importPath, prefix) {
			return true
		}
	}
	return false
}

func TestRuntimeLabExecutorAllowlistV1(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	allowed := map[string]bool{"internal/runtime/lab_executor.go": true, "internal/runtime/lab_executor_test.go": true, "internal/runtime/lifecycle_test.go": true, "internal/runtime/policy_enforcement_test.go": true, "internal/testkit/importrules/importrules_test.go": true, "internal/lab/runtimeadversary/runner.go": true}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			name := entry.Name()
			if name == ".git" || name == ".claude" || name == ".tools" || name == "planning" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		raw, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if !strings.Contains(string(raw), "ExecuteRuntimeLabFaultV1") {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		rel = filepath.ToSlash(rel)
		if !allowed[rel] {
			t.Errorf("unauthorized facade reachability: %s", rel)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeRaw, err := os.ReadFile(filepath.Join(root, "internal/runtime/lab_executor.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(runtimeRaw), "internal/testkit") || strings.Contains(string(runtimeRaw), "encoding/json") || strings.Contains(string(runtimeRaw), "os.") || strings.Contains(string(runtimeRaw), "net.") || strings.Contains(string(runtimeRaw), "log.") {
		t.Fatal("runtime lab facade reaches forbidden sink or testkit")
	}
}

func TestRealMutantCorpusMintAllowlistV1(t *testing.T) {
	root := repoRoot(t)
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			text := string(raw)
			matched := strings.Contains(text, "NewAuthLabFaultTokenV1") || strings.Contains(text, "labfault.NewTokenV1")
			if !matched {
				return nil
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			ownerAuth := strings.HasPrefix(rel, "internal/crypto/auth/")
			ownerRuntimeFiles := map[string]bool{"internal/runtime/lab_executor.go": true, "internal/runtime/link.go": true, "internal/runtime/loopback_pair.go": true, "internal/runtime/protected_channel.go": true, "internal/runtime/trace.go": true}
			ownerRuntime := ownerRuntimeFiles[rel] || strings.HasPrefix(rel, "internal/runtime/") && strings.HasSuffix(rel, "_test.go") || strings.HasPrefix(rel, "internal/runtime/labfault/")
			mutantFacade := rel == "internal/testkit/mutant/fault.go" || rel == "internal/testkit/mutant/fault_test.go"
			guardSelf := rel == "internal/testkit/importrules/importrules_test.go"
			if !ownerAuth && !ownerRuntime && !mutantFacade && !guardSelf {
				t.Errorf("unauthorized sealed-token mint reachability: %s", rel)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	mutantRaw, err := os.ReadFile(filepath.Join(root, "internal", "testkit", "mutant", "fault.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(mutantRaw), modulePath+"/internal/runtime\"") || strings.Contains(string(mutantRaw), modulePath+"/internal/runtime/") && !strings.Contains(string(mutantRaw), modulePath+"/internal/runtime/labfault") {
		t.Fatal("mutant mint facade imports root runtime")
	}
}

func TestLabFaultCapabilityCannotReachNormalPaths(t *testing.T) {
	root := repoRoot(t)
	fset := token.NewFileSet()
	forbiddenImporters := []string{
		modulePath + "/internal/protocol",
		modulePath + "/internal/runtime",
		modulePath + "/internal/product",
		modulePath + "/internal/codegen",
		modulePath + "/cmd/",
	}
	allowedCapabilityCallers := []string{
		modulePath + "/internal/lab/",
		modulePath + "/internal/testkit/mutant",
	}
	var violations []string

	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			pkgPath := modulePath + "/" + filepath.ToSlash(rel)
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			file, err := parser.ParseFile(fset, path, raw, 0)
			if err != nil {
				return err
			}
			for _, imp := range file.Imports {
				ip := strings.Trim(imp.Path.Value, `"`)
				if ip == modulePath+"/internal/testkit/mutant" && hasPrefixAny(pkgPath, forbiddenImporters) {
					violations = append(violations, pkgPath+" imports the lab fault owner")
				}
				if ip == modulePath+"/internal/lab/runtimeadversary" && hasPrefixAny(pkgPath, forbiddenImporters) {
					violations = append(violations, pkgPath+" imports the lab fault runner")
				}
			}
			if hasPrefixAny(pkgPath, []string{
				modulePath + "/internal/protocol",
				modulePath + "/internal/product",
				modulePath + "/internal/codegen",
				modulePath + "/cmd/",
			}) {
				for _, symbol := range []string{"AcquireRuntimeFault", "NewSecureChannelForLab", "runtime_accepts_replay"} {
					if strings.Contains(string(raw), symbol) {
						violations = append(violations, pkgPath+" contains lab fault symbol "+symbol)
					}
				}
			}
			allowed := hasPrefixAny(pkgPath, allowedCapabilityCallers)
			ast.Inspect(file, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.CallExpr:
					name := ""
					switch function := value.Fun.(type) {
					case *ast.SelectorExpr:
						name = function.Sel.Name
					case *ast.Ident:
						name = function.Name
					}
					if (name == "AcquireRuntimeFault" || name == "NewSecureChannelForLab") && !allowed {
						violations = append(violations, pkgPath+" calls "+name)
					}
				case *ast.FuncDecl:
					if value.Recv != nil && value.Name.Name == "RuntimeFaultMode" && !allowed {
						violations = append(violations, pkgPath+" implements RuntimeFaultMode")
					}
				case *ast.CompositeLit:
					selector, ok := value.Type.(*ast.SelectorExpr)
					if ok && selector.Sel.Name == "RuntimeFaultCapability" && !allowed {
						violations = append(violations, pkgPath+" constructs RuntimeFaultCapability")
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("lab fault capability escaped its lab/test boundary (%d violation(s)):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

func TestLegacyLabSeamRemovedV1(t *testing.T) {
	root := repoRoot(t)
	forbidden := []string{"LabFault" + "Capability", "NewSecureChannel" + "ForLab", "RuntimeFault" + "Capability", "AcquireRuntime" + "Fault", "RuntimeFault" + "Mode"}
	var findings []string
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return walkErr
			}
			if entry.IsDir() || !strings.HasSuffix(path, ".go") || filepath.Clean(path) == filepath.Clean(filepath.Join(root, "internal", "testkit", "importrules", "importrules_test.go")) {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			ast.Inspect(file, func(node ast.Node) bool {
				ident, ok := node.(*ast.Ident)
				if !ok {
					return true
				}
				for _, symbol := range forbidden {
					if ident.Name == symbol {
						rel, _ := filepath.Rel(root, path)
						findings = append(findings, filepath.ToSlash(rel)+" contains "+symbol)
					}
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(findings) != 0 {
		t.Fatalf("legacy lab seam reintroduced:\n  %s", strings.Join(findings, "\n  "))
	}
}

func TestVersionMigrationBoundaryCurrentSourceAndInjectedV1(t *testing.T) {
	sources := migrationBoundarySourcesV1(t)
	if findings := offlineMigrationFindingsV1(sources); len(findings) != 0 {
		t.Fatalf("current migration boundary:\n  %s", strings.Join(findings, "\n  "))
	}
	mutants := map[string]string{
		"internal/runtime/injected.go": `package runtime
import "kurdistan/internal/crypto/profilemigration"
func injected(raw []byte, token profilemigration.MigrationAuthorizationV1) { _, _, _ = profilemigration.MigrateProfileV1(raw, token) }`,
		"cmd/kgen/injected.go": `package main
func injected(raw []byte) { DecodeLegacyProfileForMigrationV1(raw) }`,
		"internal/product/android/injected.go": `package android
func injected(raw []byte) { MigrateProfileV1(raw, token) }`,
	}
	for path, source := range mutants {
		if findings := offlineMigrationFindingsV1(map[string]string{path: source}); len(findings) == 0 {
			t.Fatalf("migration mutant accepted: %s", path)
		}
	}
}

func TestOfflineMigrationReachabilityAllowlistV1(t *testing.T) {
	sources := migrationBoundarySourcesV1(t)
	allowedCalls := map[string]bool{
		"internal/crypto/profilemigration/migration_v1.go":      true,
		"internal/crypto/profilemigration/migration_v1_test.go": true,
		"internal/protocol/ir/migration_v1_test.go":             true,
	}
	for path, source := range sources {
		if strings.HasSuffix(path, "_test.go") && !allowedCalls[path] {
			continue
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imported := range file.Imports {
			if strings.Trim(imported.Path.Value, `"`) == modulePath+"/internal/crypto/profilemigration" && !strings.HasPrefix(path, "internal/crypto/profilemigration/") {
				t.Fatalf("offline migration import escaped leaf: %s", path)
			}
		}
	}
	if len(allowedCalls) != 3 {
		t.Fatal("offline migration allowlist cardinality")
	}
}

func TestGeneratedAuthorizationBoundaryInjectedV1(t *testing.T) {
	root := repoRoot(t)
	runtimeSources := map[string]string{}
	err := filepath.WalkDir(filepath.Join(root, "internal", "runtime"), func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(root, path)
		runtimeSources[filepath.ToSlash(rel)] = string(raw)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if findings := runtimeAuthorizationFindingsV1(runtimeSources); len(findings) != 0 {
		t.Fatalf("runtime authorization recurrence:\n  %s", strings.Join(findings, "\n  "))
	}
	for _, tree := range []string{"internal/product", "internal/relay"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(tree)), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return walkErr
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			if generatedAuthorizationForbiddenV1(string(raw)) {
				rel, _ := filepath.Rel(root, path)
				t.Errorf("product/relay embeds generated authorization: %s", filepath.ToSlash(rel))
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for name, source := range map[string]string{
		"catalog":      `package product; var x codegen.AuthorizationCatalogV1`,
		"pin":          `package runtime; const AuthorizationPinV1 = "pin"`,
		"derived":      `package runtime; func f(){ AuthorizationFromProfile(profile) }`,
		"default":      `package runtime; func f(){ DefaultClientProfileAuthorization` + `RegistryV1() }`,
		"legacy-reach": `package product; import _ "kurdistan/generated/example/protocol"`,
	} {
		if !generatedAuthorizationForbiddenV1(source) {
			t.Fatalf("authorization mutant %s accepted", name)
		}
	}
	for path, source := range map[string]string{
		"internal/runtime/manager.go": `package runtime
func NewRuntime(){ NewClientProfileAuthorization` + `RegistryV1(nil) }`,
		"internal/runtime/handshake.go": `package runtime
func NewStrictHandshakeRuntimeV1(){ _ = ClientProfileAuthorization` + `EntryV1{} }`,
		"internal/runtime/factory.go": `package runtime
func Build(){ AuthorizationFromProfile(profile) }`,
		"internal/runtime/generated_escape.go": `package runtime
import _ "kurdistan/generated/example/protocol"`,
	} {
		if findings := runtimeAuthorizationFindingsV1(map[string]string{path: source}); len(findings) == 0 {
			t.Fatalf("real-source authorization mutant accepted: %s", path)
		}
	}
	codegenRaw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "authorization_v1.go"))
	if err != nil || !strings.Contains(string(codegenRaw), "type AuthorizationCatalogV1 struct") {
		t.Fatalf("codegen catalog DTO ownership drift: %v", err)
	}
}

func TestM3ProfileLifecycleBoundaryV1(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]map[string]bool{
		"internal/product/envelope":  {"bytes": true, "encoding/base64": true, "encoding/binary": true, "errors": true, "fmt": true, "github.com/fxamacker/cbor/v2": true, "math/big": true, "net/url": true, "sort": true, "strconv": true, "strings": true, "time": true},
		"internal/product/profile":   {"bytes": true, "crypto/sha256": true, "encoding/hex": true, "errors": true, "fmt": true, "github.com/fxamacker/cbor/v2": true, "reflect": true, "slices": true, "sort": true, "strings": true, "time": true, modulePath + "/internal/product/envelope": true, modulePath + "/internal/product/lifecycle": true},
		"internal/product/lifecycle": {"errors": true, "strings": true},
	}
	allowedTests := map[string]map[string]bool{
		"internal/product/envelope":  {"bytes": true, "crypto/ecdh": true, "crypto/ecdsa": true, "crypto/elliptic": true, "crypto/hpke": true, "crypto/rand": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true, "github.com/fxamacker/cbor/v2": true, "io": true, "math/big": true, "os": true, "os/exec": true, "path/filepath": true, "runtime": true, "strings": true, "sync": true, "testing": true, "testing/cryptotest": true, "time": true, modulePath + "/internal/testkit/phase8assurance": true},
		"internal/product/profile":   {"bytes": true, "crypto/ecdh": true, "crypto/elliptic": true, "crypto/hmac": true, "crypto/hpke": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true, "math/big": true, "os": true, "path/filepath": true, "reflect": true, "sort": true, "strings": true, "testing": true, "time": true, modulePath + "/internal/product/envelope": true, modulePath + "/internal/product/lifecycle": true, modulePath + "/internal/product/profile": true, modulePath + "/internal/testkit/evidenceoverlay": true, modulePath + "/internal/testkit/phase8issuance": true, modulePath + "/internal/testkit/phase8issuancefixture": true},
		"internal/product/lifecycle": {"testing": true},
	}
	for pkg, imports := range allowed {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(pkg)), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return walkErr
			}
			fileImports := imports
			if strings.HasSuffix(path, "_test.go") {
				fileImports = allowedTests[pkg]
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range file.Imports {
				name := strings.Trim(imported.Path.Value, `"`)
				if !fileImports[name] {
					if name == "unsafe" {
						rel, err := filepath.Rel(root, path)
						if err != nil {
							return err
						}
						full, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ParseComments)
						if err != nil {
							return err
						}
						if phase18SizeofTestImportAllowedV1(filepath.ToSlash(rel), full) {
							continue
						}
					}
					t.Errorf("M3 contract %s imports forbidden dependency %s", pkg, name)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	envelopeRaw, err := os.ReadFile(filepath.Join(root, "internal", "product", "envelope", "envelope.go"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(envelopeRaw), modulePath+"/internal/product/profile") || strings.Contains(string(envelopeRaw), modulePath+"/internal/product/lifecycle") {
		t.Fatal("envelope depends on profile lifecycle")
	}
	for name, source := range map[string]string{
		"network": `package profile; import "net/http"`,
		"storage": `package lifecycle; import "os"`,
		"runtime": `package profile; import "kurdistan/internal/runtime"`,
		"crypto":  `package profile; import "crypto/ed25519"`,
		"reverse": `package envelope; import "kurdistan/internal/product/profile"`,
	} {
		file, err := parser.ParseFile(token.NewFileSet(), name+".go", source, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		blocked := false
		for _, imported := range file.Imports {
			path := strings.Trim(imported.Path.Value, `"`)
			if path == "net/http" || path == "os" || path == "crypto/ed25519" || path == modulePath+"/internal/runtime" || path == modulePath+"/internal/product/profile" {
				blocked = true
			}
		}
		if !blocked {
			t.Fatalf("M3 boundary mutant %s accepted", name)
		}
	}
}

func TestM4FallbackBoundaryV1(t *testing.T) {
	root := repoRoot(t)
	want := map[string]bool{"errors": true, "fmt": true, "strings": true, modulePath + "/internal/contracts/carrier/carrierreview": true, modulePath + "/internal/product/lifecycle": true}
	dir := filepath.Join(root, "internal", "product", "strategy")
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			name := strings.Trim(imported.Path.Value, `"`)
			if !want[name] {
				t.Errorf("M4 strategy imports forbidden dependency %s", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{"net/", "os/exec", "internal/runtime", "internal/relay", "internal/product/android"}
	raw, err := os.ReadFile(filepath.Join(dir, "strategy.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range forbidden {
		if strings.Contains(string(raw), marker) {
			t.Fatalf("M4 strategy contains forbidden capability %q", marker)
		}
	}
}

func TestM5RelayDescriptorBoundaryV1(t *testing.T) {
	root := repoRoot(t)
	want := map[string]bool{"errors": true, "reflect": true, "strings": true, modulePath + "/internal/product/strategy": true}
	dir := filepath.Join(root, "internal", "product", "relaydescriptor")
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			name := strings.Trim(imported.Path.Value, `"`)
			if !want[name] {
				t.Errorf("M5 relaydescriptor imports forbidden dependency %s", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "relaydescriptor.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"net/", "time", "os/", "internal/runtime", "internal/relay", "internal/operator", "internal/crypto", "internal/product/android"} {
		if strings.Contains(string(raw), marker) {
			t.Fatalf("M5 relaydescriptor contains forbidden capability %q", marker)
		}
	}
}

func TestM6DiagnosticExportBoundaryV1(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{"encoding/json": true, "errors": true, "reflect": true, "sort": true}
	dir := filepath.Join(root, "internal", "product", "diagnosticexport")
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			name := strings.Trim(imported.Path.Value, `"`)
			if !allowed[name] {
				t.Errorf("M6 diagnosticexport imports forbidden dependency %s", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, tree := range []string{"internal/runtime", "internal/product/lifecycle", "internal/product/strategy", "internal/product/relaydescriptor"} {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(tree)), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range file.Imports {
				if strings.Trim(imported.Path.Value, `"`) == modulePath+"/internal/product/diagnosticexport" {
					t.Errorf("diagnostic export must not grant product/runtime control authority: %s", filepath.ToSlash(path))
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestM7AppRuntimeBoundaryV1(t *testing.T) {
	root := repoRoot(t)
	allowed := map[string]bool{
		"errors": true, "reflect": true, "strings": true,
		modulePath + "/internal/product/lifecycle":       true,
		modulePath + "/internal/product/strategy":        true,
		modulePath + "/internal/product/relaydescriptor": true,
	}
	dir := filepath.Join(root, "internal", "product", "appruntime")
	err := filepath.WalkDir(dir, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return walkErr
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imported := range file.Imports {
			name := strings.Trim(imported.Path.Value, `"`)
			if !allowed[name] {
				t.Errorf("M7 appruntime imports forbidden dependency %s", name)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "appruntime.go"))
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"net/", "time.", "os/", "sync.", "internal/runtime", "internal/relay", "internal/operator", "internal/crypto", "internal/product/android", "internal/product/diagnosticexport"} {
		if strings.Contains(string(raw), marker) {
			t.Fatalf("M7 appruntime contains forbidden capability %q", marker)
		}
	}
}

func TestNoLabShortcutStrictSurfaceAndInjectedV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, "internal", "codegen", "generator_templates.go"))
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	start := strings.LastIndex(source, "func strictRuntimeTemplateV1() string")
	if start < 0 {
		t.Fatal("strict template owner missing")
	}
	strictOwner := source[start:]
	for _, forbidden := range []string{"internal/lab", "internal/testkit", "StaticProfile", "AuthorizationCatalogV1", "AuthorizationPinV1", "DefaultRegistry", "test-only-key", "secret", "credential", "payload", "destination"} {
		if strings.Contains(strings.ToLower(strictOwner), strings.ToLower(forbidden)) {
			t.Fatalf("strict template owner contains %q", forbidden)
		}
	}
	for name, emitted := range map[string]string{
		"lab-import":       "package strictv1\nimport _ \"kurdistan/internal/lab/fixtures\"",
		"testkit-import":   "package strictv1\nimport _ \"kurdistan/internal/testkit/mutant\"",
		"global":           "package strictv1\nvar x = build()",
		"secret":           "package strictv1\nconst Secret = \"fixed\"",
		"default":          "package strictv1\nfunc DefaultRuntime(){}",
		"missing-registry": "package strictv1\nfunc NewStrictRuntimeV1(){}",
		"generic-registry": "package strictv1\ntype AuthorizationRegistryV1 interface{}\nfunc NewStrictRuntimeV1(r AuthorizationRegistryV1){}",
		"cross-role":       "package strictv1\nfunc NewStrictRuntimeV1(clientRegistry, relayRegistry ClientProfileAuthorization" + "RegistryV1){}",
		"catalog-pin":      "package strictv1\nconst AuthorizationPinV1 = 1",
		"derived-registry": "package strictv1\nfunc NewStrictRuntimeV1(){ AuthorizationFromProfile(profile) }",
	} {
		if !strictSurfaceForbiddenV1(emitted) {
			t.Fatalf("strict mutant %s accepted", name)
		}
	}
}

func migrationBoundarySourcesV1(t *testing.T) map[string]string {
	t.Helper()
	root := repoRoot(t)
	out := map[string]string{}
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") {
				return walkErr
			}
			raw, err := os.ReadFile(path)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			out[filepath.ToSlash(rel)] = string(raw)
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	return out
}

func offlineMigrationFindingsV1(sources map[string]string) []string {
	var findings []string
	for path, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			findings = append(findings, path+": parse")
			continue
		}
		leaf := strings.HasPrefix(path, "internal/crypto/profilemigration/")
		irTest := path == "internal/protocol/ir/migration_v1_test.go"
		for _, imported := range file.Imports {
			if strings.Trim(imported.Path.Value, `"`) == modulePath+"/internal/crypto/profilemigration" && !leaf {
				findings = append(findings, path+": profilemigration import")
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := ""
			switch called := call.Fun.(type) {
			case *ast.Ident:
				name = called.Name
			case *ast.SelectorExpr:
				name = called.Sel.Name
			}
			if (name == "MigrateProfileV1" || name == "NewMigrationAuthorizationV1") && !leaf || name == "DecodeLegacyProfileForMigrationV1" && !leaf && !irTest {
				findings = append(findings, path+": "+name)
			}
			return true
		})
	}
	sort.Strings(findings)
	return findings
}

func generatedAuthorizationForbiddenV1(source string) bool {
	for _, forbidden := range []string{"AuthorizationCatalogV1", "AuthorizationPinV1", "AuthorizationFromProfile", "DefaultClientProfileAuthorization" + "RegistryV1", "DefaultRelayProfileAuthorization" + "RegistryV1", "/generated/", "strictv1/protocol", "strictv1/cmd"} {
		if strings.Contains(source, forbidden) {
			return true
		}
	}
	return false
}

func runtimeAuthorizationFindingsV1(sources map[string]string) []string {
	var findings []string
	for path, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), path, source, 0)
		if err != nil {
			findings = append(findings, path+": parse")
			continue
		}
		owner := path == "internal/runtime/implementation_support.go"
		labFactory := path == "internal/runtime/lab_pair_factory.go"
		handshake := path == "internal/runtime/handshake.go"
		for _, forbidden := range []string{
			"AuthorizationCatalogV1", "AuthorizationPinV1", "AuthorizationFromProfile",
			"DefaultClientProfileAuthorization" + "RegistryV1", "DefaultRelayProfileAuthorization" + "RegistryV1",
			modulePath + "/generated/", "/generated/", "strictv1/protocol", "strictv1/cmd",
		} {
			if strings.Contains(source, forbidden) {
				findings = append(findings, path+": "+forbidden)
			}
		}
		ast.Inspect(file, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.CallExpr:
				name := ""
				switch called := value.Fun.(type) {
				case *ast.Ident:
					name = called.Name
				case *ast.SelectorExpr:
					name = called.Sel.Name
				}
				if (name == "NewClientProfileAuthorization"+"RegistryV1" || name == "NewRelayProfileAuthorization"+"RegistryV1") && !owner && !labFactory {
					findings = append(findings, path+": "+name)
				}
			case *ast.CompositeLit:
				name := ""
				if ident, ok := value.Type.(*ast.Ident); ok {
					name = ident.Name
				}
				if (name == "ClientProfileAuthorization"+"EntryV1" || name == "RelayProfileAuthorization"+"EntryV1") && !owner && !labFactory {
					findings = append(findings, path+": "+name)
				}
			case *ast.Ident:
				if (value.Name == "ClientProfileAuthorization"+"RegistryV1" || value.Name == "RelayProfileAuthorization"+"RegistryV1") && !owner && !labFactory && !handshake {
					findings = append(findings, path+": "+value.Name)
				}
			}
			return true
		})
	}
	sort.Strings(findings)
	return findings
}

func strictSurfaceForbiddenV1(source string) bool {
	lower := strings.ToLower(source)
	for _, forbidden := range []string{"internal/lab", "internal/testkit", "secret", "default", "var ", "init(", "authorizationcatalogv1", "authorizationpinv1", "authorizationfromprofile", "authorizationregistryv1 interface"} {
		if strings.Contains(lower, forbidden) {
			return true
		}
	}
	if strings.Contains(source, "package strictv1") {
		if !strings.Contains(source, "NewStrictRuntimeV1") || strings.Count(source, "ClientProfileAuthorization"+"RegistryV1") != 1 || strings.Count(source, "RelayProfileAuthorization"+"RegistryV1") != 1 {
			return true
		}
	}
	return false
}

func TestVersionMigrationBoundaryDeterministicPostScopeManifestV1(t *testing.T) {
	root := repoRoot(t)
	const sealedRepoState = "fe1f8b853cfd2ff790cefc1f7da7b70dfee0e4a6c67b8ed16140b51541e51610"
	const priorLifecycleSHA256 = "117d07f338342048e0d5c48cf41021828b70abd7d68aaa7cafdfb1d7a3469ad5"
	for label, value := range map[string]string{"authorized_repo_state": sealedRepoState, "prior_lifecycle": priorLifecycleSHA256} {
		decoded, err := hex.DecodeString(value)
		if err != nil || len(decoded) != sha256.Size {
			t.Fatalf("invalid sealed %s binding", label)
		}
	}
	if _, err := validatePhase17LiveDataPlaneOverlayV1(root); err != nil {
		t.Fatal(err)
	}
	if err := committedevidence.VerifyHistoricalSet(root, "WO-044", []committedevidence.ExpectedEntry{
		{Path: "internal/testkit/importrules/importrules_test.go", PreEvidence: "UNRECORDED"},
		{Path: "docs/KZ-evidence-ref-021", PreEvidence: "UNRECORDED"},
		{Path: "docs/KZ-evidence-ref-013", PreEvidence: "UNRECORDED"},
		{Path: "docs/KZ-evidence-ref-014", PreEvidence: "UNRECORDED"},
		{Path: "README.md", PreEvidence: "UNRECORDED"},
		{Path: "internal/runtime/policy_enforcement_test.go", PreEvidence: "UNRECORDED"},
	}); err != nil {
		t.Fatal(err)
	}
	t.Logf("WO-044-SEALED-BASE authorized_repo_state=%s prior_lifecycle_sha256=%s; exact per-file pre-WO hashes were not captured and are not claimed", sealedRepoState, priorLifecycleSHA256)
}

type committedMaintenanceEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PreSHA256   string `json:"pre_sha256"`
	PostSHA256  string `json:"post_sha256"`
}

type phase17LiveDataPlaneOverlayV1 struct {
	Version                  string                        `json:"version"`
	SelfPath                 string                        `json:"self_path"`
	SelfPreEvidence          string                        `json:"self_pre_evidence"`
	SelfPreSHA256            string                        `json:"self_pre_sha256"`
	PredecessorBindingSHA256 string                        `json:"predecessor_binding_sha256"`
	Entries                  []committedMaintenanceEntryV1 `json:"entries"`
	SuccessorEntries         []phase17SuccessorEntryV1     `json:"successor_entries"`
	SuccessorEntriesV2       []phase17SuccessorEntryV1     `json:"successor_entries_v2"`
}

type phase17SuccessorEntryV1 struct {
	Path         string `json:"path"`
	PreEvidence  string `json:"pre_evidence"`
	PreSHA256    string `json:"pre_sha256"`
	PostEvidence string `json:"post_evidence"`
	PostSHA256   string `json:"post_sha256"`
}

var phase17LiveDataPlanePathsV1 = []string{
	"cmd/phase17verify/main.go",
	"cmd/phase17verify/main_test.go",
	"config/runtime/live-data-plane-v1.json",
	"docs/protocol/KURD-WIRE-V1-LIVE.md",
	"docs/self-hosting/LIVE-DATA-PLANE.md",
	"internal/product/runtimepolicy/policy_v2.go",
	"internal/product/runtimepolicy/policy_v2_fuzz_test.go",
	"internal/product/runtimepolicy/policy_v2_test.go",
	"internal/protocol/framing/codec.go",
	"internal/protocol/framing/codec_spec_v1.go",
	"internal/protocol/framing/codec_test.go",
	"internal/protocol/ir/effective_projection_v1.go",
	"internal/protocol/ir/effective_projection_v1_test.go",
	"internal/protocol/liveprogram/codec_v1.go",
	"internal/protocol/liveprogram/codec_v1_fuzz_test.go",
	"internal/protocol/liveprogram/program_v1.go",
	"internal/protocol/liveprogram/program_v1_test.go",
	"internal/protocol/liveprogramcompile/compile_v1.go",
	"internal/protocol/liveprogramcompile/compile_v1_test.go",
	"internal/protocol/scheduler/scheduler.go",
	"internal/protocol/scheduler/scheduler_test.go",
}

func loadPhase17LiveDataPlaneOverlayV1(root string) (phase17LiveDataPlaneOverlayV1, error) {
	raw, err := evidenceoverlay.ReadSubjectFile(root, evidenceoverlay.Phase17SuccessorPath)
	if err != nil {
		return phase17LiveDataPlaneOverlayV1{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var overlay phase17LiveDataPlaneOverlayV1
	if err := decoder.Decode(&overlay); err != nil {
		return phase17LiveDataPlaneOverlayV1{}, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("phase17 live-data-plane trailing JSON")
	}
	return overlay, nil
}

func validatePhase17LiveDataPlaneOverlayV1(root string) (phase17LiveDataPlaneOverlayV1, error) {
	overlay, err := loadPhase17LiveDataPlaneOverlayV1(root)
	if err != nil {
		return phase17LiveDataPlaneOverlayV1{}, err
	}
	return validatePhase17LiveDataPlaneOverlayAtPostV1(root, nil, overlay)
}

func validatePhase17LiveDataPlaneOverlayAtPostV1(root string, currentAtPost map[string]string, overlay phase17LiveDataPlaneOverlayV1) (phase17LiveDataPlaneOverlayV1, error) {
	const name = "phase17-live-data-plane-v1"
	const predecessorBinding = "77772a0daab7ba1bd148fcd437ee1c18be535bb0c4272cbc0f84d5dc0b764cf4"
	if overlay.Version != name || overlay.SelfPath != evidenceoverlay.Phase17SuccessorPath || overlay.SelfPreEvidence != "ABSENT" || overlay.SelfPreSHA256 != "" || overlay.PredecessorBindingSHA256 != predecessorBinding || len(overlay.Entries) != len(phase17LiveDataPlanePathsV1) || len(overlay.SuccessorEntries) > evidenceoverlay.Phase17SuccessorEntryLimit || len(overlay.SuccessorEntriesV2) > evidenceoverlay.Phase17SuccessorEntryLimit {
		return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 live-data-plane overlay identity/cardinality")
	}
	baseAtSuccessorV2, err := phase17SuccessorPreAtPostV1(root, currentAtPost, overlay.SuccessorEntriesV2)
	if err != nil {
		return phase17LiveDataPlaneOverlayV1{}, err
	}
	baseAtPost, err := phase17SuccessorPreAtPostV1(root, baseAtSuccessorV2, overlay.SuccessorEntries)
	if err != nil {
		return phase17LiveDataPlaneOverlayV1{}, err
	}
	binding := sha256.New()
	_, _ = fmt.Fprintf(binding, "%s\x00ABSENT\n", overlay.SelfPath)
	last := ""
	for index, path := range phase17LiveDataPlanePathsV1 {
		entry := overlay.Entries[index]
		if entry.Path != path || path <= last || strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") || !validCommittedSHA256V1(entry.PostSHA256) {
			return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 live-data-plane entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, present := baseAtPost[path]
		if !present {
			content, err := evidenceoverlay.ReadSubjectFile(root, path)
			if err != nil {
				return phase17LiveDataPlaneOverlayV1{}, err
			}
			actual = fmt.Sprintf("%x", sha256.Sum256(content))
		}
		if actual != entry.PostSHA256 {
			return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("phase17 live-data-plane hash drift %s=%s want %s", path, actual, entry.PostSHA256)
		}
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 predecessor binding")
	}
	return overlay, nil
}

func phase17SuccessorPreAtPostV1(root string, currentAtPost map[string]string, entries []phase17SuccessorEntryV1) (map[string]string, error) {
	pre := make(map[string]string, len(currentAtPost)+len(entries))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	last := ""
	for index, entry := range entries {
		if entry.Path <= last || strings.HasPrefix(entry.Path, ".tools/") || strings.HasPrefix(entry.Path, "planning/") {
			return nil, fmt.Errorf("invalid phase17 successor entry %d", index)
		}
		post := entry.PostSHA256
		if entry.PostEvidence == "ABSENT" {
			if entry.PostSHA256 != "" {
				return nil, fmt.Errorf("invalid phase17 absent successor post-state %d", index)
			}
			post = "ABSENT"
		} else if entry.PostEvidence != "" || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase17 successor post-state %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase17 absent successor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) {
			return nil, fmt.Errorf("invalid phase17 successor predecessor %d", index)
		}
		if predecessor == post {
			return nil, fmt.Errorf("phase17 successor entry does not change state %d", index)
		}
		actual, found := pre[entry.Path]
		if !found {
			var err error
			actual, err = evidenceoverlay.SubjectState(root, entry.Path)
			if err != nil {
				return nil, err
			}
		}
		if actual != post {
			return nil, fmt.Errorf("phase17 successor hash drift %s=%s want %s", entry.Path, actual, post)
		}
		pre[entry.Path] = predecessor
		last = entry.Path
	}
	return pre, nil
}

func validCommittedSHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

// allowedImporterPrefixes are the only package paths permitted to import the
// forbidden trees: the analysis/generation tooling that audits, hardens, or
// generates from the models, plus the quarantined trees themselves (intra-tree
// references are fine). The boundary's intent is that the product RUNTIME must
// not depend on models — not that no tool may; analysis tooling legitimately
// consumes them.
var allowedImporterPrefixes = []string{
	modulePath + "/internal/contracts/",
	modulePath + "/internal/product/",
	modulePath + "/internal/audit",
	modulePath + "/internal/codegen",
	modulePath + "/internal/lab/hardening",
	modulePath + "/cmd/kcheck",
	modulePath + "/internal/testkit/phase8fixturegen",
	modulePath + "/internal/testkit/phase8resourcecapture",
}

func phase8ProductConsumerV1(pkgPath string) bool {
	return pkgPath == modulePath+"/cmd/kprofile" ||
		pkgPath == modulePath+"/cmd/kandroidbridge" ||
		pkgPath == modulePath+"/cmd/phase16androidverify" ||
		pkgPath == modulePath+"/internal/androidbridge" ||
		pkgPath == modulePath+"/internal/selfhost" ||
		pkgPath == modulePath+"/internal/testkit/phase8issuance" ||
		pkgPath == modulePath+"/internal/testkit/phase8issuancefixture" ||
		strings.HasPrefix(pkgPath, modulePath+"/cmd/kprofile/") ||
		strings.HasPrefix(pkgPath, modulePath+"/cmd/phase16androidverify/") ||
		strings.HasPrefix(pkgPath, modulePath+"/internal/selfhost/") ||
		strings.HasPrefix(pkgPath, modulePath+"/internal/testkit/phase8issuance/") ||
		strings.HasPrefix(pkgPath, modulePath+"/internal/testkit/phase8issuancefixture/")
}

func TestPhase16SelfHostProductConsumerBoundaryV1(t *testing.T) {
	for _, pkgPath := range []string{
		modulePath + "/cmd/phase16androidverify",
		modulePath + "/internal/selfhost",
		modulePath + "/internal/selfhost/adapter",
	} {
		if !phase8ProductConsumerV1(pkgPath) {
			t.Fatalf("Phase 16 product consumer rejected: %s", pkgPath)
		}
	}
	for _, pkgPath := range []string{
		modulePath + "/cmd/phase16androidverify-helper",
		modulePath + "/internal/runtime",
		modulePath + "/internal/selfhoster",
	} {
		if phase8ProductConsumerV1(pkgPath) {
			t.Fatalf("Phase 16 product consumer boundary widened: %s", pkgPath)
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("go.mod not found walking up from test dir")
		}
		dir = parent
	}
}

func hasPrefixAny(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

var phase12BoundaryImportAllowlistV1 = map[string]map[string]bool{
	"internal/operator/controlplane/authority_state.go": {
		modulePath + "/internal/product/profile": true,
	},
	"internal/operator/controlplane/controlplane_test.go": {
		modulePath + "/internal/product/profile": true,
	},
	"internal/operator/controlplane/model.go": {
		modulePath + "/internal/product/profile": true,
	},
	"internal/operator/controlplane/phase_boundaries.go": {
		modulePath + "/internal/product/profile":     true,
		modulePath + "/internal/product/sessionplan": true,
	},
	"internal/operator/controlplane/phase_boundaries_test.go": {
		modulePath + "/internal/contracts/carrier/carrierreview": true,
		modulePath + "/internal/product/envelope":                true,
		modulePath + "/internal/product/lifecycle":               true,
		modulePath + "/internal/product/profile":                 true,
		modulePath + "/internal/product/relaydescriptor":         true,
		modulePath + "/internal/product/sessionplan":             true,
		modulePath + "/internal/product/strategy":                true,
	},
	"internal/operator/controlplane/reconcile_test.go": {
		modulePath + "/internal/product/profile": true,
	},
	"internal/operator/controlplane/service.go": {
		modulePath + "/internal/product/profile": true,
	},
	"internal/operator/controlplane/state.go": {
		modulePath + "/internal/product/envelope": true,
	},
	"cmd/koperator/main.go": {
		modulePath + "/internal/contracts/carrier/carrierreview": true,
		modulePath + "/internal/operator/controlplane":           true,
		modulePath + "/internal/product/envelope":                true,
		modulePath + "/internal/product/lifecycle":               true,
		modulePath + "/internal/product/profile":                 true,
		modulePath + "/internal/product/relaydescriptor":         true,
		modulePath + "/internal/product/sessionplan":             true,
		modulePath + "/internal/product/strategy":                true,
	},
	"cmd/koperator/main_test.go": {
		modulePath + "/internal/operator/controlplane": true,
	},
}

func phase12BoundaryImportAllowedV1(file, importPath string) bool {
	return phase12BoundaryImportAllowlistV1[file][importPath]
}

var phase17ProfileHPKEImportAllowlistV1 = map[string]map[string]bool{
	"internal/crypto/profilehpke/provider.go": {
		modulePath + "/internal/product/envelope": true,
		modulePath + "/internal/product/profile":  true,
	},
	"internal/crypto/profilehpke/provider_test.go": {
		modulePath + "/internal/product/envelope": true,
		modulePath + "/internal/product/profile":  true,
	},
}

func phase17ProfileHPKEImportAllowedV1(file, importPath string) bool {
	return phase17ProfileHPKEImportAllowlistV1[file][importPath]
}

var phase17KurdctlProductImportAllowlistV1 = map[string]map[string]bool{
	"cmd/kurdctl/main.go": {
		modulePath + "/internal/product/enrollment": true,
		modulePath + "/internal/product/envelope":   true,
	},
	"cmd/kurdctl/main_test.go": {
		modulePath + "/internal/product/enrollment": true,
	},
}

func phase17KurdctlProductImportAllowedV1(file, importPath string) bool {
	return phase17KurdctlProductImportAllowlistV1[file][importPath]
}

var phase17RelayNodeProductImportAllowlistV1 = map[string]map[string]bool{
	"internal/relay/node/server.go": {
		modulePath + "/internal/product/sessionplan": true,
	},
}

func phase17RelayNodeProductImportAllowedV1(file, importPath string) bool {
	return phase17RelayNodeProductImportAllowlistV1[file][importPath]
}

func TestPhase17ProfileHPKEImportExceptionsV1(t *testing.T) {
	want := map[string][]string{
		"internal/crypto/profilehpke/provider.go": {
			modulePath + "/internal/product/envelope",
			modulePath + "/internal/product/profile",
		},
		"internal/crypto/profilehpke/provider_test.go": {
			modulePath + "/internal/product/envelope",
			modulePath + "/internal/product/profile",
		},
	}
	wantCount := 0
	for file, imports := range want {
		wantCount += len(imports)
		for _, importPath := range imports {
			if !phase17ProfileHPKEImportAllowedV1(file, importPath) {
				t.Fatalf("Phase 17 profile HPKE boundary rejected intended import %s -> %s", file, importPath)
			}
		}
	}
	gotCount := 0
	for _, imports := range phase17ProfileHPKEImportAllowlistV1 {
		gotCount += len(imports)
	}
	if len(phase17ProfileHPKEImportAllowlistV1) != len(want) || gotCount != wantCount {
		t.Fatalf("Phase 17 profile HPKE boundary cardinality files=%d imports=%d want files=%d imports=%d",
			len(phase17ProfileHPKEImportAllowlistV1), gotCount, len(want), wantCount)
	}
	for name, mutant := range map[string]struct {
		file       string
		importPath string
	}{
		"extra production file": {
			file:       "internal/crypto/profilehpke/helper.go",
			importPath: modulePath + "/internal/product/profile",
		},
		"extra test file": {
			file:       "internal/crypto/profilehpke/provider_fuzz_test.go",
			importPath: modulePath + "/internal/product/envelope",
		},
		"dependency expansion": {
			file:       "internal/crypto/profilehpke/provider.go",
			importPath: modulePath + "/internal/product/lifecycle",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if phase17ProfileHPKEImportAllowedV1(mutant.file, mutant.importPath) {
				t.Fatalf("Phase 17 profile HPKE boundary accepted mutant %s -> %s", mutant.file, mutant.importPath)
			}
		})
	}
}

func TestPhase17KurdctlProductImportExceptionsV1(t *testing.T) {
	want := map[string][]string{
		"cmd/kurdctl/main.go": {
			modulePath + "/internal/product/enrollment",
			modulePath + "/internal/product/envelope",
		},
		"cmd/kurdctl/main_test.go": {
			modulePath + "/internal/product/enrollment",
		},
	}
	wantCount := 0
	for file, imports := range want {
		wantCount += len(imports)
		for _, importPath := range imports {
			if !phase17KurdctlProductImportAllowedV1(file, importPath) {
				t.Fatalf("missing exact kurdctl product exception %s -> %s", file, importPath)
			}
		}
	}
	actualCount := 0
	for file, imports := range phase17KurdctlProductImportAllowlistV1 {
		actualCount += len(imports)
		if _, ok := want[file]; !ok {
			t.Fatalf("unexpected kurdctl product exception file %s", file)
		}
	}
	if actualCount != wantCount {
		t.Fatalf("kurdctl product exception count=%d want=%d", actualCount, wantCount)
	}
	if phase17KurdctlProductImportAllowedV1("cmd/kurdctl/liveprogram.go", modulePath+"/internal/product/profile") {
		t.Fatal("unlisted kurdctl product import was accepted")
	}
}

func TestPhase17RelayNodeProductImportExceptionsV1(t *testing.T) {
	const file = "internal/relay/node/server.go"
	const importPath = modulePath + "/internal/product/sessionplan"
	if !phase17RelayNodeProductImportAllowedV1(file, importPath) {
		t.Fatalf("missing exact relay node product exception %s -> %s", file, importPath)
	}
	if len(phase17RelayNodeProductImportAllowlistV1) != 1 || len(phase17RelayNodeProductImportAllowlistV1[file]) != 1 {
		t.Fatal("relay node product exception cardinality widened")
	}
	for name, mutant := range map[string]struct {
		file       string
		importPath string
	}{
		"extra relay file": {
			file:       "internal/relay/node/session.go",
			importPath: importPath,
		},
		"dependency expansion": {
			file:       file,
			importPath: modulePath + "/internal/product/profile",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if phase17RelayNodeProductImportAllowedV1(mutant.file, mutant.importPath) {
				t.Fatalf("relay node product boundary accepted mutant %s -> %s", mutant.file, mutant.importPath)
			}
		})
	}
}

func TestPhase12BoundaryImportExceptionsV1(t *testing.T) {
	allowed := map[string][]string{
		"internal/operator/controlplane/authority_state.go": {
			modulePath + "/internal/product/profile",
		},
		"internal/operator/controlplane/controlplane_test.go": {
			modulePath + "/internal/product/profile",
		},
		"internal/operator/controlplane/model.go": {
			modulePath + "/internal/product/profile",
		},
		"internal/operator/controlplane/phase_boundaries.go": {
			modulePath + "/internal/product/profile",
			modulePath + "/internal/product/sessionplan",
		},
		"internal/operator/controlplane/phase_boundaries_test.go": {
			modulePath + "/internal/contracts/carrier/carrierreview",
			modulePath + "/internal/product/envelope",
			modulePath + "/internal/product/lifecycle",
			modulePath + "/internal/product/profile",
			modulePath + "/internal/product/relaydescriptor",
			modulePath + "/internal/product/sessionplan",
			modulePath + "/internal/product/strategy",
		},
		"internal/operator/controlplane/reconcile_test.go": {
			modulePath + "/internal/product/profile",
		},
		"internal/operator/controlplane/service.go": {
			modulePath + "/internal/product/profile",
		},
		"internal/operator/controlplane/state.go": {
			modulePath + "/internal/product/envelope",
		},
		"cmd/koperator/main.go": {
			modulePath + "/internal/contracts/carrier/carrierreview",
			modulePath + "/internal/operator/controlplane",
			modulePath + "/internal/product/envelope",
			modulePath + "/internal/product/lifecycle",
			modulePath + "/internal/product/profile",
			modulePath + "/internal/product/relaydescriptor",
			modulePath + "/internal/product/sessionplan",
			modulePath + "/internal/product/strategy",
		},
		"cmd/koperator/main_test.go": {
			modulePath + "/internal/operator/controlplane",
		},
	}
	wantCount := 0
	for file, imports := range allowed {
		wantCount += len(imports)
		for _, importPath := range imports {
			if !phase12BoundaryImportAllowedV1(file, importPath) {
				t.Fatalf("Phase 12 boundary rejected intended import %s -> %s", file, importPath)
			}
		}
	}
	gotCount := 0
	for _, imports := range phase12BoundaryImportAllowlistV1 {
		gotCount += len(imports)
	}
	if gotCount != wantCount {
		t.Fatalf("Phase 12 boundary allowlist cardinality=%d want %d", gotCount, wantCount)
	}
	for name, mutant := range map[string]struct {
		file       string
		importPath string
	}{
		"extra operator file": {
			file:       "internal/operator/controlplane/journal.go",
			importPath: modulePath + "/internal/product/profile",
		},
		"operator dependency expansion": {
			file:       "internal/operator/controlplane/service.go",
			importPath: modulePath + "/internal/product/sessionplan",
		},
		"command dependency expansion": {
			file:       "cmd/koperator/main.go",
			importPath: modulePath + "/internal/product/diagnosticexport",
		},
		"sibling command": {
			file:       "cmd/koperator-helper/main.go",
			importPath: modulePath + "/internal/operator/controlplane",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if phase12BoundaryImportAllowedV1(mutant.file, mutant.importPath) {
				t.Fatalf("Phase 12 boundary accepted mutant %s -> %s", mutant.file, mutant.importPath)
			}
		})
	}
}

func TestPhase12ReviewedImportEdgeMutationsV1(t *testing.T) {
	clone := func() map[string]map[string]bool {
		result := make(map[string]map[string]bool, len(phase12BoundaryImportAllowlistV1))
		for file, imports := range phase12BoundaryImportAllowlistV1 {
			result[file] = make(map[string]bool, len(imports))
			for importPath, allowed := range imports {
				result[file][importPath] = allowed
			}
		}
		return result
	}
	validate := func(candidate map[string]map[string]bool) error {
		if len(candidate) != len(phase12BoundaryImportAllowlistV1) {
			return fmt.Errorf("file cardinality mismatch")
		}
		for file, expectedImports := range phase12BoundaryImportAllowlistV1 {
			actualImports, ok := candidate[file]
			if !ok || len(actualImports) != len(expectedImports) {
				return fmt.Errorf("edge cardinality mismatch for %s", file)
			}
			for importPath := range expectedImports {
				if !actualImports[importPath] {
					return fmt.Errorf("missing reviewed edge %s -> %s", file, importPath)
				}
			}
		}
		return nil
	}
	mutations := map[string]func(map[string]map[string]bool){
		"delete-authority-edge": func(candidate map[string]map[string]bool) {
			delete(candidate["internal/operator/controlplane/authority_state.go"], modulePath+"/internal/product/profile")
		},
		"substitute-authority-edge": func(candidate map[string]map[string]bool) {
			imports := candidate["internal/operator/controlplane/authority_state.go"]
			delete(imports, modulePath+"/internal/product/profile")
			imports[modulePath+"/internal/product/sessionplan"] = true
		},
		"add-authority-edge": func(candidate map[string]map[string]bool) {
			candidate["internal/operator/controlplane/authority_state.go"][modulePath+"/internal/product/sessionplan"] = true
		},
		"delete-state-edge": func(candidate map[string]map[string]bool) {
			delete(candidate["internal/operator/controlplane/state.go"], modulePath+"/internal/product/envelope")
		},
		"substitute-state-edge": func(candidate map[string]map[string]bool) {
			imports := candidate["internal/operator/controlplane/state.go"]
			delete(imports, modulePath+"/internal/product/envelope")
			imports[modulePath+"/internal/product/profile"] = true
		},
		"add-state-edge": func(candidate map[string]map[string]bool) {
			candidate["internal/operator/controlplane/state.go"][modulePath+"/internal/product/profile"] = true
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			candidate := clone()
			mutate(candidate)
			if err := validate(candidate); err == nil {
				t.Fatal("reviewed Phase 12 import edge mutation accepted")
			}
		})
	}
}

func TestPhase17LiveDataPlaneOverlayMutationsV1(t *testing.T) {
	root := repoRoot(t)
	overlay, err := loadPhase17LiveDataPlaneOverlayV1(root)
	if err != nil {
		t.Fatal(err)
	}
	clone := func() phase17LiveDataPlaneOverlayV1 {
		encoded, err := json.Marshal(overlay)
		if err != nil {
			t.Fatal(err)
		}
		var copy phase17LiveDataPlaneOverlayV1
		if err := json.Unmarshal(encoded, &copy); err != nil {
			t.Fatal(err)
		}
		return copy
	}
	if _, err := validatePhase17LiveDataPlaneOverlayAtPostV1(root, nil, clone()); err != nil {
		t.Fatal(err)
	}
	if len(overlay.Entries) < 2 || overlay.Entries[0].PreEvidence != "ABSENT" {
		t.Fatalf("invalid Phase 17 mutation fixture: %+v", overlay)
	}
	mutations := map[string]func(*phase17LiveDataPlaneOverlayV1){
		"missing-overlay": func(v *phase17LiveDataPlaneOverlayV1) { *v = phase17LiveDataPlaneOverlayV1{} },
		"unknown-path": func(v *phase17LiveDataPlaneOverlayV1) {
			v.Entries[0].Path = "cmd/phase17verify/unknown.go"
		},
		"duplicate-path": func(v *phase17LiveDataPlaneOverlayV1) {
			v.Entries[1] = v.Entries[0]
		},
		"reordered-path": func(v *phase17LiveDataPlaneOverlayV1) {
			v.Entries[0], v.Entries[1] = v.Entries[1], v.Entries[0]
		},
		"pre-hash": func(v *phase17LiveDataPlaneOverlayV1) {
			v.Entries[len(v.Entries)-1].PreSHA256 = strings.Repeat("1", 64)
		},
		"absent-misuse": func(v *phase17LiveDataPlaneOverlayV1) {
			v.Entries[0].PreSHA256 = strings.Repeat("2", 64)
		},
		"post-hash": func(v *phase17LiveDataPlaneOverlayV1) {
			v.Entries[0].PostSHA256 = strings.Repeat("3", 64)
		},
		"predecessor-binding": func(v *phase17LiveDataPlaneOverlayV1) {
			v.PredecessorBindingSHA256 = strings.Repeat("4", 64)
		},
	}
	for mutation, mutate := range mutations {
		t.Run(mutation, func(t *testing.T) {
			candidate := clone()
			mutate(&candidate)
			if _, err := validatePhase17LiveDataPlaneOverlayAtPostV1(root, nil, candidate); err == nil {
				t.Fatal("Phase 17 mutation accepted")
			}
		})
	}
	t.Run("changed-added-file", func(t *testing.T) {
		current := map[string]string{overlay.Entries[0].Path: strings.Repeat("4", 64)}
		if _, err := validatePhase17LiveDataPlaneOverlayAtPostV1(root, current, clone()); err == nil {
			t.Fatal("changed Phase 17 added file accepted")
		}
	})
	deletionIndex := -1
	for index, entry := range overlay.SuccessorEntriesV2 {
		if entry.PostEvidence == "ABSENT" {
			deletionIndex = index
			break
		}
	}
	if deletionIndex < 0 {
		t.Fatal("Phase 17 successor-v2 fixture has no deletion entry")
	}
	t.Run("deletion-with-post-hash", func(t *testing.T) {
		candidate := clone()
		candidate.SuccessorEntriesV2[deletionIndex].PostSHA256 = strings.Repeat("5", 64)
		if _, err := validatePhase17LiveDataPlaneOverlayAtPostV1(root, nil, candidate); err == nil {
			t.Fatal("Phase 17 deletion with a post hash accepted")
		}
	})
	t.Run("deleted-path-present", func(t *testing.T) {
		candidate := clone()
		entry := candidate.SuccessorEntriesV2[deletionIndex]
		current := map[string]string{entry.Path: entry.PreSHA256}
		if _, err := validatePhase17LiveDataPlaneOverlayAtPostV1(root, current, candidate); err == nil {
			t.Fatal("present Phase 17 successor deletion path accepted")
		}
	})
}

func TestRuntimeDoesNotImportContracts(t *testing.T) {
	root := repoRoot(t)
	violations, err := contractImportViolationsV1(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(violations) > 0 {
		t.Fatalf("runtime/real packages must not import contracts/product and product packages must not import operator authority (%d violation(s)):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
	}
}

func contractImportViolationsV1(root string) ([]string, error) {
	fset := token.NewFileSet()
	var violations []string

	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			rel, err := filepath.Rel(root, filepath.Dir(path))
			if err != nil {
				return err
			}
			pkgPath := modulePath + "/" + filepath.ToSlash(rel)
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			relFile, err := filepath.Rel(root, path)
			if err != nil {
				return err
			}
			file := filepath.ToSlash(relFile)
			for _, imp := range f.Imports {
				ip := strings.Trim(imp.Path.Value, `"`)
				if phase17ProfileHPKEImportAllowedV1(file, ip) || phase17KurdctlProductImportAllowedV1(file, ip) || phase17RelayNodeProductImportAllowedV1(file, ip) || phase18RuntimeProductImportAllowlistV1[file][ip] {
					continue
				}
				if strings.HasPrefix(pkgPath, modulePath+"/internal/product/") &&
					(ip == modulePath+"/internal/operator" || strings.HasPrefix(ip, modulePath+"/internal/operator/")) {
					if !phase12BoundaryImportAllowedV1(file, ip) {
						violations = append(violations, file+": "+pkgPath+" imports "+ip)
					}
					continue
				}
				if hasPrefixAny(pkgPath, allowedImporterPrefixes) {
					continue
				}
				if phase8ProductConsumerV1(pkgPath) && strings.HasPrefix(ip, modulePath+"/internal/product/") {
					continue
				}
				if hasForbiddenImportPrefixV1(ip) {
					if phase12BoundaryImportAllowedV1(file, ip) {
						continue
					}
					violations = append(violations, file+": "+pkgPath+" imports "+ip)
				}
			}
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	sort.Strings(violations)
	return violations, nil
}

func TestProductOperatorReverseDependencyMutationV1(t *testing.T) {
	root := t.TempDir()
	write := func(relative, source string) {
		t.Helper()
		path := filepath.Join(root, filepath.FromSlash(relative))
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(source), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("internal/product/backup/mutant.go", `package backup
import _ "kurdistan/internal/operator/controlplane"
`)
	write("internal/product/backup/root_mutant.go", `package backup
import _ "kurdistan/internal/operator"
`)
	write("internal/product/backup/legitimate.go", `package backup
import _ "kurdistan/internal/product/profile"
`)
	write("internal/operator/controlplane/service.go", `package controlplane
import _ "kurdistan/internal/product/profile"
`)
	if err := os.MkdirAll(filepath.Join(root, "cmd"), 0o755); err != nil {
		t.Fatal(err)
	}
	violations, err := contractImportViolationsV1(root)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"internal/product/backup/mutant.go: " + modulePath + "/internal/product/backup imports " + modulePath + "/internal/operator/controlplane",
		"internal/product/backup/root_mutant.go: " + modulePath + "/internal/product/backup imports " + modulePath + "/internal/operator",
	}
	if !slices.Equal(violations, want) {
		t.Fatalf("product-to-operator mutations were not isolated: got=%v want=%v", violations, want)
	}
}

func TestStrictRelayReachabilityCompatibilityAllowlistV1(t *testing.T) {
	root := repoRoot(t)
	compatibilityAllowlist := []string{
		"internal/relay.Serve", "internal/relay.ServeEcho", "internal/relay.HandleServerConn", "internal/relay.ClientRoundTrip",
		"internal/relay.ClientHandshake", "internal/relay.ServerHandshake", "internal/protocol/framing.ReadOperation",
		"internal/protocol/framing.WriteOperation", "cmd/kclient", "cmd/kserver", "cmd/kecho", "internal/codegen/templates.go",
		"generated-* outputs", "*_bench_test.go and testing.B benchmark paths",
	}
	forbiddenCalls := map[string]struct{}{
		"Serve": {}, "ServeEcho": {}, "HandleServerConn": {}, "ClientRoundTrip": {}, "ClientHandshake": {}, "ServerHandshake": {},
		"ReadOperation": {}, "WriteOperation": {}, "Dial": {}, "DialContext": {}, "Listen": {}, "Accept": {},
		"LookupHost": {}, "LookupIP": {}, "ResolveTCPAddr": {}, "NewSecureChannel": {}, "BuildSecurityContext": {},
	}
	fset := token.NewFileSet()
	runtimeRoot := filepath.Join(root, "internal", "runtime")
	type indexedDecl struct {
		name, file             string
		receiver, receiverName string
		decl                   *ast.FuncDecl
		imports                []*ast.ImportSpec
	}
	var declarations []*indexedDecl
	byFunctionName := make(map[string][]*indexedDecl)
	byMethod := make(map[string][]*indexedDecl)
	structFields := make(map[string]map[string]string)
	baseTypeName := func(expression ast.Expr) string {
		for {
			switch value := expression.(type) {
			case *ast.Ident:
				return value.Name
			case *ast.StarExpr:
				expression = value.X
			case *ast.ParenExpr:
				expression = value.X
			default:
				return ""
			}
		}
	}
	err := filepath.WalkDir(runtimeRoot, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		name, err := filepath.Rel(runtimeRoot, path)
		if err != nil {
			return err
		}
		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, specification := range general.Specs {
				typeSpec, ok := specification.(*ast.TypeSpec)
				if !ok {
					continue
				}
				structure, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					continue
				}
				fields := make(map[string]string)
				for _, field := range structure.Fields.List {
					fieldType := baseTypeName(field.Type)
					for _, fieldName := range field.Names {
						fields[fieldName.Name] = fieldType
					}
				}
				structFields[typeSpec.Name.Name] = fields
			}
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			receiver, receiverName := "", ""
			if function.Recv != nil && len(function.Recv.List) == 1 {
				receiver = baseTypeName(function.Recv.List[0].Type)
				if len(function.Recv.List[0].Names) == 1 {
					receiverName = function.Recv.List[0].Names[0].Name
				}
			}
			indexed := &indexedDecl{name: function.Name.Name, file: name, receiver: receiver, receiverName: receiverName, decl: function, imports: file.Imports}
			declarations = append(declarations, indexed)
			if receiver == "" {
				byFunctionName[indexed.name] = append(byFunctionName[indexed.name], indexed)
			} else {
				key := receiver + "." + indexed.name
				byMethod[key] = append(byMethod[key], indexed)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	rootNames := map[string]struct{}{
		"NewInProcessProtectedRelay": {}, "validV1": {}, "Seal": {}, "SealFragments": {}, "Deliver": {}, "AcceptAck": {}, "Close": {}, "AcceptClose": {},
	}
	queue := make([]*indexedDecl, 0)
	for _, declaration := range declarations {
		if declaration.file == "loopback_pair.go" {
			if _, root := rootNames[declaration.name]; root {
				queue = append(queue, declaration)
			}
		}
	}
	reached := make(map[*ast.FuncDecl]struct{})
	var receiverType func(ast.Expr, *indexedDecl) string
	receiverType = func(expression ast.Expr, current *indexedDecl) string {
		switch value := expression.(type) {
		case *ast.Ident:
			if value.Name == current.receiverName {
				return current.receiver
			}
		case *ast.SelectorExpr:
			ownerType := receiverType(value.X, current)
			if ownerType != "" {
				return structFields[ownerType][value.Sel.Name]
			}
		case *ast.ParenExpr:
			return receiverType(value.X, current)
		case *ast.StarExpr:
			return receiverType(value.X, current)
		}
		return ""
	}
	for len(queue) > 0 {
		current := queue[0]
		queue = queue[1:]
		if _, seen := reached[current.decl]; seen {
			continue
		}
		reached[current.decl] = struct{}{}
		for _, imported := range current.imports {
			importPath := strings.Trim(imported.Path.Value, `"`)
			if importPath == "net" || strings.HasPrefix(importPath, "net/") || importPath == modulePath+"/internal/relay" || importPath == modulePath+"/internal/protocol/framing" {
				t.Errorf("strict relay reached %s:%s importing forbidden compatibility/network package %s; allowlist=%s", current.file, current.name, importPath, strings.Join(compatibilityAllowlist, ", "))
			}
		}
		ast.Inspect(current.decl.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			called := ""
			var localTargets []*indexedDecl
			switch function := call.Fun.(type) {
			case *ast.Ident:
				called = function.Name
				localTargets = byFunctionName[called]
			case *ast.SelectorExpr:
				called = function.Sel.Name
				if receiver := receiverType(function.X, current); receiver != "" {
					localTargets = byMethod[receiver+"."+called]
				}
			}
			if _, forbidden := forbiddenCalls[called]; forbidden {
				t.Errorf("strict relay reached %s:%s calling forbidden symbol %s; allowlist=%s", current.file, current.name, called, strings.Join(compatibilityAllowlist, ", "))
			}
			queue = append(queue, localTargets...)
			return true
		})
	}
	if len(reached) == 0 {
		t.Fatal("strict relay reachability roots were not indexed")
	}
	reachedNames := make(map[string]struct{}, len(reached))
	for _, declaration := range declarations {
		if _, ok := reached[declaration.decl]; ok {
			reachedNames[declaration.name] = struct{}{}
		}
	}
	for _, required := range []string{
		"newStrictProtectedChannelV1", "sealClientApplicationV1", "openClientApplicationV1",
		"sealRelayAckV1", "openRelayAckV1", "sealClientCloseV1", "openClientCloseV1",
	} {
		if _, ok := reachedNames[required]; !ok {
			t.Errorf("strict relay reachability lost required protected-path declaration %s", required)
		}
	}
	strictPath := filepath.Join(root, "internal", "runtime", "loopback_pair.go")
	raw, err := os.ReadFile(strictPath)
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	if !strings.Contains(source, "newStrictProtectedChannelV1(") || !strings.Contains(source, "NewInProcessProtectedRelay") {
		t.Fatalf("strict relay does not route exclusively through the protected pair channel; allowlist=%s", strings.Join(compatibilityAllowlist, ", "))
	}
	t.Logf("reachability traversed %d local runtime declarations from exported strict relay roots; future dynamic/reflection changes require this recurrence scan to be reviewed and rerun", len(reached))
}
