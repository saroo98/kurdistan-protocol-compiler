// Package importrules enforces the architecture-realignment boundary: the
// product runtime and real libraries must never depend on quarantined
// model/contract code. Only the analysis/generation tooling (audit, codegen,
// kcheck) and contracts/product packages themselves may import
// internal/contracts/** or internal/product/**.
//
// This is the executable form of the Stage 6 contract-import gate.
package importrules

// WO-053 freezes ExecuteRuntimeLabFaultV1 as the sole root-runtime lab facade;
// the existing recurrence scan below remains the owner of external reachability.

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

const modulePath = "kurdistan"

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
		if entry.IsDir() || !strings.HasSuffix(path, ".go") {
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
			if entry.IsDir() || !strings.HasSuffix(path, ".go") {
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
	modulePath + "/internal/product/",
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
			if name == ".git" || name == "planning" {
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
		"internal/product/envelope":  {"errors": true, "fmt": true, "net/url": true, "sort": true, "strings": true, "time": true},
		"internal/product/profile":   {"errors": true, "fmt": true, "strings": true, "time": true, modulePath + "/internal/product/envelope": true},
		"internal/product/lifecycle": {"errors": true},
	}
	for pkg, imports := range allowed {
		err := filepath.WalkDir(filepath.Join(root, filepath.FromSlash(pkg)), func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imported := range file.Imports {
				name := strings.Trim(imported.Path.Value, `"`)
				if !imports[name] {
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
	verifyCommittedEvidenceSetV1(t, root, "WO-044", []committedEvidenceExpectationV1{
		{"internal/testkit/importrules/importrules_test.go", "UNRECORDED"},
		{"docs/KIP-0067-stage6a-version-migration.md", "UNRECORDED"},
		{"docs/KIP-0012-generated-source-backend.md", "UNRECORDED"},
		{"docs/KIP-0013-generated-backend-audit.md", "UNRECORDED"},
		{"README.md", "UNRECORDED"},
		{"internal/runtime/policy_enforcement_test.go", "UNRECORDED"},
	})
	t.Logf("WO-044-SEALED-BASE authorized_repo_state=%s prior_lifecycle_sha256=%s; exact per-file pre-WO hashes were not captured and are not claimed", sealedRepoState, priorLifecycleSHA256)
}

const committedEvidenceManifestPathV1 = "testdata/evidence/phase1-m0-committed-sha256.json"

type committedEvidenceManifestV1 struct {
	Schema                      string                                   `json:"schema"`
	HashAlgorithm               string                                   `json:"hash_algorithm"`
	SourceCandidate             string                                   `json:"source_candidate"`
	Sets                        map[string][]committedEvidenceEntryV1    `json:"sets"`
	MaintenanceOverlays         map[string]committedMaintenanceOverlayV1 `json:"maintenance_overlays"`
	HelperOwnerOverlays         map[string]committedLayeredOverlayV1     `json:"helper_owner_overlays"`
	ValidatorOverlays           map[string]committedLayeredOverlayV1     `json:"validator_overlays"`
	ValidatorConsumerOverlays   map[string]committedLayeredOverlayV1     `json:"validator_consumer_overlays"`
	EvidenceConvergenceOverlays map[string]committedLayeredOverlayV1     `json:"evidence_convergence_overlays"`
	Phase2CompleteOverlays      map[string]phase2CompleteOverlayV1       `json:"phase2_complete_overlays"`
	Phase3ContractOverlays      map[string]phase2CompleteOverlayV1       `json:"phase3_contract_overlays"`
}

type committedMaintenanceOverlayV1 struct {
	Version       string                        `json:"version"`
	SelfPath      string                        `json:"self_path"`
	SelfPreSHA256 string                        `json:"self_pre_sha256"`
	Paths         []string                      `json:"paths"`
	Entries       []committedMaintenanceEntryV1 `json:"entries"`
}

type committedMaintenanceEntryV1 struct {
	Path       string `json:"path"`
	PreSHA256  string `json:"pre_sha256"`
	PostSHA256 string `json:"post_sha256"`
}

type committedLayeredOverlayV1 struct {
	Version                string                        `json:"version"`
	PredecessorManifestSHA string                        `json:"predecessor_manifest_sha256"`
	Entries                []committedMaintenanceEntryV1 `json:"entries"`
}

type phase2CompleteOverlayV1 struct {
	Version                   string                         `json:"version"`
	PredecessorManifestSHA256 string                         `json:"predecessor_manifest_sha256"`
	Paths                     []string                       `json:"paths"`
	Entries                   []phase2CompleteOverlayEntryV1 `json:"entries"`
}

type phase2CompleteOverlayEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

const m2MaintenanceOverlayNameV1 = "m2-governance-foundation-v1"
const m2HelperOverlayNameV1 = "m2-governance-foundation-helper-owners-v1"
const m2HelperOverlayNameV2 = "m2-governance-foundation-helper-owners-v2"
const m2ValidatorOverlayNameV1 = "m2-governance-foundation-validators-v1"
const m2ValidatorConsumerOverlayNameV1 = "m2-governance-foundation-validator-consumer-v1"
const m2EvidenceConvergenceOverlayNameV1 = "m2-governance-foundation-evidence-convergence-v1"
const phase2CompleteOverlayNameV1 = "m2-governance-foundation-phase2-complete-v1"
const phase2PredecessorManifestSHA256V1 = "c89a6be543ec35e68bef3cd6d5a91b685b1a05e523aca264faabc6d4933c398b"

var m2MaintenanceExactPathsV1 = []string{
	"README.md", "ROADMAP.md", "docs/GOVERNANCE.md", "docs/safety.md",
	"internal/audit/security.go", "internal/audit/security_test.go",
	"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go",
	committedEvidenceManifestPathV1,
}

var m2HelperExactPathsV1 = []string{"internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", "cmd/kgen/main_test.go"}
var m2HelperPreV1 = []string{"0874db08bb14f2d94b94b88171f1d78cd87dd34122e6ca39e3eb4ec9942a00ec", "9f1941a9ef49c70aedddddf11890ea97df0563c2b921c75a3300aee713faf9ac", "a80d10983b1e5684faf64011ee482a3a8216f2ab2393fbe9cd7570cbf4d5524d"}
var m2HelperV1PostV1 = []string{"5e7fff88d4e75aadf0b2306c9d9574b76e13a62c585deeebda53ba6a191832d1", "96e6e30ccfe131cfa0384fc4463ac2f75a4e9d0630179233dc40157f7839f30b", "bad5ffb692075048785a98b0c048761f06003462f1a202660b60bddf4c9103e4"}
var m2HelperV2PostV1 = []string{"7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0"}
var m2ValidatorExactPathsV1 = []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go"}
var m2ValidatorPreV1 = []string{"b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136"}
var m2ConvergencePathsV1 = []string{"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go"}
var m2ConvergencePreV1 = []string{"aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0", "7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "985d46009b1ed6c0faade46de2574b940954de92ad6db8de3ddac0e29ea4a3ae", "f6b623b865407412856cbfc1c3748524b47ccae39ad3d33e40bd8977c9dbeab3", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "53f9635f8761701cd2a9ce2762b3004ff3a0143097cb7334930e7b6f086e33b9", "81ae4a98530acc4a643fd824a939aa658eba6f8f6c4857b7978c1ebeb6853c9f"}
var phase2CompletePathsV1 = []string{"README.md", "ROADMAP.md", "cmd/kgen/main_test.go", "docs/GOVERNANCE.md", "docs/KIP-0001-threat-model.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md", "docs/safety.md", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}

type committedEvidenceEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

type committedEvidenceExpectationV1 struct {
	Path        string
	PreEvidence string
}

func verifyCommittedEvidenceSetV1(t *testing.T, root, set string, want []committedEvidenceExpectationV1) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Schema != "kurdistan.phase1-m0.committed-sha256.v1" || manifest.HashAlgorithm != "sha256" || manifest.SourceCandidate != "cad48bb4be28a09a6293944f78724d7026de4c12" {
		t.Fatalf("invalid committed evidence manifest identity: %+v", manifest)
	}
	historicalByPath, err := validateCommittedEvidenceOverlaysV1(root, manifest)
	if err != nil {
		t.Fatal(err)
	}
	requiredSets := map[string]bool{"WO-040": true, "WO-041": true, "WO-042": true, "WO-043": true, "WO-044": true}
	if len(manifest.Sets) != len(requiredSets) {
		t.Fatalf("committed evidence sets=%v", manifest.Sets)
	}
	for name := range manifest.Sets {
		if !requiredSets[name] {
			t.Fatalf("unexpected committed evidence set %q", name)
		}
	}
	entries, ok := manifest.Sets[set]
	if !ok || len(entries) != len(want) {
		t.Fatalf("%s evidence entries=%v want %d", set, entries, len(want))
	}
	for i, expected := range want {
		entry := entries[i]
		if entry.Path != expected.Path || entry.PreEvidence != expected.PreEvidence {
			t.Fatalf("%s evidence[%d]=%+v want path=%s pre=%s", set, i, entry, expected.Path, expected.PreEvidence)
		}
		if entry.Path == committedEvidenceManifestPathV1 || filepath.IsAbs(entry.Path) || filepath.ToSlash(filepath.Clean(entry.Path)) != entry.Path {
			t.Fatalf("%s invalid evidence path %q", set, entry.Path)
		}
		postBytes, err := hex.DecodeString(entry.PostSHA256)
		if err != nil || len(postBytes) != sha256.Size || entry.PostSHA256 != strings.ToLower(entry.PostSHA256) || entry.PostSHA256 == strings.Repeat("0", 64) {
			t.Fatalf("%s invalid post SHA-256 for %s", set, entry.Path)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			preBytes, err := hex.DecodeString(entry.PreEvidence)
			if err != nil || len(preBytes) != sha256.Size || entry.PreEvidence != strings.ToLower(entry.PreEvidence) || entry.PreEvidence == entry.PostSHA256 {
				t.Fatalf("%s invalid pre evidence for %s", set, entry.Path)
			}
		}
		current, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(current)
		post := hex.EncodeToString(sum[:])
		if historical, maintained := historicalByPath[entry.Path]; maintained {
			post = historical
		}
		if post != entry.PostSHA256 {
			t.Fatalf("%s committed SHA-256 %s=%s want %s", set, entry.Path, post, entry.PostSHA256)
		}
		t.Logf("%s-SHA256 %s pre=%s post=%s", set, entry.Path, entry.PreEvidence, post)
	}
}

func validateCommittedEvidenceOverlaysV1(root string, manifest committedEvidenceManifestV1) (map[string]string, error) {
	currentAtM2, err := validatePhase3ContractOverlayV1(root, manifest.Phase3ContractOverlays)
	if err != nil {
		return nil, err
	}
	currentAtPre, err := validatePhase2CompleteOverlayV1(root, currentAtM2, manifest.Phase2CompleteOverlays)
	if err != nil {
		return nil, err
	}
	currentAtPre, err = validateCommittedConvergenceV1(currentAtPre, manifest.EvidenceConvergenceOverlays)
	if err != nil {
		return nil, err
	}
	overlay, ok := manifest.MaintenanceOverlays[m2MaintenanceOverlayNameV1]
	if len(manifest.MaintenanceOverlays) != 1 || !ok {
		return nil, fmt.Errorf("invalid maintenance overlays")
	}
	if overlay.Version != m2MaintenanceOverlayNameV1 || overlay.SelfPath != committedEvidenceManifestPathV1 || len(overlay.Paths) != len(m2MaintenanceExactPathsV1) || len(overlay.Entries) != len(m2MaintenanceExactPathsV1)-1 {
		return nil, fmt.Errorf("invalid M2 maintenance overlay identity/cardinality")
	}
	if !validCommittedSHA256V1(overlay.SelfPreSHA256) {
		return nil, fmt.Errorf("invalid M2 self pre-hash")
	}
	for i, path := range m2MaintenanceExactPathsV1 {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("M2 maintenance path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
	}
	if len(manifest.HelperOwnerOverlays) != 2 {
		return nil, fmt.Errorf("invalid helper overlay count")
	}
	helperV1, ok1 := manifest.HelperOwnerOverlays[m2HelperOverlayNameV1]
	helperV2, ok2 := manifest.HelperOwnerOverlays[m2HelperOverlayNameV2]
	if !ok1 || helperV1.Version != m2HelperOverlayNameV1 || helperV1.PredecessorManifestSHA != "b2a95c93332afbc13c73a4bb08e92067db97e93e843cb55e1f191b9c398e3c7b" || len(helperV1.Entries) != 3 || !ok2 || helperV2.Version != m2HelperOverlayNameV2 || helperV2.PredecessorManifestSHA != "7258697b4806469afea99342d981e96b328114036668e874f7c0e5a597a94cc6" || len(helperV2.Entries) != 3 {
		return nil, fmt.Errorf("invalid helper overlay identity/cardinality")
	}
	historical := map[string]string{overlay.SelfPath: overlay.SelfPreSHA256}
	for i, path := range m2HelperExactPathsV1 {
		oldEntry, newEntry := helperV1.Entries[i], helperV2.Entries[i]
		if oldEntry.Path != path || oldEntry.PreSHA256 != m2HelperPreV1[i] || oldEntry.PostSHA256 != m2HelperV1PostV1[i] || newEntry.Path != path || newEntry.PreSHA256 != oldEntry.PostSHA256 || newEntry.PostSHA256 != m2HelperV2PostV1[i] {
			return nil, fmt.Errorf("invalid helper overlay entry %d", i)
		}
		actual := currentAtPre[path]
		if actual != newEntry.PostSHA256 {
			return nil, fmt.Errorf("helper hash drift %s=%s want %s: %v", path, actual, newEntry.PostSHA256, err)
		}
		historical[path] = oldEntry.PreSHA256
	}
	validators, ok := manifest.ValidatorOverlays[m2ValidatorOverlayNameV1]
	if len(manifest.ValidatorOverlays) != 1 || !ok || validators.Version != m2ValidatorOverlayNameV1 || validators.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(validators.Entries) != 3 {
		return nil, fmt.Errorf("invalid validator overlay identity/cardinality")
	}
	validatorByPath := map[string]committedMaintenanceEntryV1{}
	for i, entry := range validators.Entries {
		if entry.Path != m2ValidatorExactPathsV1[i] || entry.PreSHA256 != m2ValidatorPreV1[i] || !validCommittedSHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
			return nil, fmt.Errorf("invalid validator entry %d", i)
		}
		actual := currentAtPre[entry.Path]
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("validator hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		validatorByPath[entry.Path] = entry
	}
	consumer, ok := manifest.ValidatorConsumerOverlays[m2ValidatorConsumerOverlayNameV1]
	if len(manifest.ValidatorConsumerOverlays) != 1 || !ok || consumer.Version != m2ValidatorConsumerOverlayNameV1 || !validCommittedSHA256V1(consumer.PredecessorManifestSHA) || len(consumer.Entries) != 1 {
		return nil, fmt.Errorf("invalid validator-consumer overlay identity/cardinality")
	}
	consumerEntry := consumer.Entries[0]
	if consumerEntry.Path != "internal/testkit/importrules/importrules_test.go" || consumerEntry.PreSHA256 != "3a170c4752fea63a728d55abff9b0c8a7c91e25e0c98d14bdd4c401e3b56a178" || !validCommittedSHA256V1(consumerEntry.PostSHA256) || consumerEntry.PostSHA256 == consumerEntry.PreSHA256 {
		return nil, fmt.Errorf("invalid validator-consumer entry")
	}
	actualConsumer := currentAtPre[consumerEntry.Path]
	if actualConsumer != consumerEntry.PostSHA256 {
		return nil, fmt.Errorf("validator-consumer hash drift %s=%s want %s: %v", consumerEntry.Path, actualConsumer, consumerEntry.PostSHA256, err)
	}
	for i, entry := range overlay.Entries {
		if entry.Path != m2MaintenanceExactPathsV1[i] || entry.Path == overlay.SelfPath || !validCommittedSHA256V1(entry.PreSHA256) || !validCommittedSHA256V1(entry.PostSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid M2 maintenance entry %d", i)
		}
		actual := currentAtPre[entry.Path]
		if actual == "" {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil {
			return nil, fmt.Errorf("M2 maintenance path %s: %w", entry.Path, err)
		}
		if validator, layered := validatorByPath[entry.Path]; layered {
			if validator.PreSHA256 != entry.PostSHA256 || actual != validator.PostSHA256 {
				return nil, fmt.Errorf("validator chain drift %s", entry.Path)
			}
			actual = validator.PreSHA256
		}
		if entry.Path == consumerEntry.Path {
			if consumerEntry.PreSHA256 != entry.PostSHA256 || actual != consumerEntry.PostSHA256 {
				return nil, fmt.Errorf("validator-consumer chain drift %s", entry.Path)
			}
			actual = consumerEntry.PreSHA256
		}
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("M2 maintenance hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		historical[entry.Path] = entry.PreSHA256
	}
	return historical, nil
}

func validatePhase2CompleteOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	overlay, ok := overlays[phase2CompleteOverlayNameV1]
	if len(overlays) != 1 || !ok || overlay.Version != phase2CompleteOverlayNameV1 || overlay.PredecessorManifestSHA256 != phase2PredecessorManifestSHA256V1 || len(overlay.Paths) != len(phase2CompletePathsV1) || len(overlay.Entries) != len(phase2CompletePathsV1)-1 {
		return nil, fmt.Errorf("invalid phase2-complete overlay identity/cardinality")
	}
	for i, path := range phase2CompletePathsV1 {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("phase2-complete path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if entry.Path != phase2CompletePathsV1[i] || entry.Path == committedEvidenceManifestPathV1 || !validCommittedSHA256V1(entry.PostSHA256) || (entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" && !validCommittedSHA256V1(entry.PreEvidence)) {
			return nil, fmt.Errorf("invalid phase2-complete entry %d", i)
		}
		actual, ok := currentAtPost[entry.Path]
		var err error
		if !ok {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase2-complete hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase3ContractOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase3 contract overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase3 contract entry %d", i)
		}
		actual, err := committedFileSHA256V1(root, entry.Path)
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validCommittedSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validateCommittedConvergenceV1(currentAtPost map[string]string, overlays map[string]committedLayeredOverlayV1) (map[string]string, error) {
	convergence, ok := overlays[m2EvidenceConvergenceOverlayNameV1]
	if len(overlays) != 1 || !ok || convergence.Version != m2EvidenceConvergenceOverlayNameV1 || convergence.PredecessorManifestSHA != "1502ae4db6d151839f554e6becde9e81994286cbff378945282739015492bf1e" || len(convergence.Entries) != 7 {
		return nil, fmt.Errorf("invalid convergence overlay identity/cardinality")
	}
	result := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		result[path] = hash
	}
	for i, entry := range convergence.Entries {
		if entry.Path != m2ConvergencePathsV1[i] || entry.PreSHA256 != m2ConvergencePreV1[i] || !validCommittedSHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
			return nil, fmt.Errorf("invalid convergence entry %d", i)
		}
		actual := currentAtPost[entry.Path]
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("convergence hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		result[entry.Path] = entry.PreSHA256
	}
	return result, nil
}

func committedFileSHA256V1(root, path string) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func validCommittedSHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

func TestM2MaintenanceOverlayExactContentAndMutationsV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	overlay := manifest.MaintenanceOverlays[m2MaintenanceOverlayNameV1]
	if _, err := validateCommittedEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}

	missing := overlay
	missing.Paths = append([]string(nil), overlay.Paths[:len(overlay.Paths)-1]...)
	missingManifest := manifest
	missingManifest.MaintenanceOverlays = map[string]committedMaintenanceOverlayV1{m2MaintenanceOverlayNameV1: missing}
	if _, err := validateCommittedEvidenceOverlaysV1(root, missingManifest); err == nil {
		t.Fatal("missing M2 path accepted")
	}
	extra := overlay
	extra.Paths = append(append([]string(nil), overlay.Paths...), "extra.md")
	extraManifest := manifest
	extraManifest.MaintenanceOverlays = map[string]committedMaintenanceOverlayV1{m2MaintenanceOverlayNameV1: extra}
	if _, err := validateCommittedEvidenceOverlaysV1(root, extraManifest); err == nil {
		t.Fatal("extra M2 path accepted")
	}
	drift := overlay
	drift.Entries = append([]committedMaintenanceEntryV1(nil), overlay.Entries...)
	drift.Entries[0].PostSHA256 = strings.Repeat("1", 64)
	driftManifest := manifest
	driftManifest.MaintenanceOverlays = map[string]committedMaintenanceOverlayV1{m2MaintenanceOverlayNameV1: drift}
	if _, err := validateCommittedEvidenceOverlaysV1(root, driftManifest); err == nil || !strings.Contains(err.Error(), "hash drift") {
		t.Fatalf("changed M2 content error=%v", err)
	}
	historical := manifest.Sets["WO-044"][4]
	if historical.PostSHA256 != "68ebebb5c733c2c8aa31d9d67bed24489635c82e38a0451a9ca6e9e6e0adcb8b" {
		t.Fatalf("historical README binding changed: %+v", historical)
	}
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

func TestRuntimeDoesNotImportContracts(t *testing.T) {
	root := repoRoot(t)
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
			if hasPrefixAny(pkgPath, allowedImporterPrefixes) {
				return nil // this package is permitted to import the quarantined trees
			}
			f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
			if err != nil {
				return err
			}
			for _, imp := range f.Imports {
				ip := strings.Trim(imp.Path.Value, `"`)
				if hasPrefixAny(ip, forbiddenImportPrefixes) {
					violations = append(violations, pkgPath+" imports "+ip)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	if len(violations) > 0 {
		t.Fatalf("runtime/real packages must not import contracts/product (%d violation(s)):\n  %s",
			len(violations), strings.Join(violations, "\n  "))
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
		name, file string
		decl       *ast.FuncDecl
		imports    []*ast.ImportSpec
	}
	var declarations []*indexedDecl
	byName := make(map[string][]*indexedDecl)
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
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil {
				continue
			}
			indexed := &indexedDecl{name: function.Name.Name, file: name, decl: function, imports: file.Imports}
			declarations = append(declarations, indexed)
			byName[indexed.name] = append(byName[indexed.name], indexed)
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
			switch function := call.Fun.(type) {
			case *ast.Ident:
				called = function.Name
			case *ast.SelectorExpr:
				called = function.Sel.Name
			}
			if _, forbidden := forbiddenCalls[called]; forbidden {
				t.Errorf("strict relay reached %s:%s calling forbidden symbol %s; allowlist=%s", current.file, current.name, called, strings.Join(compatibilityAllowlist, ", "))
			}
			queue = append(queue, byName[called]...)
			return true
		})
	}
	if len(reached) == 0 {
		t.Fatal("strict relay reachability roots were not indexed")
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
