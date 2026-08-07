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
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"

	"kurdistan/internal/testkit/evidenceoverlay"
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
	for _, releaseRoot := range []string{"internal/androidbridge", "internal/product", "internal/runtime", "cmd/kandroidbridge"} {
		assertNoImportV1(t, root, releaseRoot, forbiddenCompiler)
	}
	for _, forbidden := range []string{
		modulePath + "/internal/protocol/ir",
		modulePath + "/internal/protocol/compiler",
		modulePath + "/internal/testkit",
		modulePath + "/internal/lab",
	} {
		assertNoImportV1(t, root, "internal/protocol/liveprogram", forbidden)
	}
}

func TestLiveProgramConversionImportGraphV1(t *testing.T) {
	root := repoRoot(t)
	graph, err := loadImportGraphV1(root, []string{"cmd", "internal"})
	if err != nil {
		t.Fatal(err)
	}
	if err := validateLiveProgramConversionImportGraphV1(graph); err != nil {
		t.Fatal(err)
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

	graph, err := loadImportGraphV1(root, []string{"internal/product"})
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

func loadImportGraphV1(root string, sourceRoots []string) (map[string][]string, error) {
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
			imports, err := localImportsV1(path)
			if err != nil {
				return err
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
			graph[packagePath] = nil
			for _, entry := range entries {
				if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
					continue
				}
				imports, err := localImportsV1(filepath.Join(base, entry.Name()))
				if err != nil {
					return nil, err
				}
				graph[packagePath] = append(graph[packagePath], imports...)
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
		"internal/product/profile":   {"bytes": true, "crypto/ecdh": true, "crypto/elliptic": true, "crypto/hmac": true, "crypto/hpke": true, "crypto/sha256": true, "encoding/hex": true, "encoding/json": true, "errors": true, "fmt": true, "math/big": true, "os": true, "path/filepath": true, "reflect": true, "sort": true, "strings": true, "testing": true, "time": true, modulePath + "/internal/product/envelope": true, modulePath + "/internal/product/lifecycle": true, modulePath + "/internal/product/profile": true, modulePath + "/internal/testkit/phase8issuance": true, modulePath + "/internal/testkit/phase8issuancefixture": true},
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
	Schema                              string                                   `json:"schema"`
	HashAlgorithm                       string                                   `json:"hash_algorithm"`
	SourceCandidate                     string                                   `json:"source_candidate"`
	Sets                                map[string][]committedEvidenceEntryV1    `json:"sets"`
	MaintenanceOverlays                 map[string]committedMaintenanceOverlayV1 `json:"maintenance_overlays"`
	HelperOwnerOverlays                 map[string]committedLayeredOverlayV1     `json:"helper_owner_overlays"`
	ValidatorOverlays                   map[string]committedLayeredOverlayV1     `json:"validator_overlays"`
	ValidatorConsumerOverlays           map[string]committedLayeredOverlayV1     `json:"validator_consumer_overlays"`
	EvidenceConvergenceOverlays         map[string]committedLayeredOverlayV1     `json:"evidence_convergence_overlays"`
	Phase2CompleteOverlays              map[string]phase2CompleteOverlayV1       `json:"phase2_complete_overlays"`
	Phase3ContractOverlays              map[string]phase2CompleteOverlayV1       `json:"phase3_contract_overlays"`
	Phase4FallbackOverlays              map[string]phase2CompleteOverlayV1       `json:"phase4_fallback_overlays"`
	Phase5RelayDescriptorOverlays       map[string]phase2CompleteOverlayV1       `json:"phase5_relay_descriptor_overlays"`
	Phase6DiagnosticExportOverlays      map[string]phase2CompleteOverlayV1       `json:"phase6_diagnostic_export_overlays"`
	Phase7AppRuntimeOverlays            map[string]phase2CompleteOverlayV1       `json:"phase7_app_runtime_overlays"`
	BaselineStabilizationOverlays       map[string]phase2CompleteOverlayV1       `json:"baseline_stabilization_overlays"`
	Phase8ProfileCryptographyOverlays   map[string]phase2CompleteOverlayV1       `json:"phase8_profile_cryptography_overlays"`
	Phase8WO801ThreatModelOverlays      map[string]phase2CompleteOverlayV1       `json:"phase8_wo801_threat_model_overlays"`
	Phase8WO801AdoptionOverlays         map[string]phase2CompleteOverlayV1       `json:"phase8_wo801_adoption_overlays"`
	Phase8GuardMaintenanceOverlays      map[string]committedMaintenanceOverlayV1 `json:"phase8_guard_maintenance_overlays"`
	Phase8FinalGuardMaintenanceOverlays map[string]committedMaintenanceOverlayV1 `json:"phase8_final_guard_maintenance_overlays"`
	Phase9GuardMaintenanceOverlays      map[string]committedMaintenanceOverlayV1 `json:"phase9_guard_maintenance_overlays"`
	Phase10VPNRuntimeOverlays           map[string]committedMaintenanceOverlayV1 `json:"phase10_vpn_runtime_overlays"`
	Phase11LocalTransportOverlays       map[string]committedMaintenanceOverlayV1 `json:"phase11_local_transport_overlays"`
	Phase12OperatorControlPlaneOverlays map[string]committedMaintenanceOverlayV1 `json:"phase12_operator_control_plane_overlays"`
	Phase13AndroidProductOverlays       map[string]committedMaintenanceOverlayV1 `json:"phase13_android_product_overlays"`
	Phase14AssuranceOverlays            map[string]committedMaintenanceOverlayV1 `json:"phase14_assurance_overlays"`
}

type committedMaintenanceOverlayV1 struct {
	Version       string                        `json:"version"`
	SelfPath      string                        `json:"self_path"`
	SelfPreSHA256 string                        `json:"self_pre_sha256"`
	Paths         []string                      `json:"paths"`
	Entries       []committedMaintenanceEntryV1 `json:"entries"`
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
	SuccessorEntries         []committedMaintenanceEntryV1 `json:"successor_entries"`
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
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(evidenceoverlay.Phase17SuccessorPath)))
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
	if overlay.Version != name || overlay.SelfPath != evidenceoverlay.Phase17SuccessorPath || overlay.SelfPreEvidence != "ABSENT" || overlay.SelfPreSHA256 != "" || overlay.PredecessorBindingSHA256 != predecessorBinding || len(overlay.Entries) != len(phase17LiveDataPlanePathsV1) || len(overlay.SuccessorEntries) > 128 {
		return phase17LiveDataPlaneOverlayV1{}, fmt.Errorf("invalid phase17 live-data-plane overlay identity/cardinality")
	}
	baseAtPost, err := phase17SuccessorPreAtPostV1(root, currentAtPost, overlay.SuccessorEntries)
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
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
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

func phase17SuccessorPreAtPostV1(root string, currentAtPost map[string]string, entries []committedMaintenanceEntryV1) (map[string]string, error) {
	pre := make(map[string]string, len(currentAtPost)+len(entries))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	last := ""
	for index, entry := range entries {
		if entry.Path <= last || strings.HasPrefix(entry.Path, ".tools/") || strings.HasPrefix(entry.Path, "planning/") || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase17 successor entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase17 absent successor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase17 successor predecessor %d", index)
		}
		actual, found := pre[entry.Path]
		if !found {
			content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
			if err != nil {
				return nil, err
			}
			actual = fmt.Sprintf("%x", sha256.Sum256(content))
		}
		if actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase17 successor hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
		pre[entry.Path] = predecessor
		last = entry.Path
	}
	return pre, nil
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
	if manifest.Schema != "kurdistan.phase1-m0.committed-sha256.v1" || manifest.HashAlgorithm != "sha256" || manifest.SourceCandidate != "68d50f3bca0f1839dd7b04a1551e5fcce47b1b71" {
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
	if _, err := validatePhase17LiveDataPlaneOverlayV1(root); err != nil {
		return nil, err
	}
	phase14Pre, err := validatePhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		return nil, err
	}
	phase13Pre, err := validatePhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		return nil, err
	}
	phase12Pre, err := validatePhase12OperatorControlPlaneOverlayAtPostV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		return nil, err
	}
	phase11Pre, err := validatePhase11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
	if err != nil {
		return nil, err
	}
	phase10Pre, err := validatePhase10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
	if err != nil {
		return nil, err
	}
	phase9Pre, err := validatePhase9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, manifest.Phase9GuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	finalGuardPre, err := validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	guardPre, err := validatePhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, manifest.Phase8GuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range guardPre {
		if hash == "ABSENT" {
			continue
		}
		finalGuardPre[path] = hash
	}
	currentAtWO801, err := validatePhase8WO801AdoptionOverlayAtPostV1(root, finalGuardPre, manifest.Phase8WO801AdoptionOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range finalGuardPre {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtWO801[path]; !replaced {
			currentAtWO801[path] = hash
		}
	}
	currentAtWO800, err := validatePhase8WO801ThreatModelOverlayAtPostV1(root, currentAtWO801, manifest.Phase8WO801ThreatModelOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range currentAtWO801 {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtWO800[path]; !replaced {
			currentAtWO800[path] = hash
		}
	}
	currentAtPhase8, err := validatePhase8ProfileCryptographyOverlayAtPostV1(root, currentAtWO800, manifest.Phase8ProfileCryptographyOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range currentAtWO800 {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtPhase8[path]; !replaced {
			currentAtPhase8[path] = hash
		}
	}
	currentAtM7, err := validateBaselineStabilizationEvidenceOverlayV1(root, currentAtPhase8, manifest.BaselineStabilizationOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM6, err := validatePhase7AppRuntimeOverlayV1(root, currentAtM7, manifest.Phase7AppRuntimeOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM5, err := validatePhase6DiagnosticExportOverlayV1(root, currentAtM6, manifest.Phase6DiagnosticExportOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM4, err := validatePhase5RelayDescriptorOverlayV1(root, currentAtM5, manifest.Phase5RelayDescriptorOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM3, err := validatePhase4FallbackOverlayV1(root, currentAtM4, manifest.Phase4FallbackOverlays)
	if err != nil {
		return nil, err
	}
	currentAtM2, err := validatePhase3ContractOverlayV1(root, currentAtM3, manifest.Phase3ContractOverlays)
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

func validatePhase8ProfileCryptographyOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	return validatePhase8ProfileCryptographyOverlayAtPostV1(root, nil, overlays)
}

func validatePhase8ProfileCryptographyOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-profile-cryptography-authorization-v1"
	wantPaths := []string{
		"ROADMAP.md", "docs/GOVERNANCE.md", "docs/safety.md", "docs/KIP-0066-product-layer-scaffold.md",
		"docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md", "docs/KIP-0070-profile-admission-lifecycle-contract.md",
		"docs/KIP-0075-phase8-offline-profile-cryptography.md", "testdata/evidence/phase8-stabilization-baseline-2026-07-17.json",
		"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go",
		committedEvidenceManifestPathV1,
	}
	wantStabilized := map[string]string{
		"cmd/kgen/main_test.go":                            "02957beb4e2f7175685d0301277bf87684a60f3a5124bf9665cf1602f44f716f",
		"internal/audit/codegen_test.go":                   "829049208bbe59f4c3589ebbc9224ce4a0c4ba48e208a1fc63cb92e9df04c15a",
		"internal/audit/security.go":                       "b5bd8ac00051ebb5afa2fce66d103eedd91535ac70065edf0da5c21d555396e9",
		"internal/audit/security_test.go":                  "756907f5700a7e6b74668da0e65c3de12f8c684fa763bc310b2e9ceef8909f7e",
		"internal/codegen/authorization_v1_test.go":        "240899c2ee09e28fec883a1de9f84f6e000342933583e63e34796f13f9657f45",
		"internal/runtime/policy_enforcement_test.go":      "8d4103ded5371325e22e4bef362de31f049c8f857487a0f04866524763c32ec8",
		"internal/testkit/importrules/importrules_test.go": "8d54c23846b2b0e679ac55c710a4b3615d03efb2489ea22d438bef63c7e68021",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "dbe03c03259b9446e17836a5f1318d3a472b5a3483ae7880318b108c174cebba" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase8 profile cryptography overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 profile cryptography path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography entry %d", i)
		}
		wantAbsent := i == 7 || i == 8
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor %d", i)
		}
		if !wantAbsent && !validCommittedSHA256V1(entry.PreEvidence) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor hash %d", i)
		}
		if want, guarded := wantStabilized[entry.Path]; guarded && entry.PreEvidence != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 profile cryptography hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if !wantAbsent {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	for path, want := range wantStabilized {
		if pre[path] != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstructed %s=%s want %s", path, pre[path], want)
		}
	}
	return pre, nil
}

func validatePhase8WO801ThreatModelOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	return validatePhase8WO801ThreatModelOverlayAtPostV1(root, nil, overlays)
}

func validatePhase8WO801ThreatModelOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-threat-model-v1"
	wantPaths := []string{
		"docs/KIP-0076-phase8-profile-threat-model.md",
		"internal/product/envelope/phase8_trust.go",
		"internal/product/envelope/phase8_trust_test.go",
		"internal/product/profile/phase8_trust.go",
		"internal/product/profile/phase8_trust_test.go",
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		committedEvidenceManifestPathV1,
	}
	wantWO800 := map[string]string{
		"cmd/kgen/main_test.go":                            "9ec962c5601a6090e6289a48b142e200e5e601a4ecf3d366adefa740ea30b0f6",
		"internal/audit/codegen_test.go":                   "e2c3b0e1b7274da45d3861424bb0218f9640ad703f608d03858993531cddec2d",
		"internal/audit/security.go":                       "328e8382c05082b28aa35b92426e6622da030b460a6505b49c1761bd9c45efe9",
		"internal/audit/security_test.go":                  "076830912ef1742d6a7c7cc18279a28af652371eba9bd61db120cfc9ac9f760e",
		"internal/codegen/authorization_v1_test.go":        "421deed4c4aeafc9c8ffdc27432b10aef34a6050d8d87efb1a048da8a6046477",
		"internal/runtime/policy_enforcement_test.go":      "7ec77a79a641ce792a94cbebdc8b8a6c17cafb72c92b9b260203908df5537114",
		"internal/testkit/importrules/importrules_test.go": "29376a1a91fba2100cfc894dae836399f7e84d9756bc65c0bfb41c840a25246d",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "7373da738dde935a1eae25522b1bc9a2ce4efd7ebe50dd221fcf2c8847cb25ae" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase8 WO-801 threat-model overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model entry %d", i)
		}
		wantAbsent := i < 5
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 WO-801 threat-model predecessor %d", i)
		}
		if !wantAbsent && entry.PreEvidence != wantWO800[entry.Path] {
			return nil, fmt.Errorf("phase8 WO-801 reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 threat-model hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if !wantAbsent {
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase8WO801AdoptionOverlayV1(root string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	return validatePhase8WO801AdoptionOverlayAtPostV1(root, nil, overlays)
}

func validatePhase8GuardMaintenanceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	return validatePhase8GuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validatePhase8GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase8-wo806-guard-convergence-v1"
	paths := []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", committedEvidenceManifestPathV1}
	preHashes := []string{"10f4a412739c3896e88fb7b649774e0243ccfcfab2c77335b2e7ecaa8948f3ae", "8ed3f3c023baa71d60dbe81c94bb0e4254e8fcaf35b5c4b75d027b2c2290b15b", "1333f376b7ff19580719c40ec831a61ff6c66dd2ea90721a1d257370d698e45e", "4420c4c6582124b04c9330329bfedf213f2976f3c536cb2fa815ab28a28a1fb5", "c3fb2ce202af327107885f8a5866908cbd984aa74b09ee702514d6ed2442901d", "a7e40a30f7a30122bf23e538f8714890f3bba945799466cf378c3566160c4041", "a4664fe1fb3b6a6050af2c8e04eab51263ce32989e5d673c1ae35b97f7b8b79e"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != committedEvidenceManifestPathV1 || o.SelfPreSHA256 != "37ece675df4e2f17bb253a3a5d648c3a7b6e62d9319fd27a138be00cedb3e77a" || len(o.Paths) != 8 || len(o.Entries) != 7 {
		return nil, fmt.Errorf("invalid phase8 guard-maintenance overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		if entry.Path != paths[i] || entry.PreSHA256 != preHashes[i] || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreSHA256
	}
	return pre, nil
}

func validatePhase8FinalGuardMaintenanceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	return validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase8-wo808-final-guard-convergence-v1"
	paths := []string{
		"README.md", "ROADMAP.md", "docs/GOVERNANCE.md",
		"docs/safety.md", "cmd/gate/main.go", ".github/workflows/ci.yml",
		"internal/product/envelope/phase8_suite_test.go", "testdata/evidence/independent/phase8_interop.py", "testdata/evidence/phase8-independent-interop-report.json",
		"internal/product/envelope/phase8_profile_codec.go", "internal/product/envelope/phase8_profile_codec_test.go", "cmd/kprofile/main.go",
		"cmd/kprofile/main_test.go", "internal/product/profile/testdata/phase8-issuance/offline-boundary-report.json", "internal/product/profile/testdata/phase8-issuance/redacted-inspect-report.json",
		"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go",
		"internal/codegen/authorization_v1_test.go", ".gitignore", "internal/audit/status.go",
		"cmd/kprofile/path_other.go", "cmd/kprofile/path_unsupported.go", "cmd/kprofile/path_windows_test.go",
		"cmd/kprofile/path_windows.go", "cmd/kprofile/path.go", "docs/KIP-0082-phase8-integrated-assurance.md",
		"docs/PHASE8_EVIDENCE_INDEX.md", "docs/PHASE8_RECOVERY_RUNBOOK.md", "internal/product/envelope/phase8_evidence_test.go",
		"internal/product/envelope/phase8_suite.go", "internal/product/profile/phase8_activation_test.go", "internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_providers.go", "internal/product/profile/phase8_tooling_evidence_test.go", "internal/product/profile/phase8_tooling_external_test.go",
		"internal/product/profile/phase8_tooling.go", "internal/product/profile/testdata/phase8-activation/activation-crash-report.json", "internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json", "internal/product/profile/testdata/phase8-activation/policy-bypass-report.json", "internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json", "internal/product/profile/testdata/phase8-issuance/fixture-manifest.json", "internal/product/profile/testdata/phase8-issuance/fixture-reproduction-report.json",
		"internal/product/profile/testdata/phase8-issuance/issuance-negative-report.json", "internal/product/profile/testdata/phase8-issuance/issuance-roundtrip-report.json", "internal/product/profile/testdata/phase8-issuance/production-wiring-negative-report.json",
		"internal/testkit/phase8fixturegen/main_test.go", "internal/testkit/phase8fixturegen/main.go", "internal/testkit/phase8issuancefixture/generate.go",
		"STATUS.md", "testdata/evidence/phase8-release-corpus-manifest.json", "testdata/evidence/phase8-wo807-recovery-report.json",
		"testdata/evidence/phase1-m0-committed-sha256.json",
	}

	preHashes := []string{
		"65b6fe472d0b3bf59704e3793a6337ba8ebd8602bd92e9d70b34e30f445bbed5", "4c4b327d58efabe3569b7a525cf9bc18298b3027d5993ebc9a5f36b9520cb6d2", "483ac28d0d371e10784d83721b7e2efac5e46bffe031dc18fcfb253012781e4d",
		"62fabcee4d7451804f2c7f7df32e9b2e4457c8a8a16687677d20097cca616769", "c7d9d7127fec76e135fe0ea7bebd86285764025c735d8e733c12b9a0e662663f", "ABSENT",
		"f8608b81c1c0b7b2e499a1217e258ba7a9fe842ee61f68cf6728f06506204cb3", "8a312973d42f25c127827db419b0b07355a1b779d2cd243b45a77492bf55288a", "b6424fd088cc2c437175adccafff1c94b3afc6bcf0750491a1c05e72ceaf3cb5",
		"197304bba879d092cf0b37c96f2d260ccc3137ca35378c562ab17f43f7ed92f2", "12dcdff0b67c56c55b3cc29ed5ef10a3d3bfb273b1da02d6012a03940c056a3b", "d3bd61e8094ba10253cde22306b6dde0ca1c4ffe28d34616d5471a34864caa09",
		"82915c199c88ab52bdca5a74c56eab99fc61b095420064f1f3e2d51a3d9818a9", "1cc9b6f1af5157e468870e3cfc849a9e83e2513d7e06ea54f2c8388b1acc437c", "6c4e0ff29540248a2c919eaf4444ab8ee33cdb8a4ac6c8407fcbbd37deb155b4",
		"d7f33f3194065c6b4900a92843da772b74396090ae311532d82118037b2b7b3d", "251c31fcf024a5bebb11a742a0ba03ffca8ae98f146b9c5242e7c82d30cc929a", "9bc732efbf56adcbec93722f206227a43d3f0946cbc8acd0a03b96b66439d1d7",
		"3a46df826b5c108818723af77ff2e7de6530bf2e66e993d2cda364e05eb51fa9", "372f479b0c541f61e2cad4869f62ae8cce895db00ffcc3b19e03bd6925677c14", "e87df0637cdc5c93129a73855e641a98f80b750b2e27a6343e7f37072c816201",
		"9e0feb195c40a435f3d3baf80ef8a2a91d8f38f0b5134fb6bbf50f7760b767bc", "5b183df65d579d6956f2fee4771afc35f32fa0eeb87d1cfa8bb1729e19e92f20", "94dc5eb6ba2ff56fd46820592ecb01e7e5705c2200350ad9d4534221fee0f954",
		"4de767d8872d04668c0077d45be834b3397ca723e6bd9b1d66de85bee32e3d0b", "ABSENT", "ABSENT",
		"a0ada14afde8b72fb1e66513208fc020e9d674f73238896bed3f876dff83674b", "ABSENT", "9514b51d5b3320e11c875b0224e6dc9e6cf4b99b6c88d0f516441086d366daa3",
		"20a6e8732887d76ef49c957369a1132d8bdf3d10df20b3f2abcae5903bbf2cd1", "7ca541e419a2de0f4ef2f1987e21277ec78aba38c8b5acac7b74a31a6d3ca2fd", "e1b66f934f62efdc947c3ac15480e36ae4986f14042bb4a38e92dd6313c41645",
		"71c67b4e27d4f8708115030dd9469f3b133a7b4fdc09a3732e2efb6c2d67944f", "03ef0f0d758f220be50d3b517aebb8e1b2d8cace59836a2c991422c3d5162331", "0747653f3b1efb3783535572bf68843cf0e1a494bd2098a82ccfc7d224dfe1bd",
		"db08f48f7305f9543c2a6e3094218c0b31ed8185298149af05d0a4a671b19bae", "6d894e73ad19bdd05afc504212e93ef18f18e8962db06c9629be4d3bc7cd5d91", "60b60d1932bffb4b6597fb0659b9153c0531a51bab944e4263b620fdfd3af028",
		"154178a1b0bd6da95a1327a32b11c3d5c5a2023a4d323c7dbb999f89e0f807b7", "5eba165b5ea9317b51f609ab4b34ef57d3dc0a42c85ab7d4aae78b1c4b7b15ba", "fd393e178e02ab8f5c96b2502dcb7b2ad411758eb55c7ef4f8144536e47db069",
		"5eba165b5ea9317b51f609ab4b34ef57d3dc0a42c85ab7d4aae78b1c4b7b15ba", "7ce8dc7e7ddb93454c24fad8c9a8c7f375d5bba25d07673e60a757335a13aecc", "e83737cbb6ef895748045a1af296e82a6ee0bfeff72c1615bd003c1cd375b1d1",
		"0c6ca80025d973546aa2d44442f739f94b4e0b1ec9132dafc08ca72bb2f88afc", "993739b3577ab5418bec2c3790e26495c16b9bbb423ef08fce8d96d36d601b36", "19685e69c2e8b9d66b5116d74b7e75cf3e6c61abb8ae4803ab4f782debfb6688",
		"766b6b14fffc20436ad5b0ff5d623582e41dbf7907396a1599bf484639214ac7", "58f43dc6b85ae04dcd682ee7e58a506463fb6118e9eae080d57c1d7618af465b", "8007954c8ec687664fe70841982172c717e11a2933c16a373259b28a001feb55",
		"ABSENT", "00b45845fd49a2d39e1489b61e117dd91c83aa715925f82ae8cb931664230e3a", "05de9cb9f0cd0f40721c7aa6465c619e400f0e19911451629737741bc4f489df",
		"8ed8a14111d09e948879d5cebe3979cf20ce1eb048e996c9bf39e6e409f1bbf1", "7ccec20947e3733149efbf2a38d161a017d698587360353836f52811fda0b6e0", "8db7027e428d1fd09498202f33eacb7285ae56c9b28f061297f60b8642a37583",
	}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != committedEvidenceManifestPathV1 || o.SelfPreSHA256 != "afcef52b1302379c2172815138219421e2dcf2b4e7280724f7c9ae4829d5f76a" || len(o.Paths) != len(paths) || len(o.Entries) != len(preHashes) {
		return nil, fmt.Errorf("invalid phase8 final guard-maintenance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		expectedPre := preHashes[i]
		if entry.Path != paths[i] || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance entry %d", i)
		}
		if expectedPre == "ABSENT" {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase8 final guard-maintenance absent predecessor %d", i)
			}
		} else if entry.PreEvidence != "" || entry.PreSHA256 != expectedPre || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase8 final guard-maintenance predecessor %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 final guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = expectedPre
	}
	return pre, nil
}

func validatePhase14AssuranceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase14-assurance-v1"
	const predecessorBinding = "eefcbeb7a93a4472fa7563a3b0fb8d7399001da4fe309ae735861369ed57a0fa"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.SelfPath != committedEvidenceManifestPathV1 || !validCommittedSHA256V1(overlay.SelfPreSHA256) || len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase14 assurance overlay identity/cardinality")
	}
	successor, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return nil, fmt.Errorf("load Phase 15 successor overlay: %w", err)
	}
	pre := make(map[string]string, len(overlay.Paths))
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath || strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase14 assurance overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase14 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase14 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, found := successor[path]
		if !found {
			actual, err = committedFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase14 assurance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return nil, fmt.Errorf("invalid phase14 predecessor binding")
	}
	return pre, nil
}

func validatePhase13AndroidProductOverlayV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase13-android-product-v1"
	const predecessorBinding = "53dde098ac5c6f2febee7f5069d8b11f5809f58ef94a5ada55835c2467ebd58f"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 || !validCommittedSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase13 Android product overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase13 Android product overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase13 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase13 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase13 Android product hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		last = path
	}
	if fmt.Sprintf("%x", binding.Sum(nil)) != predecessorBinding {
		return nil, fmt.Errorf("invalid phase13 predecessor binding")
	}
	return pre, nil
}

func validatePhase12OperatorControlPlaneOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	return validatePhase12OperatorControlPlaneOverlayAtPostV1(root, nil, overlays)
}

func validatePhase12OperatorControlPlaneOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase12-operator-control-plane-v1"
	paths := []string{
		"ROADMAP.md",
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"cmd/koperator/evidence_test.go",
		"cmd/koperator/main.go",
		"cmd/koperator/main_test.go",
		"cmd/phase9verify/phase11_overlay_test.go",
		"docs/KIP-0087-phase12-operator-provisioning-relay-fleet.md",
		"docs/PHASE12_EVIDENCE_INDEX.md",
		"docs/safety.md",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator_templates.go",
		"internal/codegen/generator_test.go",
		"internal/operator/controlplane/authority_state.go",
		"internal/operator/controlplane/controlplane_test.go",
		"internal/operator/controlplane/errors.go",
		"internal/operator/controlplane/journal.go",
		"internal/operator/controlplane/model.go",
		"internal/operator/controlplane/phase_boundaries.go",
		"internal/operator/controlplane/phase_boundaries_test.go",
		"internal/operator/controlplane/reconcile.go",
		"internal/operator/controlplane/reconcile_test.go",
		"internal/operator/controlplane/service.go",
		"internal/operator/controlplane/state.go",
		"internal/product/lifecycle/phase8_verified.go",
		"internal/product/lifecycle/phase8_verified_test.go",
		"internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_admission.go",
		"internal/product/profile/phase8_admission_test.go",
		"internal/product/profile/phase8_emergency_signed.go",
		"internal/product/profile/phase8_emergency_signed_test.go",
		"internal/product/profile/phase8_providers.go",
		"internal/product/profile/phase8_revocation_admission.go",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		"testdata/evidence/phase12/acceptance-status.json",
		"testdata/evidence/phase8-wo807-recovery-report.json",
	}
	preHashes := map[string]string{
		"ROADMAP.md":                                         "586a5e7f377c1809eb67cfe932d996ae81703bb562f52b539935e26ccdc93e8b",
		"cmd/gate/main.go":                                   "8f0e4e86384ea012ac54f1c9f795c3a4f760b5ab6c7f4b24f3ab553cad3c96c1",
		"cmd/gate/main_test.go":                              "c2b868ec7b155ed5ae95f667181284af9672722ceea8b3c018f4dd32df2d4fdd",
		"cmd/kgen/main_test.go":                              "2fabad2630c546749cde3c0c67dd9885ffa855230c298dacb741c65ef497c846",
		"cmd/phase9verify/phase11_overlay_test.go":           "95c7e090b93beab82e673513735e6725e1f636f10244a6b37b504adc91cb3a67",
		"docs/safety.md":                                     "2846c0453c9a20d8fee0a355d339ba70f658d3f064e2dcd6ddef693d7bbb50b0",
		"internal/audit/codegen_test.go":                     "c1896696926104de33e540f207c4cc3e7f477edfddc006cfc9f279dd34e5df94",
		"internal/audit/security.go":                         "a180d1b42b37ac390a1bdf718a4c8172cafc8f14b8afd9c46c24831fe461cbe9",
		"internal/audit/security_test.go":                    "b4674dd844d0f006fe83ced7fbd6855a309e1bbd76ac1cd2fb6c8a73711a5519",
		"internal/codegen/authorization_v1_test.go":          "e2d8caf8757c35bc9e1aea7ba6c5a129d328f507d9aa54889223b83e536e4c51",
		"internal/codegen/generator_templates.go":            "53651959c9fbc7a936c23d4ae6cf5e4821e2322befc38596cbf215f3f24ff643",
		"internal/codegen/generator_test.go":                 "2a519ad4aaf1d0ba4e4f9cf6294dc0772059f677e82a113b81c3712ac2832f31",
		"internal/product/lifecycle/phase8_verified.go":      "e9fd50ec54dca326be6580815153a3983555f1b31ea028e4a3c052257e7e17c6",
		"internal/product/lifecycle/phase8_verified_test.go": "7e3aad03d9af6dcec588c37225c4791cce3d38c7d0b3dfb7c69218b3ae5e5769",
		"internal/product/profile/phase8_activation.go":      "3de078f241b4bd4da039891cf19db34f30eae083363cd23ea21b393d88a3a080",
		"internal/product/profile/phase8_providers.go":       "9bf824c879fc0186de623f4c6a589a0ef2dce0cefb33b6168397363cd0a5f33c",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json":            "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json": "20b5867ab1fd0ff1aff509702021c2ccc0d529f5cd4434ad48cf74864d8b185b",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json":    "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
		"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json":               "d4987c0461d703870dcfc2a53d107537fc529cacfff0cb7ceef55343cb3722fa",
		"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json":       "6f2c3e15819d1fd18954aa242f5283e89fa1cc6a3c3964ea9ed864ee7553f364",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json":     "2fe3a7161549f9366a7d03e3724e9ec2d341659dec8af9e74e31778a908da2f0",
		"internal/runtime/policy_enforcement_test.go":                                                 "24ee3246889bf9393bece92e0016b464c3bd252ab4cf4a10038a69c069a2af20",
		"internal/testkit/importrules/importrules_test.go":                                            "f9f719b207174e13a2a1577c8fb450412fe0c2135b301c49311311fe84863221",
		"testdata/evidence/phase8-wo807-recovery-report.json":                                         "9ab249ec04fc5c012c5ed052e6bc927bcf1ed058760e26b2bbf48c0948a81c66",
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		overlay.SelfPreSHA256 != "050dd24b449122dfd58a79df263c61a1e9cb8c83f4b038df82e7629e49d6dfc2" ||
		len(overlay.Paths) != len(paths) || len(overlay.Entries) != len(paths) {
		return nil, fmt.Errorf("invalid phase12 operator control-plane overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range paths {
		entry := overlay.Entries[i]
		if overlay.Paths[i] != path || entry.Path != path || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase12 operator control-plane entry %d", i)
		}
		predecessor, existed := preHashes[path]
		if existed {
			if entry.PreEvidence != "" || entry.PreSHA256 != predecessor || entry.PostSHA256 == entry.PreSHA256 {
				return nil, fmt.Errorf("invalid phase12 operator control-plane predecessor %d", i)
			}
		} else {
			if entry.PreEvidence != "ABSENT" || entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase12 operator control-plane absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase12 operator control-plane hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
	}
	return pre, nil
}

func validatePhase11LocalTransportOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	return validatePhase11LocalTransportOverlayAtPostV1(root, nil, overlays)
}

func validatePhase11LocalTransportOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase11-local-transport-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		!validCommittedSHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 128 ||
		len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase11 local transport overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || path == committedEvidenceManifestPathV1 ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase11 local transport entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase11 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase11 existing predecessor %d", i)
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase11 local transport hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	return pre, nil
}

func validatePhase10VPNRuntimeOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	return validatePhase10VPNRuntimeOverlayAtPostV1(root, nil, overlays)
}

func validatePhase10VPNRuntimeOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase10-local-vpn-runtime-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		overlay.SelfPreSHA256 != "45559ed3772b777924c8ef5e2a24980b8ddfccab89e67613ff379f5b48824d76" ||
		len(overlay.Paths) != 56 || len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase10 VPN runtime overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	scope := sha256.New()
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase10 VPN runtime entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase10 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase10 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase10 VPN runtime hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "beab1c7016ca1eb01da57ccd4e0b46fb5d0ae07cfa98cfc084caebd001023f28" {
		return nil, fmt.Errorf("phase10 VPN runtime scope drift %s", got)
	}
	return pre, nil
}

func validatePhase9GuardMaintenanceOverlayV1(root string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	return validatePhase9GuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validatePhase9GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]committedMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase9-wo909-final-guard-convergence-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != committedEvidenceManifestPathV1 ||
		overlay.SelfPreSHA256 != "1f8149bb5ff5057e6b25dcad186c07303d57af4073f940708f257a17c9656623" ||
		len(overlay.Paths) != 159 || len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase9 guard-maintenance overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	scope := sha256.New()
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase9 guard-maintenance entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase9 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validCommittedSHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase9 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase9 guard-maintenance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "f079c69d9c8b9f4649198ca5d948907d4ed44dc989bd5420a8e703ee37c2fb54" {
		return nil, fmt.Errorf("phase9 guard-maintenance scope drift %s", got)
	}
	return pre, nil
}

func validatePhase8WO801AdoptionOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-adoption-v1"
	wantPaths := []string{"testdata/evidence/phase8-wo801-adoption-2026-07-17.json", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1}
	wantPre := map[string]string{"cmd/kgen/main_test.go": "f3756c80bd358535e929a8bffa4ef79129f346318fb6304fdd01abd6c915a846", "internal/audit/codegen_test.go": "00ac00353fda287944ba5fd1965a130830514b2807c5df1ea46eccbcc1299791", "internal/audit/security.go": "d71fc4a337b995790ee397b944e3d7cf47ba675dc9204eeb8b5f2c513250b73d", "internal/audit/security_test.go": "dba0df11ef69fa6364a262d2f3fdf4bb8046f089fa314148ed5a7ae13c4cf7d8", "internal/codegen/authorization_v1_test.go": "c9b8f29d924a37e1b2fbba5b6a69ef04fc6043e4c2e0f77aafd162edf66d5adc", "internal/runtime/policy_enforcement_test.go": "ab7ab4f454448750a82e5a50a8acfba96b08ca5c4c492539c371f4a6f9f49241", "internal/testkit/importrules/importrules_test.go": "1c465b2026c31246a3685f96849604d0879e0025e892fc6a4b3875bf0ef09a17"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.PredecessorManifestSHA256 != "989df23699da6edfb8e5279752dbe66863a854b530a532119a2689320049c56f" || len(o.Paths) != 9 || len(o.Entries) != 8 {
		return nil, fmt.Errorf("invalid phase8 WO-801 adoption overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range wantPaths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption path %d", i)
		}
	}
	for i, e := range o.Entries {
		if e.Path != wantPaths[i] || !validCommittedSHA256V1(e.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption entry %d", i)
		}
		if i == 0 {
			if e.PreEvidence != "ABSENT" {
				return nil, fmt.Errorf("invalid phase8 WO-801 adoption evidence predecessor")
			}
		} else if !validCommittedSHA256V1(e.PreEvidence) || e.PreEvidence != wantPre[e.Path] {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstruction drift %s", e.Path)
		}
		a, present := currentAtPost[e.Path]
		var err error
		if !present {
			a, err = committedFileSHA256V1(root, e.Path)
		}
		if err != nil || a != e.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 adoption current hash drift %s=%s want %s: %v", e.Path, a, e.PostSHA256, err)
		}
		if i > 0 {
			pre[e.Path] = e.PreEvidence
		}
	}
	for path, want := range wantPre {
		if pre[path] != want {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstructed %s=%s want %s", path, pre[path], want)
		}
	}
	return pre, nil
}

func validateBaselineStabilizationEvidenceOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "go126-clean-worktree-stabilization-v1"
	wantPaths := []string{
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		committedEvidenceManifestPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "4bc0e7279b17cfbac0dc7138654991f20331b535d0c097c406efee68a1af8f74" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid baseline stabilization overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid baseline stabilization path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validCommittedSHA256V1(entry.PreEvidence) || !validCommittedSHA256V1(entry.PostSHA256) || entry.PreEvidence == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid baseline stabilization entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("baseline stabilization hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreEvidence
	}
	return pre, nil
}

func validatePhase7AppRuntimeOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m7-offline-app-runtime-contract-v1"
	wantPaths := []string{
		"ROADMAP.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md",
		"docs/KIP-0074-offline-app-runtime-contract.md", "internal/product/appruntime/appruntime.go", "internal/product/appruntime/appruntime_test.go",
		"testdata/consumer/m7-app-runtime-sdk/go.mod", "testdata/consumer/m7-app-runtime-sdk/app_runtime_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "34f5d8d2048faf1de49c2ccd2ebb4a5c507ad3bf0b2d75b5db1e7e6d5c13a0a7" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase7 app runtime overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase7 app runtime path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase7 app runtime entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase7 app runtime hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validCommittedSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase7 app runtime pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase6DiagnosticExportOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m6-offline-diagnostic-export-contract-v1"
	wantPaths := []string{
		"ROADMAP.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md",
		"docs/KIP-0073-offline-diagnostic-export-contract.md", "internal/product/diagnosticexport/diagnosticexport.go", "internal/product/diagnosticexport/diagnosticexport_test.go",
		"testdata/consumer/m6-diagnostic-export-sdk/go.mod", "testdata/consumer/m6-diagnostic-export-sdk/diagnostic_export_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", committedEvidenceManifestPathV1,
	}
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "77fcaaa94436a401f071fbfbade94baeb0cd770574c7309ae5c427a76c030977" || len(overlay.Paths) != len(wantPaths) || len(overlay.Entries) != len(wantPaths)-1 {
		return nil, fmt.Errorf("invalid phase6 diagnostic export overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, path := range wantPaths {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase6 diagnostic export path %d", i)
		}
	}
	for i, entry := range overlay.Entries {
		if entry.Path != wantPaths[i] || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase6 diagnostic export entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase6 diagnostic export hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validCommittedSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase6 diagnostic export pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase5RelayDescriptorOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m5-offline-relay-descriptor-admission-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "709e4a5a7412ee115fc71c2d825ebe9ac4f167439b4861a1649dd63fcf0c150f" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase5 relay descriptor overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase5 relay descriptor entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase5 relay descriptor hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validCommittedSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase5 relay descriptor pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase4FallbackOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m4-permitted-fallback-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "772ae344c99edb21a4d04fadd77f51978a6e81aa4d555ec30190cb64e7a7c2d9" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase4 fallback overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase4 fallback entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase4 fallback hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			if !validCommittedSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase4 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePhase3ContractOverlayV1(root string, currentAtPost map[string]string, overlays map[string]phase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != committedEvidenceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase3 contract overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validCommittedSHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase3 contract entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = committedFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validCommittedSHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		} else {
			delete(pre, entry.Path)
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
	return evidenceoverlay.ResolveCurrentSHA256(root, path)
}

func validCommittedSHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

func TestPhase8ProfileCryptographyOverlayMutationsV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCommittedEvidenceOverlaysV1(root, manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":        func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra":          func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *phase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8ProfileCryptographyOverlayV1(root, map[string]phase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
}

func TestPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	mutations := map[string]func(*phase2CompleteOverlayV1){
		"missing-path":   func(v *phase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":     func(v *phase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry":  func(v *phase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry":    func(v *phase2CompleteOverlayV1) { v.Entries = append(v.Entries, phase2CompleteOverlayEntryV1{}) },
		"swapped":        func(v *phase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *phase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *phase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *phase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePhase8WO801ThreatModelOverlayV1(root, map[string]phase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
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
}

func TestPhase12OperatorControlPlaneOverlayMutationsV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]committedMaintenanceOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase12OperatorControlPlaneOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var overlays map[string]committedMaintenanceOverlayV1
		if err := json.Unmarshal(encoded, &overlays); err != nil {
			t.Fatal(err)
		}
		return overlays
	}
	phase14Pre, err := validatePhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase13Pre, err := validatePhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePhase12OperatorControlPlaneOverlayAtPostV1(root, phase13Pre, clone()); err != nil {
		t.Fatal(err)
	}
	const name = "phase12-operator-control-plane-v1"
	mutations := map[string]func(map[string]committedMaintenanceOverlayV1){
		"missing-overlay": func(overlays map[string]committedMaintenanceOverlayV1) {
			delete(overlays, name)
		},
		"extra-overlay": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlays["extra"] = overlays[name]
		},
		"missing-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries = overlay.Entries[:len(overlay.Entries)-1]
			overlays[name] = overlay
		},
		"extra-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Paths = append(overlay.Paths, "zz-phase12-extra")
			overlay.Entries = append(overlay.Entries, committedMaintenanceEntryV1{
				Path: "zz-phase12-extra", PreEvidence: "ABSENT",
				PostSHA256: strings.Repeat("1", 64),
			})
			overlays[name] = overlay
		},
		"reordered-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0], overlay.Entries[1] = overlay.Entries[1], overlay.Entries[0]
			overlays[name] = overlay
		},
		"substituted-entry": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0].Path = "README.md"
			overlays[name] = overlay
		},
		"substituted-scope-with-self-authorized-absence": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			index := 4
			overlay.Paths[index] = "zz-phase12-self-authorized"
			overlay.Entries[index] = committedMaintenanceEntryV1{
				Path:        "zz-phase12-self-authorized",
				PreEvidence: "ABSENT",
				PostSHA256:  strings.Repeat("3", 64),
			}
			overlays[name] = overlay
		},
		"existing-path-self-authorized-as-absent": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0].PreSHA256 = ""
			overlay.Entries[0].PreEvidence = "ABSENT"
			overlays[name] = overlay
		},
		"delete-authority-state-path": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			index := 15
			overlay.Paths = append(overlay.Paths[:index], overlay.Paths[index+1:]...)
			overlay.Entries = append(overlay.Entries[:index], overlay.Entries[index+1:]...)
			overlays[name] = overlay
		},
		"substitute-authority-state-path": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			index := 15
			overlay.Paths[index] = "internal/operator/controlplane/authority_substitute.go"
			overlay.Entries[index] = committedMaintenanceEntryV1{
				Path:        "internal/operator/controlplane/authority_substitute.go",
				PreEvidence: "ABSENT",
				PostSHA256:  strings.Repeat("4", 64),
			}
			overlays[name] = overlay
		},
		"add-authority-state-sibling": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Paths = append(overlay.Paths, "zz-authority-state-sibling.go")
			overlay.Entries = append(overlay.Entries, committedMaintenanceEntryV1{
				Path:        "zz-authority-state-sibling.go",
				PreEvidence: "ABSENT",
				PostSHA256:  strings.Repeat("5", 64),
			})
			overlays[name] = overlay
		},
		"post-hash-drift": func(overlays map[string]committedMaintenanceOverlayV1) {
			overlay := overlays[name]
			overlay.Entries[0].PostSHA256 = strings.Repeat("2", 64)
			overlays[name] = overlay
		},
	}
	for mutation, mutate := range mutations {
		t.Run(mutation, func(t *testing.T) {
			overlays := clone()
			mutate(overlays)
			if _, err := validatePhase12OperatorControlPlaneOverlayAtPostV1(root, phase13Pre, overlays); err == nil {
				t.Fatal("Phase 12 operator control-plane overlay mutation accepted")
			}
		})
	}
}

func TestPhase8GuardMaintenanceOverlayMutationsV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]committedMaintenanceOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase8GuardMaintenanceOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]committedMaintenanceOverlayV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase14Pre, err := validatePhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase13Pre, err := validatePhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase12Pre, err := validatePhase12OperatorControlPlaneOverlayAtPostV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase11Pre, err := validatePhase11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase10Pre, err := validatePhase10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
	if err != nil {
		t.Fatal(err)
	}
	phase9Pre, err := validatePhase9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, manifest.Phase9GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	finalGuardPre, err := validatePhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, clone()); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]committedMaintenanceOverlayV1){
		"missing-overlay": func(v map[string]committedMaintenanceOverlayV1) { delete(v, "phase8-wo806-guard-convergence-v1") },
		"extra-overlay":   func(v map[string]committedMaintenanceOverlayV1) { v["extra"] = v["phase8-wo806-guard-convergence-v1"] },
		"missing-path": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = o.Paths[:len(o.Paths)-1]
			v[o.Version] = o
		},
		"extra-path": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = append(o.Paths, "README.md")
			v[o.Version] = o
		},
		"reordered-path": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Paths[1] = o.Paths[1], o.Paths[0]
			v[o.Version] = o
		},
		"self-pre": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.SelfPreSHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"pre-hash": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PreSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
		"post-hash": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("3", 64)
			v[o.Version] = o
		},
		"path-substitution": func(v map[string]committedMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Entries[0].Path = "README.md", "README.md"
			v[o.Version] = o
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := clone()
			mutate(v)
			if _, err := validatePhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, v); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
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
func TestPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := repoRoot(t)
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(committedEvidenceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var m committedEvidenceManifestV1
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	base := m.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	muts := map[string]func(map[string]phase2CompleteOverlayV1){"missing-map": func(v map[string]phase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") }, "extra-map": func(v map[string]phase2CompleteOverlayV1) { v["extra"] = base }, "wrong-version": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Version = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-predecessor": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-path": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = x.Paths[:8]
		v["phase8-wo801-adoption-v1"] = x
	}, "extra-path": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = append(x.Paths, "x")
		v["phase8-wo801-adoption-v1"] = x
	}, "reordered": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-not-last": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-entry": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = x.Entries[:7]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-entry": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = append(x.Entries, phase2CompleteOverlayEntryV1{})
		v["phase8-wo801-adoption-v1"] = x
	}, "entry-path": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].Path = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "malformed": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PostSHA256 = "bad"
		v["phase8-wo801-adoption-v1"] = x
	}, "evidence-pre": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PreEvidence = strings.Repeat("2", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "consumer-absent": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = "ABSENT"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-pre": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = strings.Repeat("3", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "current-drift": func(v map[string]phase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
		v["phase8-wo801-adoption-v1"] = x
	}}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]phase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]phase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mut(v)
			if _, err := validatePhase8WO801AdoptionOverlayV1(root, v); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}
