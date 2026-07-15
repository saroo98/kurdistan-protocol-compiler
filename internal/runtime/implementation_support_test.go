// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	goruntime "runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

type callbackIdentityV1 struct {
	base auth.IdentityProvider
	once sync.Once
	call func()
}

func literalStringV1(expr ast.Expr) (string, bool) {
	switch value := expr.(type) {
	case *ast.BasicLit:
		if value.Kind != token.STRING {
			return "", false
		}
		text, err := strconv.Unquote(value.Value)
		return text, err == nil
	case *ast.BinaryExpr:
		if value.Op != token.ADD {
			return "", false
		}
		left, leftOK := literalStringV1(value.X)
		right, rightOK := literalStringV1(value.Y)
		return left + right, leftOK && rightOK
	case *ast.ParenExpr:
		return literalStringV1(value.X)
	default:
		return "", false
	}
}

func validateErrorfFormatV1(format string) (int, error) {
	wrappedOperands := 0
	for index := 0; index < len(format); index++ {
		if format[index] != '%' {
			continue
		}
		index++
		if index >= len(format) || (format[index] != '%' && format[index] != 'w') {
			return 0, errors.New("fmt.Errorf format contains a forbidden directive")
		}
		if format[index] == 'w' {
			wrappedOperands++
		}
	}
	return wrappedOperands, nil
}

func validateErrorConstructionV1(file *ast.File) error {
	aliases := map[string]string{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || (path != "errors" && path != "fmt") {
			continue
		}
		alias := path
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." {
			return fmt.Errorf("dot import of %s is forbidden", path)
		}
		if alias != "_" {
			aliases[alias] = path
		}
	}

	var shadow string
	checkName := func(name string) {
		if shadow == "" && aliases[name] != "" {
			shadow = name
		}
	}
	checkFields := func(fields *ast.FieldList) {
		if fields == nil {
			return
		}
		for _, field := range fields.List {
			for _, name := range field.Names {
				checkName(name.Name)
			}
		}
	}
	ast.Inspect(file, func(node ast.Node) bool {
		if shadow != "" {
			return false
		}
		switch value := node.(type) {
		case *ast.FuncDecl:
			checkName(value.Name.Name)
			checkFields(value.Recv)
			checkFields(value.Type.TypeParams)
			checkFields(value.Type.Params)
			checkFields(value.Type.Results)
		case *ast.FuncLit:
			checkFields(value.Type.TypeParams)
			checkFields(value.Type.Params)
			checkFields(value.Type.Results)
		case *ast.ValueSpec:
			for _, name := range value.Names {
				checkName(name.Name)
			}
		case *ast.TypeSpec:
			checkName(value.Name.Name)
			checkFields(value.TypeParams)
		case *ast.AssignStmt:
			if value.Tok == token.DEFINE {
				for _, expr := range value.Lhs {
					if name, ok := expr.(*ast.Ident); ok {
						checkName(name.Name)
					}
				}
			}
		case *ast.RangeStmt:
			if value.Tok == token.DEFINE {
				for _, expr := range []ast.Expr{value.Key, value.Value} {
					if name, ok := expr.(*ast.Ident); ok {
						checkName(name.Name)
					}
				}
			}
		}
		return shadow == ""
	})
	if shadow != "" {
		return fmt.Errorf("error package import alias %s is shadowed", shadow)
	}

	var finding error
	ast.Inspect(file, func(node ast.Node) bool {
		if finding != nil {
			return false
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		pkg, ok := selector.X.(*ast.Ident)
		if !ok {
			return true
		}
		path := aliases[pkg.Name]
		if !((path == "errors" && selector.Sel.Name == "New") || (path == "fmt" && selector.Sel.Name == "Errorf")) {
			return true
		}
		if len(call.Args) == 0 {
			finding = fmt.Errorf("%s.%s has no message/format argument", pkg.Name, selector.Sel.Name)
			return false
		}
		message, ok := literalStringV1(call.Args[0])
		if !ok {
			finding = fmt.Errorf("%s.%s message/format is not composed only of string-literal fragments", pkg.Name, selector.Sel.Name)
			return false
		}
		if path == "fmt" {
			if call.Ellipsis != token.NoPos {
				finding = errors.New("variadic fmt.Errorf operands are forbidden")
				return false
			}
			wrappedOperands, err := validateErrorfFormatV1(message)
			if err != nil {
				finding = err
				return false
			}
			if len(call.Args)-1 != wrappedOperands {
				finding = errors.New("fmt.Errorf operand count does not exactly match %w directives")
				return false
			}
		}
		return true
	})
	return finding
}

func TestImplementationSupportV1LiteralOnlyErrorConstructionDetector(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		wantErr bool
	}{
		{"aliased literals wrapped operand and escaped percent", `package p; import (e "errors"; f "fmt"); func g(err error) { _ = e.New("profile " + ("mismatch")); _ = f.Errorf("%w: fixed %%", err) }`, false},
		{"fixed format zero operands", `package p; import f "fmt"; func g() { _ = f.Errorf("fixed") }`, false},
		{"escaped percent zero operands", `package p; import f "fmt"; func g() { _ = f.Errorf("fixed %%") }`, false},
		{"one wrapped operand", `package p; import f "fmt"; func g(err error) { _ = f.Errorf("fixed: %w", err) }`, false},
		{"two wrapped operands", `package p; import f "fmt"; func g(first, second error) { _ = f.Errorf("first: %w; second: %w", first, second) }`, false},
		{"fixed format extra operand", `package p; import f "fmt"; func g(secret string) { _ = f.Errorf("fixed", secret) }`, true},
		{"wrapped format extra operand", `package p; import f "fmt"; func g(err error, secret string) { _ = f.Errorf("fixed: %w", err, secret) }`, true},
		{"missing wrapped operand", `package p; import f "fmt"; func g() { _ = f.Errorf("fixed: %w") }`, true},
		{"variadic operands", `package p; import f "fmt"; func g(args []any) { _ = f.Errorf("fixed: %w", args...) }`, true},
		{"aliased dynamic errors.New concatenation", `package p; import e "errors"; func g(rejectedProfile string) { _ = e.New("profile mismatch: " + rejectedProfile) }`, true},
		{"aliased dynamic fmt.Errorf concatenation", `package p; import f "fmt"; func g(err error, rejectedProfile string) { _ = f.Errorf("%w: " + rejectedProfile, err) }`, true},
		{"errors dot import", `package p; import . "errors"; func g() { _ = New("fixed") }`, true},
		{"fmt dot import", `package p; import . "fmt"; func g(err error) { _ = Errorf("%w", err) }`, true},
		{"alias shadowed by parameter", `package p; import e "errors"; func g(e string) {}`, true},
		{"alias shadowed by local var", `package p; import e "errors"; func g() { var e string; _ = e }`, true},
		{"alias shadowed by local const", `package p; import e "errors"; func g() { const e = "value"; _ = e }`, true},
		{"alias shadowed by local type", `package p; import e "errors"; func g() { type e string }`, true},
		{"alias shadowed by range declaration", `package p; import e "errors"; func g(values []string) { for e := range values { _ = e } }`, true},
		{"alias shadowed by short declaration", `package p; import e "errors"; func g() { e := "value"; _ = e }`, true},
		{"named const message rejected", `package p; import e "errors"; const message = "fixed"; func g() { _ = e.New(message) }`, true},
		{"uppercase hex directive rejected", `package p; import f "fmt"; func g(value int) { _ = f.Errorf("bad %X", value) }`, true},
		{"indexed directive rejected", `package p; import f "fmt"; func g(value int) { _ = f.Errorf("bad %[1]v", value) }`, true},
		{"flagged directive rejected", `package p; import f "fmt"; func g(err error) { _ = f.Errorf("bad %+w", err) }`, true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			file, err := parser.ParseFile(token.NewFileSet(), "witness.go", test.source, 0)
			if err != nil {
				t.Fatal(err)
			}
			err = validateErrorConstructionV1(file)
			if (err != nil) != test.wantErr {
				t.Fatalf("detector error=%v wantErr=%v", err, test.wantErr)
			}
		})
	}
}

type runtimeFunctionSignatureV1 struct {
	parameterSupport bool
	parameterEntropy bool
	receiverSupport  bool
	receiverEntropy  bool
	resultSupport    bool
	resultEntropy    bool
}

func (s runtimeFunctionSignatureV1) exposesSupport() bool {
	return s.parameterSupport || s.receiverSupport || s.resultSupport
}

func (s runtimeFunctionSignatureV1) exposesEntropy() bool {
	return s.parameterEntropy || s.receiverEntropy || s.resultEntropy
}

type runtimeTypeIdentityResolverV1 struct {
	supportNames map[string]bool
	entropyNames map[string]bool
	ioAliases    map[*ast.File]map[string]bool
}

func newRuntimeTypeIdentityResolverV1(files map[string]*ast.File) (*runtimeTypeIdentityResolverV1, error) {
	resolver := &runtimeTypeIdentityResolverV1{
		supportNames: map[string]bool{"ImplementationSupportV1": true},
		entropyNames: map[string]bool{},
		ioAliases:    map[*ast.File]map[string]bool{},
	}
	for _, file := range files {
		resolver.ioAliases[file] = map[string]bool{}
		for _, spec := range file.Imports {
			path, err := strconv.Unquote(spec.Path.Value)
			if err != nil || path != "io" {
				continue
			}
			alias := "io"
			if spec.Name != nil {
				alias = spec.Name.Name
			}
			if alias == "." {
				return nil, errors.New("dot import of io is forbidden because bare Reader obscures entropy identity")
			}
			if alias != "_" {
				resolver.ioAliases[file][alias] = true
			}
		}
	}

	const opaqueOwnerName = "HandshakeRuntime"
	opaqueOwnerCount := 0
	for _, file := range files {
		for _, declaration := range file.Decls {
			general, ok := declaration.(*ast.GenDecl)
			if !ok || general.Tok != token.TYPE {
				continue
			}
			for _, spec := range general.Specs {
				typeSpec := spec.(*ast.TypeSpec)
				if typeSpec.Name.Name != opaqueOwnerName {
					continue
				}
				opaqueOwnerCount++
				owner, ok := typeSpec.Type.(*ast.StructType)
				if !ok {
					return nil, errors.New("HandshakeRuntime opaque owner is not a struct")
				}
				for _, field := range owner.Fields.List {
					if len(field.Names) == 0 {
						return nil, errors.New("HandshakeRuntime opaque owner has an embedded field")
					}
					for _, name := range field.Names {
						if ast.IsExported(name.Name) {
							return nil, errors.New("HandshakeRuntime opaque owner has an exported field")
						}
					}
				}
			}
		}
	}
	if opaqueOwnerCount != 1 {
		return nil, fmt.Errorf("HandshakeRuntime opaque owner declarations=%d want=1", opaqueOwnerCount)
	}

	var typeIdentity func(*ast.File, ast.Expr) (bool, bool)
	fieldIdentity := func(file *ast.File, fields *ast.FieldList) (bool, bool) {
		hasSupport, hasEntropy := false, false
		if fields == nil {
			return false, false
		}
		for _, field := range fields.List {
			support, entropy := typeIdentity(file, field.Type)
			hasSupport = hasSupport || support
			hasEntropy = hasEntropy || entropy
		}
		return hasSupport, hasEntropy
	}
	merge := func(leftSupport, leftEntropy, rightSupport, rightEntropy bool) (bool, bool) {
		return leftSupport || rightSupport, leftEntropy || rightEntropy
	}
	typeIdentity = func(file *ast.File, expr ast.Expr) (bool, bool) {
		switch value := expr.(type) {
		case *ast.Ident:
			return resolver.supportNames[value.Name], resolver.entropyNames[value.Name]
		case *ast.SelectorExpr:
			base, ok := value.X.(*ast.Ident)
			return false, ok && resolver.ioAliases[file][base.Name] && value.Sel.Name == "Reader"
		case *ast.ParenExpr:
			return typeIdentity(file, value.X)
		case *ast.StarExpr:
			return typeIdentity(file, value.X)
		case *ast.ArrayType:
			return typeIdentity(file, value.Elt)
		case *ast.MapType:
			keySupport, keyEntropy := typeIdentity(file, value.Key)
			valueSupport, valueEntropy := typeIdentity(file, value.Value)
			return merge(keySupport, keyEntropy, valueSupport, valueEntropy)
		case *ast.ChanType:
			return typeIdentity(file, value.Value)
		case *ast.Ellipsis:
			return typeIdentity(file, value.Elt)
		case *ast.FuncType:
			typeSupport, typeEntropy := fieldIdentity(file, value.TypeParams)
			parameterSupport, parameterEntropy := fieldIdentity(file, value.Params)
			resultSupport, resultEntropy := fieldIdentity(file, value.Results)
			typeSupport, typeEntropy = merge(typeSupport, typeEntropy, parameterSupport, parameterEntropy)
			return merge(typeSupport, typeEntropy, resultSupport, resultEntropy)
		case *ast.InterfaceType:
			return fieldIdentity(file, value.Methods)
		case *ast.StructType:
			return fieldIdentity(file, value.Fields)
		case *ast.IndexExpr:
			baseSupport, baseEntropy := typeIdentity(file, value.X)
			indexSupport, indexEntropy := typeIdentity(file, value.Index)
			return merge(baseSupport, baseEntropy, indexSupport, indexEntropy)
		case *ast.IndexListExpr:
			hasSupport, hasEntropy := typeIdentity(file, value.X)
			for _, index := range value.Indices {
				indexSupport, indexEntropy := typeIdentity(file, index)
				hasSupport, hasEntropy = merge(hasSupport, hasEntropy, indexSupport, indexEntropy)
			}
			return hasSupport, hasEntropy
		case *ast.UnaryExpr:
			return typeIdentity(file, value.X)
		case *ast.BinaryExpr:
			leftSupport, leftEntropy := typeIdentity(file, value.X)
			rightSupport, rightEntropy := typeIdentity(file, value.Y)
			return merge(leftSupport, leftEntropy, rightSupport, rightEntropy)
		default:
			return false, false
		}
	}
	for changed := true; changed; {
		changed = false
		for _, file := range files {
			for _, declaration := range file.Decls {
				general, ok := declaration.(*ast.GenDecl)
				if !ok || general.Tok != token.TYPE {
					continue
				}
				for _, spec := range general.Specs {
					typeSpec := spec.(*ast.TypeSpec)
					if typeSpec.Name.Name == opaqueOwnerName {
						continue
					}
					support, entropy := typeIdentity(file, typeSpec.Type)
					if support && !resolver.supportNames[typeSpec.Name.Name] {
						resolver.supportNames[typeSpec.Name.Name] = true
						changed = true
					}
					if entropy && !resolver.entropyNames[typeSpec.Name.Name] {
						resolver.entropyNames[typeSpec.Name.Name] = true
						changed = true
					}
				}
			}
		}
	}
	return resolver, nil
}

func (r *runtimeTypeIdentityResolverV1) classifyFields(file *ast.File, fields *ast.FieldList) (bool, bool) {
	if fields == nil {
		return false, false
	}
	hasSupport, hasEntropy := false, false
	for _, field := range fields.List {
		ast.Inspect(field.Type, func(node ast.Node) bool {
			switch value := node.(type) {
			case *ast.Ident:
				hasSupport = hasSupport || r.supportNames[value.Name]
				hasEntropy = hasEntropy || r.entropyNames[value.Name]
			case *ast.SelectorExpr:
				base, ok := value.X.(*ast.Ident)
				hasEntropy = hasEntropy || (ok && r.ioAliases[file][base.Name] && value.Sel.Name == "Reader")
			}
			return true
		})
	}
	return hasSupport, hasEntropy
}

func (r *runtimeTypeIdentityResolverV1) classifyFunction(file *ast.File, fn *ast.FuncDecl) runtimeFunctionSignatureV1 {
	var signature runtimeFunctionSignatureV1
	signature.parameterSupport, signature.parameterEntropy = r.classifyFields(file, fn.Type.Params)
	signature.receiverSupport, signature.receiverEntropy = r.classifyFields(file, fn.Recv)
	signature.resultSupport, signature.resultEntropy = r.classifyFields(file, fn.Type.Results)
	return signature
}

func validateRuntimeProductionSignatureV1(resolver *runtimeTypeIdentityResolverV1, file *ast.File, fn *ast.FuncDecl) (runtimeFunctionSignatureV1, error) {
	signature := resolver.classifyFunction(file, fn)
	if ast.IsExported(fn.Name.Name) && (signature.exposesSupport() || signature.exposesEntropy()) {
		return signature, fmt.Errorf("exported function or method %s exposes strict support or entropy in parameters, receiver, or results", fn.Name.Name)
	}
	if signature.parameterSupport && signature.parameterEntropy && fn.Name.Name != "newStrictHandshakeRuntimeV1" {
		return signature, fmt.Errorf("unexpected support+entropy seam %s", fn.Name.Name)
	}
	if !signature.parameterSupport && signature.parameterEntropy && fn.Name.Name != "newHandshakeRuntime" {
		return signature, fmt.Errorf("unexpected entropy-only seam %s", fn.Name.Name)
	}
	return signature, nil
}

func validateRuntimePackageSignaturesV1(files map[string]*ast.File) (int, int, error) {
	resolver, err := newRuntimeTypeIdentityResolverV1(files)
	if err != nil {
		return 0, 0, err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	strictSupportEntropySeams, legacyEntropyOnlySeams := 0, 0
	for _, name := range names {
		file := files[name]
		for _, declaration := range file.Decls {
			fn, ok := declaration.(*ast.FuncDecl)
			if !ok {
				continue
			}
			signature, err := validateRuntimeProductionSignatureV1(resolver, file, fn)
			if err != nil {
				return 0, 0, fmt.Errorf("%s in %s", err, name)
			}
			if signature.parameterSupport && signature.parameterEntropy {
				strictSupportEntropySeams++
			}
			if !signature.parameterSupport && signature.parameterEntropy {
				legacyEntropyOnlySeams++
			}
		}
	}
	if strictSupportEntropySeams != 1 || legacyEntropyOnlySeams != 1 {
		return strictSupportEntropySeams, legacyEntropyOnlySeams, fmt.Errorf("runtime production seam counts strict-support+entropy=%d legacy-entropy-only=%d", strictSupportEntropySeams, legacyEntropyOnlySeams)
	}
	return strictSupportEntropySeams, legacyEntropyOnlySeams, nil
}

func parseRuntimeWitnessPackageV1(t *testing.T, sources map[string]string) map[string]*ast.File {
	t.Helper()
	files := make(map[string]*ast.File, len(sources))
	for name, source := range sources {
		file, err := parser.ParseFile(token.NewFileSet(), name, source, 0)
		if err != nil {
			t.Fatal(err)
		}
		files[name] = file
	}
	return files
}

func TestImplementationSupportV1PackageWideSignatureDetector(t *testing.T) {
	base := `package runtime
import "io"
type ImplementationSupportV1 struct{}
type HandshakeRuntime struct {
	support ImplementationSupportV1
	entropy io.Reader
}
func privateSupportOnly(s ImplementationSupportV1) {}
func newStrictHandshakeRuntimeV1(s ImplementationSupportV1, entropy io.Reader) {}
func newHandshakeRuntime(entropy io.Reader) {}`
	with := func(extras map[string]string) map[string]string {
		sources := map[string]string{"base.go": base}
		for name, source := range extras {
			sources[name] = source
		}
		return sources
	}

	t.Run("clean private support and intended seams", func(t *testing.T) {
		strict, legacy, err := validateRuntimePackageSignaturesV1(parseRuntimeWitnessPackageV1(t, with(nil)))
		if err != nil || strict != 1 || legacy != 1 {
			t.Fatalf("strict=%d legacy=%d error=%v", strict, legacy, err)
		}
	})
	negative := []struct {
		name   string
		extra  map[string]string
		marker string
	}{
		{"direct support alias exported parameter", map[string]string{"expose.go": `package runtime; type SupportAlias = ImplementationSupportV1; func Exposed(SupportAlias) {}`}, ""},
		{"chained support alias exported parameter", map[string]string{
			"first.go":  `package runtime; type FirstSupport = ImplementationSupportV1`,
			"second.go": `package runtime; type SecondSupport FirstSupport; func Exposed(SecondSupport) {}`,
		}, ""},
		{"support alias exported result getter", map[string]string{"expose.go": `package runtime; type SupportAlias ImplementationSupportV1; func Exposed() SupportAlias { panic("unreachable") }`}, ""},
		{"support wrapper exported method receiver", map[string]string{"expose.go": `package runtime; type SupportWrapper ImplementationSupportV1; func (SupportWrapper) Exposed() {}`}, ""},
		{"support slice wrapper exported parameter", map[string]string{"expose.go": `package runtime; type SupportBag []ImplementationSupportV1; func Exposed(SupportBag) {}`}, ""},
		{"chained composite support wrapper", map[string]string{
			"pointer.go": `package runtime; type SupportPointer *ImplementationSupportV1`,
			"map.go":     `package runtime; type SupportMap map[string]SupportPointer; func Exposed(SupportMap) {}`,
		}, ""},
		{"struct support wrapper exported parameter", map[string]string{"expose.go": `package runtime; type SupportStruct struct { support ImplementationSupportV1 }; func Exposed(SupportStruct) {}`}, ""},
		{"dot io bare Reader", map[string]string{"expose.go": `package runtime; import . "io"; func ExposedEntropy(Reader) {}`}, "dot import of io"},
		{"exported entropy alias parameter", map[string]string{"expose.go": `package runtime; import stream "io"; type EntropyAlias = stream.Reader; func ExposedEntropy(EntropyAlias) {}`}, ""},
		{"entropy interface wrapper exported parameter", map[string]string{"expose.go": `package runtime; import stream "io"; type EntropyWrapper interface { stream.Reader }; func ExposedEntropy(EntropyWrapper) {}`}, ""},
		{"entropy wrapper exported result", map[string]string{"expose.go": `package runtime; import stream "io"; type EntropyResult struct { reader stream.Reader }; func ExposedEntropy() EntropyResult { panic("unreachable") }`}, ""},
		{"entropy wrapper exported receiver", map[string]string{"expose.go": `package runtime; import stream "io"; type EntropyReceiver struct { reader stream.Reader }; func (EntropyReceiver) ExposedEntropy() {}`}, ""},
	}
	for _, test := range negative {
		t.Run(test.name, func(t *testing.T) {
			_, _, err := validateRuntimePackageSignaturesV1(parseRuntimeWitnessPackageV1(t, with(test.extra)))
			if err == nil || (test.marker != "" && !strings.Contains(err.Error(), test.marker)) {
				t.Fatalf("detector error=%v marker=%q", err, test.marker)
			}
		})
	}

	t.Run("imported io entropy alias identity", func(t *testing.T) {
		files := parseRuntimeWitnessPackageV1(t, with(map[string]string{
			"alias.go": `package runtime; import stream "io"; type EntropyAlias = stream.Reader`,
		}))
		resolver, err := newRuntimeTypeIdentityResolverV1(files)
		if err != nil || !resolver.entropyNames["EntropyAlias"] {
			t.Fatalf("entropy alias resolved=%v error=%v", resolver != nil && resolver.entropyNames["EntropyAlias"], err)
		}
	})
}

func (p *callbackIdentityV1) Local(id string) (ed25519.PrivateKey, error) {
	p.once.Do(p.call)
	return p.base.Local(id)
}

type strictSupportFixtureV1 struct {
	input          auth.FirstContactInput
	snapshot       auth.FirstContactInput
	view           auth.FirstContactPreflightViewV1
	dependencies   runtimeDependencyFixture
	clientEntry    ClientProfileAuthorizationEntryV1
	relayEntry     RelayProfileAuthorizationEntryV1
	clientRegistry ClientProfileAuthorizationRegistryV1
	relayRegistry  RelayProfileAuthorizationRegistryV1
}

func newStrictSupportFixtureV1(t *testing.T, mode, downgrade, capability string) strictSupportFixtureV1 {
	t.Helper()
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	selected := floor
	if capability != "strict_required" {
		selected = known
	}
	return newStrictSupportFixtureWithSetsV1(t, mode, downgrade, capability, floor, floor, known, known, selected)
}

func newStrictSupportFixtureWithSetsV1(t *testing.T, mode, downgrade, capability string, clientFloor, relayFloor, clientOffer, relayOffer, selected []string) strictSupportFixtureV1 {
	return newStrictSupportFixturePolicyWithSetsV1(t, mode, downgrade, capability, "strict_schema", "strict_required", clientFloor, relayFloor, clientOffer, relayOffer, selected)
}

func newStrictSupportFixturePolicyWithSetsV1(t *testing.T, mode, downgrade, capability, profilePolicy, configPolicy string, clientFloor, relayFloor, clientOffer, relayOffer, selected []string) strictSupportFixtureV1 {
	t.Helper()
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = mode
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = downgrade
	p.Security.CapabilityNegotiationPolicy = capability
	p.Security.ProfileCompatibilityPolicy = profilePolicy
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = configPolicy
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, clientFloor, relayFloor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, clientOffer, clientFloor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, relayOffer, relayFloor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{
		Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), selected...),
		ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay,
	}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	clientEntry := clientAuthorizationEntryV1(snapshot.Client.ProfileHash, policyHash, policy, view.ClientModeBinding)
	relayEntry := relayAuthorizationEntryV1(snapshot.Server.ProfileHash, policyHash, policy, view.ServerModeBinding)
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{clientEntry})
	if err != nil {
		t.Fatal(err)
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{relayEntry})
	if err != nil {
		t.Fatal(err)
	}
	return strictSupportFixtureV1{
		input: input, snapshot: snapshot, view: view, dependencies: dependencies,
		clientEntry: clientEntry, relayEntry: relayEntry,
		clientRegistry: clientRegistry, relayRegistry: relayRegistry,
	}
}

func generatedPolicyRuntimeFixtureV1(t *testing.T, seed int64) (strictSupportFixtureV1, ir.EffectiveSecurityPolicy) {
	t.Helper()
	generated, err := compiler.Generate(seed)
	if err != nil {
		t.Fatal(err)
	}
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security = generated.Security
	p.Compatibility.MaxReplayWindow = p.Security.ReplayWindowSize
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	p.Compatibility.RequiredCapabilities = append([]string(nil), floor...)
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	selected := floor
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), selected...), ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	clientEntry := clientAuthorizationEntryV1(snapshot.Client.ProfileHash, policyHash, policy, view.ClientModeBinding)
	relayEntry := relayAuthorizationEntryV1(snapshot.Server.ProfileHash, policyHash, policy, view.ServerModeBinding)
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{clientEntry})
	if err != nil {
		t.Fatal(err)
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{relayEntry})
	if err != nil {
		t.Fatal(err)
	}
	return strictSupportFixtureV1{input: input, snapshot: snapshot, view: view, dependencies: dependencies, clientEntry: clientEntry, relayEntry: relayEntry, clientRegistry: clientRegistry, relayRegistry: relayRegistry}, policy
}

func clientAuthorizationEntryV1(profileHash, policyHash [32]byte, policy ir.EffectiveSecurityPolicy, binding security.HandshakeModeBinding) ClientProfileAuthorizationEntryV1 {
	return ClientProfileAuthorizationEntryV1{
		ProfileHash: profileHash, EffectivePolicyHash: policyHash,
		ReplayWindowSize: uint32(policy.ReplayWindowSize), MaxConcurrentStreams: binding.LimitBlock.SessionMaxConcurrentStreams,
		MaxFrameBytes: binding.MaxFrameBytes, MaxEnvelopeBytes: binding.EnvelopeLimit,
		FramingPolicyHash: binding.FramingPolicyHash, StateMachinePolicyHash: binding.StateMachinePolicyHash,
		SchedulerPolicyHash: binding.SchedulerPolicyHash, PaddingPolicyHash: binding.PaddingPolicyHash,
		StreamPolicyHash: binding.StreamPolicyHash, ProxyPolicyHash: binding.ProxyPolicyHash,
		CarrierContextPolicyHash: binding.CarrierContextHash,
	}
}

func relayAuthorizationEntryV1(profileHash, policyHash [32]byte, policy ir.EffectiveSecurityPolicy, binding security.HandshakeModeBinding) RelayProfileAuthorizationEntryV1 {
	return RelayProfileAuthorizationEntryV1{
		ProfileHash: profileHash, EffectivePolicyHash: policyHash,
		ReplayWindowSize: uint32(policy.ReplayWindowSize), MaxConcurrentStreams: binding.LimitBlock.SessionMaxConcurrentStreams,
		MaxFrameBytes: binding.MaxFrameBytes, MaxEnvelopeBytes: binding.EnvelopeLimit,
		FramingPolicyHash: binding.FramingPolicyHash, StateMachinePolicyHash: binding.StateMachinePolicyHash,
		SchedulerPolicyHash: binding.SchedulerPolicyHash, PaddingPolicyHash: binding.PaddingPolicyHash,
		StreamPolicyHash: binding.StreamPolicyHash, ProxyPolicyHash: binding.ProxyPolicyHash,
		CarrierContextPolicyHash: binding.CarrierContextHash,
	}
}

func sortedStringsV1(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	return out
}

func strictRuntimeForFixtureV1(t *testing.T, fixture strictSupportFixtureV1, clientSupport, relaySupport ImplementationSupportV1, entropy interface{ Read([]byte) (int, error) }) *HandshakeRuntime {
	t.Helper()
	runtime, err := newStrictHandshakeRuntimeV1(
		fixture.dependencies.client, fixture.dependencies.server,
		fixture.clientRegistry, fixture.relayRegistry,
		clientSupport, relaySupport, entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func assertStrictSuccessV1(t *testing.T, runtime *HandshakeRuntime, input auth.FirstContactInput) auth.FirstContactResult {
	t.Helper()
	result, err := runtime.FirstContact(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(result.ChannelSecret) == 0 {
		t.Fatal("strict first contact returned no channel secret")
	}
	t.Cleanup(func() {
		for i := range result.ChannelSecret {
			result.ChannelSecret[i] = 0
		}
	})
	return result
}

func advancedPolicySupportInputV1(t *testing.T, profilePolicy string) (*HandshakeRuntime, supportAuthorizationInputV1) {
	return policySupportInputV1(t, security.TranscriptCanonicalV1, profilePolicy)
}

func policySupportInputV1(t *testing.T, transcriptMode, profilePolicy string) (*HandshakeRuntime, supportAuthorizationInputV1) {
	t.Helper()
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	fixture := newStrictSupportFixturePolicyWithSetsV1(t, transcriptMode, "strict_capabilities", "strict_required", profilePolicy, "strict_required", floor, floor, known, known, floor)
	policies := []ir.EffectiveSecurityPolicy{
		fixture.view.ClientOfferPolicy.Clone(), fixture.view.ClientFloorPolicy.Clone(), fixture.view.ServerOfferPolicy.Clone(),
		fixture.view.ServerFloorPolicy.Clone(), fixture.view.SelectedPolicy.Clone(),
	}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{7}, 64)))
	return runtime, supportAuthorizationInputV1{
		policies: policies, selectedCapabilities: append([]string(nil), fixture.view.SelectedCapabilities...),
		clientProfileHash: fixture.snapshot.Client.ProfileHash, relayProfileHash: fixture.snapshot.Server.ProfileHash,
		clientBinding: fixture.view.ClientModeBinding.Clone(), relayBinding: fixture.view.ServerModeBinding.Clone(),
		clientOffered: append([]string(nil), fixture.view.ClientOfferedCapabilities...), clientRequired: append([]string(nil), fixture.view.ClientRequiredCapabilities...),
		relayOffered: append([]string(nil), fixture.view.ServerOfferedCapabilities...), relayRequired: append([]string(nil), fixture.view.ServerRequiredCapabilities...),
	}
}

func TestPolicyMatrixSupportOwnerSentinelPrecedenceV1(t *testing.T) {
	tests := []struct {
		name   string
		make   func(*testing.T) (*HandshakeRuntime, supportAuthorizationInputV1)
		mutate func(*HandshakeRuntime, *supportAuthorizationInputV1)
		want   error
	}{
		{"profile-source-first", func(t *testing.T) (*HandshakeRuntime, supportAuthorizationInputV1) {
			return advancedPolicySupportInputV1(t, "full_policy_binding")
		}, func(_ *HandshakeRuntime, input *supportAuthorizationInputV1) { input.clientProfileHash[0] ^= 1 }, ErrProfileMismatch},
		{"full-policy-effective-tuple", func(t *testing.T) (*HandshakeRuntime, supportAuthorizationInputV1) {
			return advancedPolicySupportInputV1(t, "full_policy_binding")
		}, func(runtime *HandshakeRuntime, _ *supportAuthorizationInputV1) {
			runtime.clientRegistry.entries[0].maxFrameBytes--
		}, ErrProfileIncompatible},
		{"canonical-full-seven-hash", func(t *testing.T) (*HandshakeRuntime, supportAuthorizationInputV1) {
			return policySupportInputV1(t, security.TranscriptFullBindingV1, "strict_schema")
		}, func(runtime *HandshakeRuntime, _ *supportAuthorizationInputV1) {
			runtime.clientRegistry.entries[0].framingPolicyHash[0] ^= 1
		}, ErrFullBindingInvalid},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, input := test.make(t)
			if err := runtime.verifySupportAndAuthorizationV1(input); err != nil {
				t.Fatalf("valid owner: %v", err)
			}
			test.mutate(runtime, &input)
			err := runtime.verifySupportAndAuthorizationV1(input)
			if !errors.Is(err, test.want) || err.Error() != test.want.Error() {
				t.Fatalf("err=%v want exact %v", err, test.want)
			}
		})
	}
}

func TestAdvancedPolicySupportSchemaAndFeatureV1(t *testing.T) {
	for _, role := range []string{"client", "relay"} {
		for _, namespace := range []string{"capability", "carrier", "proxy", "stream", "adapter"} {
			for _, source := range []string{"support", "descriptor"} {
				t.Run(role+"-missing-"+namespace+"-"+source, func(t *testing.T) {
					runtime, input := advancedPolicySupportInputV1(t, "schema_and_feature")
					support := &runtime.clientSupport
					binding := &input.clientBinding
					if role == "relay" {
						support = &runtime.relaySupport
						binding = &input.relayBinding
					}
					prefix, value := namespace+":", ""
					for _, feature := range binding.FeatureVectors {
						if strings.HasPrefix(feature, prefix) {
							value = strings.TrimPrefix(feature, prefix)
							break
						}
					}
					if source == "support" {
						switch namespace {
						case "capability":
							support.capabilities = removeStringV1(support.capabilities, input.selectedCapabilities[0])
						case "carrier":
							support.carrierFamilies = removeStringV1(support.carrierFamilies, binding.CarrierFamily)
						case "proxy":
							support.proxyFeatures = removeStringV1(support.proxyFeatures, value)
						case "stream":
							support.streamFeatures = removeStringV1(support.streamFeatures, value)
						case "adapter":
							support.adapterClasses = removeStringV1(support.adapterClasses, binding.LocalAdapterClass)
						}
					} else {
						switch namespace {
						case "capability":
							binding.CompatibilityBlock.RequiredCapabilities = removeStringV1(binding.CompatibilityBlock.RequiredCapabilities, input.selectedCapabilities[0])
							binding.ClientOptional = removeStringV1(binding.ClientOptional, input.selectedCapabilities[0])
							binding.ServerOptional = removeStringV1(binding.ServerOptional, input.selectedCapabilities[0])
						case "carrier":
							binding.CompatibilityBlock.SupportedCarrierFamilies = removeStringV1(binding.CompatibilityBlock.SupportedCarrierFamilies, binding.CarrierFamily)
						case "proxy":
							binding.CompatibilityBlock.SupportedProxyFeatures = removeStringV1(binding.CompatibilityBlock.SupportedProxyFeatures, value)
						case "stream":
							binding.CompatibilityBlock.SupportedStreamFeatures = removeStringV1(binding.CompatibilityBlock.SupportedStreamFeatures, value)
						case "adapter":
							binding.ConfigSourceBlock.AdapterClass = "descriptor_missing_adapter"
						}
					}
					if verifySchemaAndFeatureV1(*support, input.selectedCapabilities, *binding) {
						t.Fatalf("missing %s %s %s coverage passed", role, namespace, source)
					}
				})
			}
		}
	}
	runtime, input := advancedPolicySupportInputV1(t, "schema_and_feature")
	if err := runtime.verifySupportAndAuthorizationV1(input); err != nil {
		t.Fatal(err)
	}
}

func TestAdvancedPolicySupportFullPolicyBindingV1(t *testing.T) {
	runtime, input := advancedPolicySupportInputV1(t, "full_policy_binding")
	if err := runtime.verifySupportAndAuthorizationV1(input); err != nil {
		t.Fatal(err)
	}
	for _, role := range []string{"client", "relay"} {
		t.Run(role+"-missing", func(t *testing.T) {
			clientEntry := runtime.clientRegistry.entries[0]
			relayEntry := runtime.relayRegistry.entries[0]
			defer func() {
				runtime.clientRegistry.entries[0] = clientEntry
				runtime.relayRegistry.entries[0] = relayEntry
			}()
			if role == "client" {
				runtime.clientRegistry.entries[0].maxFrameBytes--
			} else {
				runtime.relayRegistry.entries[0].maxEnvelopeBytes--
			}
			if err := runtime.verifySupportAndAuthorizationV1(input); !errors.Is(err, ErrProfileIncompatible) || err.Error() != "profile_incompatible" {
				t.Fatalf("missing %s full binding err=%v", role, err)
			}
		})
	}
}

func TestAdvancedPolicySupportAdvertisedWitnessV1(t *testing.T) {
	witnesses := advancedPolicyWitnessesV1()
	for _, support := range []ImplementationSupportV1{reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1} {
		if !advertisedSupportMatchesWitnessV1(support) {
			t.Fatal("advertised support differs from witness inventory")
		}
	}
	cases := []struct {
		name        string
		defaults    []string
		witness     map[string]string
		setDefaults func(*ImplementationSupportV1, []string)
	}{
		{"nonce", reviewedClientImplementationSupportV1.nonceModes, witnesses.nonce, func(s *ImplementationSupportV1, v []string) { s.nonceModes = v }},
		{"replay", reviewedClientImplementationSupportV1.replayPolicies, witnesses.replay, func(s *ImplementationSupportV1, v []string) { s.replayPolicies = v }},
		{"profile", reviewedClientImplementationSupportV1.profilePolicies, witnesses.profile, func(s *ImplementationSupportV1, v []string) { s.profilePolicies = v }},
		{"rotation", reviewedClientImplementationSupportV1.rotationPolicies, witnesses.rotation, func(s *ImplementationSupportV1, v []string) { s.rotationPolicies = v }},
		{"config", reviewedClientImplementationSupportV1.configPolicies, witnesses.config, func(s *ImplementationSupportV1, v []string) { s.configPolicies = v }},
		{"envelope", reviewedClientImplementationSupportV1.envelopeModes, witnesses.envelope, func(s *ImplementationSupportV1, v []string) { s.envelopeModes = v }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			for value, owner := range tc.witness {
				parts := strings.Split(owner, ":")
				if len(parts) != 2 || (!strings.HasPrefix(parts[0], "internal/runtime/") && !strings.HasPrefix(parts[0], "internal/crypto/security/")) || !strings.HasSuffix(parts[0], "_test.go") {
					t.Fatalf("%s witness %q has invalid owner %q", tc.name, value, owner)
				}
				file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", filepath.FromSlash(parts[0])), nil, 0)
				if err != nil {
					t.Fatalf("parse witness owner %q: %v", owner, err)
				}
				found := false
				for _, declaration := range file.Decls {
					function, ok := declaration.(*ast.FuncDecl)
					if ok && function.Recv == nil && function.Name.Name == parts[1] {
						ast.Inspect(function.Body, func(node ast.Node) bool {
							literal, ok := node.(*ast.BasicLit)
							if ok && literal.Kind == token.STRING {
								decoded, err := strconv.Unquote(literal.Value)
								if err == nil && decoded == value {
									found = true
								}
							}
							return !found
						})
						break
					}
				}
				if !found {
					t.Fatalf("%s witness %q owner function does not contain the exact literal: %q", tc.name, value, owner)
				}
			}
			withoutDefault := reviewedClientImplementationSupportV1.clone()
			tc.setDefaults(&withoutDefault, removeStringV1(tc.defaults, tc.defaults[0]))
			if advertisedSupportMatchesWitnessV1(withoutDefault) {
				t.Fatal("missing default unexpectedly matched witness")
			}
			delete(tc.witness, tc.defaults[0])
			if equalStringsV1(tc.defaults, witnessValuesV1(tc.witness)) {
				t.Fatal("missing witness unexpectedly matched defaults")
			}
		})
	}
}

func TestAdvancedPolicySupportConfigValidationV1(t *testing.T) {
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	for _, configPolicy := range []string{"strict_with_redaction", "strict_profile_bound"} {
		t.Run(configPolicy, func(t *testing.T) {
			fixture := newStrictSupportFixturePolicyWithSetsV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required", "schema_and_feature", configPolicy, floor, floor, known, known, floor)
			input := lifecyclePairInputV1(t, fixture)
			clientQueue, relayQueue := uint32(1), uint32(1)
			if configPolicy == "strict_profile_bound" {
				clientQueue = fixture.view.ClientModeBinding.LimitBlock.CarrierMaxQueueDepth
				relayQueue = fixture.view.ServerModeBinding.LimitBlock.CarrierMaxQueueDepth
			}
			input.ClientControls = ClientLocalRuntimeControlsV1{RuntimeID: "advanced-client", EventCapacity: 3, QueueCeiling: clientQueue}
			input.RelayControls = RelayLocalRuntimeControlsV1{RuntimeID: "advanced-relay", EventCapacity: 5, QueueCeiling: relayQueue}
			runtime := lifecycleRuntimeV1(t, fixture)
			client, relay, err := runtime.NewAuthenticatedChannelPair(input)
			if err != nil {
				t.Fatal(err)
			}
			client.Close()
			relay.Close()
			for _, variant := range []string{"client-missing", "relay-missing", "cross-role"} {
				t.Run(variant, func(t *testing.T) {
					variantRuntime := lifecycleRuntimeV1(t, fixture)
					variantInput := lifecyclePairInputV1(t, fixture)
					variantInput.ClientControls = input.ClientControls
					variantInput.RelayControls = input.RelayControls
					switch variant {
					case "client-missing":
						variantRuntime.clientSupport.redaction = redactionCertificateV1{}
					case "relay-missing":
						variantRuntime.relaySupport.redaction = redactionCertificateV1{}
					case "cross-role":
						variantRuntime.relaySupport.redaction = variantRuntime.clientSupport.redaction
					}
					if _, _, err := variantRuntime.NewAuthenticatedChannelPair(variantInput); !errors.Is(err, ErrConfigInvalid) {
						t.Fatalf("private certificate variant %s err=%v", variant, err)
					}
				})
			}
		})
	}
}

func assertOnlyWO031SentinelV1(t *testing.T, err, want error) {
	t.Helper()
	all := []error{
		ErrImplementationSupportInvalid, ErrProfileAuthorizationInvalid, ErrPolicyInvalid,
		ErrProfileMismatch, ErrTranscriptMismatch, ErrCapabilityTranscriptInvalid,
		ErrCarrierBindingInvalid, ErrFullBindingInvalid, ErrDowngradeRejected,
		ErrCapabilityRejected, ErrProfileIncompatible,
	}
	if !errors.Is(err, want) {
		t.Fatalf("error=%v want sentinel=%v", err, want)
	}
	for _, candidate := range all {
		if candidate != want && errors.Is(err, candidate) {
			t.Fatalf("error=%v contains competing sentinel=%v; want only %v", err, candidate, want)
		}
	}
}

func TestImplementationSupportV1ReviewedDefaultsAndCarrierHashWitness(t *testing.T) {
	suite := security.SelectedSuiteV1{KDFSuite: "kdf_hkdf_sha256", AEADSuite: "aead_aes_256_gcm", MACSuite: "mac_hmac_sha256"}
	transcripts := []string{"canonical_full_binding_v1", "canonical_v1", "canonical_with_capabilities_v1", "canonical_with_carrier_binding_v1"}
	carriers := []string{"batch_carrier", "chunked_carrier", "datagram_like_carrier", "interactive_carrier", "long_poll_style_carrier", "lossy_reordered_carrier", "message_carrier", "stream_carrier"}
	proxy := []string{"open_relay", "target_close", "target_data", "target_descriptor", "target_error", "target_metadata", "target_reset", "target_response"}
	stream := []string{"close_stream", "data", "open_stream", "reset_stream", "session_close", "window_update"}
	features := make([]string, 0, len(carriers)+len(proxy)+len(stream))
	for _, value := range carriers {
		features = append(features, "carrier:"+value)
	}
	for _, value := range proxy {
		features = append(features, "proxy:"+value)
	}
	for _, value := range stream {
		features = append(features, "stream:"+value)
	}
	witness := [32]byte{
		0xc8, 0x36, 0xfa, 0x4b, 0xf6, 0x62, 0x31, 0xd6,
		0xf6, 0x6d, 0x6f, 0x18, 0x81, 0x51, 0x1c, 0x64,
		0x31, 0x59, 0xae, 0x99, 0x8d, 0xf6, 0x90, 0x94,
		0x5e, 0xea, 0xf5, 0x41, 0x74, 0x0b, 0x50, 0xad,
	}
	want := ImplementationSupportV1{
		schemaVersions: []string{"0.2.0-lab"}, compilerSecurityVersions: []string{"0.13.0-lab"},
		minimumRuntimeVersions: []string{"0.13.0-lab"}, securityVersions: []string{"0.13.0-lab"},
		suites:           []security.SelectedSuiteV1{suite},
		securitySuiteIDs: []string{"kdf_hkdf_sha256/aead_aes_256_gcm/mac_hmac_sha256/transcript_sha256_v1"},
		transcriptModes:  transcripts,
		capabilities:     []string{"adapter_interface", "carrier_abstraction", "carrier_backpressure", "carrier_loss_recovery", "generated_backend", "multi_stream", "nonce_schedule", "proxy_semantics", "replay_window", "transcript_binding"},
		featureVectors:   features, carrierFamilies: carriers, carrierPolicyHashes: [][32]byte{witness},
		proxyFeatures: proxy, streamFeatures: stream,
		adapterClasses: []string{"metadata_bound_stream", "one_flow_one_stream", "priority_mapped_stream", "state_derived_mapping"},
		nonceModes:     []string{"counter_append_base", "counter_xor_base", "directional_counter", "stream_partitioned_counter"}, replayPolicies: []string{"bounded_reorder", "ordered_only", "windowed_replay"},
		downgradePolicies:  []string{"strict_capabilities", "strict_suite_and_capabilities", "suite_bound_transcript"},
		capabilityPolicies: []string{"intersection_with_required", "profile_declared_required", "strict_required"},
		profilePolicies:    []string{"full_policy_binding", "schema_and_feature", "strict_schema"}, rotationPolicies: []string{"message_lifetime_bound", "profile_lifetime_bound", "session_only"},
		configPolicies: []string{"strict_profile_bound", "strict_required", "strict_with_redaction"}, envelopeModes: []string{"full_context_bound_envelope", "metadata_authenticated", "synthetic_aead_test"},
		maxEnvelopeBytes: 1 << 20, maxFrameBytes: 1 << 20, maxQueueDepth: 256, maxStreams: 16,
		maxReplayWindow: 4096, maxSessionMessages: 1 << 24, maxKeyLifetimeMessages: 1 << 24,
		suiteTranscriptPairs: []selectedSuiteTranscriptV1{
			{suite: suite, transcriptMode: "canonical_full_binding_v1"},
			{suite: suite, transcriptMode: "canonical_v1"},
			{suite: suite, transcriptMode: "canonical_with_capabilities_v1"},
			{suite: suite, transcriptMode: "canonical_with_carrier_binding_v1"},
		},
	}
	for name, item := range map[string]struct {
		support ImplementationSupportV1
		role    implementationRoleV1
	}{
		"client": {reviewedClientImplementationSupportV1, implementationRoleClientV1},
		"relay":  {reviewedRelayImplementationSupportV1, implementationRoleRelayV1},
	} {
		t.Run(name, func(t *testing.T) {
			if err := validateImplementationSupportV1(item.support, item.role); err != nil {
				t.Fatal(err)
			}
			expected := want.clone()
			expected.role = item.role
			expected.redaction = redactionCertificateV1{version: redactionCertificateVersionV1, role: item.role, marker: clientRedactionMarkerV1}
			if item.role == implementationRoleRelayV1 {
				expected.redaction.marker = relayRedactionMarkerV1
			}
			if !reflect.DeepEqual(item.support, expected) {
				t.Fatalf("reviewed %s support inventory drifted\n got: %#v\nwant: %#v", name, item.support, expected)
			}
		})
	}
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	if !containsHashV1(reviewedClientImplementationSupportV1.carrierPolicyHashes, fixture.view.ClientModeBinding.CarrierPolicyHash) ||
		!containsHashV1(reviewedRelayImplementationSupportV1.carrierPolicyHashes, fixture.view.ServerModeBinding.CarrierPolicyHash) {
		t.Fatal("reviewed package defaults do not contain the real carrier-policy witness")
	}
}

func TestImplementationSupportV1ExactOperandFreeErrors(t *testing.T) {
	want := map[error]string{
		ErrImplementationSupportInvalid: "implementation_support_invalid",
		ErrProfileAuthorizationInvalid:  "profile_authorization_invalid",
		ErrPolicyInvalid:                "policy_invalid",
		ErrProfileMismatch:              "profile_mismatch",
		ErrTranscriptMismatch:           "transcript_mismatch",
		ErrCapabilityTranscriptInvalid:  "capability_transcript_invalid",
		ErrCarrierBindingInvalid:        "carrier_binding_invalid",
		ErrFullBindingInvalid:           "full_binding_invalid",
		ErrDowngradeRejected:            "downgrade_rejected",
		ErrCapabilityRejected:           "capability_rejected",
		ErrProfileIncompatible:          "profile_incompatible",
	}
	for sentinel, text := range want {
		if sentinel.Error() != text || strings.ContainsAny(sentinel.Error(), "0123456789/: ") {
			t.Fatalf("sentinel %q is not the exact operand-free literal %q", sentinel, text)
		}
	}
}

func TestImplementationSupportV1ValidationAndDeepClone(t *testing.T) {
	base := reviewedClientImplementationSupportV1.clone()
	tests := []struct {
		name   string
		mutate func(*ImplementationSupportV1)
	}{
		{"wrong role", func(v *ImplementationSupportV1) { v.role = implementationRoleRelayV1 }},
		{"empty declaration", func(v *ImplementationSupportV1) { v.schemaVersions = nil }},
		{"duplicate declaration", func(v *ImplementationSupportV1) {
			v.schemaVersions = []string{ir.SupportedVersion, ir.SupportedVersion}
		}},
		{"noncanonical declaration", func(v *ImplementationSupportV1) {
			v.transcriptModes[0], v.transcriptModes[1] = v.transcriptModes[1], v.transcriptModes[0]
		}},
		{"over capacity declaration", func(v *ImplementationSupportV1) {
			v.capabilities = make([]string, implementationSupportListCapacityV1+1)
			for i := range v.capabilities {
				v.capabilities[i] = fmt.Sprintf("cap-%03d", i)
			}
		}},
		{"zero carrier hash", func(v *ImplementationSupportV1) { v.carrierPolicyHashes[0] = [32]byte{} }},
		{"suite KDF empty", func(v *ImplementationSupportV1) { v.suites[0].KDFSuite = "" }},
		{"suite KDF non-ascii", func(v *ImplementationSupportV1) { v.suites[0].KDFSuite = "kdf-\u0080" }},
		{"suite AEAD empty", func(v *ImplementationSupportV1) { v.suites[0].AEADSuite = "" }},
		{"suite AEAD non-ascii", func(v *ImplementationSupportV1) { v.suites[0].AEADSuite = "aead-\u0080" }},
		{"suite MAC empty", func(v *ImplementationSupportV1) { v.suites[0].MACSuite = "" }},
		{"suite MAC non-ascii", func(v *ImplementationSupportV1) { v.suites[0].MACSuite = "mac-\u0080" }},
		{"zero ceiling", func(v *ImplementationSupportV1) { v.maxFrameBytes = 0 }},
		{"envelope over frame", func(v *ImplementationSupportV1) { v.maxEnvelopeBytes = v.maxFrameBytes + 1 }},
		{"invalid replay ceiling", func(v *ImplementationSupportV1) { v.maxReplayWindow = 1 }},
		{"invalid session ceiling", func(v *ImplementationSupportV1) { v.maxSessionMessages = 0 }},
		{"key over session", func(v *ImplementationSupportV1) { v.maxKeyLifetimeMessages = v.maxSessionMessages + 1 }},
		{"empty tuple", func(v *ImplementationSupportV1) { v.suiteTranscriptPairs = nil }},
		{"cross tuple", func(v *ImplementationSupportV1) { v.suiteTranscriptPairs[0].transcriptMode = "unsupported" }},
		{"tuple suite absent from suite inventory", func(v *ImplementationSupportV1) {
			v.suiteTranscriptPairs = []selectedSuiteTranscriptV1{{
				suite:          security.SelectedSuiteV1{KDFSuite: "valid-but-absent", AEADSuite: "aead", MACSuite: "mac"},
				transcriptMode: v.transcriptModes[0],
			}}
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := base.clone()
			test.mutate(&value)
			if !errors.Is(validateImplementationSupportV1(value, implementationRoleClientV1), ErrImplementationSupportInvalid) {
				t.Fatal("invalid support accepted")
			}
		})
	}
	numericInvalid := []struct {
		name   string
		mutate func(*ImplementationSupportV1)
	}{
		{"envelope below lower bound", func(v *ImplementationSupportV1) { v.maxEnvelopeBytes = 0 }},
		{"envelope above upper bound", func(v *ImplementationSupportV1) { v.maxEnvelopeBytes = 1<<20 + 1 }},
		{"frame below lower bound", func(v *ImplementationSupportV1) { v.maxFrameBytes = 0 }},
		{"frame above upper bound", func(v *ImplementationSupportV1) { v.maxFrameBytes = 1<<20 + 1 }},
		{"queue below lower bound", func(v *ImplementationSupportV1) { v.maxQueueDepth = 0 }},
		{"queue above upper bound", func(v *ImplementationSupportV1) { v.maxQueueDepth = 257 }},
		{"streams below lower bound", func(v *ImplementationSupportV1) { v.maxStreams = 0 }},
		{"streams above upper bound", func(v *ImplementationSupportV1) { v.maxStreams = 65536 }},
		{"replay below lower bound", func(v *ImplementationSupportV1) { v.maxReplayWindow = 1 }},
		{"replay above upper bound", func(v *ImplementationSupportV1) { v.maxReplayWindow = 4097 }},
		{"session below lower bound", func(v *ImplementationSupportV1) { v.maxSessionMessages = 0 }},
		{"session above upper bound", func(v *ImplementationSupportV1) { v.maxSessionMessages = 1<<24 + 1 }},
		{"key lifetime below lower bound", func(v *ImplementationSupportV1) { v.maxKeyLifetimeMessages = 0 }},
		{"key lifetime above upper bound", func(v *ImplementationSupportV1) { v.maxKeyLifetimeMessages = 1<<24 + 1 }},
		{"envelope exceeds frame", func(v *ImplementationSupportV1) { v.maxEnvelopeBytes = v.maxFrameBytes + 1 }},
		{"key lifetime exceeds session", func(v *ImplementationSupportV1) { v.maxKeyLifetimeMessages = v.maxSessionMessages + 1 }},
	}
	for _, test := range numericInvalid {
		t.Run("numeric/"+test.name, func(t *testing.T) {
			value := base.clone()
			test.mutate(&value)
			if !errors.Is(validateImplementationSupportV1(value, implementationRoleClientV1), ErrImplementationSupportInvalid) {
				t.Fatal("invalid numeric support bound accepted")
			}
		})
	}
	for name, mutate := range map[string]func(*ImplementationSupportV1){
		"exact minimums": func(v *ImplementationSupportV1) {
			v.maxEnvelopeBytes, v.maxFrameBytes = 1, 1
			v.maxQueueDepth, v.maxStreams, v.maxReplayWindow = 1, 1, 2
			v.maxSessionMessages, v.maxKeyLifetimeMessages = 1, 1
		},
		"exact maximums": func(v *ImplementationSupportV1) {
			v.maxEnvelopeBytes, v.maxFrameBytes = 1<<20, 1<<20
			v.maxQueueDepth, v.maxStreams, v.maxReplayWindow = 256, 65535, 4096
			v.maxSessionMessages, v.maxKeyLifetimeMessages = 1<<24, 1<<24
		},
	} {
		t.Run("numeric/"+name, func(t *testing.T) {
			value := base.clone()
			mutate(&value)
			if err := validateImplementationSupportV1(value, implementationRoleClientV1); err != nil {
				t.Fatalf("valid exact numeric boundary rejected: %v", err)
			}
		})
	}

	stringLists := []struct {
		name string
		list func(*ImplementationSupportV1) *[]string
	}{
		{"schema versions", func(v *ImplementationSupportV1) *[]string { return &v.schemaVersions }},
		{"compiler versions", func(v *ImplementationSupportV1) *[]string { return &v.compilerSecurityVersions }},
		{"runtime versions", func(v *ImplementationSupportV1) *[]string { return &v.minimumRuntimeVersions }},
		{"security versions", func(v *ImplementationSupportV1) *[]string { return &v.securityVersions }},
		{"suite ids", func(v *ImplementationSupportV1) *[]string { return &v.securitySuiteIDs }},
		{"transcript modes", func(v *ImplementationSupportV1) *[]string { return &v.transcriptModes }},
		{"capabilities", func(v *ImplementationSupportV1) *[]string { return &v.capabilities }},
		{"feature vectors", func(v *ImplementationSupportV1) *[]string { return &v.featureVectors }},
		{"carrier families", func(v *ImplementationSupportV1) *[]string { return &v.carrierFamilies }},
		{"proxy features", func(v *ImplementationSupportV1) *[]string { return &v.proxyFeatures }},
		{"stream features", func(v *ImplementationSupportV1) *[]string { return &v.streamFeatures }},
		{"adapter classes", func(v *ImplementationSupportV1) *[]string { return &v.adapterClasses }},
		{"nonce modes", func(v *ImplementationSupportV1) *[]string { return &v.nonceModes }},
		{"replay policies", func(v *ImplementationSupportV1) *[]string { return &v.replayPolicies }},
		{"downgrade policies", func(v *ImplementationSupportV1) *[]string { return &v.downgradePolicies }},
		{"capability policies", func(v *ImplementationSupportV1) *[]string { return &v.capabilityPolicies }},
		{"profile policies", func(v *ImplementationSupportV1) *[]string { return &v.profilePolicies }},
		{"rotation policies", func(v *ImplementationSupportV1) *[]string { return &v.rotationPolicies }},
		{"config policies", func(v *ImplementationSupportV1) *[]string { return &v.configPolicies }},
		{"envelope modes", func(v *ImplementationSupportV1) *[]string { return &v.envelopeModes }},
	}
	for _, item := range stringLists {
		for _, shape := range []string{"empty", "empty-element", "non-ascii-element", "duplicate", "noncanonical", "over-capacity"} {
			t.Run(item.name+"/"+shape, func(t *testing.T) {
				value := base.clone()
				list := item.list(&value)
				switch shape {
				case "empty":
					*list = nil
				case "empty-element":
					*list = []string{""}
				case "non-ascii-element":
					*list = []string{"non-ascii-\u0080"}
				case "duplicate":
					*list = append(append([]string(nil), (*list)...), (*list)[len(*list)-1])
				case "noncanonical":
					*list = []string{"z-value", "a-value"}
				case "over-capacity":
					*list = make([]string, implementationSupportListCapacityV1+1)
					for i := range *list {
						(*list)[i] = fmt.Sprintf("value-%04d", i)
					}
				}
				if !errors.Is(validateImplementationSupportV1(value, implementationRoleClientV1), ErrImplementationSupportInvalid) {
					t.Fatal("invalid support list accepted")
				}
			})
		}
	}

	baseSuite := base.suites[0]
	for _, shape := range []string{"empty", "duplicate", "noncanonical", "over-capacity"} {
		t.Run("suites/"+shape, func(t *testing.T) {
			value := base.clone()
			switch shape {
			case "empty":
				value.suites = nil
			case "duplicate":
				value.suites = []security.SelectedSuiteV1{baseSuite, baseSuite}
			case "noncanonical":
				value.suites = []security.SelectedSuiteV1{
					{KDFSuite: "z-suite", AEADSuite: "aead", MACSuite: "mac"},
					{KDFSuite: "a-suite", AEADSuite: "aead", MACSuite: "mac"},
				}
			case "over-capacity":
				value.suites = make([]security.SelectedSuiteV1, implementationSupportListCapacityV1+1)
				for i := range value.suites {
					value.suites[i] = security.SelectedSuiteV1{KDFSuite: fmt.Sprintf("kdf-%04d", i), AEADSuite: "aead", MACSuite: "mac"}
				}
			}
			if !errors.Is(validateImplementationSupportV1(value, implementationRoleClientV1), ErrImplementationSupportInvalid) {
				t.Fatal("invalid suite inventory accepted")
			}
		})
	}
	baseHash := base.carrierPolicyHashes[0]
	for _, shape := range []string{"empty", "duplicate", "noncanonical", "over-capacity"} {
		t.Run("carrier hashes/"+shape, func(t *testing.T) {
			value := base.clone()
			switch shape {
			case "empty":
				value.carrierPolicyHashes = nil
			case "duplicate":
				value.carrierPolicyHashes = [][32]byte{baseHash, baseHash}
			case "noncanonical":
				value.carrierPolicyHashes = [][32]byte{{2}, {1}}
			case "over-capacity":
				value.carrierPolicyHashes = make([][32]byte, implementationSupportListCapacityV1+1)
				for i := range value.carrierPolicyHashes {
					binary.BigEndian.PutUint32(value.carrierPolicyHashes[i][28:], uint32(i+1))
				}
			}
			if !errors.Is(validateImplementationSupportV1(value, implementationRoleClientV1), ErrImplementationSupportInvalid) {
				t.Fatal("invalid carrier hash inventory accepted")
			}
		})
	}
	for _, shape := range []string{"empty", "duplicate", "noncanonical", "over-capacity"} {
		t.Run("suite transcript tuples/"+shape, func(t *testing.T) {
			value := base.clone()
			switch shape {
			case "empty":
				value.suiteTranscriptPairs = nil
			case "duplicate":
				value.suiteTranscriptPairs = []selectedSuiteTranscriptV1{value.suiteTranscriptPairs[0], value.suiteTranscriptPairs[0]}
			case "noncanonical":
				value.suiteTranscriptPairs[0], value.suiteTranscriptPairs[1] = value.suiteTranscriptPairs[1], value.suiteTranscriptPairs[0]
			case "over-capacity":
				value.suiteTranscriptPairs = make([]selectedSuiteTranscriptV1, implementationSupportListCapacityV1+1)
			}
			if !errors.Is(validateImplementationSupportV1(value, implementationRoleClientV1), ErrImplementationSupportInvalid) {
				t.Fatal("invalid suite/transcript inventory accepted")
			}
		})
	}

	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	clientSource := reviewedClientImplementationSupportV1.clone()
	relaySource := reviewedRelayImplementationSupportV1.clone()
	runtime := strictRuntimeForFixtureV1(t, fixture, clientSource, relaySource, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	clientSource.schemaVersions[0] = "mutated"
	relaySource.capabilities[0] = "mutated"
	if runtime.clientSupport.schemaVersions[0] != ir.SupportedVersion || runtime.relaySupport.capabilities[0] == "mutated" {
		t.Fatal("runtime support aliases constructor source")
	}
}

func TestImplementationSupportV1DeepCloneEveryCollectionBothRoles(t *testing.T) {
	mutators := []struct {
		name   string
		mutate func(*ImplementationSupportV1)
	}{
		{"schema versions", func(v *ImplementationSupportV1) { v.schemaVersions[0] += "-mutated" }},
		{"compiler versions", func(v *ImplementationSupportV1) { v.compilerSecurityVersions[0] += "-mutated" }},
		{"runtime versions", func(v *ImplementationSupportV1) { v.minimumRuntimeVersions[0] += "-mutated" }},
		{"security versions", func(v *ImplementationSupportV1) { v.securityVersions[0] += "-mutated" }},
		{"suites", func(v *ImplementationSupportV1) { v.suites[0].KDFSuite += "-mutated" }},
		{"suite ids", func(v *ImplementationSupportV1) { v.securitySuiteIDs[0] += "-mutated" }},
		{"transcript modes", func(v *ImplementationSupportV1) { v.transcriptModes[0] += "-mutated" }},
		{"capabilities", func(v *ImplementationSupportV1) { v.capabilities[0] += "-mutated" }},
		{"feature vectors", func(v *ImplementationSupportV1) { v.featureVectors[0] += "-mutated" }},
		{"carrier families", func(v *ImplementationSupportV1) { v.carrierFamilies[0] += "-mutated" }},
		{"carrier hashes", func(v *ImplementationSupportV1) { v.carrierPolicyHashes[0][0] ^= 1 }},
		{"proxy features", func(v *ImplementationSupportV1) { v.proxyFeatures[0] += "-mutated" }},
		{"stream features", func(v *ImplementationSupportV1) { v.streamFeatures[0] += "-mutated" }},
		{"adapter classes", func(v *ImplementationSupportV1) { v.adapterClasses[0] += "-mutated" }},
		{"nonce modes", func(v *ImplementationSupportV1) { v.nonceModes[0] += "-mutated" }},
		{"replay policies", func(v *ImplementationSupportV1) { v.replayPolicies[0] += "-mutated" }},
		{"downgrade policies", func(v *ImplementationSupportV1) { v.downgradePolicies[0] += "-mutated" }},
		{"capability policies", func(v *ImplementationSupportV1) { v.capabilityPolicies[0] += "-mutated" }},
		{"profile policies", func(v *ImplementationSupportV1) { v.profilePolicies[0] += "-mutated" }},
		{"rotation policies", func(v *ImplementationSupportV1) { v.rotationPolicies[0] += "-mutated" }},
		{"config policies", func(v *ImplementationSupportV1) { v.configPolicies[0] += "-mutated" }},
		{"envelope modes", func(v *ImplementationSupportV1) { v.envelopeModes[0] += "-mutated" }},
		{"suite transcript tuples", func(v *ImplementationSupportV1) { v.suiteTranscriptPairs[0].transcriptMode += "-mutated" }},
	}
	for _, item := range []struct {
		name   string
		source ImplementationSupportV1
	}{
		{"client", reviewedClientImplementationSupportV1},
		{"relay", reviewedRelayImplementationSupportV1},
	} {
		for _, mutation := range mutators {
			t.Run(item.name+"/"+mutation.name+"/clone-to-source", func(t *testing.T) {
				source := item.source.clone()
				before := source.clone()
				cloned := source.clone()
				mutation.mutate(&cloned)
				if !reflect.DeepEqual(source, before) {
					t.Fatal("mutating clone changed source")
				}
			})
			t.Run(item.name+"/"+mutation.name+"/source-to-clone", func(t *testing.T) {
				source := item.source.clone()
				cloned := source.clone()
				before := cloned.clone()
				mutation.mutate(&source)
				if !reflect.DeepEqual(cloned, before) {
					t.Fatal("mutating source changed clone")
				}
			})
		}
	}
}

func TestProfileAuthorizationV1ValidationBoundsRolesAndClones(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	valid := fixture.clientEntry
	tests := []struct {
		name   string
		mutate func(*ClientProfileAuthorizationEntryV1)
	}{
		{"zero profile", func(v *ClientProfileAuthorizationEntryV1) { v.ProfileHash = [32]byte{} }},
		{"zero policy", func(v *ClientProfileAuthorizationEntryV1) { v.EffectivePolicyHash = [32]byte{} }},
		{"replay below", func(v *ClientProfileAuthorizationEntryV1) { v.ReplayWindowSize = 1 }},
		{"replay above", func(v *ClientProfileAuthorizationEntryV1) { v.ReplayWindowSize = 4097 }},
		{"streams zero", func(v *ClientProfileAuthorizationEntryV1) { v.MaxConcurrentStreams = 0 }},
		{"streams above", func(v *ClientProfileAuthorizationEntryV1) { v.MaxConcurrentStreams = 65536 }},
		{"frame zero", func(v *ClientProfileAuthorizationEntryV1) { v.MaxFrameBytes = 0 }},
		{"frame above", func(v *ClientProfileAuthorizationEntryV1) { v.MaxFrameBytes = 1<<20 + 1 }},
		{"envelope zero", func(v *ClientProfileAuthorizationEntryV1) { v.MaxEnvelopeBytes = 0 }},
		{"envelope above frame", func(v *ClientProfileAuthorizationEntryV1) { v.MaxEnvelopeBytes = v.MaxFrameBytes + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := valid
			test.mutate(&entry)
			if _, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{entry}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	for name, mutate := range map[string]func(*ClientProfileAuthorizationEntryV1){
		"framing":   func(v *ClientProfileAuthorizationEntryV1) { v.FramingPolicyHash = [32]byte{} },
		"state":     func(v *ClientProfileAuthorizationEntryV1) { v.StateMachinePolicyHash = [32]byte{} },
		"scheduler": func(v *ClientProfileAuthorizationEntryV1) { v.SchedulerPolicyHash = [32]byte{} },
		"padding":   func(v *ClientProfileAuthorizationEntryV1) { v.PaddingPolicyHash = [32]byte{} },
		"stream":    func(v *ClientProfileAuthorizationEntryV1) { v.StreamPolicyHash = [32]byte{} },
		"proxy":     func(v *ClientProfileAuthorizationEntryV1) { v.ProxyPolicyHash = [32]byte{} },
		"carrier":   func(v *ClientProfileAuthorizationEntryV1) { v.CarrierContextPolicyHash = [32]byte{} },
	} {
		t.Run("missing "+name, func(t *testing.T) {
			entry := valid
			mutate(&entry)
			if _, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{entry}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
				t.Fatalf("error = %v", err)
			}
		})
	}
	if _, err := NewClientProfileAuthorizationRegistryV1(nil); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("empty client registry error = %v", err)
	}
	if _, err := NewRelayProfileAuthorizationRegistryV1(nil); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("empty relay registry error = %v", err)
	}
	if _, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{fixture.relayEntry}); err != nil {
		t.Fatal(err)
	}

	first, second := valid, valid
	first.ProfileHash = [32]byte{1}
	second.ProfileHash = [32]byte{2}
	if _, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{first, first}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("duplicate error = %v", err)
	}
	if _, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{second, first}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("noncanonical error = %v", err)
	}
	entries := make([]ClientProfileAuthorizationEntryV1, profileAuthorizationCapacityV1)
	for i := range entries {
		entries[i] = valid
		entries[i].ProfileHash = [32]byte{}
		binary.BigEndian.PutUint32(entries[i].ProfileHash[28:], uint32(i+1))
	}
	if _, err := NewClientProfileAuthorizationRegistryV1(entries); err != nil {
		t.Fatalf("512-entry boundary rejected: %v", err)
	}
	over := append(entries, valid)
	over[len(over)-1].ProfileHash = [32]byte{}
	binary.BigEndian.PutUint32(over[len(over)-1].ProfileHash[28:], uint32(len(over)))
	if _, err := NewClientProfileAuthorizationRegistryV1(over); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("513-entry boundary error = %v", err)
	}

	if reflect.TypeOf(ClientProfileAuthorizationEntryV1{}).ConvertibleTo(reflect.TypeOf(RelayProfileAuthorizationEntryV1{})) ||
		reflect.TypeOf(ClientProfileAuthorizationRegistryV1{}).ConvertibleTo(reflect.TypeOf(RelayProfileAuthorizationRegistryV1{})) {
		t.Fatal("role-typed authorization values are explicitly convertible")
	}
	source := []ClientProfileAuthorizationEntryV1{valid}
	registry, err := NewClientProfileAuthorizationRegistryV1(source)
	if err != nil {
		t.Fatal(err)
	}
	originalHash := valid.ProfileHash
	source[0].ProfileHash[0] ^= 0xff
	if _, ok := findProfileAuthorizationEntryV1(registry.entries, originalHash); !ok {
		t.Fatal("registry aliases source entry")
	}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	fixture.clientRegistry.entries[0].profileHash[0] ^= 0xff
	if _, ok := findProfileAuthorizationEntryV1(runtime.clientRegistry.entries, originalHash); !ok {
		t.Fatal("runtime registry aliases explicit owner registry")
	}
}

func TestRelayProfileAuthorizationV1ValidationBoundsOrderCapacityAndClones(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	valid := fixture.relayEntry
	tests := []struct {
		name   string
		mutate func(*RelayProfileAuthorizationEntryV1)
	}{
		{"zero profile", func(v *RelayProfileAuthorizationEntryV1) { v.ProfileHash = [32]byte{} }},
		{"zero policy", func(v *RelayProfileAuthorizationEntryV1) { v.EffectivePolicyHash = [32]byte{} }},
		{"replay below", func(v *RelayProfileAuthorizationEntryV1) { v.ReplayWindowSize = 1 }},
		{"replay above", func(v *RelayProfileAuthorizationEntryV1) { v.ReplayWindowSize = 4097 }},
		{"streams zero", func(v *RelayProfileAuthorizationEntryV1) { v.MaxConcurrentStreams = 0 }},
		{"streams above", func(v *RelayProfileAuthorizationEntryV1) { v.MaxConcurrentStreams = 65536 }},
		{"frame zero", func(v *RelayProfileAuthorizationEntryV1) { v.MaxFrameBytes = 0 }},
		{"frame above", func(v *RelayProfileAuthorizationEntryV1) { v.MaxFrameBytes = 1<<20 + 1 }},
		{"envelope zero", func(v *RelayProfileAuthorizationEntryV1) { v.MaxEnvelopeBytes = 0 }},
		{"envelope above frame", func(v *RelayProfileAuthorizationEntryV1) { v.MaxEnvelopeBytes = v.MaxFrameBytes + 1 }},
		{"framing hash", func(v *RelayProfileAuthorizationEntryV1) { v.FramingPolicyHash = [32]byte{} }},
		{"state hash", func(v *RelayProfileAuthorizationEntryV1) { v.StateMachinePolicyHash = [32]byte{} }},
		{"scheduler hash", func(v *RelayProfileAuthorizationEntryV1) { v.SchedulerPolicyHash = [32]byte{} }},
		{"padding hash", func(v *RelayProfileAuthorizationEntryV1) { v.PaddingPolicyHash = [32]byte{} }},
		{"stream hash", func(v *RelayProfileAuthorizationEntryV1) { v.StreamPolicyHash = [32]byte{} }},
		{"proxy hash", func(v *RelayProfileAuthorizationEntryV1) { v.ProxyPolicyHash = [32]byte{} }},
		{"carrier hash", func(v *RelayProfileAuthorizationEntryV1) { v.CarrierContextPolicyHash = [32]byte{} }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			entry := valid
			test.mutate(&entry)
			if _, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{entry}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
				t.Fatalf("error=%v", err)
			}
		})
	}
	first, second := valid, valid
	first.ProfileHash = [32]byte{1}
	second.ProfileHash = [32]byte{2}
	if _, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{first, first}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("duplicate error=%v", err)
	}
	if _, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{second, first}); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("noncanonical error=%v", err)
	}
	entries := make([]RelayProfileAuthorizationEntryV1, profileAuthorizationCapacityV1)
	for i := range entries {
		entries[i] = valid
		entries[i].ProfileHash = [32]byte{}
		binary.BigEndian.PutUint32(entries[i].ProfileHash[28:], uint32(i+1))
	}
	if _, err := NewRelayProfileAuthorizationRegistryV1(entries); err != nil {
		t.Fatalf("512-entry boundary rejected: %v", err)
	}
	over := append(entries, valid)
	over[len(over)-1].ProfileHash = [32]byte{}
	binary.BigEndian.PutUint32(over[len(over)-1].ProfileHash[28:], uint32(len(over)))
	if _, err := NewRelayProfileAuthorizationRegistryV1(over); !errors.Is(err, ErrProfileAuthorizationInvalid) {
		t.Fatalf("513-entry boundary error=%v", err)
	}
	source := []RelayProfileAuthorizationEntryV1{valid}
	registry, err := NewRelayProfileAuthorizationRegistryV1(source)
	if err != nil {
		t.Fatal(err)
	}
	originalHash := valid.ProfileHash
	source[0].ProfileHash[0] ^= 0xff
	if _, ok := findProfileAuthorizationEntryV1(registry.entries, originalHash); !ok {
		t.Fatal("relay registry aliases source entry")
	}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	fixture.relayRegistry.entries[0].profileHash[0] ^= 0xff
	if _, ok := findProfileAuthorizationEntryV1(runtime.relayRegistry.entries, originalHash); !ok {
		t.Fatal("runtime relay registry aliases explicit owner registry")
	}
}

func TestProfileAuthorizationV1ConstructorsRetainEveryFieldExactly(t *testing.T) {
	hash := func(value byte) [32]byte { return [32]byte{value} }
	want := profileAuthorizationEntryV1{
		profileHash: hash(1), effectivePolicyHash: hash(2), replayWindowSize: 3,
		maxConcurrentStreams: 4, maxFrameBytes: 100, maxEnvelopeBytes: 50,
		framingPolicyHash: hash(3), stateMachinePolicyHash: hash(4), schedulerPolicyHash: hash(5),
		paddingPolicyHash: hash(6), streamPolicyHash: hash(7), proxyPolicyHash: hash(8),
		carrierContextPolicyHash: hash(9),
	}
	client := ClientProfileAuthorizationEntryV1{
		ProfileHash: want.profileHash, EffectivePolicyHash: want.effectivePolicyHash,
		ReplayWindowSize: want.replayWindowSize, MaxConcurrentStreams: want.maxConcurrentStreams,
		MaxFrameBytes: want.maxFrameBytes, MaxEnvelopeBytes: want.maxEnvelopeBytes,
		FramingPolicyHash: want.framingPolicyHash, StateMachinePolicyHash: want.stateMachinePolicyHash,
		SchedulerPolicyHash: want.schedulerPolicyHash, PaddingPolicyHash: want.paddingPolicyHash,
		StreamPolicyHash: want.streamPolicyHash, ProxyPolicyHash: want.proxyPolicyHash,
		CarrierContextPolicyHash: want.carrierContextPolicyHash,
	}
	relay := RelayProfileAuthorizationEntryV1{
		ProfileHash: want.profileHash, EffectivePolicyHash: want.effectivePolicyHash,
		ReplayWindowSize: want.replayWindowSize, MaxConcurrentStreams: want.maxConcurrentStreams,
		MaxFrameBytes: want.maxFrameBytes, MaxEnvelopeBytes: want.maxEnvelopeBytes,
		FramingPolicyHash: want.framingPolicyHash, StateMachinePolicyHash: want.stateMachinePolicyHash,
		SchedulerPolicyHash: want.schedulerPolicyHash, PaddingPolicyHash: want.paddingPolicyHash,
		StreamPolicyHash: want.streamPolicyHash, ProxyPolicyHash: want.proxyPolicyHash,
		CarrierContextPolicyHash: want.carrierContextPolicyHash,
	}
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{client})
	if err != nil {
		t.Fatal(err)
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{relay})
	if err != nil {
		t.Fatal(err)
	}
	if len(clientRegistry.entries) != 1 || !reflect.DeepEqual(clientRegistry.entries[0], want) {
		t.Fatalf("client constructor field mapping drifted: got=%#v want=%#v", clientRegistry.entries, want)
	}
	if len(relayRegistry.entries) != 1 || !reflect.DeepEqual(relayRegistry.entries[0], want) {
		t.Fatalf("relay constructor field mapping drifted: got=%#v want=%#v", relayRegistry.entries, want)
	}
}

type countingEntropyV1 struct {
	reads int
	fail  bool
}

type zeroEntropyV1 struct{ reads int }

func (r *zeroEntropyV1) Read(target []byte) (int, error) {
	r.reads++
	clear(target)
	return len(target), nil
}

func (r *countingEntropyV1) Read(target []byte) (int, error) {
	r.reads++
	if r.fail {
		return 0, errors.New("entropy read")
	}
	for i := range target {
		target[i] = byte(i + 1)
	}
	return len(target), nil
}

func TestStrictHandshakeRuntimeV1PublicDefaultsAndExactConstructor(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	runtime, err := NewStrictHandshakeRuntimeV1(
		fixture.dependencies.client, fixture.dependencies.server,
		fixture.clientRegistry, fixture.relayRegistry,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertStrictSuccessV1(t, runtime, fixture.input)
	legacy, err := NewHandshakeRuntime(fixture.dependencies.client, fixture.dependencies.server)
	if err != nil {
		t.Fatal(err)
	}
	if legacy.strict || runtime.strict == false {
		t.Fatal("legacy and strict constructor ownership collapsed")
	}
}

func TestStrictHandshakeRuntimeV1ProductionPostSuccessVerifierClosesAndWipes(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "suite_bound_transcript", "strict_required")
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	called := false
	runtime.clientDependencies.Identity = &callbackIdentityV1{
		base: runtime.clientDependencies.Identity,
		call: func() {
			called = true
			// The preflight has already accepted this owner registry. Auth then
			// succeeds using its immutable snapshot, and only the production
			// post-success verifier can observe this stale authorization.
			runtime.clientRegistry.entries[0].effectivePolicyHash[0] ^= 1
		},
	}
	result, err := runtime.FirstContact(fixture.input)
	if !called || !errors.Is(err, ErrProfileMismatch) {
		t.Fatalf("called=%v error=%v", called, err)
	}
	assertRuntimeClosed(t, result)
	if len(result.ChannelSecret) != 0 {
		t.Fatalf("post-check failure returned %d secret bytes", len(result.ChannelSecret))
	}
	if _, ok := result.AuthenticatedContextSnapshotV1(); ok {
		t.Fatal("post-check failure returned authenticated context")
	}
}

func TestStrictHandshakeRuntimeV1ProductionSnapshotIsolation(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "suite_bound_transcript", "strict_required")
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	called := false
	runtime.clientDependencies.Identity = &callbackIdentityV1{
		base: runtime.clientDependencies.Identity,
		call: func() {
			called = true
			// Identity lookup is the first executable-authority boundary after
			// strictFirstContactV1 has snapshotted and preflighted public input.
			fixture.input.SelectedCapabilities[0] = "zz-mutated-source"
			fixture.input.Client.OfferedCapabilities[0] = "zz-mutated-client-offer"
			fixture.input.Server.RequiredCapabilities[0] = "zz-mutated-relay-floor"
			fixture.view.SelectedCapabilities[0] = "zz-mutated-independent-view"
		},
	}
	result, err := runtime.FirstContact(fixture.input)
	if err != nil || !called {
		t.Fatalf("production snapshot did not isolate post-snapshot source/view mutation: called=%v error=%v", called, err)
	}
	if len(result.ChannelSecret) == 0 {
		t.Fatal("isolated production handshake returned no secret")
	}
	for i := range result.ChannelSecret {
		result.ChannelSecret[i] = 0
	}

	fresh := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "suite_bound_transcript", "strict_required")
	snapshot, view, err := auth.SnapshotFirstContactInputV1(fresh.input)
	if err != nil {
		t.Fatal(err)
	}
	sourceCapability := snapshot.SelectedCapabilities[0]
	fresh.input.SelectedCapabilities[0] = "zz-source"
	if snapshot.SelectedCapabilities[0] != sourceCapability || view.SelectedCapabilities[0] != sourceCapability {
		t.Fatal("production snapshot/view aliases original source")
	}
	view.SelectedCapabilities[0] = "zz-view"
	if snapshot.SelectedCapabilities[0] != sourceCapability {
		t.Fatal("production snapshot aliases independently mutable view")
	}
	matrix := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "suite_bound_transcript", "strict_required")
	matrixCapability := matrix.snapshot.SelectedCapabilities[0]
	snapshotLists := []struct {
		name string
		list func(*auth.FirstContactInput) *[]string
	}{
		{"client offered", func(v *auth.FirstContactInput) *[]string { return &v.Client.OfferedCapabilities }},
		{"client required", func(v *auth.FirstContactInput) *[]string { return &v.Client.RequiredCapabilities }},
		{"relay offered", func(v *auth.FirstContactInput) *[]string { return &v.Server.OfferedCapabilities }},
		{"relay required", func(v *auth.FirstContactInput) *[]string { return &v.Server.RequiredCapabilities }},
		{"selected", func(v *auth.FirstContactInput) *[]string { return &v.SelectedCapabilities }},
	}
	for _, item := range snapshotLists {
		t.Run("snapshot-isolation/"+item.name, func(t *testing.T) {
			leftSnapshot, leftView, err := auth.SnapshotFirstContactInputV1(matrix.input)
			if err != nil {
				t.Fatal(err)
			}
			rightSnapshot, rightView, err := auth.SnapshotFirstContactInputV1(matrix.input)
			if err != nil {
				t.Fatal(err)
			}
			beforeSnapshot, beforeView := rightSnapshot, clonePreflightViewV1(rightView)
			beforeSnapshot.Client.OfferedCapabilities = append([]string(nil), rightSnapshot.Client.OfferedCapabilities...)
			beforeSnapshot.Client.RequiredCapabilities = append([]string(nil), rightSnapshot.Client.RequiredCapabilities...)
			beforeSnapshot.Server.OfferedCapabilities = append([]string(nil), rightSnapshot.Server.OfferedCapabilities...)
			beforeSnapshot.Server.RequiredCapabilities = append([]string(nil), rightSnapshot.Server.RequiredCapabilities...)
			beforeSnapshot.SelectedCapabilities = append([]string(nil), rightSnapshot.SelectedCapabilities...)
			values := item.list(&leftSnapshot)
			(*values)[0] = "zz-independent-snapshot"
			if !reflect.DeepEqual(rightSnapshot.Client.OfferedCapabilities, beforeSnapshot.Client.OfferedCapabilities) ||
				!reflect.DeepEqual(rightSnapshot.Client.RequiredCapabilities, beforeSnapshot.Client.RequiredCapabilities) ||
				!reflect.DeepEqual(rightSnapshot.Server.OfferedCapabilities, beforeSnapshot.Server.OfferedCapabilities) ||
				!reflect.DeepEqual(rightSnapshot.Server.RequiredCapabilities, beforeSnapshot.Server.RequiredCapabilities) ||
				!reflect.DeepEqual(rightSnapshot.SelectedCapabilities, beforeSnapshot.SelectedCapabilities) ||
				!reflect.DeepEqual(leftView, beforeView) {
				t.Fatal("mutating one production snapshot changed an independent snapshot/view")
			}
		})
	}
	viewLists := []struct {
		name string
		list func(*auth.FirstContactPreflightViewV1) *[]string
	}{
		{"client optional/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string { return &v.ClientModeBinding.ClientOptional }},
		{"server optional/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string { return &v.ClientModeBinding.ServerOptional }},
		{"features/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string { return &v.ClientModeBinding.FeatureVectors }},
		{"required/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ClientModeBinding.CompatibilityBlock.RequiredCapabilities
		}},
		{"carriers/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ClientModeBinding.CompatibilityBlock.SupportedCarrierFamilies
		}},
		{"proxy/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures
		}},
		{"stream/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ClientModeBinding.CompatibilityBlock.SupportedStreamFeatures
		}},
		{"suites/client binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ClientModeBinding.CompatibilityBlock.SupportedSecuritySuites
		}},
		{"client optional/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string { return &v.ServerModeBinding.ClientOptional }},
		{"server optional/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string { return &v.ServerModeBinding.ServerOptional }},
		{"features/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string { return &v.ServerModeBinding.FeatureVectors }},
		{"required/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ServerModeBinding.CompatibilityBlock.RequiredCapabilities
		}},
		{"carriers/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ServerModeBinding.CompatibilityBlock.SupportedCarrierFamilies
		}},
		{"proxy/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ServerModeBinding.CompatibilityBlock.SupportedProxyFeatures
		}},
		{"stream/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ServerModeBinding.CompatibilityBlock.SupportedStreamFeatures
		}},
		{"suites/relay binding", func(v *auth.FirstContactPreflightViewV1) *[]string {
			return &v.ServerModeBinding.CompatibilityBlock.SupportedSecuritySuites
		}},
	}
	for _, item := range viewLists {
		t.Run("view-isolation/"+item.name, func(t *testing.T) {
			leftSnapshot, leftView, err := auth.SnapshotFirstContactInputV1(matrix.input)
			if err != nil {
				t.Fatal(err)
			}
			rightSnapshot, rightView, err := auth.SnapshotFirstContactInputV1(matrix.input)
			if err != nil {
				t.Fatal(err)
			}
			beforeSnapshot := rightSnapshot
			beforeSnapshot.SelectedCapabilities = append([]string(nil), rightSnapshot.SelectedCapabilities...)
			beforeView := clonePreflightViewV1(rightView)
			values := item.list(&leftView)
			if len(*values) == 0 {
				t.Fatal("expected nonempty retained mode-binding list")
			}
			(*values)[0] = "zz-independent-view"
			if !reflect.DeepEqual(rightView, beforeView) || !reflect.DeepEqual(rightSnapshot.SelectedCapabilities, beforeSnapshot.SelectedCapabilities) || leftSnapshot.SelectedCapabilities[0] != matrixCapability {
				t.Fatal("mutating one production view changed an independent snapshot/view")
			}
		})
	}
	probe := strictRuntimeForFixtureV1(t, fresh, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, &countingEntropyV1{fail: true})
	staleSnapshot := snapshot
	staleSnapshot.Client.ProfileHash[0] ^= 1
	if err := probe.verifySupportAndAuthorizationPreflightV1(staleSnapshot, fresh.view); !errors.Is(err, ErrProfileMismatch) {
		t.Fatalf("mutated snapshot created authorization: %v", err)
	}
	staleView := clonePreflightViewV1(fresh.view)
	staleView.SelectedCapabilities[0] = "zz-view"
	if err := probe.verifySupportAndAuthorizationPreflightV1(fresh.snapshot, staleView); !errors.Is(err, ErrCapabilityRejected) {
		t.Fatalf("mutated view created authorization: %v", err)
	}
}

func TestSupportPreflightV1FailsBeforeEntropyByRoleAndField(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	selectedCapability := fixture.view.SelectedCapabilities[0]
	actualCarrier := fixture.view.ClientModeBinding.CarrierFamily
	actualAdapter := fixture.view.ClientModeBinding.LocalAdapterClass
	tests := []struct {
		name   string
		want   error
		mutate func(*ImplementationSupportV1)
	}{
		{"transcript", ErrTranscriptMismatch, func(v *ImplementationSupportV1) {
			v.transcriptModes = removeStringV1(v.transcriptModes, fixture.view.SelectedPolicy.TranscriptMode)
			v.suiteTranscriptPairs = removeTupleV1(v.suiteTranscriptPairs, fixture.view.SelectedPolicy.TranscriptMode)
		}},
		{"capability", ErrCapabilityRejected, func(v *ImplementationSupportV1) { v.capabilities = removeStringV1(v.capabilities, selectedCapability) }},
		{"schema", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.schemaVersions = []string{"unsupported-schema"} }},
		{"carrier", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.carrierFamilies = removeStringV1(v.carrierFamilies, actualCarrier) }},
		{"adapter", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.adapterClasses = removeStringV1(v.adapterClasses, actualAdapter) }},
		{"policy", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.nonceModes = []string{"directional_counter"} }},
	}
	for _, role := range []string{"client", "relay"} {
		for _, test := range tests {
			t.Run(role+"/"+test.name, func(t *testing.T) {
				clientSupport := reviewedClientImplementationSupportV1.clone()
				relaySupport := reviewedRelayImplementationSupportV1.clone()
				if role == "client" {
					test.mutate(&clientSupport)
				} else {
					test.mutate(&relaySupport)
				}
				entropy := &countingEntropyV1{fail: true}
				runtime := strictRuntimeForFixtureV1(t, fixture, clientSupport, relaySupport, entropy)
				result, err := runtime.FirstContact(fixture.input)
				assertOnlyWO031SentinelV1(t, err, test.want)
				if entropy.reads != 0 {
					t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
				}
				assertRuntimeClosed(t, result)
			})
		}
	}
	entropy := &countingEntropyV1{fail: true}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
	if entropy.reads != 0 {
		t.Fatal("strict constructor consumed entropy")
	}
	if _, err := runtime.FirstContact(fixture.input); !errors.Is(err, ErrSecureChannel) || entropy.reads == 0 {
		t.Fatalf("supported control error=%v reads=%d", err, entropy.reads)
	}
}

func TestSupportPreflightV1ExpandedOwnerDescriptorCoverageBeforeEntropy(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "suite_bound_transcript", "strict_required")
	selectedCapability := fixture.view.SelectedCapabilities[0]
	proxyFeature := firstFeatureWithPrefixV1(fixture.view.ClientModeBinding.FeatureVectors, "proxy:")
	tests := []struct {
		name   string
		want   error
		mutate func(*ImplementationSupportV1)
	}{
		{"compiler security version", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.compilerSecurityVersions = []string{"unsupported"} }},
		{"minimum runtime version", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.minimumRuntimeVersions = []string{"unsupported"} }},
		{"security version", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.securityVersions = []string{"unsupported"} }},
		{"suite", ErrProfileIncompatible, func(v *ImplementationSupportV1) {
			v.suites = []security.SelectedSuiteV1{{KDFSuite: "unsupported", AEADSuite: "aead", MACSuite: "mac"}}
			for i := range v.suiteTranscriptPairs {
				v.suiteTranscriptPairs[i].suite = v.suites[0]
			}
		}},
		{"suite id", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.securitySuiteIDs = []string{"unsupported"} }},
		{"transcript", ErrTranscriptMismatch, func(v *ImplementationSupportV1) {
			v.transcriptModes = []string{"unsupported"}
			v.suiteTranscriptPairs = []selectedSuiteTranscriptV1{{suite: v.suites[0], transcriptMode: "unsupported"}}
		}},
		{"selected capability", ErrCapabilityRejected, func(v *ImplementationSupportV1) { v.capabilities = removeStringV1(v.capabilities, selectedCapability) }},
		{"feature vector", ErrCapabilityTranscriptInvalid, func(v *ImplementationSupportV1) { v.featureVectors = removeStringV1(v.featureVectors, proxyFeature) }},
		{"carrier policy hash", ErrCarrierBindingInvalid, func(v *ImplementationSupportV1) { v.carrierPolicyHashes = [][32]byte{{1}} }},
		{"nonce mode", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.nonceModes = []string{"unsupported"} }},
		{"replay policy", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.replayPolicies = []string{"unsupported"} }},
		{"downgrade policy", ErrDowngradeRejected, func(v *ImplementationSupportV1) { v.downgradePolicies = []string{"unsupported"} }},
		{"capability policy", ErrCapabilityRejected, func(v *ImplementationSupportV1) { v.capabilityPolicies = []string{"unsupported"} }},
		{"profile policy", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.profilePolicies = []string{"unsupported"} }},
		{"rotation policy", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.rotationPolicies = []string{"unsupported"} }},
		{"config policy", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.configPolicies = []string{"unsupported"} }},
		{"envelope mode", ErrProfileIncompatible, func(v *ImplementationSupportV1) { v.envelopeModes = []string{"unsupported"} }},
		{"frame ceiling", ErrCarrierBindingInvalid, func(v *ImplementationSupportV1) {
			v.maxFrameBytes = fixture.view.ClientModeBinding.MaxFrameBytes - 1
			v.maxEnvelopeBytes = v.maxFrameBytes
		}},
		{"envelope ceiling", ErrCarrierBindingInvalid, func(v *ImplementationSupportV1) {
			v.maxEnvelopeBytes = fixture.view.ClientModeBinding.EnvelopeLimit - 1
		}},
		{"queue ceiling", ErrCarrierBindingInvalid, func(v *ImplementationSupportV1) {
			v.maxQueueDepth = fixture.view.ClientModeBinding.LimitBlock.CarrierMaxQueueDepth - 1
		}},
		{"stream ceiling", ErrCarrierBindingInvalid, func(v *ImplementationSupportV1) {
			v.maxStreams = fixture.view.ClientModeBinding.LimitBlock.SessionMaxConcurrentStreams - 1
		}},
		{"replay ceiling", ErrProfileIncompatible, func(v *ImplementationSupportV1) {
			v.maxReplayWindow = uint32(fixture.view.SelectedPolicy.ReplayWindowSize - 1)
		}},
		{"session ceiling", ErrProfileIncompatible, func(v *ImplementationSupportV1) {
			v.maxSessionMessages = uint64(fixture.view.SelectedPolicy.MaxSessionMessages - 1)
			v.maxKeyLifetimeMessages = v.maxSessionMessages
		}},
		{"key lifetime ceiling", ErrProfileIncompatible, func(v *ImplementationSupportV1) {
			v.maxKeyLifetimeMessages = uint64(fixture.view.SelectedPolicy.MaxKeyLifetimeMessages - 1)
		}},
	}
	for _, role := range []string{"client", "relay"} {
		for _, test := range tests {
			t.Run(role+"/"+test.name, func(t *testing.T) {
				clientSupport := reviewedClientImplementationSupportV1.clone()
				relaySupport := reviewedRelayImplementationSupportV1.clone()
				if role == "client" {
					test.mutate(&clientSupport)
				} else {
					test.mutate(&relaySupport)
				}
				entropy := &countingEntropyV1{fail: true}
				runtime := strictRuntimeForFixtureV1(t, fixture, clientSupport, relaySupport, entropy)
				result, err := runtime.FirstContact(fixture.input)
				assertOnlyWO031SentinelV1(t, err, test.want)
				if entropy.reads != 0 {
					t.Fatalf("result=%s/%s error=%v want=%v reads=%d", result.ClientState, result.ServerState, err, test.want, entropy.reads)
				}
				assertRuntimeClosed(t, result)
			})
		}
	}
	for _, role := range []string{"client", "relay"} {
		t.Run("owner-valid-wrong-key/"+role, func(t *testing.T) {
			clientRegistry := fixture.clientRegistry
			relayRegistry := fixture.relayRegistry
			if role == "client" {
				wrong := fixture.clientEntry
				wrong.ProfileHash[0] ^= 1
				var err error
				clientRegistry, err = NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{wrong})
				if err != nil {
					t.Fatal(err)
				}
			} else {
				wrong := fixture.relayEntry
				wrong.ProfileHash[0] ^= 1
				var err error
				relayRegistry, err = NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{wrong})
				if err != nil {
					t.Fatal(err)
				}
			}
			entropy := &countingEntropyV1{fail: true}
			runtime, err := newStrictHandshakeRuntimeV1(
				fixture.dependencies.client, fixture.dependencies.server, clientRegistry, relayRegistry,
				reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy,
			)
			if err != nil {
				t.Fatal(err)
			}
			result, err := runtime.FirstContact(fixture.input)
			if !errors.Is(err, ErrProfileMismatch) || entropy.reads != 0 {
				t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
			}
			assertRuntimeClosed(t, result)
		})
	}
}

func TestStrictHandshakeRuntimeV1EntropyFailureIsTerminal(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	for name, entropy := range map[string]interface{ Read([]byte) (int, error) }{
		"read failure": &countingEntropyV1{fail: true},
		"zero epoch":   &zeroEntropyV1{},
	} {
		t.Run(name, func(t *testing.T) {
			runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
			for attempt := 0; attempt < 2; attempt++ {
				result, err := runtime.FirstContact(fixture.input)
				if !errors.Is(err, ErrSecureChannel) {
					t.Fatalf("attempt %d error=%v", attempt, err)
				}
				assertRuntimeClosed(t, result)
			}
			var reads int
			switch value := entropy.(type) {
			case *countingEntropyV1:
				reads = value.reads
			case *zeroEntropyV1:
				reads = value.reads
			}
			if reads != 1 || !runtime.strictEntropyFailed || runtime.strictEntropy != nil {
				t.Fatalf("reads=%d failed=%v entropy=%v", reads, runtime.strictEntropyFailed, runtime.strictEntropy)
			}
		})
	}
	t.Run("input rehash does not create authorization", func(t *testing.T) {
		other := newStrictSupportFixtureV1(t, security.TranscriptCapabilitiesV1, "suite_bound_transcript", "strict_required")
		entropy := &countingEntropyV1{fail: true}
		runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
		if _, err := runtime.FirstContact(other.input); !errors.Is(err, ErrProfileMismatch) || entropy.reads != 0 {
			t.Fatalf("error=%v reads=%d", err, entropy.reads)
		}
	})
}

func TestStrictHandshakeRuntimeV1SuccessfulHandshakesReadEpochEntropyExactlyOnce(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required")
	entropy := &countingEntropyV1{}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
	for attempt := 0; attempt < 3; attempt++ {
		result, err := runtime.FirstContact(fixture.input)
		if err != nil {
			t.Fatalf("attempt %d error=%v", attempt, err)
		}
		if len(result.ChannelSecret) == 0 {
			t.Fatalf("attempt %d returned no channel secret", attempt)
		}
		for i := range result.ChannelSecret {
			result.ChannelSecret[i] = 0
		}
	}
	if entropy.reads != 1 {
		t.Fatalf("successful strict runtime epoch reads=%d want=1", entropy.reads)
	}
}

func TestStrictHandshakeRuntimeV1StaleAndRehashedProfilesBeforeEntropy(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required")
	for _, role := range []string{"client", "relay"} {
		t.Run("stale-sealed-hash/"+role, func(t *testing.T) {
			input := fixture.input
			if role == "client" {
				input.Client.ProfileHash[0] ^= 1
			} else {
				input.Server.ProfileHash[0] ^= 1
			}
			entropy := &countingEntropyV1{fail: true}
			runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
			result, err := runtime.FirstContact(input)
			if !errors.Is(err, ErrProfileMismatch) || entropy.reads != 0 {
				t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
			}
			assertRuntimeClosed(t, result)
		})
	}
	t.Run("valid-auto-rehashed-mutated-profile", func(t *testing.T) {
		mutated := newStrictSupportFixtureV1(t, security.TranscriptCapabilitiesV1, "suite_bound_transcript", "strict_required")
		entropy := &countingEntropyV1{fail: true}
		runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
		result, err := runtime.FirstContact(mutated.input)
		if !errors.Is(err, ErrProfileMismatch) || entropy.reads != 0 {
			t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
		}
		assertRuntimeClosed(t, result)
	})
}

func TestSupportPreflightV1DescriptorMembershipAndCarrierSentinels(t *testing.T) {
	capFixture := newStrictSupportFixtureV1(t, security.TranscriptCapabilitiesV1, "strict_suite_and_capabilities", "strict_required")
	clientSupport := reviewedClientImplementationSupportV1.clone()
	clientSupport.featureVectors = removeStringV1(clientSupport.featureVectors, firstFeatureWithPrefixV1(capFixture.view.ClientModeBinding.FeatureVectors, "proxy:"))
	capRuntime := strictRuntimeForFixtureV1(t, capFixture, clientSupport, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := capRuntime.verifySupportAndAuthorizationPreflightV1(capFixture.snapshot, capFixture.view); !errors.Is(err, ErrCapabilityTranscriptInvalid) {
		t.Fatalf("dead feature-vector registry error=%v", err)
	}
	unknown := clonePreflightViewV1(capFixture.view)
	unknown.ClientModeBinding.FeatureVectors = append(unknown.ClientModeBinding.FeatureVectors, "unknown:feature")
	capRuntime = strictRuntimeForFixtureV1(t, capFixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := capRuntime.verifySupportAndAuthorizationPreflightV1(capFixture.snapshot, unknown); !errors.Is(err, ErrCapabilityTranscriptInvalid) {
		t.Fatalf("unknown feature prefix error=%v", err)
	}

	carrierFixture := newStrictSupportFixtureV1(t, security.TranscriptCarrierBindingV1, "strict_suite_and_capabilities", "strict_required")
	carrierSupport := reviewedClientImplementationSupportV1.clone()
	carrierSupport.featureVectors = removeStringV1(carrierSupport.featureVectors, firstFeatureWithPrefixV1(carrierFixture.view.ClientModeBinding.FeatureVectors, "carrier:"))
	carrierRuntime := strictRuntimeForFixtureV1(t, carrierFixture, carrierSupport, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := carrierRuntime.verifySupportAndAuthorizationPreflightV1(carrierFixture.snapshot, carrierFixture.view); !errors.Is(err, ErrCarrierBindingInvalid) {
		t.Fatalf("carrier feature-vector registry error=%v", err)
	}
	carrierView := clonePreflightViewV1(carrierFixture.view)
	carrierView.ClientModeBinding.CarrierFamily = "unsupported-carrier"
	carrierRuntime = strictRuntimeForFixtureV1(t, carrierFixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := carrierRuntime.verifySupportAndAuthorizationPreflightV1(carrierFixture.snapshot, carrierView); !errors.Is(err, ErrCarrierBindingInvalid) {
		t.Fatalf("carrier-mode active component error=%v", err)
	}
	canonical := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	canonicalView := clonePreflightViewV1(canonical.view)
	canonicalView.ClientModeBinding.CarrierFamily = "unsupported-carrier"
	canonicalRuntime := strictRuntimeForFixtureV1(t, canonical, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := canonicalRuntime.verifySupportAndAuthorizationPreflightV1(canonical.snapshot, canonicalView); !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("canonical active component error=%v", err)
	}

	suiteSupport := reviewedClientImplementationSupportV1.clone()
	suiteSupport.securitySuiteIDs = []string{"unsupported-suite-id"}
	suiteRuntime := strictRuntimeForFixtureV1(t, canonical, suiteSupport, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := suiteRuntime.verifySupportAndAuthorizationPreflightV1(canonical.snapshot, canonical.view); !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("selected suite-id support error=%v", err)
	}
	inactiveSuite := clonePreflightViewV1(canonical.view)
	inactiveSuite.ClientModeBinding.CompatibilityBlock.SupportedSecuritySuites = append(inactiveSuite.ClientModeBinding.CompatibilityBlock.SupportedSecuritySuites, "zz_inactive_suite")
	goodRuntime := strictRuntimeForFixtureV1(t, canonical, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	if err := goodRuntime.verifySupportAndAuthorizationPreflightV1(canonical.snapshot, inactiveSuite); err != nil {
		t.Fatalf("inactive advertised suite rejected under strict_schema: %v", err)
	}
}

func TestSupportPreflightV1IndependentFeatureAndInactiveCarrierMembershipBeforeEntropy(t *testing.T) {
	tests := []struct {
		name   string
		mode   string
		want   error
		mutate func(*ImplementationSupportV1, strictSupportFixtureV1)
	}{
		{
			name: "proxy features", mode: security.TranscriptCapabilitiesV1, want: ErrCapabilityTranscriptInvalid,
			mutate: func(support *ImplementationSupportV1, fixture strictSupportFixtureV1) {
				member := fixture.view.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures[0]
				support.proxyFeatures = removeStringV1(support.proxyFeatures, member)
			},
		},
		{
			name: "stream features", mode: security.TranscriptCapabilitiesV1, want: ErrCapabilityTranscriptInvalid,
			mutate: func(support *ImplementationSupportV1, fixture strictSupportFixtureV1) {
				member := fixture.view.ClientModeBinding.CompatibilityBlock.SupportedStreamFeatures[0]
				support.streamFeatures = removeStringV1(support.streamFeatures, member)
			},
		},
		{
			name: "inactive advertised carrier", mode: security.TranscriptCarrierBindingV1, want: ErrCarrierBindingInvalid,
			mutate: func(support *ImplementationSupportV1, fixture strictSupportFixtureV1) {
				active := fixture.view.ClientModeBinding.CarrierFamily
				inactive := ""
				for _, family := range fixture.view.ClientModeBinding.CompatibilityBlock.SupportedCarrierFamilies {
					if family != active {
						inactive = family
						break
					}
				}
				if inactive == "" {
					panic("fixture has no inactive advertised carrier")
				}
				support.carrierFamilies = removeStringV1(support.carrierFamilies, inactive)
			},
		},
	}
	for _, test := range tests {
		for _, role := range []string{"client", "relay"} {
			t.Run(test.name+"/"+role, func(t *testing.T) {
				fixture := newStrictSupportFixtureV1(t, test.mode, "strict_capabilities", "strict_required")
				clientSupport := reviewedClientImplementationSupportV1.clone()
				relaySupport := reviewedRelayImplementationSupportV1.clone()
				if role == "client" {
					test.mutate(&clientSupport, fixture)
				} else {
					test.mutate(&relaySupport, fixture)
				}
				entropy := &countingEntropyV1{fail: true}
				runtime := strictRuntimeForFixtureV1(t, fixture, clientSupport, relaySupport, entropy)
				result, err := runtime.FirstContact(fixture.input)
				assertOnlyWO031SentinelV1(t, err, test.want)
				if entropy.reads != 0 {
					t.Fatalf("result=%s/%s reads=%d", result.ClientState, result.ServerState, entropy.reads)
				}
				assertRuntimeClosed(t, result)
			})
		}
	}
}

func TestStrictHandshakeRuntimeV1PublicModeAndOwnerNegativesBeforeEntropy(t *testing.T) {
	modeCases := []struct {
		name   string
		mode   string
		want   error
		mutate func(*HandshakeRuntime, string)
	}{
		{
			name: "capability", mode: security.TranscriptCapabilitiesV1, want: ErrCapabilityTranscriptInvalid,
			mutate: func(runtime *HandshakeRuntime, role string) {
				support := &runtime.clientSupport
				if role == "relay" {
					support = &runtime.relaySupport
				}
				support.featureVectors = removeStringV1(support.featureVectors, firstFeatureWithPrefixV1(support.featureVectors, "proxy:"))
			},
		},
		{
			name: "carrier", mode: security.TranscriptCarrierBindingV1, want: ErrCarrierBindingInvalid,
			mutate: func(runtime *HandshakeRuntime, role string) {
				support := &runtime.clientSupport
				if role == "relay" {
					support = &runtime.relaySupport
				}
				support.carrierPolicyHashes = [][32]byte{{1}}
			},
		},
		{
			name: "full", mode: security.TranscriptFullBindingV1, want: ErrFullBindingInvalid,
			mutate: func(runtime *HandshakeRuntime, role string) {
				if role == "client" {
					runtime.clientRegistry.entries[0].framingPolicyHash[0] ^= 1
				} else {
					runtime.relayRegistry.entries[0].framingPolicyHash[0] ^= 1
				}
			},
		},
	}
	for _, test := range modeCases {
		for _, role := range []string{"client", "relay"} {
			t.Run(test.name+"/"+role, func(t *testing.T) {
				fixture := newStrictSupportFixtureV1(t, test.mode, "strict_suite_and_capabilities", "strict_required")
				entropy := &countingEntropyV1{fail: true}
				runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
				test.mutate(runtime, role)
				result, err := runtime.FirstContact(fixture.input)
				assertOnlyWO031SentinelV1(t, err, test.want)
				if entropy.reads != 0 {
					t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
				}
				assertRuntimeClosed(t, result)
			})
		}
	}

	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required")
	for _, role := range []string{"client", "relay"} {
		for _, shape := range []string{"missing", "stale-policy", "stale-profile"} {
			t.Run("owner/"+role+"/"+shape, func(t *testing.T) {
				entropy := &countingEntropyV1{fail: true}
				runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
				if role == "client" {
					switch shape {
					case "missing":
						runtime.clientRegistry.entries = nil
					case "stale-policy":
						runtime.clientRegistry.entries[0].effectivePolicyHash[0] ^= 1
					case "stale-profile":
						runtime.clientRegistry.entries[0].profileHash[0] ^= 1
					}
				} else {
					switch shape {
					case "missing":
						runtime.relayRegistry.entries = nil
					case "stale-policy":
						runtime.relayRegistry.entries[0].effectivePolicyHash[0] ^= 1
					case "stale-profile":
						runtime.relayRegistry.entries[0].profileHash[0] ^= 1
					}
				}
				result, err := runtime.FirstContact(fixture.input)
				if !errors.Is(err, ErrProfileMismatch) || entropy.reads != 0 {
					t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
				}
				assertRuntimeClosed(t, result)
			})
		}
	}
}

func firstFeatureWithPrefixV1(values []string, prefix string) string {
	for _, value := range values {
		if strings.HasPrefix(value, prefix) {
			return value
		}
	}
	return ""
}

func TestTranscriptSupportV1AllModesAndModeSeparation(t *testing.T) {
	modes := []string{
		security.TranscriptCanonicalV1,
		security.TranscriptCapabilitiesV1,
		security.TranscriptCarrierBindingV1,
		security.TranscriptFullBindingV1,
	}
	for _, mode := range modes {
		for _, downgrade := range []string{"strict_capabilities", "strict_suite_and_capabilities", "suite_bound_transcript"} {
			t.Run(mode+"/"+downgrade, func(t *testing.T) {
				fixture := newStrictSupportFixtureV1(t, mode, downgrade, "strict_required")
				runtime, err := NewStrictHandshakeRuntimeV1(fixture.dependencies.client, fixture.dependencies.server, fixture.clientRegistry, fixture.relayRegistry)
				if err != nil {
					t.Fatal(err)
				}
				assertStrictSuccessV1(t, runtime, fixture.input)
			})
		}
	}

	capFixture := newStrictSupportFixtureV1(t, security.TranscriptCapabilitiesV1, "strict_suite_and_capabilities", "strict_required")
	capRuntime := strictRuntimeForFixtureV1(t, capFixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	capView := clonePreflightViewV1(capFixture.view)
	capView.ClientModeBinding.CarrierPolicyHash[0] ^= 1
	if err := capRuntime.verifySupportAndAuthorizationPreflightV1(capFixture.snapshot, capView); err != nil {
		t.Fatalf("capabilities mode consumed carrier-only mutation: %v", err)
	}

	carrierFixture := newStrictSupportFixtureV1(t, security.TranscriptCarrierBindingV1, "strict_suite_and_capabilities", "strict_required")
	carrierRuntime := strictRuntimeForFixtureV1(t, carrierFixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	carrierView := clonePreflightViewV1(carrierFixture.view)
	carrierView.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures = append(carrierView.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures, "zz_unsupported")
	if err := carrierRuntime.verifySupportAndAuthorizationPreflightV1(carrierFixture.snapshot, carrierView); err != nil {
		t.Fatalf("carrier mode consumed proxy-only mutation: %v", err)
	}

	fullFixture := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "strict_suite_and_capabilities", "strict_required")
	fullRuntime := strictRuntimeForFixtureV1(t, fullFixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	fullCarrier := clonePreflightViewV1(fullFixture.view)
	fullCarrier.ClientModeBinding.CarrierPolicyHash[0] ^= 1
	if err := fullRuntime.verifySupportAndAuthorizationPreflightV1(fullFixture.snapshot, fullCarrier); !errors.Is(err, ErrCarrierBindingInvalid) {
		t.Fatalf("full carrier error=%v", err)
	}
	fullProxy := clonePreflightViewV1(fullFixture.view)
	fullProxy.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures = append(fullProxy.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures, "zz_unsupported")
	if err := fullRuntime.verifySupportAndAuthorizationPreflightV1(fullFixture.snapshot, fullProxy); !errors.Is(err, ErrCapabilityTranscriptInvalid) {
		t.Fatalf("full proxy error=%v", err)
	}

	emptyProxy := clonePreflightViewV1(capFixture.view)
	emptyProxy.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures = nil
	emptyProxy.ClientModeBinding.CompatibilityBlock.SupportedStreamFeatures = nil
	emptyProxy.ClientModeBinding.FeatureVectors = filterFeaturePrefixesV1(emptyProxy.ClientModeBinding.FeatureVectors, "carrier:")
	if err := capRuntime.verifySupportAndAuthorizationPreflightV1(capFixture.snapshot, emptyProxy); err != nil {
		t.Fatalf("empty optional proxy/stream lists rejected: %v", err)
	}
}

func TestDowngradeSupportV1AllPoliciesAndExactTuple(t *testing.T) {
	for _, policy := range []string{"strict_suite_and_capabilities", "strict_capabilities", "suite_bound_transcript"} {
		t.Run(policy, func(t *testing.T) {
			fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, policy, "strict_required")
			runtime, err := NewStrictHandshakeRuntimeV1(fixture.dependencies.client, fixture.dependencies.server, fixture.clientRegistry, fixture.relayRegistry)
			if err != nil {
				t.Fatal(err)
			}
			assertStrictSuccessV1(t, runtime, fixture.input)
		})
	}
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "suite_bound_transcript", "strict_required")
	for _, role := range []string{"client", "relay"} {
		for _, shape := range []string{"missing-exact-pair", "cross-pair-is-not-exact-pair"} {
			t.Run(role+"-"+shape, func(t *testing.T) {
				clientSupport := reviewedClientImplementationSupportV1.clone()
				relaySupport := reviewedRelayImplementationSupportV1.clone()
				mutate := func(support *ImplementationSupportV1) {
					support.suiteTranscriptPairs = removeTupleV1(support.suiteTranscriptPairs, security.TranscriptCanonicalV1)
					if shape == "cross-pair-is-not-exact-pair" {
						alternateSuite := security.SelectedSuiteV1{KDFSuite: "kdf_zz_alternate", AEADSuite: "aead_aes_256_gcm", MACSuite: "mac_hmac_sha256"}
						support.suites = append(support.suites, alternateSuite)
						support.suiteTranscriptPairs = append(support.suiteTranscriptPairs, selectedSuiteTranscriptV1{suite: alternateSuite, transcriptMode: security.TranscriptCanonicalV1})
					}
				}
				if role == "client" {
					mutate(&clientSupport)
				} else {
					mutate(&relaySupport)
				}
				entropy := &countingEntropyV1{fail: true}
				runtime := strictRuntimeForFixtureV1(t, fixture, clientSupport, relaySupport, entropy)
				if _, err := runtime.FirstContact(fixture.input); !errors.Is(err, ErrDowngradeRejected) || entropy.reads != 0 {
					t.Fatalf("error=%v reads=%d", err, entropy.reads)
				}
			})
		}
	}
}

func TestProfileAuthorizationV1CapabilityPoliciesAndProfileDeclaredRequired(t *testing.T) {
	for _, policy := range []string{"strict_required", "intersection_with_required", "profile_declared_required"} {
		t.Run(policy, func(t *testing.T) {
			fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", policy)
			runtime, err := NewStrictHandshakeRuntimeV1(fixture.dependencies.client, fixture.dependencies.server, fixture.clientRegistry, fixture.relayRegistry)
			if err != nil {
				t.Fatal(err)
			}
			assertStrictSuccessV1(t, runtime, fixture.input)
		})
	}
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "profile_declared_required")
	for _, role := range []string{"client", "relay"} {
		t.Run("profile-declared-retained/"+role, func(t *testing.T) {
			runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
			view := clonePreflightViewV1(fixture.view)
			if role == "client" {
				view.ClientModeBinding.CompatibilityBlock.RequiredCapabilities = append(view.ClientModeBinding.CompatibilityBlock.RequiredCapabilities, "zz_required")
			} else {
				view.ServerModeBinding.CompatibilityBlock.RequiredCapabilities = append(view.ServerModeBinding.CompatibilityBlock.RequiredCapabilities, "zz_required")
			}
			if err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, view); !errors.Is(err, ErrCapabilityRejected) {
				t.Fatalf("profile-declared retained requirement error=%v", err)
			}
		})
	}
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	negativeCases := []struct {
		name     string
		policy   string
		selected []string
	}{
		{"strict-required-rejects-intersection", "strict_required", known},
		{"intersection-rejects-floor-only", "intersection_with_required", floor},
	}
	for _, test := range negativeCases {
		t.Run(test.name, func(t *testing.T) {
			validSelected := floor
			if test.policy == "intersection_with_required" {
				validSelected = known
			}
			negative := newStrictSupportFixtureWithSetsV1(t, security.TranscriptCanonicalV1, "strict_capabilities", test.policy, floor, floor, known, known, validSelected)
			negative.input.SelectedCapabilities = append([]string(nil), test.selected...)
			entropy := &countingEntropyV1{fail: true}
			runtime := strictRuntimeForFixtureV1(t, negative, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
			result, err := runtime.FirstContact(negative.input)
			if !errors.Is(err, ErrCapabilityRejected) || entropy.reads != 0 {
				t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
			}
			assertRuntimeClosed(t, result)
		})
	}
}

func TestProfileAuthorizationV1ProfileDeclaredRequiredAuthenticRetainedRequirementRejectsBeforeEntropy(t *testing.T) {
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:1]...)
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = "strict_capabilities"
	p.Security.CapabilityNegotiationPolicy = "profile_declared_required"
	p.Security.ProfileCompatibilityPolicy = "strict_schema"
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = "strict_required"
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.Compatibility.RequiredCapabilities = []string{known[1]}
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{
		Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), floor...),
		ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay,
	}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		t.Fatalf("authentic retained-requirement snapshot failed before runtime check: %v", err)
	}
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{
		clientAuthorizationEntryV1(snapshot.Client.ProfileHash, policyHash, policy, view.ClientModeBinding),
	})
	if err != nil {
		t.Fatal(err)
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{
		relayAuthorizationEntryV1(snapshot.Server.ProfileHash, policyHash, policy, view.ServerModeBinding),
	})
	if err != nil {
		t.Fatal(err)
	}
	entropy := &countingEntropyV1{fail: true}
	runtime, err := newStrictHandshakeRuntimeV1(
		dependencies.client, dependencies.server, clientRegistry, relayRegistry,
		reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy,
	)
	if err != nil {
		t.Fatal(err)
	}
	result, err := runtime.FirstContact(input)
	if !errors.Is(err, ErrCapabilityRejected) || entropy.reads != 0 {
		t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
	}
	assertRuntimeClosed(t, result)
}

func newProfileDeclaredIntersectionFixtureV1(t *testing.T) (strictSupportFixtureV1, []string, []string) {
	t.Helper()
	known := sortedStringsV1(ir.SecurityCapabilities())
	required := append([]string(nil), known[:1]...)
	clientOffer := sortedStringsV1([]string{known[0], known[1], known[2]})
	relayOffer := sortedStringsV1([]string{known[0], known[2], known[3]})
	selected := sortedStringsV1([]string{known[0], known[2]})
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = "strict_capabilities"
	p.Security.CapabilityNegotiationPolicy = "profile_declared_required"
	p.Security.ProfileCompatibilityPolicy = "strict_schema"
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = "strict_required"
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.Compatibility.RequiredCapabilities = append([]string(nil), required...)
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, required, required, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, clientOffer, required)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, relayOffer, required)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{
		Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), selected...),
		ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay,
	}
	snapshot, view, err := auth.SnapshotFirstContactInputV1(input)
	if err != nil {
		t.Fatal(err)
	}
	policyHash, err := security.EffectivePolicyHashV1(policy)
	if err != nil {
		t.Fatal(err)
	}
	clientEntry := clientAuthorizationEntryV1(snapshot.Client.ProfileHash, policyHash, policy, view.ClientModeBinding)
	relayEntry := relayAuthorizationEntryV1(snapshot.Server.ProfileHash, policyHash, policy, view.ServerModeBinding)
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{clientEntry})
	if err != nil {
		t.Fatal(err)
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{relayEntry})
	if err != nil {
		t.Fatal(err)
	}
	return strictSupportFixtureV1{
		input: input, snapshot: snapshot, view: view, dependencies: dependencies,
		clientEntry: clientEntry, relayEntry: relayEntry, clientRegistry: clientRegistry, relayRegistry: relayRegistry,
	}, required, selected
}

func TestProfileAuthorizationV1ProfileDeclaredIntersectionSemantics(t *testing.T) {
	fixture, floor, intersection := newProfileDeclaredIntersectionFixtureV1(t)
	if !equalStringsV1(fixture.view.SelectedCapabilities, intersection) ||
		!containsAllV1(intersection, fixture.view.ClientModeBinding.CompatibilityBlock.RequiredCapabilities) ||
		!containsAllV1(intersection, fixture.view.ServerModeBinding.CompatibilityBlock.RequiredCapabilities) {
		t.Fatal("fixture does not isolate exact intersection with satisfied retained requirements")
	}
	positive, err := NewStrictHandshakeRuntimeV1(
		fixture.dependencies.client, fixture.dependencies.server, fixture.clientRegistry, fixture.relayRegistry,
	)
	if err != nil {
		t.Fatal(err)
	}
	assertStrictSuccessV1(t, positive, fixture.input)
	extra := sortedStringsV1(append(append([]string(nil), intersection...), fixture.input.Client.OfferedCapabilities[1]))
	for name, selected := range map[string][]string{
		"floor-only":      floor,
		"extra-selection": extra,
	} {
		t.Run(name, func(t *testing.T) {
			input := fixture.input
			input.SelectedCapabilities = append([]string(nil), selected...)
			entropy := &countingEntropyV1{fail: true}
			runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
			result, err := runtime.FirstContact(input)
			assertOnlyWO031SentinelV1(t, err, ErrCapabilityRejected)
			if entropy.reads != 0 {
				t.Fatalf("result=%s/%s reads=%d", result.ClientState, result.ServerState, entropy.reads)
			}
			assertRuntimeClosed(t, result)
		})
	}
}

func removeStringV1(values []string, remove string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		if value != remove {
			out = append(out, value)
		}
	}
	return out
}

func removeTupleV1(values []selectedSuiteTranscriptV1, mode string) []selectedSuiteTranscriptV1 {
	out := make([]selectedSuiteTranscriptV1, 0, len(values))
	for _, value := range values {
		if value.transcriptMode != mode {
			out = append(out, value)
		}
	}
	return out
}

func filterFeaturePrefixesV1(values []string, keep ...string) []string {
	out := make([]string, 0, len(values))
	for _, value := range values {
		for _, prefix := range keep {
			if strings.HasPrefix(value, prefix) {
				out = append(out, value)
				break
			}
		}
	}
	return out
}

func clonePreflightViewV1(view auth.FirstContactPreflightViewV1) auth.FirstContactPreflightViewV1 {
	view.ClientOfferPolicy = view.ClientOfferPolicy.Clone()
	view.ClientFloorPolicy = view.ClientFloorPolicy.Clone()
	view.ServerOfferPolicy = view.ServerOfferPolicy.Clone()
	view.ServerFloorPolicy = view.ServerFloorPolicy.Clone()
	view.SelectedPolicy = view.SelectedPolicy.Clone()
	view.ClientOfferedCapabilities = append([]string(nil), view.ClientOfferedCapabilities...)
	view.ClientRequiredCapabilities = append([]string(nil), view.ClientRequiredCapabilities...)
	view.ServerOfferedCapabilities = append([]string(nil), view.ServerOfferedCapabilities...)
	view.ServerRequiredCapabilities = append([]string(nil), view.ServerRequiredCapabilities...)
	view.SelectedCapabilities = append([]string(nil), view.SelectedCapabilities...)
	view.ClientModeBinding = view.ClientModeBinding.Clone()
	view.ServerModeBinding = view.ServerModeBinding.Clone()
	return view
}

func TestSupportPreflightV1CausalGroupedRuntimeSupportLedger(t *testing.T) {
	ownerIDs := map[string]string{"strict_suite_and_capabilities": "pm-owner:downgrade/strict_suite_and_capabilities", "strict_capabilities": "pm-owner:downgrade/strict_capabilities", "suite_bound_transcript": "pm-owner:downgrade/suite_bound_transcript", "strict_required": "pm-owner:capability/strict_required", "intersection_with_required": "pm-owner:capability/intersection_with_required", "profile_declared_required": "pm-owner:capability/profile_declared_required", "strict_schema": "pm-owner:compatibility/strict_schema", "schema_and_feature": "pm-owner:compatibility/schema_and_feature", "full_policy_binding": "pm-owner:compatibility/full_policy_binding"}
	type ledgerCase struct {
		group, value                       string
		mode, downgrade, capability        string
		profileCompatibility, configPolicy string
		want                               error
		mutateSupport                      func(*ImplementationSupportV1, strictSupportFixtureV1)
		mutateRuntime                      func(*HandshakeRuntime, string)
	}
	removeSelected := func(values []string, selected string) []string {
		removed := removeStringV1(values, selected)
		if len(removed) != len(values)-1 {
			t.Fatalf("ledger mutation did not remove exactly one %q member from %v", selected, values)
		}
		return removed
	}
	defaults := func(test ledgerCase) ledgerCase {
		if test.mode == "" {
			test.mode = security.TranscriptCanonicalV1
		}
		if test.downgrade == "" {
			test.downgrade = "strict_capabilities"
		}
		if test.capability == "" {
			test.capability = "strict_required"
		}
		if test.profileCompatibility == "" {
			test.profileCompatibility = "strict_schema"
		}
		if test.configPolicy == "" {
			test.configPolicy = "strict_required"
		}
		return test
	}

	var tests []ledgerCase
	for _, value := range []string{"strict_capabilities", "strict_suite_and_capabilities", "suite_bound_transcript"} {
		value := value
		tests = append(tests, ledgerCase{
			group: ownerIDs[value], value: value, downgrade: value, want: ErrDowngradeRejected,
			mutateSupport: func(s *ImplementationSupportV1, _ strictSupportFixtureV1) {
				s.downgradePolicies = removeSelected(s.downgradePolicies, value)
			},
		})
	}
	for _, value := range []string{"intersection_with_required", "profile_declared_required", "strict_required"} {
		value := value
		tests = append(tests, ledgerCase{
			group: ownerIDs[value], value: value, capability: value, want: ErrCapabilityRejected,
			mutateSupport: func(s *ImplementationSupportV1, _ strictSupportFixtureV1) {
				s.capabilityPolicies = removeSelected(s.capabilityPolicies, value)
			},
		})
	}
	for _, value := range []string{"strict_schema", "schema_and_feature", "full_policy_binding"} {
		value := value
		tests = append(tests, ledgerCase{
			group: ownerIDs[value], value: value, profileCompatibility: value, want: ErrProfileIncompatible,
			mutateSupport: func(s *ImplementationSupportV1, _ strictSupportFixtureV1) {
				s.profilePolicies = removeSelected(s.profilePolicies, value)
			},
		})
	}
	for _, value := range []string{"strict_profile_bound", "strict_required", "strict_with_redaction"} {
		value := value
		tests = append(tests, ledgerCase{
			group: "config", value: value, configPolicy: value, want: ErrProfileIncompatible,
			mutateSupport: func(s *ImplementationSupportV1, _ strictSupportFixtureV1) {
				s.configPolicies = removeSelected(s.configPolicies, value)
			},
		})
	}
	tests = append(tests,
		ledgerCase{
			group: "transcript-supplemental", value: security.TranscriptCapabilitiesV1,
			mode: security.TranscriptCapabilitiesV1, want: ErrCapabilityTranscriptInvalid,
			mutateSupport: func(s *ImplementationSupportV1, fixture strictSupportFixtureV1) {
				member := fixture.view.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures[0]
				s.proxyFeatures = removeSelected(s.proxyFeatures, member)
			},
		},
		ledgerCase{
			group: "transcript-supplemental", value: security.TranscriptCarrierBindingV1,
			mode: security.TranscriptCarrierBindingV1, want: ErrCarrierBindingInvalid,
			mutateSupport: func(s *ImplementationSupportV1, fixture strictSupportFixtureV1) {
				want := fixture.view.ClientModeBinding.CarrierPolicyHash
				out := make([][32]byte, 0, len(s.carrierPolicyHashes))
				for _, hash := range s.carrierPolicyHashes {
					if hash != want {
						out = append(out, hash)
					}
				}
				if len(out) != len(s.carrierPolicyHashes)-1 {
					t.Fatalf("carrier supplemental mutation removed %d values, want 1", len(s.carrierPolicyHashes)-len(out))
				}
				s.carrierPolicyHashes = out
			},
		},
		ledgerCase{
			group: "transcript-supplemental", value: security.TranscriptFullBindingV1,
			mode: security.TranscriptFullBindingV1, want: ErrFullBindingInvalid,
			mutateRuntime: func(runtime *HandshakeRuntime, role string) {
				entry := &runtime.clientRegistry.entries[0]
				if role == "relay" {
					entry = &runtime.relayRegistry.entries[0]
				}
				entry.framingPolicyHash[0] ^= 1
			},
		},
		ledgerCase{
			group: "precedence", value: "profile-source-before-canonical-supplementals",
			want: ErrProfileMismatch,
			mutateRuntime: func(runtime *HandshakeRuntime, role string) {
				entry := &runtime.clientRegistry.entries[0]
				if role == "relay" {
					entry = &runtime.relayRegistry.entries[0]
				}
				entry.effectivePolicyHash[0] ^= 1
			},
		},
	)

	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	for _, raw := range tests {
		test := defaults(raw)
		for _, role := range []string{"client", "relay"} {
			t.Run(test.group+"/"+test.value+"/"+role, func(t *testing.T) {
				selected := floor
				if test.capability != "strict_required" {
					selected = known
				}
				fixture := newStrictSupportFixturePolicyWithSetsV1(
					t, test.mode, test.downgrade, test.capability, test.profileCompatibility, test.configPolicy,
					floor, floor, known, known, selected,
				)
				clientSupport := reviewedClientImplementationSupportV1.clone()
				relaySupport := reviewedRelayImplementationSupportV1.clone()
				runtime := strictRuntimeForFixtureV1(t, fixture, clientSupport, relaySupport, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
				if err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, fixture.view); err != nil {
					t.Fatalf("valid(%s) did not reach production verifier: %v", test.value, err)
				}

				mutations := 0
				if test.mutateSupport != nil {
					mutations++
					if role == "client" {
						test.mutateSupport(&runtime.clientSupport, fixture)
					} else {
						test.mutateSupport(&runtime.relaySupport, fixture)
					}
				}
				if test.mutateRuntime != nil {
					mutations++
					test.mutateRuntime(runtime, role)
				}
				if mutations != 1 {
					t.Fatalf("mutation cardinality=%d want=1", mutations)
				}
				err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, fixture.view)
				if err == nil || !errors.Is(err, test.want) || err != test.want || err.Error() != test.want.Error() {
					t.Fatalf("actual error=%v errors.Is=%v exact=%v text=%q want=%v", err, errors.Is(err, test.want), err == test.want, errorTextV1(err), test.want)
				}
			})
		}
	}
}

func errorTextV1(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func TestProfileAuthorizationV1PrecedenceSevenHashesAndDeferredTuple(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptFullBindingV1, "suite_bound_transcript", "strict_required")
	newRuntime := func(t *testing.T) *HandshakeRuntime {
		return strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	}

	t.Run("profile before supplemental", func(t *testing.T) {
		runtime := newRuntime(t)
		runtime.clientRegistry.entries[0].effectivePolicyHash[0] ^= 1
		view := clonePreflightViewV1(fixture.view)
		view.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures = append(view.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures, "zz_unsupported")
		view.ClientModeBinding.CarrierPolicyHash[0] ^= 1
		err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, view)
		assertOnlyWO031SentinelV1(t, err, ErrProfileMismatch)
	})
	t.Run("capability before carrier and full", func(t *testing.T) {
		runtime := newRuntime(t)
		runtime.clientRegistry.entries[0].framingPolicyHash[0] ^= 1
		view := clonePreflightViewV1(fixture.view)
		view.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures = append(view.ClientModeBinding.CompatibilityBlock.SupportedProxyFeatures, "zz_unsupported")
		view.ClientModeBinding.CarrierPolicyHash[0] ^= 1
		err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, view)
		assertOnlyWO031SentinelV1(t, err, ErrCapabilityTranscriptInvalid)
	})
	t.Run("carrier before full", func(t *testing.T) {
		runtime := newRuntime(t)
		runtime.clientRegistry.entries[0].framingPolicyHash[0] ^= 1
		view := clonePreflightViewV1(fixture.view)
		view.ClientModeBinding.CarrierPolicyHash[0] ^= 1
		err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, view)
		assertOnlyWO031SentinelV1(t, err, ErrCarrierBindingInvalid)
	})

	hashMutations := []struct {
		name   string
		mutate func(*profileAuthorizationEntryV1)
	}{
		{"framing", func(v *profileAuthorizationEntryV1) { v.framingPolicyHash[0] ^= 1 }},
		{"state", func(v *profileAuthorizationEntryV1) { v.stateMachinePolicyHash[0] ^= 1 }},
		{"scheduler", func(v *profileAuthorizationEntryV1) { v.schedulerPolicyHash[0] ^= 1 }},
		{"padding", func(v *profileAuthorizationEntryV1) { v.paddingPolicyHash[0] ^= 1 }},
		{"stream", func(v *profileAuthorizationEntryV1) { v.streamPolicyHash[0] ^= 1 }},
		{"proxy", func(v *profileAuthorizationEntryV1) { v.proxyPolicyHash[0] ^= 1 }},
		{"carrier-context", func(v *profileAuthorizationEntryV1) { v.carrierContextPolicyHash[0] ^= 1 }},
	}
	for _, role := range []string{"client", "relay"} {
		for _, mutation := range hashMutations {
			t.Run(role+"/"+mutation.name, func(t *testing.T) {
				runtime := newRuntime(t)
				if role == "client" {
					mutation.mutate(&runtime.clientRegistry.entries[0])
				} else {
					mutation.mutate(&runtime.relayRegistry.entries[0])
				}
				err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, fixture.view)
				assertOnlyWO031SentinelV1(t, err, ErrFullBindingInvalid)
			})
		}
	}

	for _, mode := range []string{security.TranscriptCanonicalV1, security.TranscriptCapabilitiesV1, security.TranscriptCarrierBindingV1} {
		for _, role := range []string{"client", "relay"} {
			for _, mutation := range hashMutations {
				t.Run("seven-hash-deferred/"+mode+"/"+role+"/"+mutation.name, func(t *testing.T) {
					outsideFull := newStrictSupportFixtureV1(t, mode, "strict_capabilities", "strict_required")
					runtime := strictRuntimeForFixtureV1(t, outsideFull, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
					if role == "client" {
						mutation.mutate(&runtime.clientRegistry.entries[0])
					} else {
						mutation.mutate(&runtime.relayRegistry.entries[0])
					}
					if err := runtime.verifySupportAndAuthorizationPreflightV1(outsideFull.snapshot, outsideFull.view); err != nil {
						t.Fatalf("seven-hash mismatch leaked outside full mode: %v", err)
					}
				})
			}
		}
	}
	for _, role := range []string{"client", "relay"} {
		for _, field := range []string{"replay", "streams", "frame", "envelope"} {
			t.Run("effective-tuple-deferred/"+role+"/"+field, func(t *testing.T) {
				fullRuntime := newRuntime(t)
				entry := &fullRuntime.clientRegistry.entries[0]
				if role == "relay" {
					entry = &fullRuntime.relayRegistry.entries[0]
				}
				switch field {
				case "replay":
					entry.replayWindowSize++
				case "streams":
					entry.maxConcurrentStreams++
				case "frame":
					entry.maxFrameBytes++
				case "envelope":
					entry.maxEnvelopeBytes++
				}
				if err := fullRuntime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, fixture.view); err != nil {
					t.Fatalf("effective tuple compared before WO-033: %v", err)
				}
			})
		}
	}

	for _, role := range []string{"client", "relay"} {
		t.Run("missing-"+role, func(t *testing.T) {
			runtime := newRuntime(t)
			if role == "client" {
				runtime.clientRegistry.entries = nil
			} else {
				runtime.relayRegistry.entries = nil
			}
			if err := runtime.verifySupportAndAuthorizationPreflightV1(fixture.snapshot, fixture.view); !errors.Is(err, ErrProfileMismatch) {
				t.Fatalf("error=%v", err)
			}
		})
	}
}

func TestSupportPreflightV1SentinelClassificationAndRepeatVerifier(t *testing.T) {
	known := sortedStringsV1(ir.SecurityCapabilities())
	clientFloor, relayFloor := known[:1], known[1:2]
	selected := sortedStringsV1(append(append([]string(nil), clientFloor...), relayFloor...))

	unequal := newStrictSealedInputV1(t, "strict_suite_and_capabilities", "strict_required", clientFloor, relayFloor, known, known, selected)
	unequalRuntime := strictRuntimeForSealedInputV1(t, unequal)
	_, err := unequalRuntime.FirstContact(unequal.input)
	assertOnlyWO031SentinelV1(t, err, ErrDowngradeRejected)

	missingOffer := newStrictSealedInputV1(t, "strict_capabilities", "intersection_with_required", clientFloor, relayFloor, clientFloor, known, selected)
	missingRuntime := strictRuntimeForSealedInputV1(t, missingOffer)
	_, err = missingRuntime.FirstContact(missingOffer.input)
	assertOnlyWO031SentinelV1(t, err, ErrDowngradeRejected)

	valid := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required")
	invalidSelection := valid.input
	invalidSelection.SelectedCapabilities = append(invalidSelection.SelectedCapabilities, "zz_extra")
	runtime := strictRuntimeForFixtureV1(t, valid, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, &countingEntropyV1{fail: true})
	_, err = runtime.FirstContact(invalidSelection)
	assertOnlyWO031SentinelV1(t, err, ErrCapabilityRejected)
	invalidPolicy := valid.input
	invalidPolicy.SelectedPolicy.TranscriptMode = "unknown_transcript"
	_, err = runtime.FirstContact(invalidPolicy)
	assertOnlyWO031SentinelV1(t, err, ErrPolicyInvalid)
	otherMode := newStrictSupportFixtureV1(t, security.TranscriptCapabilitiesV1, "strict_capabilities", "strict_required")
	transcriptMismatch := valid.input
	transcriptMismatch.SelectedPolicy = otherMode.input.SelectedPolicy.Clone()
	transcriptMismatch.SelectedCapabilities = append([]string(nil), otherMode.input.SelectedCapabilities...)
	_, err = runtime.FirstContact(transcriptMismatch)
	assertOnlyWO031SentinelV1(t, err, ErrTranscriptMismatch)

	asymmetric := newStrictSupportFixtureWithSetsV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "intersection_with_required", clientFloor, relayFloor, known, known, known)
	asymmetricRuntime, err := NewStrictHandshakeRuntimeV1(asymmetric.dependencies.client, asymmetric.dependencies.server, asymmetric.clientRegistry, asymmetric.relayRegistry)
	if err != nil {
		t.Fatal(err)
	}
	result := assertStrictSuccessV1(t, asymmetricRuntime, asymmetric.input)
	contextSnapshot, ok := result.AuthenticatedContextSnapshotV1()
	if !ok {
		t.Fatal("missing sealed context snapshot")
	}
	if err := asymmetricRuntime.verifySupportAndAuthorizationContextV1(contextSnapshot); err != nil {
		t.Fatalf("repeat verifier positive error=%v", err)
	}
	clientMissing := contextSnapshot
	clientMissing.ClientModeBinding = contextSnapshot.ClientModeBinding.Clone()
	clientMissing.ClientModeBinding.ClientOptional = removeStringV1(clientMissing.ClientModeBinding.ClientOptional, relayFloor[0])
	if err := asymmetricRuntime.verifySupportAndAuthorizationContextV1(clientMissing); !errors.Is(err, ErrDowngradeRejected) {
		t.Fatalf("repeat client offer error=%v", err)
	}
	relayMissing := contextSnapshot
	relayMissing.ServerModeBinding = contextSnapshot.ServerModeBinding.Clone()
	relayMissing.ServerModeBinding.ServerOptional = removeStringV1(relayMissing.ServerModeBinding.ServerOptional, clientFloor[0])
	if err := asymmetricRuntime.verifySupportAndAuthorizationContextV1(relayMissing); !errors.Is(err, ErrDowngradeRejected) {
		t.Fatalf("repeat relay offer error=%v", err)
	}
}

func TestSupportPreflightV1DirectFiveCopyPolicyEncodingMatrix(t *testing.T) {
	base := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_capabilities", "strict_required").view.SelectedPolicy
	alternate := newStrictSupportFixtureV1(t, security.TranscriptCapabilitiesV1, "suite_bound_transcript", "strict_required").view.SelectedPolicy
	baseRaw, err := security.EncodePolicyV1(base)
	if err != nil {
		t.Fatal(err)
	}
	alternateRaw, err := security.EncodePolicyV1(alternate)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(baseRaw, alternateRaw) {
		t.Fatal("genuinely distinct valid policies encoded to equal PolicyV1 bytes")
	}
	equal := []ir.EffectiveSecurityPolicy{base, base, base, base, base}
	if err := verifyFiveCopyPolicyV1(equal); err != nil {
		t.Fatalf("equal five-copy PolicyV1 set rejected: %v", err)
	}
	for index, position := range []string{"client-offer", "client-floor", "relay-offer", "relay-floor", "selected"} {
		t.Run(position, func(t *testing.T) {
			policies := append([]ir.EffectiveSecurityPolicy(nil), equal...)
			policies[index] = alternate
			err := verifyFiveCopyPolicyV1(policies)
			assertOnlyWO031SentinelV1(t, err, ErrDowngradeRejected)
		})
	}
	// This directly freezes encoded PolicyV1 equality. Public authenticated
	// construction of a same-profile encoded-field mismatch is intentionally
	// unreachable: NewPeerParameters requires every valid policy to bind the
	// one validated profile, whose security fields determine those bytes.
}

func TestStrictHandshakeRuntimeV1CapabilityOnlyCopyDifferencesStayCapabilityOwned(t *testing.T) {
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:1]...)
	selectedAlternate := append([]string(nil), known[:2]...)
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = "strict_capabilities"
	p.Security.CapabilityNegotiationPolicy = "strict_required"
	p.Security.ProfileCompatibilityPolicy = "strict_schema"
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = "strict_required"
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	base, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	alternate, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, selectedAlternate)
	if err != nil {
		t.Fatal(err)
	}
	for _, position := range []string{"client-offer", "client-floor", "relay-offer", "relay-floor", "selected-policy"} {
		t.Run(position, func(t *testing.T) {
			clientOffer, clientFloor := base, base
			relayOffer, relayFloor := base, base
			selectedPolicy := base
			selectedCapabilities := append([]string(nil), floor...)
			switch position {
			case "client-offer":
				clientOffer = alternate
			case "client-floor":
				clientFloor = alternate
			case "relay-offer":
				relayOffer = alternate
			case "relay-floor":
				relayFloor = alternate
			case "selected-policy":
				selectedPolicy = alternate
				selectedCapabilities = append([]string(nil), selectedAlternate...)
			}
			client, err := auth.NewPeerParameters("runtime-client", p, clientOffer, clientFloor, known, floor)
			if err != nil {
				t.Fatal(err)
			}
			relay, err := auth.NewPeerParameters("runtime-server", p, relayOffer, relayFloor, known, floor)
			if err != nil {
				t.Fatal(err)
			}
			sealed := sealedStrictInputV1{
				input:        auth.FirstContactInput{Client: client, Server: relay, SelectedPolicy: selectedPolicy, SelectedCapabilities: selectedCapabilities},
				dependencies: runtimeDependenciesFixture(t),
			}
			runtime := strictRuntimeForSealedInputV1(t, sealed)
			entropy := runtime.strictEntropy.(*countingEntropyV1)
			result, err := runtime.FirstContact(sealed.input)
			if !errors.Is(err, ErrCapabilityRejected) || entropy.reads != 0 {
				t.Fatalf("result=%s/%s error=%v reads=%d", result.ClientState, result.ServerState, err, entropy.reads)
			}
			assertRuntimeClosed(t, result)
		})
	}
}

type sealedStrictInputV1 struct {
	input        auth.FirstContactInput
	dependencies runtimeDependencyFixture
}

func newStrictSealedInputV1(t *testing.T, downgrade, capability string, clientFloor, relayFloor, clientOffer, relayOffer, selected []string) sealedStrictInputV1 {
	t.Helper()
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = downgrade
	p.Security.CapabilityNegotiationPolicy = capability
	p.Security.ProfileCompatibilityPolicy = "strict_schema"
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = "strict_required"
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := ir.BuildEffectiveSecurityPolicy(p, clientFloor, relayFloor, selected)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, clientOffer, clientFloor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, relayOffer, relayFloor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	return sealedStrictInputV1{
		input:        auth.FirstContactInput{Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), selected...)},
		dependencies: dependencies,
	}
}

func strictRuntimeForSealedInputV1(t *testing.T, sealed sealedStrictInputV1) *HandshakeRuntime {
	t.Helper()
	policyHash, err := security.EffectivePolicyHashV1(sealed.input.SelectedPolicy)
	if err != nil {
		t.Fatal(err)
	}
	hash := [32]byte{1}
	clientEntry := ClientProfileAuthorizationEntryV1{
		ProfileHash: sealed.input.Client.ProfileHash, EffectivePolicyHash: policyHash,
		ReplayWindowSize: uint32(sealed.input.SelectedPolicy.ReplayWindowSize), MaxConcurrentStreams: 1, MaxFrameBytes: 1, MaxEnvelopeBytes: 1,
		FramingPolicyHash: hash, StateMachinePolicyHash: hash, SchedulerPolicyHash: hash, PaddingPolicyHash: hash,
		StreamPolicyHash: hash, ProxyPolicyHash: hash, CarrierContextPolicyHash: hash,
	}
	relayEntry := RelayProfileAuthorizationEntryV1{
		ProfileHash: sealed.input.Server.ProfileHash, EffectivePolicyHash: policyHash,
		ReplayWindowSize: uint32(sealed.input.SelectedPolicy.ReplayWindowSize), MaxConcurrentStreams: 1, MaxFrameBytes: 1, MaxEnvelopeBytes: 1,
		FramingPolicyHash: hash, StateMachinePolicyHash: hash, SchedulerPolicyHash: hash, PaddingPolicyHash: hash,
		StreamPolicyHash: hash, ProxyPolicyHash: hash, CarrierContextPolicyHash: hash,
	}
	clientRegistry, err := NewClientProfileAuthorizationRegistryV1([]ClientProfileAuthorizationEntryV1{clientEntry})
	if err != nil {
		t.Fatal(err)
	}
	relayRegistry, err := NewRelayProfileAuthorizationRegistryV1([]RelayProfileAuthorizationEntryV1{relayEntry})
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := newStrictHandshakeRuntimeV1(
		sealed.dependencies.client, sealed.dependencies.server, clientRegistry, relayRegistry,
		reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, &countingEntropyV1{fail: true},
	)
	if err != nil {
		t.Fatal(err)
	}
	return runtime
}

func TestImplementationSupportV1SnapshotIsolationAndStaticAPI(t *testing.T) {
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	view := clonePreflightViewV1(fixture.view)
	wantSnapshotCapability := fixture.snapshot.SelectedCapabilities[0]
	view.SelectedCapabilities[0] = "mutated"
	view.ClientModeBinding.FeatureVectors[0] = "mutated"
	if fixture.snapshot.SelectedCapabilities[0] != wantSnapshotCapability || fixture.view.SelectedCapabilities[0] == "mutated" {
		t.Fatal("source/view/snapshot capability alias")
	}
	if fixture.view.ClientModeBinding.FeatureVectors[0] == "mutated" {
		t.Fatal("mode-binding clone alias")
	}

	constructor := reflect.TypeOf(NewStrictHandshakeRuntimeV1)
	if constructor.NumIn() != 4 || constructor.NumOut() != 2 ||
		constructor.In(0) != reflect.TypeOf(auth.Dependencies{}) || constructor.In(1) != reflect.TypeOf(auth.Dependencies{}) ||
		constructor.In(2) != reflect.TypeOf(ClientProfileAuthorizationRegistryV1{}) ||
		constructor.In(3) != reflect.TypeOf(RelayProfileAuthorizationRegistryV1{}) ||
		constructor.Out(0) != reflect.TypeOf((*HandshakeRuntime)(nil)) || constructor.Out(1) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("strict constructor signature = %v", constructor)
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(ImplementationSupportV1{}), reflect.TypeOf(ClientProfileAuthorizationRegistryV1{}), reflect.TypeOf(RelayProfileAuthorizationRegistryV1{})} {
		for i := range typ.NumField() {
			if typ.Field(i).IsExported() {
				t.Fatalf("%s exposes mutable field %s", typ, typ.Field(i).Name)
			}
		}
		if typ.NumMethod() != 0 {
			t.Fatalf("%s exposes methods", typ)
		}
	}

	_, thisFile, _, ok := goruntime.Caller(0)
	if !ok {
		t.Fatal("caller path unavailable")
	}
	runtimeDir := filepath.Dir(thisFile)
	handshakeRaw, err := os.ReadFile(filepath.Join(runtimeDir, "handshake.go"))
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	parsed, err := parser.ParseFile(fset, filepath.Join(runtimeDir, "handshake.go"), handshakeRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	declarations := 0
	usesReviewedClient, usesReviewedRelay, delegatesPrivate := false, false, false
	var strictDecl *ast.FuncDecl
	ast.Inspect(parsed, func(node ast.Node) bool {
		decl, ok := node.(*ast.FuncDecl)
		if ok && decl.Name.Name == "NewStrictHandshakeRuntimeV1" {
			declarations++
			ast.Inspect(decl.Body, func(child ast.Node) bool {
				ident, ok := child.(*ast.Ident)
				if !ok {
					return true
				}
				switch ident.Name {
				case "reviewedClientImplementationSupportV1":
					usesReviewedClient = true
				case "reviewedRelayImplementationSupportV1":
					usesReviewedRelay = true
				case "newStrictHandshakeRuntimeV1":
					delegatesPrivate = true
				}
				return true
			})
			return false
		}
		if ok && decl.Name.Name == "strictFirstContactV1" {
			strictDecl = decl
		}
		return true
	})
	if declarations != 1 || !usesReviewedClient || !usesReviewedRelay || !delegatesPrivate || strictDecl == nil {
		t.Fatalf("strict constructor AST route: declarations=%d client=%v relay=%v private=%v", declarations, usesReviewedClient, usesReviewedRelay, delegatesPrivate)
	}
	callName := func(call *ast.CallExpr) string {
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			return fun.Name
		case *ast.SelectorExpr:
			return fun.Sel.Name
		default:
			return ""
		}
	}
	var contextAccessorPos, contextVerifierPos token.Pos
	forbiddenStrictCall := ""
	ast.Inspect(strictDecl.Body, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call)
		switch name {
		case "AuthenticatedContextSnapshotV1":
			contextAccessorPos = call.Pos()
		case "verifySupportAndAuthorizationContextV1":
			contextVerifierPos = call.Pos()
		case "DeriveKeyScheduleV1":
			forbiddenStrictCall = name
		}
		if strings.Contains(strings.ToLower(name), "transfer") {
			forbiddenStrictCall = name
		}
		return true
	})
	if contextAccessorPos == token.NoPos || contextVerifierPos == token.NoPos || contextAccessorPos >= contextVerifierPos || forbiddenStrictCall != "" {
		t.Fatalf("strict post-auth order accessor=%v verifier=%v forbidden=%q", contextAccessorPos, contextVerifierPos, forbiddenStrictCall)
	}
	implementationRaw, err := os.ReadFile(filepath.Join(runtimeDir, "implementation_support.go"))
	if err != nil {
		t.Fatal(err)
	}
	forbiddenLiterals := []string{"profile-hash-canary", "policy-hash-canary", "capability-canary", "suite-canary", "%x", "%q", "%s", "%v", "%d"}
	for _, production := range []struct {
		name string
		raw  []byte
	}{{"handshake.go", handshakeRaw}, {"implementation_support.go", implementationRaw}} {
		for _, forbidden := range forbiddenLiterals {
			if bytes.Contains(production.raw, []byte(forbidden)) {
				t.Fatalf("%s strict error path contains rejected operand/canary %q", production.name, forbidden)
			}
		}
	}
	implementationAST, err := parser.ParseFile(token.NewFileSet(), filepath.Join(runtimeDir, "implementation_support.go"), implementationRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, production := range []struct {
		name string
		file *ast.File
	}{{"handshake.go", parsed}, {"implementation_support.go", implementationAST}} {
		if err := validateErrorConstructionV1(production.file); err != nil {
			t.Fatalf("%s dynamic error construction: %v", production.name, err)
		}
		literalViolation := ""
		ast.Inspect(production.file, func(node ast.Node) bool {
			expr, ok := node.(ast.Expr)
			if !ok {
				return true
			}
			text, ok := literalStringV1(expr)
			if !ok {
				return true
			}
			for _, forbidden := range forbiddenLiterals {
				if strings.Contains(text, forbidden) {
					literalViolation = forbidden
					return false
				}
			}
			return true
		})
		if literalViolation != "" {
			t.Fatalf("%s string-literal fragments contain rejected operand/canary %q", production.name, literalViolation)
		}
	}
	forbiddenPreflightCall := ""
	ast.Inspect(implementationAST, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := callName(call)
		if name == "DeriveKeyScheduleV1" || strings.Contains(strings.ToLower(name), "transfer") {
			forbiddenPreflightCall = name
		}
		return true
	})
	if forbiddenPreflightCall != "" {
		t.Fatalf("support/authorization preflight contains forbidden key/transfer call %q", forbiddenPreflightCall)
	}
	runtimeEntries, err := os.ReadDir(runtimeDir)
	if err != nil {
		t.Fatal(err)
	}
	runtimeProductionFiles := map[string]*ast.File{}
	for _, entry := range runtimeEntries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		path := filepath.Join(runtimeDir, entry.Name())
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		runtimeProductionFiles[path] = file
	}
	if _, _, err := validateRuntimePackageSignaturesV1(runtimeProductionFiles); err != nil {
		t.Fatal(err)
	}

	for _, root := range []string{filepath.Join(runtimeDir, "..", "protocol"), filepath.Join(runtimeDir, "..", "crypto")} {
		err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
			if err != nil {
				return err
			}
			if info.IsDir() || !strings.HasSuffix(path, ".go") {
				return nil
			}
			file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if err != nil {
				return err
			}
			var leaked string
			ast.Inspect(file, func(node ast.Node) bool {
				ident, ok := node.(*ast.Ident)
				if ok && (ident.Name == "ClientProfileAuthorizationRegistryV1" || ident.Name == "RelayProfileAuthorizationRegistryV1" || ident.Name == "ImplementationSupportV1") {
					leaked = ident.Name
					return false
				}
				return leaked == ""
			})
			if leaked != "" {
				return fmt.Errorf("strict runtime owner state %s leaked into %s", leaked, path)
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}

	repoRoot := filepath.Clean(filepath.Join(runtimeDir, "..", ".."))
	ownerTypeNames := map[string]bool{
		"ImplementationSupportV1": true, "ClientProfileAuthorizationRegistryV1": true,
		"RelayProfileAuthorizationRegistryV1": true, "ClientProfileAuthorizationEntryV1": true,
		"RelayProfileAuthorizationEntryV1": true,
	}
	allowedOwnerFiles := map[string]bool{
		filepath.Clean(filepath.Join(runtimeDir, "implementation_support.go")):      true,
		filepath.Clean(filepath.Join(runtimeDir, "implementation_support_test.go")): true,
		filepath.Clean(filepath.Join(runtimeDir, "handshake.go")):                   true,
		filepath.Clean(filepath.Join(runtimeDir, "handshake_test.go")):              true,
	}
	labPairFactoryPath := filepath.Clean(filepath.Join(runtimeDir, "lab_pair_factory.go"))
	strictTrueCompositeRoutes := 0
	err = filepath.Walk(repoRoot, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if info.Name() == ".git" || info.Name() == "planning" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		leakedOwnerType := ""
		privateSeamCall := false
		ast.Inspect(file, func(node ast.Node) bool {
			if ident, ok := node.(*ast.Ident); ok {
				labFactoryOwnerInput := filepath.Clean(path) == labPairFactoryPath && (ident.Name == "ClientProfileAuthorizationRegistryV1" || ident.Name == "RelayProfileAuthorizationRegistryV1" || ident.Name == "ClientProfileAuthorizationEntryV1" || ident.Name == "RelayProfileAuthorizationEntryV1")
				if ownerTypeNames[ident.Name] && !allowedOwnerFiles[filepath.Clean(path)] && !labFactoryOwnerInput {
					leakedOwnerType = ident.Name
					return false
				}
			}
			if literal, ok := node.(*ast.BasicLit); ok && literal.Kind == token.STRING && !allowedOwnerFiles[filepath.Clean(path)] {
				text, unquoteErr := strconv.Unquote(literal.Value)
				if unquoteErr == nil {
					for ownerType := range ownerTypeNames {
						if strings.Contains(text, ownerType) {
							leakedOwnerType = ownerType + " (emitted string literal)"
							return false
						}
					}
				}
			}
			if composite, ok := node.(*ast.CompositeLit); ok {
				typeName := ""
				switch typ := composite.Type.(type) {
				case *ast.Ident:
					typeName = typ.Name
				case *ast.SelectorExpr:
					typeName = typ.Sel.Name
				}
				if typeName == "HandshakeRuntime" {
					for _, element := range composite.Elts {
						pair, ok := element.(*ast.KeyValueExpr)
						if !ok {
							continue
						}
						key, keyOK := pair.Key.(*ast.Ident)
						value, valueOK := pair.Value.(*ast.Ident)
						if keyOK && valueOK && key.Name == "strict" && value.Name == "true" {
							if filepath.Clean(path) != filepath.Clean(filepath.Join(runtimeDir, "handshake.go")) {
								leakedOwnerType = "strict=true HandshakeRuntime route"
								return false
							}
							strictTrueCompositeRoutes++
						}
					}
				}
			}
			if assignment, ok := node.(*ast.AssignStmt); ok {
				for i := range assignment.Lhs {
					if i >= len(assignment.Rhs) {
						break
					}
					field := ""
					switch lhs := assignment.Lhs[i].(type) {
					case *ast.Ident:
						field = lhs.Name
					case *ast.SelectorExpr:
						field = lhs.Sel.Name
					}
					value, valueOK := assignment.Rhs[i].(*ast.Ident)
					if field == "strict" && valueOK && value.Name == "true" {
						leakedOwnerType = "strict=true assignment route"
						return false
					}
				}
			}
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			name := callName(call)
			if name == "NewStrictHandshakeRuntimeV1" && len(call.Args) != 4 {
				t.Errorf("strict constructor call in %s has %d operands", path, len(call.Args))
			}
			if name == "newStrictHandshakeRuntimeV1" {
				privateSeamCall = true
			}
			return true
		})
		if leakedOwnerType != "" {
			return fmt.Errorf("strict owner type %s leaked into non-owner path %s (including PairInput/profile/peer/wire/TH/KDF/AAD/restore/configured-pair/codegen/generated/cmd sinks)", leakedOwnerType, path)
		}
		if filepath.Clean(path) == labPairFactoryPath {
			forbiddenPrivateNames := map[string]bool{
				"profileAuthorizationEntryV1": true, "clientProfileAuthorizationEntriesV1": true,
				"relayProfileAuthorizationEntriesV1": true, "validateProfileAuthorizationEntriesV1": true,
				"clientProfileAuthorizationEntryRoleV1": true, "relayProfileAuthorizationEntryRoleV1": true,
				"clientProfileAuthorizationRegistryRoleV1": true, "relayProfileAuthorizationRegistryRoleV1": true,
			}
			privateFinding := ""
			ast.Inspect(file, func(node ast.Node) bool {
				switch value := node.(type) {
				case *ast.Ident:
					if forbiddenPrivateNames[value.Name] || value.Name == "entries" {
						privateFinding = value.Name
						return false
					}
				case *ast.SelectorExpr:
					if value.Sel.Name == "entries" {
						privateFinding = "entries selector"
						return false
					}
				}
				return true
			})
			if privateFinding != "" {
				return fmt.Errorf("runtime lab pair factory accessed private registry representation %s", privateFinding)
			}
			var factory *ast.FuncDecl
			for _, declaration := range file.Decls {
				candidate, ok := declaration.(*ast.FuncDecl)
				if ok && candidate.Name.Name == "NewRuntimeLabEndpointPairV1" {
					factory = candidate
					break
				}
			}
			if factory == nil {
				return errors.New("runtime lab pair factory declaration missing")
			}
			registryNames := map[string]bool{"clientRegistry": true, "relayRegistry": true}
			registryUses := map[string]int{"clientRegistry": 0, "relayRegistry": 0}
			registryTypeUses := map[string]int{"ClientProfileAuthorizationRegistryV1": 0, "RelayProfileAuthorizationRegistryV1": 0}
			registryConstructorCalls := map[string]int{"NewClientProfileAuthorizationRegistryV1": 0, "NewRelayProfileAuthorizationRegistryV1": 0}
			strictCalls := 0
			invalidRegistryUse := ""
			ast.Inspect(factory, func(node ast.Node) bool {
				if ident, ok := node.(*ast.Ident); ok {
					if _, tracked := registryUses[ident.Name]; tracked {
						registryUses[ident.Name]++
					}
					if _, tracked := registryTypeUses[ident.Name]; tracked {
						registryTypeUses[ident.Name]++
					}
				}
				call, ok := node.(*ast.CallExpr)
				if ok {
					if _, tracked := registryConstructorCalls[callName(call)]; tracked {
						registryConstructorCalls[callName(call)]++
					}
				}
				if !ok || callName(call) != "NewStrictHandshakeRuntimeV1" {
					return true
				}
				strictCalls++
				if len(call.Args) != 4 {
					invalidRegistryUse = "strict constructor arity"
					return false
				}
				for _, argument := range call.Args[2:] {
					ident, ok := argument.(*ast.Ident)
					if !ok || !registryNames[ident.Name] {
						invalidRegistryUse = "registry is not a direct local strict-constructor operand"
						return false
					}
				}
				return true
			})
			if invalidRegistryUse != "" || strictCalls != 2 || registryUses["clientRegistry"] != 3 || registryUses["relayRegistry"] != 3 || registryTypeUses["ClientProfileAuthorizationRegistryV1"] != 0 || registryTypeUses["RelayProfileAuthorizationRegistryV1"] != 0 || registryConstructorCalls["NewClientProfileAuthorizationRegistryV1"] != 1 || registryConstructorCalls["NewRelayProfileAuthorizationRegistryV1"] != 1 {
				return fmt.Errorf("runtime lab registry exception invalid: calls=%d registry-uses=%v type-uses=%v constructors=%v finding=%s", strictCalls, registryUses, registryTypeUses, registryConstructorCalls, invalidRegistryUse)
			}
			for _, declaration := range file.Decls {
				other, ok := declaration.(*ast.FuncDecl)
				if !ok || other == factory {
					continue
				}
				containsRegistryType := false
				ast.Inspect(other, func(node ast.Node) bool {
					ident, ok := node.(*ast.Ident)
					if ok && (ident.Name == "ClientProfileAuthorizationRegistryV1" || ident.Name == "RelayProfileAuthorizationRegistryV1") {
						containsRegistryType = true
						return false
					}
					return true
				})
				if containsRegistryType {
					return fmt.Errorf("runtime lab registry exception escaped factory into %s", other.Name.Name)
				}
			}
		}
		if privateSeamCall && filepath.Clean(path) != filepath.Clean(filepath.Join(runtimeDir, "handshake.go")) && filepath.Clean(path) != filepath.Clean(filepath.Join(runtimeDir, "implementation_support_test.go")) {
			return fmt.Errorf("private strict support/entropy seam called from %s", path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if strictTrueCompositeRoutes != 1 {
		t.Fatalf("strict=true HandshakeRuntime composite routes=%d want=1", strictTrueCompositeRoutes)
	}
}
