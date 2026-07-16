// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

var policyCoveringArraySeedsV1 = func() []int64 {
	seeds := make([]int64, len(generatedProfileParityPinsV1))
	for i, row := range generatedProfileParityPinsV1 {
		seeds[i] = row.seed
	}
	return seeds
}()

func independentPolicyMatrixTupleV1(policy ir.SecurityPolicy) policyMatrixTupleV1 {
	values := []string{policy.TranscriptMode, policy.NonceMode, policy.ReplayPolicy, policy.DowngradePolicy,
		policy.CapabilityNegotiationPolicy, policy.ProfileCompatibilityPolicy, policy.KeyRotationPolicy,
		policy.ConfigValidationPolicy, policy.SecureEnvelopeMode}
	return policyMatrixTupleV1{Transcript: values[0], Nonce: values[1], Replay: values[2], Downgrade: values[3],
		Capability: values[4], Compatibility: values[5], Rotation: values[6], Config: values[7], Envelope: values[8],
		ReplayWindow: []int{policy.ReplayWindowSize, policy.MaxSessionMessages, policy.MaxKeyLifetimeMessages}[0],
		MaxSession:   policy.MaxSessionMessages, MaxKey: policy.MaxKeyLifetimeMessages}
}

func TestRuntimeLabExecutorClassifierPolicyGuardV1(t *testing.T) {
	raw, err := os.ReadFile("lab_executor.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "lab_executor.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	exported := map[string]bool{}
	for _, decl := range file.Decls {
		switch value := decl.(type) {
		case *ast.FuncDecl:
			if ast.IsExported(value.Name.Name) {
				exported[value.Name.Name] = true
				signature := string(raw[value.Type.Pos()-1 : value.Type.End()-1])
				if value.Name.Name != "ExecuteRuntimeLabFaultV1" || !strings.Contains(signature, "labfault.Token") || strings.Contains(signature, "string,") {
					t.Fatalf("invalid exported facade %s %s", value.Name.Name, signature)
				}
			}
		case *ast.GenDecl:
			for _, spec := range value.Specs {
				if typed, ok := spec.(*ast.TypeSpec); ok && ast.IsExported(typed.Name.Name) {
					exported[typed.Name.Name] = true
				}
			}
		}
	}
	if len(exported) != 2 || !exported["ExecuteRuntimeLabFaultV1"] || !exported["RuntimeLabFaultObservationV1"] {
		t.Fatalf("exported facade surface=%v", exported)
	}
	text := string(raw)
	frozen := map[string]bool{"reused_nonce": true, "accepts_replay": true, "runtime_accepts_replay": true, "runtime_no_state_validation": true, "secret_trace_leak": true, "runtime_leaks_secret_trace": true, "runtime_leaks_payload_trace": true, "runtime_ignores_backpressure": true, "runtime_padding_only_diversity": true}
	classifierCalls := 0
	var classifier *ast.FuncDecl
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if ok && fn.Name.Name == "classifyRuntimeLabFaultV1" {
			classifier = fn
		}
	}
	if classifier == nil || classifier.Type.Results == nil || len(classifier.Type.Results.List) != 2 {
		t.Fatal("missing/private classifier result shape")
	}
	for _, statement := range classifier.Body.List {
		item, ok := statement.(*ast.IfStmt)
		if !ok {
			continue
		}
		assign, ok := item.Init.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 2 || len(assign.Rhs) != 1 {
			t.Fatal("classifier call not local assignment")
		}
		call, ok := assign.Rhs[0].(*ast.CallExpr)
		if !ok {
			t.Fatal("classifier assignment is not call")
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || selector.Sel.Name != "NewTokenV1" || len(call.Args) != 1 {
			t.Fatal("classifier call shape")
		}
		literal, ok := call.Args[0].(*ast.BasicLit)
		if !ok || literal.Kind != token.STRING {
			t.Fatal("classifier arg not direct string literal")
		}
		name, err := strconv.Unquote(literal.Value)
		if err != nil || !frozen[name] {
			t.Fatalf("classifier name=%q", name)
		}
		delete(frozen, name)
		classifierCalls++
		left := assign.Lhs[0].(*ast.Ident).Name
		uses := 0
		ast.Inspect(item, func(node ast.Node) bool {
			if id, ok := node.(*ast.Ident); ok && id.Name == left {
				uses++
			}
			return true
		})
		if uses != 2 {
			t.Fatalf("expected token local %s uses=%d", left, uses)
		}
		condition, ok := item.Cond.(*ast.BinaryExpr)
		if !ok || condition.Op != token.EQL {
			t.Fatal("classifier does not use equality")
		}
	}
	if classifierCalls != 9 || len(frozen) != 0 {
		t.Fatalf("classifier calls=%d missing=%v", classifierCalls, frozen)
	}
	files, _ := filepath.Glob("*.go")
	ownerAllow := map[string]map[string]map[string]bool{
		"protected_channel.go": {"newStrictProtectedChannelWithLabFaultV1": {"reused_nonce": true, "accepts_replay": true, "runtime_accepts_replay": true, "runtime_no_state_validation": true}},
		"trace.go":             {"newRuntimeTraceFaultObservationV1": {"secret_trace_leak": true, "runtime_leaks_secret_trace": true, "runtime_leaks_payload_trace": true}},
		"link.go":              {"newMemoryLinkWithLabFaultV1": {"runtime_ignores_backpressure": true}},
		"loopback_pair.go":     {"newInProcessProtectedRelayWithLabFaultV1": {"runtime_padding_only_diversity": true}},
	}
	totalCalls := classifierCalls
	ownerHashes := map[string]string{"protected_channel.go": "4523d20b60fb9df4533c284386d359073de9c2b5745166b842ae42424aabded0", "trace.go": "4d53711a2c0a9d834b7c5024bc9e076e6b70215e19c496c1a3b3a52ae1dc9844", "link.go": "dae7aeb583ae7ec13433a1dc4ead2c2d20ab3d1e6713e82f1465070f913e0e02", "loopback_pair.go": "7f924e9883b5607be2a6738c51938e0fbdefc3d285dfa67a25bf62cae351e3b6"}
	for _, path := range files {
		if path == "lab_executor.go" || strings.HasSuffix(path, "_test.go") {
			continue
		}
		otherRaw, _ := os.ReadFile(path)
		if want, ok := ownerHashes[path]; ok && fmt.Sprintf("%x", sha256.Sum256(otherRaw)) != want {
			t.Fatalf("WO-054 owner changed: %s", path)
		}
		other, _ := parser.ParseFile(token.NewFileSet(), path, otherRaw, 0)
		for _, decl := range other.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				call, ok := node.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "NewTokenV1" {
					return true
				}
				if len(call.Args) != 1 {
					t.Fatalf("mint arity %s::%s", path, fn.Name.Name)
				}
				literal, ok := call.Args[0].(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					t.Fatalf("variable mint arg %s::%s", path, fn.Name.Name)
				}
				name, _ := strconv.Unquote(literal.Value)
				names := ownerAllow[path][fn.Name.Name]
				if names == nil || !names[name] {
					t.Fatalf("unauthorized owner mint %s::%s(%s)", path, fn.Name.Name, name)
				}
				delete(names, name)
				totalCalls++
				return true
			})
		}
	}
	if totalCalls != 18 {
		t.Fatalf("root runtime mint total=%d want 18", totalCalls)
	}
	for path, functions := range ownerAllow {
		for fn, names := range functions {
			if len(names) != 0 {
				t.Fatalf("owner mint omissions %s::%s=%v", path, fn, names)
			}
		}
	}
	mapping := map[string][2]string{"runtimeLabReusedNonceV1": {"sealClientApplicationV1", "nonce"}, "runtimeLabAcceptsReplayV1": {"openClientApplicationV1", "security_replay"}, "runtimeLabAcceptsRuntimeReplayV1": {"retryClientApplicationV1", "runtime_replay"}, "runtimeLabNoStateValidationV1": {"openRelayApplicationV1", "state"}, "runtimeLabSecretTraceV1": {"newRuntimeTraceFaultObservationV1", "trace"}, "runtimeLabRuntimeSecretTraceV1": {"newRuntimeTraceFaultObservationV1", "trace"}, "runtimeLabRuntimePayloadTraceV1": {"newRuntimeTraceFaultObservationV1", "trace"}, "runtimeLabIgnoresBackpressureV1": {"newMemoryLinkWithLabFaultV1", "backpressure"}, "runtimeLabPaddingDiversityV1": {"newInProcessProtectedRelayWithLabFaultV1", "padding"}}
	ast.Inspect(file, func(node ast.Node) bool {
		if statement, ok := node.(*ast.IfStmt); ok {
			segment := string(raw[statement.Pos()-1 : statement.End()-1])
			if strings.Contains(segment, "mode == runtimeLabPaddingDiversityV1") {
				want := mapping["runtimeLabPaddingDiversityV1"]
				if !strings.Contains(segment, want[0]) || !strings.Contains(segment, "\""+want[1]+"\"") {
					t.Fatal("padding dispatch mismatch")
				}
				delete(mapping, "runtimeLabPaddingDiversityV1")
			}
		}
		clause, ok := node.(*ast.CaseClause)
		if !ok {
			return true
		}
		segment := string(raw[clause.Pos()-1 : clause.End()-1])
		for _, expr := range clause.List {
			if id, ok := expr.(*ast.Ident); ok {
				if want, exists := mapping[id.Name]; exists {
					if !strings.Contains(segment, want[0]) || !strings.Contains(segment, "\""+want[1]+"\"") {
						t.Fatalf("mode %s dispatch mismatch", id.Name)
					}
					delete(mapping, id.Name)
				}
			}
		}
		return true
	})
	if len(mapping) != 0 {
		t.Fatalf("unmapped modes=%v", mapping)
	}
	for _, forbidden := range []string{"json.", "os.", "net.", "log.", "fmt.", "WriteFile", "Marshal", "testkit", "Token "} {
		if forbidden != "Token " && strings.Contains(text, forbidden) {
			t.Fatalf("facade forbidden reach %s", forbidden)
		}
	}
}

func TestRuntimeLabEndpointPairPolicyGuardV1(t *testing.T) {
	raw, err := os.ReadFile("lab_pair_factory.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "lab_pair_factory.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	text := string(raw)
	for _, forbidden := range []string{"os.", "net.", "json.", "log.", "fmt.", "WriteFile", "Marshal", "Dial", "Listen", "ClientAuthenticatedEndpointV1{", "RelayAuthenticatedEndpointV1{", ".state", "newStrictHandshakeRuntimeV1", "newAuthenticatedChannelPairV1"} {
		if strings.Contains(text, forbidden) {
			t.Fatalf("factory file reaches forbidden constructor, field, or sink %q", forbidden)
		}
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewRuntimeLabEndpointPairV1" {
			continue
		}
		found = true
		if fn.Type.Params == nil || len(fn.Type.Params.List) != 1 || len(fn.Type.Params.List[0].Names) != 1 || fn.Type.Params.List[0].Names[0].Name != "seed" {
			t.Fatalf("factory parameter shape changed")
		}
		parameter, ok := fn.Type.Params.List[0].Type.(*ast.Ident)
		if !ok || parameter.Name != "int64" || fn.Type.Results == nil || len(fn.Type.Results.List) != 3 {
			t.Fatalf("factory parameter or result cardinality changed")
		}
		wantResults := []string{"ClientAuthenticatedEndpointV1", "RelayAuthenticatedEndpointV1"}
		for i, want := range wantResults {
			pointer, ok := fn.Type.Results.List[i].Type.(*ast.StarExpr)
			if !ok {
				t.Fatalf("factory result %d is not a pointer", i)
			}
			name, ok := pointer.X.(*ast.Ident)
			if !ok || name.Name != want {
				t.Fatalf("factory result %d=%T want *%s", i, pointer.X, want)
			}
		}
		errorResult, ok := fn.Type.Results.List[2].Type.(*ast.Ident)
		if !ok || errorResult.Name != "error" {
			t.Fatalf("factory error result changed")
		}
		body := string(raw[fn.Body.Pos()-1 : fn.Body.End()-1])
		strictAt := strings.Index(body, "NewStrictHandshakeRuntimeV1")
		pairAt := strings.Index(body, "NewAuthenticatedChannelPair")
		if strictAt < 0 || pairAt < 0 || strictAt >= pairAt {
			t.Fatalf("factory call chain positions strict=%d pair=%d", strictAt, pairAt)
		}
		for _, forbidden := range []string{"newEndpointLifecycleV1", "pairConstructV1", "os.", "net.", "json.", "env"} {
			if strings.Contains(body, forbidden) {
				t.Fatalf("factory forbidden path %s", forbidden)
			}
		}
	}
	if !found {
		t.Fatal("factory missing")
	}
	root := filepath.Join("..", "..")
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			if entry.Name() == ".git" || entry.Name() == "planning" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.Contains(filepath.ToSlash(path), "/internal/runtime/") {
			return nil
		}
		content, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(content), "NewRuntimeLabEndpointPairV1") {
			rel, relErr := filepath.Rel(root, path)
			if relErr != nil {
				return relErr
			}
			if filepath.ToSlash(rel) != "internal/lab/runtimeadversary/runner.go" {
				t.Errorf("runtime lab pair factory has non-runtime caller %s", path)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func tupleFactorsV1(tuple policyMatrixTupleV1) []string {
	return []string{tuple.Transcript, tuple.Nonce, tuple.Replay, fmt.Sprint(tuple.ReplayWindow), tuple.Downgrade,
		tuple.Capability, tuple.Compatibility, tuple.Rotation, tuple.Config, tuple.Envelope, fmt.Sprint(tuple.MaxSession), fmt.Sprint(tuple.MaxKey)}
}

func TestInterpretedPolicyParityCoveringArrayV1(t *testing.T) {
	seeds := policyCoveringArraySeedsV1
	seedParts := make([]string, len(seeds))
	for i, seed := range seeds {
		if i > 0 && seeds[i-1] >= seed {
			t.Fatalf("seeds not strictly sorted/unique at %d", i)
		}
		seedParts[i] = strconv.FormatInt(seed, 10)
	}
	seedText := strings.Join(seedParts, ",")
	if seedText != "1,2,3,4,6,7,19,25,26,27,35,40,42,58,66,69,78,80,91,94,102,107,110,123,135,171,174,202,223" {
		t.Fatalf("canonical seed CSV=%q", seedText)
	}
	if got := fmt.Sprintf("%x", sha256.Sum256([]byte(seedText))); got != "2577a6114b5df02b44d43ae02fd80fa08f8c593c2449f79a46f84aa63fa5efaa" {
		t.Fatalf("seed CSV hash=%s", got)
	}
	domains := make([]map[string]struct{}, 12)
	selectedPairs := make(map[string]struct{})
	selected := make(map[int64]struct{}, len(seeds))
	for _, seed := range seeds {
		selected[seed] = struct{}{}
	}
	for seed := int64(1); seed <= 256; seed++ {
		profile, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		first := policyMatrixTupleFromPolicyV1(profile.Security)
		floor := append([]string(nil), profile.Compatibility.RequiredCapabilities...)
		if len(floor) == 0 {
			floor = []string{ir.SecurityCapabilities()[0]}
		}
		effective, err := ir.BuildEffectiveSecurityPolicy(profile, floor, floor, floor)
		if err != nil {
			t.Fatalf("seed %d effective owner: %v", seed, err)
		}
		second := policyMatrixTupleV1{Transcript: effective.TranscriptMode, Nonce: effective.NonceMode, Replay: effective.ReplayPolicy,
			Downgrade: effective.DowngradePolicy, Capability: effective.CapabilityNegotiationPolicy, Compatibility: effective.ProfileCompatibilityPolicy,
			Rotation: effective.KeyRotationPolicy, Config: effective.ConfigValidationPolicy, Envelope: effective.SecureEnvelopeMode,
			ReplayWindow: effective.ReplayWindowSize, MaxSession: effective.MaxSessionMessages, MaxKey: effective.MaxKeyLifetimeMessages}
		if first != second {
			t.Fatalf("seed %d independent tuple mismatch", seed)
		}
		factors := tupleFactorsV1(first)
		for i, value := range factors {
			if domains[i] == nil {
				domains[i] = make(map[string]struct{})
			}
			domains[i][value] = struct{}{}
		}
		if _, ok := selected[seed]; ok {
			for i := 0; i < len(factors); i++ {
				for j := i + 1; j < len(factors); j++ {
					selectedPairs[fmt.Sprintf("%d=%s|%d=%s", i, factors[i], j, factors[j])] = struct{}{}
				}
			}
		}
	}
	universe := 0
	for i := 0; i < len(domains); i++ {
		for j := i + 1; j < len(domains); j++ {
			universe += len(domains[i]) * len(domains[j])
		}
	}
	if universe != 732 || len(selectedPairs) != universe {
		t.Fatalf("pairwise coverage=%d/%d want 732/732", len(selectedPairs), universe)
	}
	if len(selected) != 29 || reflect.DeepEqual(seeds, []int64{1, 2, 3, 4, 5, 6, 7, 8}) {
		t.Fatal("covering array substituted or drifted")
	}
}

func TestPolicyMatrixOwnerWitnessLiteralCompleteV1(t *testing.T) {
	witnesses := advancedPolicyWitnessesV1()
	for name, values := range map[string]map[string]string{"nonce": witnesses.nonce, "replay": witnesses.replay, "compatibility": witnesses.profile, "rotation": witnesses.rotation, "config": witnesses.config, "envelope": witnesses.envelope} {
		for value, owner := range values {
			if value == "" || owner == "" || !strings.Contains(owner, "_test.go:Test") {
				t.Fatalf("%s witness %q owner=%q", name, value, owner)
			}
		}
	}
	for _, seed := range policyCoveringArraySeedsV1 {
		profile, err := compiler.Generate(seed)
		if err != nil || ir.Validate(profile) != nil {
			t.Fatalf("seed %d owner admission failed: generate=%v validate=%v", seed, err, ir.Validate(profile))
		}
	}
	reviewedOwner := "internal/runtime/implementation_support_test.go:Test" + "Implementation" + "SupportV1ReviewedDefaultsAndCarrierHashWitness"
	owners := map[string]string{
		"canonical_v1": reviewedOwner, "canonical_with_capabilities_v1": reviewedOwner,
		"canonical_with_carrier_binding_v1": reviewedOwner, "canonical_full_binding_v1": reviewedOwner,
		"kdf_hkdf_sha256": reviewedOwner, "aead_aes_256_gcm": reviewedOwner, "mac_hmac_sha256": reviewedOwner,
		"strict_suite_and_capabilities": reviewedOwner, "strict_capabilities": reviewedOwner, "suite_bound_transcript": reviewedOwner,
		"intersection_with_required": reviewedOwner, "profile_declared_required": reviewedOwner, "strict_required": reviewedOwner,
	}
	for _, values := range []map[string]string{witnesses.nonce, witnesses.replay, witnesses.profile, witnesses.rotation, witnesses.config, witnesses.envelope} {
		for value, owner := range values {
			owners[value] = owner
		}
	}
	for value, owner := range owners {
		parts := strings.Split(owner, ":")
		if len(parts) != 2 {
			t.Fatalf("literal %q owner=%q", value, owner)
		}
		file, err := parser.ParseFile(token.NewFileSet(), filepath.Join("..", "..", filepath.FromSlash(parts[0])), nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		found := false
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Name.Name != parts[1] {
				continue
			}
			ast.Inspect(function.Body, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if ok && literal.Kind == token.STRING {
					decoded, _ := strconv.Unquote(literal.Value)
					found = found || decoded == value
				}
				return !found
			})
		}
		if !found {
			t.Fatalf("literal %q not exercised by exact owner %q", value, owner)
		}
	}
}

func TestExactSentinelParityV1(t *testing.T) {
	for err, want := range map[error]string{
		ErrPolicyInvalid: "policy_invalid", ErrProfileIncompatible: "profile_incompatible",
		ErrConfigInvalid: "config_invalid", errConfigProfileMismatchV1: "config_profile_mismatch",
		ErrDowngradeRejected: "downgrade_rejected", ErrCapabilityRejected: "capability_rejected",
		ErrFullBindingInvalid: "full_binding_invalid",
	} {
		if err.Error() != want || strings.ContainsAny(err.Error(), " :") {
			t.Fatalf("sentinel=%q want operand-free %q", err, want)
		}
	}
}

func TestLegacyTraceResearchOnlyV1(t *testing.T) {
	owners := map[string][]string{
		"trace.go": {"RuntimeDiagnosticEventV1", "LinkDiagnosticEventV1", "SecureDiagnosticEventV1"},
		filepath.Join("..", "crypto", "security", "trace.go"): {"SecureEnvelopeDiagnosticV1"},
		filepath.Join("..", "audit", "runtime.go"):            {"RuntimeTraceHygieneGate"},
		filepath.Join("..", "audit", "security.go"):           {"SecuritySecretTraceHygieneGate"},
	}
	for path, functions := range owners {
		wanted := make(map[string]bool, len(functions))
		for _, name := range functions {
			wanted[name] = true
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		seen := map[string]bool{}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || function.Body == nil || !wanted[function.Name.Name] {
				continue
			}
			seen[function.Name.Name] = true
			ast.Inspect(function.Body, func(node ast.Node) bool {
				selector, ok := node.(*ast.SelectorExpr)
				if ok && (selector.Sel.Name == "Event" || selector.Sel.Name == "Recorder" || selector.Sel.Name == "SecureEnvelopeTrace") {
					t.Errorf("strict diagnostic %s:%s reaches legacy %s", path, function.Name.Name, selector.Sel.Name)
				}
				return true
			})
		}
		if len(seen) != len(functions) {
			t.Fatalf("strict diagnostic owners in %s=%v want=%v", path, seen, functions)
		}
	}
}

func TestDiagnosticAuditConsumptionV1(t *testing.T) {
	checks := map[string]string{
		filepath.Join("..", "audit", "runtime.go"):  "ValidateDiagnosticEventV1",
		filepath.Join("..", "audit", "security.go"): "SecureEnvelopeDiagnosticV1",
	}
	for path, required := range checks {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		text := string(raw)
		if !strings.Contains(text, required) || strings.Contains(text, "SecureEnvelopeTrace(ctx, env)") {
			t.Fatalf("audit %s does not exclusively consume strict diagnostics", path)
		}
	}
}

func TestPolicyMatrixAdmissionOnlyExecutedLedgerV1(t *testing.T) {
	type row struct {
		field, validValue, ownerEntrypoint, mutatedOperand, invalidValueOrOperation string
		sentinelIdentity                                                            error
		exactString, precedenceContext                                              string
		mutate                                                                      func(*ir.EffectiveSecurityPolicy, string)
	}
	setText := func(field string) func(*ir.EffectiveSecurityPolicy, string) {
		return func(policy *ir.EffectiveSecurityPolicy, invalid string) {
			reflect.ValueOf(policy).Elem().FieldByName(field).SetString(invalid)
		}
	}
	setInt := func(field string) func(*ir.EffectiveSecurityPolicy, string) {
		return func(policy *ir.EffectiveSecurityPolicy, invalid string) {
			value, err := strconv.Atoi(invalid)
			if err != nil {
				panic(err)
			}
			reflect.ValueOf(policy).Elem().FieldByName(field).SetInt(int64(value))
		}
	}
	text := func(field, value string) row {
		return row{field, value, "classifyStrictPolicyMismatchV1", "SelectedPolicy." + field,
			"wo050_unknown_" + strings.ToLower(field), ErrPolicyInvalid, ErrPolicyInvalid.Error(),
			"policy admission precedes transcript, downgrade, capability, compatibility, config, and record owners", setText(field)}
	}
	number := func(field, value, invalid string) row {
		return row{field, value, "classifyStrictPolicyMismatchV1", "SelectedPolicy." + field, invalid,
			ErrPolicyInvalid, ErrPolicyInvalid.Error(), "malformed/out-of-bounds policy admission is first", setInt(field)}
	}
	rows := []row{
		text("TranscriptMode", "canonical_v1"), text("TranscriptMode", "canonical_with_capabilities_v1"), text("TranscriptMode", "canonical_with_carrier_binding_v1"), text("TranscriptMode", "canonical_full_binding_v1"),
		text("KDFSuite", "kdf_hkdf_sha256"), text("AEADSuite", "aead_aes_256_gcm"), text("MACSuite", "mac_hmac_sha256"),
		text("NonceMode", "counter_xor_base"), text("NonceMode", "counter_append_base"), text("NonceMode", "directional_counter"), text("NonceMode", "stream_partitioned_counter"),
		text("ReplayPolicy", "ordered_only"), text("ReplayPolicy", "bounded_reorder"), text("ReplayPolicy", "windowed_replay"),
		number("ReplayWindowSize", "2", "1"), number("ReplayWindowSize", "4096", "4097"),
		text("DowngradePolicy", "strict_suite_and_capabilities"), text("DowngradePolicy", "strict_capabilities"), text("DowngradePolicy", "suite_bound_transcript"),
		text("CapabilityNegotiationPolicy", "strict_required"), text("CapabilityNegotiationPolicy", "intersection_with_required"), text("CapabilityNegotiationPolicy", "profile_declared_required"),
		text("ProfileCompatibilityPolicy", "strict_schema"), text("ProfileCompatibilityPolicy", "schema_and_feature"), text("ProfileCompatibilityPolicy", "full_policy_binding"),
		text("ConfigValidationPolicy", "strict_required"), text("ConfigValidationPolicy", "strict_with_redaction"), text("ConfigValidationPolicy", "strict_profile_bound"),
		text("SecureEnvelopeMode", "metadata_authenticated"), text("SecureEnvelopeMode", "synthetic_aead_test"), text("SecureEnvelopeMode", "full_context_bound_envelope"),
		text("KeyRotationPolicy", "session_only"), text("KeyRotationPolicy", "message_lifetime_bound"), text("KeyRotationPolicy", "profile_lifetime_bound"),
		number("MaxSessionMessages", "1", "0"), number("MaxSessionMessages", "16777216", "16777217"),
		number("MaxKeyLifetimeMessages", "1", "0"), number("MaxKeyLifetimeMessages", "16777216", "16777217"),
	}
	counts := make(map[string]int)
	for _, item := range rows {
		t.Run(item.field+"/"+item.validValue, func(t *testing.T) {
			profile, err := compiler.Generate(1)
			if err != nil {
				t.Fatal(err)
			}
			field := reflect.ValueOf(&profile.Security).Elem().FieldByName(item.field)
			if field.Kind() == reflect.String {
				field.SetString(item.validValue)
			} else {
				value, _ := strconv.Atoi(item.validValue)
				field.SetInt(int64(value))
			}
			if item.field == "ReplayWindowSize" && profile.Security.ReplayWindowSize > profile.Compatibility.MaxReplayWindow {
				profile.Compatibility.MaxReplayWindow = profile.Security.ReplayWindowSize
			}
			if item.field == "MaxKeyLifetimeMessages" && profile.Security.MaxKeyLifetimeMessages > profile.Security.MaxSessionMessages {
				profile.Security.MaxSessionMessages = profile.Security.MaxKeyLifetimeMessages
			} else if profile.Security.MaxKeyLifetimeMessages > profile.Security.MaxSessionMessages {
				profile.Security.MaxKeyLifetimeMessages = profile.Security.MaxSessionMessages
			}
			profile.GenerationHash = ""
			profile.GenerationHash, err = ir.CanonicalHash(profile)
			if err != nil {
				t.Fatal(err)
			}
			floor := append([]string(nil), profile.Compatibility.RequiredCapabilities...)
			valid, err := ir.BuildEffectiveSecurityPolicy(profile, floor, floor, floor)
			if err != nil {
				t.Fatalf("valid reached witness %s=%s: %v", item.field, item.validValue, err)
			}
			peer := auth.PeerParameters{OfferPolicy: valid, FloorPolicy: valid}
			input := auth.FirstContactInput{Client: peer, Server: peer, SelectedPolicy: valid}
			if !strictPoliciesValidV1(input) {
				t.Fatal("valid reached witness did not reach runtime owner")
			}
			item.mutate(&input.SelectedPolicy, item.invalidValueOrOperation)
			err = classifyStrictPolicyMismatchV1(input)
			if err == nil || !errors.Is(err, item.sentinelIdentity) || err.Error() != item.exactString {
				t.Fatalf("%s %s mutation %s=%s precedence=%s: error=%v", item.ownerEntrypoint, item.field, item.mutatedOperand, item.invalidValueOrOperation, item.precedenceContext, err)
			}
			counts[item.field+"\x00"+item.validValue]++
		})
	}
	if len(counts) != len(rows) {
		t.Fatalf("executed rows=%d want %d", len(counts), len(rows))
	}
	for key, count := range counts {
		if count != 1 {
			t.Fatalf("row %q executions=%d", key, count)
		}
	}
}

// TestPolicyMatrixCausalOwnerRegistryCompleteV1 ties every contract-ledger case
// to exactly one owner-local causal test. The owner test contains the case ID and
// executes the production owner; this meta-test only verifies the partition.
func TestPolicyMatrixCausalOwnerRegistryCompleteV1(t *testing.T) {
	type group struct {
		file, function, sentinel string
		cases                    []string
	}
	groups := []group{
		{"internal/crypto/auth/handshake_test.go", "TestHandshakeFourTranscriptModesExactOrderedVectorsAndTamper", "ErrHandshake", []string{"transcript/canonical_v1", "transcript/canonical_with_capabilities_v1", "transcript/canonical_with_carrier_binding_v1", "transcript/canonical_full_binding_v1", "suite/aead_aes_256_gcm", "suite/mac_hmac_sha256"}},
		{"internal/crypto/security/keyschedule_test.go", "TestPolicyMatrixOwnerWitnessLiteralKeyScheduleSentinelV1", "ErrKDFInvalid", []string{"suite/kdf_hkdf_sha256"}},
		{"internal/crypto/security/nonce_v1_test.go", "TestPolicyMatrixOwnerWitnessLiteralNonceSentinelV1", "ErrNonce", []string{"nonce/counter_xor_base", "nonce/counter_append_base", "nonce/directional_counter", "nonce/stream_partitioned_counter"}},
		{"internal/crypto/security/replay_v1_test.go", "TestPolicyMatrixCoveringArrayOwnerWitnessReplaySentinelV1", "ErrReplay", []string{"replay/ordered_only", "replay/bounded_reorder", "replay/windowed_replay", "replay_window/2", "replay_window/4096"}},
		{"internal/runtime/implementation_support_test.go", "TestSupportPreflightV1CausalGroupedRuntimeSupportLedger", "runtime_support_sentinels", []string{"downgrade/strict_suite_and_capabilities", "downgrade/strict_capabilities", "downgrade/suite_bound_transcript", "capability/strict_required", "capability/intersection_with_required", "capability/profile_declared_required", "compatibility/strict_schema", "compatibility/schema_and_feature", "compatibility/full_policy_binding"}},
		{"internal/runtime/policy_enforcement_test.go", "TestPolicyMatrixConfigOwnerCausalSentinelV1", "ErrConfigInvalid", []string{"config/strict_required", "config/strict_with_redaction", "config/strict_profile_bound"}},
		{"internal/crypto/security/replay_policy_test.go", "TestPolicyMatrixEnvelopeClassOwnerWitnessAuthenticatedContextV1", "envelope_sentinels", []string{"envelope/metadata_authenticated", "envelope/synthetic_aead_test", "envelope/full_context_bound_envelope"}},
		{"internal/runtime/protected_channel_test.go", "TestPolicyMatrixPrivateEntrypointCausalBypassSentinelV1", "ErrKeyLifetimeExhausted", []string{"rotation/session_only", "rotation/message_lifetime_bound", "rotation/profile_lifetime_bound", "max_session/1", "max_session/16777216", "max_key/1", "max_key/16777216"}},
	}
	want := make(map[string]group)
	for _, owner := range groups {
		for _, id := range owner.cases {
			if _, duplicate := want[id]; duplicate {
				t.Fatalf("case %q claimed twice", id)
			}
			want[id] = owner
		}
	}
	if len(want) != 38 {
		t.Fatalf("causal owner cases=%d want 38", len(want))
	}
	claims := make(map[string]int)
	for id, owner := range want {
		raw, err := os.ReadFile(filepath.Join("..", "..", filepath.FromSlash(owner.file)))
		if err != nil {
			t.Fatal(err)
		}
		file, err := parser.ParseFile(token.NewFileSet(), owner.file, raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		foundFunction, foundID := false, false
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Name.Name != owner.function {
				continue
			}
			foundFunction = true
			hasCausalDispatch := false
			ast.Inspect(fn.Body, func(node ast.Node) bool {
				if assignment, ok := node.(*ast.AssignStmt); ok {
					blank := false
					for _, lhs := range assignment.Lhs {
						if ident, ok := lhs.(*ast.Ident); ok && ident.Name == "_" {
							blank = true
						}
					}
					if blank {
						for _, rhs := range assignment.Rhs {
							ast.Inspect(rhs, func(child ast.Node) bool {
								if lit, ok := child.(*ast.BasicLit); ok && strings.Contains(lit.Value, "pm-owner:") {
									t.Fatalf("causal owner %s parks owner ID in blank assignment", owner.function)
								}
								return true
							})
						}
					}
				}
				if call, ok := node.(*ast.CallExpr); ok {
					if selector, ok := call.Fun.(*ast.SelectorExpr); ok && selector.Sel.Name == "Run" {
						hasCausalDispatch = true
					}
				}
				lit, ok := node.(*ast.BasicLit)
				if ok && lit.Kind == token.STRING {
					value, _ := strconv.Unquote(lit.Value)
					if value == "pm-owner:"+id {
						foundID = true
						claims[id]++
					}
				}
				return true
			})
			if !hasCausalDispatch {
				t.Fatalf("case %q owner %s lacks causal subcase dispatch", id, owner.function)
			}
		}
		if !foundFunction || !foundID {
			t.Fatalf("case %q not consumed by causal owner %s:%s sentinel=%s", id, owner.file, owner.function, owner.sentinel)
		}
	}
	for id, count := range claims {
		if count != 1 {
			t.Fatalf("case %q causal claims=%d want 1", id, count)
		}
	}
}

func TestPolicyMatrixConfigOwnerCausalSentinelV1(t *testing.T) {
	type row struct {
		id       string
		value    string
		sentinel error
		mutate   func(*ClientLocalRuntimeControlsV1, *RelayLocalRuntimeControlsV1, *redactionCertificateV1, *redactionCertificateV1)
	}
	rows := []row{
		{"pm-owner:config/strict_required", "strict_required", ErrConfigInvalid, func(_ *ClientLocalRuntimeControlsV1, _ *RelayLocalRuntimeControlsV1, _ *redactionCertificateV1, _ *redactionCertificateV1) {
		}},
		{"pm-owner:config/strict_with_redaction", "strict_with_redaction", ErrConfigInvalid, func(_ *ClientLocalRuntimeControlsV1, _ *RelayLocalRuntimeControlsV1, client, _ *redactionCertificateV1) {
			*client = redactionCertificateV1{}
		}},
		{"pm-owner:config/strict_profile_bound", "strict_profile_bound", errConfigProfileMismatchV1, func(client *ClientLocalRuntimeControlsV1, _ *RelayLocalRuntimeControlsV1, _ *redactionCertificateV1, _ *redactionCertificateV1) {
			client.QueueCeiling--
		}},
	}
	for _, item := range rows {
		t.Run(item.id, func(t *testing.T) {
			client := ClientLocalRuntimeControlsV1{RuntimeID: "client", EventCapacity: 1, QueueCeiling: 8}
			relay := RelayLocalRuntimeControlsV1{RuntimeID: "relay", EventCapacity: 1, QueueCeiling: 8}
			clientCertificate, relayCertificate := reviewedClientImplementationSupportV1.redaction, reviewedRelayImplementationSupportV1.redaction
			if err := validateAdvancedLocalControlsV1(item.value, 8, 8, client, relay, clientCertificate, relayCertificate); err != nil {
				t.Fatalf("valid owner not reached: %v", err)
			}
			if item.value == "strict_required" {
				mutations := 1 // ConfigValidationPolicy only.
				err := validateAdvancedLocalControlsV1("wo050_unknown_config", 8, 8, client, relay, clientCertificate, relayCertificate)
				if mutations != 1 || !errors.Is(err, item.sentinel) || err.Error() != item.sentinel.Error() {
					t.Fatalf("mutations=%d actual owner err=%v want exact %v", mutations, err, item.sentinel)
				}
				return
			}
			beforeClient, beforeRelay, beforeClientCertificate, beforeRelayCertificate := client, relay, clientCertificate, relayCertificate
			item.mutate(&client, &relay, &clientCertificate, &relayCertificate)
			mutations := 0
			if client != beforeClient {
				mutations++
			}
			if relay != beforeRelay {
				mutations++
			}
			if clientCertificate != beforeClientCertificate {
				mutations++
			}
			if relayCertificate != beforeRelayCertificate {
				mutations++
			}
			if mutations != 1 {
				t.Fatalf("mutation cardinality=%d", mutations)
			}
			err := validateAdvancedLocalControlsV1(item.value, 8, 8, client, relay, clientCertificate, relayCertificate)
			if !errors.Is(err, item.sentinel) || err.Error() != item.sentinel.Error() {
				t.Fatalf("actual owner err=%v want exact %v", err, item.sentinel)
			}
		})
	}
}

func TestPolicyMatrixOwnerBypassGuardASTV1(t *testing.T) {
	baseline := map[string]string{
		"internal/runtime/policy_enforcement.go": "bcf6dc27f69bc39cc9a0d541baf0c7b65d46d2d3cea34567ff970dbef7c87317", "internal/runtime/policy_enforcement_test.go": "",
		"internal/runtime/protected_channel.go": "47b571863dd40e18847ce63a4d6939a266331a86e607883b28784eb33af9db62", "internal/runtime/protected_channel_test.go": "3ccca5790b4c8c462784086e209854d8046e978891c65024e3bccd9ebc434554", "internal/runtime/loopback_pair_test.go": "d90b1c14389cc2ad77e0ccc90e5dcbe9168b7b26b4890bd97db85f7216b4d82b",
		"internal/runtime/implementation_support.go": "de3b74090b95fbdf3bbf0b24bcfb61a0460930ca55d88083cb362a3e69378998", "internal/runtime/implementation_support_test.go": "e0d36092a384c142415efda9a7fe01daf404501004963313a01980595621e429",
		"internal/crypto/auth/handshake_test.go": "b55e7f88aa09f292324e654299ffbc920993b9f37695e9c902cd06916b2772fa", "internal/crypto/security/keyschedule_test.go": "527dcb4142571dc79eeb03cf4edadb11f7c142e72f99e9b30434f12bf4857fa7", "internal/crypto/security/nonce_v1_test.go": "62858d1e658cf2ce0eda5e604250885a7caea5de9c6ff6dabd152653b11f3421", "internal/crypto/security/replay_v1_test.go": "c2ba48c70ae64955fb0571ea8c5734e964039961cf2d276c261577bdf033bc91", "internal/crypto/security/replay_policy_test.go": "82df37d61242f3694bc0ce8e6087977009731feae9503079360f7eef409d2ca3", "internal/crypto/security/envelope_v1_test.go": "5e3a84e97c2e06bcdebccb5a063a46fd46c9f4e660f61e4fdaf5cda744473c57",
	}
	if len(baseline) != 13 {
		t.Fatalf("authorized manifest paths=%d want 13", len(baseline))
	}
	manifestPaths := make([]string, 0, len(baseline))
	for path := range baseline {
		manifestPaths = append(manifestPaths, path)
	}
	sort.Strings(manifestPaths)
	preWO050 := []string{
		"go.mod", "internal/codegen/generator_test.go", "internal/codegen/templates.go", "internal/crypto/security/capabilities.go", "internal/crypto/security/compatibility.go", "internal/crypto/security/config.go", "internal/crypto/security/context.go", "internal/crypto/security/envelope.go", "internal/crypto/security/errors.go", "internal/crypto/security/keyschedule.go", "internal/crypto/security/nonce.go", "internal/crypto/security/replay.go", "internal/crypto/security/transcript.go", "internal/lab/runtimeadversary/runner.go", "internal/protocol/framing/codec.go", "internal/protocol/framing/codec_test.go", "internal/protocol/ir/profile.go", "internal/protocol/ir/validate.go", "internal/relay/relay.go", "internal/relay/relay_test.go", "internal/runtime/config.go", "internal/runtime/errors.go", "internal/runtime/harness.go", "internal/runtime/lifecycle.go", "internal/runtime/negotiation.go", "internal/runtime/runtime_test.go", "internal/runtime/secure_channel.go", "internal/testkit/importrules/importrules_test.go",
		"internal/crypto/auth/handshake.go", "internal/crypto/security/authenticated_context.go", "internal/crypto/security/authenticated_context_test.go", "internal/crypto/security/context_identity_test.go", "internal/crypto/security/nonce_uniqueness_test.go", "internal/crypto/security/replay_authentication_test.go", "internal/runtime/application_record_v1.go", "internal/runtime/application_record_v1_test.go", "internal/runtime/authenticated_pair.go", "internal/runtime/authenticated_pair_test.go", "internal/runtime/config_v1_test.go", "internal/runtime/control_record_v1.go", "internal/runtime/control_record_v1_test.go", "internal/runtime/handshake.go", "internal/runtime/handshake_test.go", "internal/runtime/lifecycle_test.go", "internal/runtime/loopback_pair.go", "internal/runtime/policy_test.go", "internal/testkit/mutant/fault.go", "internal/testkit/mutant/fault_test.go",
	}
	allowed := make(map[string]bool, len(preWO050)+len(manifestPaths))
	for _, path := range preWO050 {
		if allowed[path] {
			t.Fatalf("duplicate pre-WO050 path %s", path)
		}
		allowed[path] = true
	}
	for _, path := range manifestPaths {
		if allowed[path] {
			t.Fatalf("WO-050 path already in baseline: %s", path)
		}
		allowed[path] = true
	}
	if len(allowed)-len(preWO050) != 13 {
		t.Fatalf("WO-050 delta=%d want exact 13", len(allowed)-len(preWO050))
	}
	wo025 := []string{"internal/crypto/auth/lab_fault.go", "internal/crypto/auth/lab_fault_test.go", "internal/crypto/auth/handshake.go", "internal/runtime/authenticated_pair.go", "internal/runtime/config_v1_test.go", "internal/runtime/lifecycle_test.go", "internal/runtime/policy_enforcement_test.go"}
	wo025Seen := make(map[string]bool, 7)
	for _, path := range wo025 {
		if wo025Seen[path] {
			t.Fatalf("duplicate WO-025 path: %s", path)
		}
		wo025Seen[path] = true
		if _, overlap := baseline[path]; overlap && path != "internal/runtime/policy_enforcement_test.go" {
			t.Fatalf("WO-025 overlaps immutable WO-050 path: %s", path)
		}
		allowed[path] = true
	}
	if len(wo025Seen) != 7 {
		t.Fatalf("WO-025 delta paths=%d want 7", len(wo025Seen))
	}
	wo026 := []string{"internal/runtime/labfault/token.go", "internal/runtime/labfault/token_test.go", "internal/runtime/protected_channel.go", "internal/runtime/lifecycle.go", "internal/runtime/protected_channel_test.go", "internal/runtime/policy_enforcement_test.go"}
	wo026Seen := make(map[string]bool, 6)
	for _, path := range wo026 {
		if wo026Seen[path] {
			t.Fatalf("duplicate WO-026 path: %s", path)
		}
		wo026Seen[path] = true
		allowed[path] = true
	}
	if len(wo026Seen) != 6 {
		t.Fatalf("WO-026 delta paths=%d want 6", len(wo026Seen))
	}
	wo027 := []string{"internal/runtime/labfault/token.go", "internal/runtime/labfault/token_test.go", "internal/runtime/trace.go", "internal/runtime/trace_test.go", "internal/runtime/policy_enforcement_test.go"}
	wo027Seen := make(map[string]bool, 5)
	for _, path := range wo027 {
		if wo027Seen[path] {
			t.Fatalf("duplicate WO-027 path: %s", path)
		}
		wo027Seen[path] = true
		allowed[path] = true
	}
	if len(wo027Seen) != 5 {
		t.Fatalf("WO-027 delta paths=%d want 5", len(wo027Seen))
	}
	wo051 := []string{"internal/runtime/labfault/token.go", "internal/runtime/labfault/token_test.go", "internal/runtime/link.go", "internal/runtime/runtime_test.go", "internal/runtime/policy_enforcement_test.go"}
	wo051Seen := make(map[string]bool, 5)
	for _, path := range wo051 {
		if wo051Seen[path] {
			t.Fatalf("duplicate WO-051 path: %s", path)
		}
		wo051Seen[path] = true
		allowed[path] = true
	}
	if len(wo051Seen) != 5 {
		t.Fatalf("WO-051 delta paths=%d want 5", len(wo051Seen))
	}
	wo052 := []string{"internal/runtime/labfault/token.go", "internal/runtime/labfault/token_test.go", "internal/runtime/loopback_pair.go", "internal/runtime/loopback_pair_test.go", "internal/runtime/policy_enforcement_test.go"}
	wo052Seen := make(map[string]bool, 5)
	for _, path := range wo052 {
		if wo052Seen[path] {
			t.Fatalf("duplicate WO-052 path: %s", path)
		}
		wo052Seen[path] = true
		allowed[path] = true
	}
	if len(wo052Seen) != 5 {
		t.Fatalf("WO-052 delta paths=%d want 5", len(wo052Seen))
	}
	wo053 := []string{"internal/runtime/lab_executor.go", "internal/runtime/lab_executor_test.go", "internal/runtime/lifecycle_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go"}
	for _, path := range wo053 {
		allowed[path] = true
	}
	if len(wo053) != 5 {
		t.Fatal("WO-053 path cardinality")
	}
	wo056 := []string{"internal/runtime/lab_pair_factory.go", "internal/runtime/lab_pair_factory_test.go", "internal/runtime/lifecycle_test.go", "internal/runtime/implementation_support_test.go", "internal/runtime/policy_enforcement_test.go"}
	wo056Seen := make(map[string]bool, 5)
	for _, path := range wo056 {
		if wo056Seen[path] {
			t.Fatalf("duplicate WO-056 path: %s", path)
		}
		wo056Seen[path] = true
		allowed[path] = true
	}
	if len(wo056Seen) != 5 {
		t.Fatal("WO-056 paths")
	}
	wo016 := []string{
		"internal/runtime/generated_profile_parity_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/lab/runtimeadversary/scenario_test.go",
		"internal/testkit/importrules/importrules_test.go",
	}
	wo016Seen := make(map[string]bool, 4)
	for _, path := range wo016 {
		if wo016Seen[path] {
			t.Fatalf("duplicate WO-016 path: %s", path)
		}
		wo016Seen[path] = true
		allowed[path] = true
	}
	if len(wo016Seen) != 4 {
		t.Fatalf("WO-016 paths=%d want 4", len(wo016Seen))
	}
	wo012 := []string{
		"internal/observe/trace/trace.go",
		"internal/observe/trace/scan.go",
		"internal/runtime/trace.go",
		"internal/crypto/security/trace.go",
		"internal/observe/trace/correlation_test.go",
	}
	wo012Seen := make(map[string]bool, 5)
	for _, path := range wo012 {
		if wo012Seen[path] {
			t.Fatalf("duplicate WO-012 path: %s", path)
		}
		wo012Seen[path] = true
		allowed[path] = true
	}
	if len(wo012Seen) != 5 {
		t.Fatalf("WO-012 paths=%d want 5", len(wo012Seen))
	}
	wo057 := []string{
		"internal/observe/trace/trace.go", "internal/observe/trace/scan.go", "internal/observe/trace/correlation_test.go",
		"internal/runtime/trace.go", "internal/crypto/security/trace.go", "internal/runtime/trace_test.go",
		"internal/crypto/security/trace_test.go", "internal/audit/runtime.go", "internal/audit/security.go",
		"internal/runtime/policy_enforcement_test.go",
	}
	wo057Seen := make(map[string]bool, 10)
	for _, path := range wo057 {
		if wo057Seen[path] {
			t.Fatalf("duplicate WO-057 path: %s", path)
		}
		wo057Seen[path] = true
		allowed[path] = true
	}
	if len(wo057Seen) != 10 {
		t.Fatalf("WO-057 paths=%d want 10", len(wo057Seen))
	}
	wo013 := []string{
		"internal/testkit/importrules/importrules_test.go",
		"internal/runtime/config.go",
		"internal/runtime/secure_channel.go",
		"internal/protocol/compiler/generator.go",
		"internal/protocol/compiler/generator_test.go",
	}
	wo013Seen := make(map[string]bool, 5)
	for _, path := range wo013 {
		if wo013Seen[path] {
			t.Fatalf("duplicate WO-013 path: %s", path)
		}
		wo013Seen[path] = true
		allowed[path] = true
	}
	if len(wo013Seen) != 5 {
		t.Fatalf("WO-013 paths=%d want 5", len(wo013Seen))
	}
	wo030 := []string{
		"internal/audit/security.go", "internal/audit/security_test.go", "internal/audit/runtime.go", "internal/audit/status.go",
		"internal/lab/runtimeadversary/runner.go", "internal/lab/runtimeadversary/scenario_test.go", "internal/testkit/mutant/fault_test.go",
		"internal/runtime/policy_enforcement_test.go",
	}
	wo030Seen := make(map[string]bool, 8)
	for _, path := range wo030 {
		if wo030Seen[path] {
			t.Fatalf("duplicate WO-030 path: %s", path)
		}
		wo030Seen[path] = true
		allowed[path] = true
	}
	if len(wo030Seen) != 8 {
		t.Fatalf("WO-030 paths=%d want 8", len(wo030Seen))
	}
	wo034 := []string{
		"internal/audit/status.go", "STATUS.md", "README.md", "docs/safety.md",
		"docs/KIP-0011-mutation-and-longitudinal-testing.md", "internal/runtime/policy_enforcement_test.go",
	}
	wo034Seen := make(map[string]bool, 6)
	for _, path := range wo034 {
		if wo034Seen[path] {
			t.Fatalf("duplicate WO-034 path: %s", path)
		}
		wo034Seen[path] = true
		allowed[path] = true
	}
	if len(wo034Seen) != 6 {
		t.Fatalf("WO-034 paths=%d want 6", len(wo034Seen))
	}
	wo036 := []string{
		"internal/characterization/char_test.go",
		"internal/characterization/testdata/baseline.json",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
	}
	wo036Seen := make(map[string]bool, 4)
	for _, path := range wo036 {
		if wo036Seen[path] {
			t.Fatalf("duplicate WO-036 path: %s", path)
		}
		wo036Seen[path] = true
		allowed[path] = true
	}
	if len(wo036Seen) != 4 {
		t.Fatalf("WO-036 paths=%d want 4", len(wo036Seen))
	}
	wo037 := []string{
		"internal/protocol/ir/profile.go",
		"internal/characterization/testdata/baseline.json",
		"internal/runtime/generated_profile_parity_test.go",
		"internal/characterization/char_test.go",
		"internal/audit/security_test.go",
		"internal/protocol/compiler/generator_test.go",
		"internal/runtime/implementation_support_test.go",
		"internal/crypto/auth/handshake_test.go",
		"internal/runtime/policy_enforcement_test.go",
	}
	wo037Seen := make(map[string]bool, 9)
	for _, path := range wo037 {
		if wo037Seen[path] {
			t.Fatalf("duplicate WO-037 path: %s", path)
		}
		wo037Seen[path] = true
		allowed[path] = true
	}
	if len(wo037Seen) != 9 {
		t.Fatalf("WO-037 paths=%d want 9", len(wo037Seen))
	}
	wo038 := []string{
		"internal/protocol/ir/migration_v1.go",
		"internal/protocol/ir/migration_v1_test.go",
		"internal/protocol/ir/validate.go",
		"internal/crypto/profilemigration/migration_v1.go",
		"internal/crypto/profilemigration/migration_v1_test.go",
	}
	wo038Seen := make(map[string]bool, 5)
	for _, path := range wo038 {
		if wo038Seen[path] {
			t.Fatalf("duplicate WO-038 path: %s", path)
		}
		wo038Seen[path] = true
		allowed[path] = true
	}
	if len(wo038Seen) != 5 {
		t.Fatalf("WO-038 paths=%d want 5", len(wo038Seen))
	}
	wo039 := []string{
		"internal/runtime/profile_loader.go",
		"internal/runtime/profile_loader_test.go",
		"internal/runtime/config.go",
		"internal/runtime/manager.go",
		"internal/runtime/errors.go",
	}
	wo039Seen := make(map[string]bool, 5)
	for _, path := range wo039 {
		if wo039Seen[path] {
			t.Fatalf("duplicate WO-039 path: %s", path)
		}
		wo039Seen[path] = true
		allowed[path] = true
	}
	if len(wo039Seen) != 5 {
		t.Fatalf("WO-039 paths=%d want 5", len(wo039Seen))
	}
	wo040 := []string{
		"internal/codegen/authorization_v1.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/codegen/generator.go",
		"internal/codegen/generator_test.go",
		"internal/codegen/manifest.go",
	}
	wo040Seen := make(map[string]bool, 5)
	for _, path := range wo040 {
		if wo040Seen[path] {
			t.Fatalf("duplicate WO-040 path: %s", path)
		}
		wo040Seen[path] = true
		allowed[path] = true
	}
	if len(wo040Seen) != 5 {
		t.Fatalf("WO-040 paths=%d want 5", len(wo040Seen))
	}
	wo041 := []string{"cmd/kgen/main.go", "cmd/kgen/main_test.go"}
	wo041Seen := make(map[string]bool, 2)
	for _, path := range wo041 {
		if wo041Seen[path] {
			t.Fatalf("duplicate WO-041 path: %s", path)
		}
		wo041Seen[path] = true
		allowed[path] = true
	}
	if len(wo041Seen) != 2 {
		t.Fatalf("WO-041 paths=%d want 2", len(wo041Seen))
	}
	wo042 := []string{
		"internal/audit/codegen.go",
		"internal/audit/codegen_test.go",
		"testdata/codegen/profile-authorization-v1.json",
		"cmd/kcheck/main.go",
		"cmd/kcheck/registry_test.go",
		"internal/runtime/policy_enforcement_test.go",
	}
	wo042Seen := make(map[string]bool, 6)
	for _, path := range wo042 {
		if wo042Seen[path] {
			t.Fatalf("duplicate WO-042 path: %s", path)
		}
		wo042Seen[path] = true
		allowed[path] = true
	}
	if len(wo042Seen) != 6 {
		t.Fatalf("WO-042 paths=%d want 6", len(wo042Seen))
	}
	wo043 := []string{"internal/codegen/generator.go", "internal/codegen/generator_templates.go", "internal/codegen/generator_test.go", "internal/codegen/scanner.go", "internal/codegen/scanner_test.go"}
	wo043Seen := make(map[string]bool, 5)
	for _, path := range wo043 {
		if wo043Seen[path] {
			t.Fatalf("duplicate WO-043 path: %s", path)
		}
		wo043Seen[path] = true
		allowed[path] = true
	}
	if len(wo043Seen) != 5 || !allowed["internal/runtime/policy_enforcement_test.go"] {
		t.Fatalf("WO-043 owned paths=%d; exact six-path scope requires guard", len(wo043Seen))
	}
	wo044 := []string{"internal/testkit/importrules/importrules_test.go", "docs/KIP-0067-stage6a-version-migration.md", "docs/KIP-0012-generated-source-backend.md", "docs/KIP-0013-generated-backend-audit.md", "README.md"}
	wo044Seen := make(map[string]bool, 5)
	for _, path := range wo044 {
		if wo044Seen[path] {
			t.Fatalf("duplicate WO-044 path: %s", path)
		}
		wo044Seen[path] = true
		allowed[path] = true
	}
	if len(wo044Seen) != 5 || !allowed["internal/runtime/policy_enforcement_test.go"] {
		t.Fatalf("WO-044 owned paths=%d; exact six-path scope requires guard", len(wo044Seen))
	}
	command := exec.Command("git", "status", "--porcelain", "--untracked-files=all")
	command.Dir = filepath.Join("..", "..")
	output, err := command.Output()
	if err != nil {
		t.Fatalf("unscoped git status: %v", err)
	}
	changed := make(map[string]bool)
	for _, line := range strings.Split(strings.TrimRight(string(output), "\r\n"), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" {
			continue
		}
		if len(line) < 4 {
			t.Fatalf("malformed git status line %q", line)
		}
		changed[filepath.ToSlash(strings.TrimSpace(line[3:]))] = true
	}
	if len(changed) == 0 {
		if len(output) != 0 {
			t.Fatalf("clean status must be exactly empty, got %q", output)
		}
		args := append([]string{"ls-files", "--error-unmatch", "--"}, manifestPaths...)
		trackedCommand := exec.Command("git", args...)
		trackedCommand.Dir = filepath.Join("..", "..")
		trackedOutput, err := trackedCommand.Output()
		if err != nil {
			t.Fatalf("clean status requires all WO-050 paths tracked: %v", err)
		}
		tracked := make(map[string]bool)
		for _, line := range strings.Split(strings.TrimRight(string(trackedOutput), "\r\n"), "\n") {
			line = filepath.ToSlash(strings.TrimSpace(strings.TrimSuffix(line, "\r")))
			if line != "" {
				tracked[line] = true
			}
		}
		if len(tracked) != 13 {
			t.Fatalf("clean tracked WO-050 paths=%d want 13", len(tracked))
		}
		for _, path := range manifestPaths {
			if !tracked[path] {
				t.Fatalf("clean WO-050 path is not tracked: %s", path)
			}
			if _, err := os.Stat(filepath.Join("..", "..", filepath.FromSlash(path))); err != nil {
				t.Fatalf("clean tracked WO-050 path missing: %s: %v", path, err)
			}
		}
		if err := validatePolicyMaintenanceStatusV1(filepath.Join("..", ".."), changed, allowed); err != nil {
			t.Fatal(err)
		}
	} else if err := validatePolicyMaintenanceStatusV1(filepath.Join("..", ".."), changed, allowed); err != nil {
		t.Fatal(err)
	}
	baselineExportedFunctions := map[string]map[string]bool{
		"internal/runtime/implementation_support.go": {
			"NewClientProfileAuthorization" + "RegistryV1": true,
			"NewRelayProfileAuthorization" + "RegistryV1":  true,
		},
	}
	for path, before := range baseline {
		local := filepath.Join("..", "..", filepath.FromSlash(path))
		raw, err := os.ReadFile(local)
		if err != nil {
			t.Fatalf("manifest path %s: %v", path, err)
		}
		current := fmt.Sprintf("%x", sha256.Sum256(raw))
		if path != "internal/runtime/policy_enforcement_test.go" && !wo026Seen[path] && !wo052Seen[path] && !wo056Seen[path] && !wo037Seen[path] && !wo038Seen[path] && (len(before) != 64 || current != before) {
			t.Fatalf("invalid manifest hash for %s before=%q current=%q", path, before, current)
		}
		file, err := parser.ParseFile(token.NewFileSet(), local, raw, 0)
		if err != nil {
			t.Fatal(err)
		}
		for _, declaration := range file.Decls {
			function, ok := declaration.(*ast.FuncDecl)
			if !ok || !ast.IsExported(function.Name.Name) {
				continue
			}
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			if baselineExportedFunctions[path][function.Name.Name] {
				continue
			}
			t.Fatalf("WO-050 added exported API %s in %s", function.Name.Name, path)
		}
		if path == "internal/runtime/policy_enforcement.go" {
			ast.Inspect(file, func(node ast.Node) bool {
				switch node.(type) {
				case *ast.SwitchStmt, *ast.TypeSwitchStmt:
					t.Fatalf("policy aggregation helper contains semantic switch: %T", node)
				}
				return true
			})
		}
	}
	protectedRaw, err := os.ReadFile("protected_channel.go")
	if err != nil {
		t.Fatal(err)
	}
	protectedFile, err := parser.ParseFile(token.NewFileSet(), "protected_channel.go", protectedRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range protectedFile.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if ast.IsExported(function.Name.Name) && strings.Contains(function.Name.Name, "LabFault") && function.Name.Name != "ExecuteRuntimeLabFaultV1" {
			t.Fatalf("exported runtime lab API: %s", function.Name.Name)
		}
		if function.Name.Name == "newStrictProtectedChannelV1" || function.Name.Name == "newStrictProtectedChannelWithObserverV1" {
			if strings.Contains(string(protectedRaw[function.Type.Pos()-1:function.Type.End()-1]), "labfault") {
				t.Fatalf("normal constructor accepts lab authority: %s", function.Name.Name)
			}
		}
	}
	lifecycleRaw, err := os.ReadFile("lifecycle.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lifecycleRaw), "NewTokenV1(") || strings.Contains(string(lifecycleRaw), "internal/testkit") {
		t.Fatal("lifecycle gained unauthorized lab mint or testkit reachability")
	}
	traceRaw, err := os.ReadFile("trace.go")
	if err != nil {
		t.Fatal(err)
	}
	traceFile, err := parser.ParseFile(token.NewFileSet(), "trace.go", traceRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	normalTrace := map[string]bool{"RuntimeTraceEvent": true, "LinkTraceEvent": true, "SecureTraceEvent": true, "TraceHasSensitive": true}
	for _, declaration := range traceFile.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		signature := string(traceRaw[function.Type.Pos()-1 : function.Type.End()-1])
		if normalTrace[function.Name.Name] && strings.Contains(signature, "labfault") {
			t.Fatalf("normal trace API accepts lab authority: %s", function.Name.Name)
		}
		if function.Name.Name == "newRuntimeTraceFaultObservationV1" {
			body := string(traceRaw[function.Body.Pos()-1 : function.Body.End()-1])
			for _, forbidden := range []string{"ktrace.", "json.", "os.", "net.", "log.", "TraceHasSensitive"} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("trace fault helper reaches %s", forbidden)
				}
			}
		}
	}
	linkRaw, err := os.ReadFile("link.go")
	if err != nil {
		t.Fatal(err)
	}
	linkFile, err := parser.ParseFile(token.NewFileSet(), "link.go", linkRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, declaration := range linkFile.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok {
			continue
		}
		signature := string(linkRaw[function.Type.Pos()-1 : function.Type.End()-1])
		if ast.IsExported(function.Name.Name) && strings.Contains(signature, "labfault") {
			t.Fatalf("public link API accepts lab token: %s", function.Name.Name)
		}
		if function.Name.Name == "NewMemoryLink" && (strings.Contains(signature, "string") || strings.Contains(signature, "Token")) {
			t.Fatal("normal memory link gained fault selector")
		}
	}
}

type policyMaintenanceEntryV1 struct {
	Path       string `json:"path"`
	PreSHA256  string `json:"pre_sha256"`
	PostSHA256 string `json:"post_sha256"`
}

type policyMaintenanceOverlayV1 struct {
	Version       string                     `json:"version"`
	SelfPath      string                     `json:"self_path"`
	SelfPreSHA256 string                     `json:"self_pre_sha256"`
	Paths         []string                   `json:"paths"`
	Entries       []policyMaintenanceEntryV1 `json:"entries"`
}

type policyLayeredOverlayV1 struct {
	Version                string                     `json:"version"`
	PredecessorManifestSHA string                     `json:"predecessor_manifest_sha256"`
	Entries                []policyMaintenanceEntryV1 `json:"entries"`
}

type policyPhase2CompleteOverlayV1 struct {
	Version                   string                               `json:"version"`
	PredecessorManifestSHA256 string                               `json:"predecessor_manifest_sha256"`
	Paths                     []string                             `json:"paths"`
	Entries                   []policyPhase2CompleteOverlayEntryV1 `json:"entries"`
}

type policyPhase2CompleteOverlayEntryV1 struct {
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PostSHA256  string `json:"post_sha256"`
}

const policyMaintenanceManifestPathV1 = "testdata/evidence/phase1-m0-committed-sha256.json"
const policyMaintenanceOverlayNameV1 = "m2-governance-foundation-v1"
const policyHelperOverlayNameV1 = "m2-governance-foundation-helper-owners-v1"
const policyHelperOverlayNameV2 = "m2-governance-foundation-helper-owners-v2"
const policyValidatorOverlayNameV1 = "m2-governance-foundation-validators-v1"
const policyValidatorConsumerOverlayNameV1 = "m2-governance-foundation-validator-consumer-v1"
const policyEvidenceConvergenceOverlayNameV1 = "m2-governance-foundation-evidence-convergence-v1"
const policyPhase2CompleteOverlayNameV1 = "m2-governance-foundation-phase2-complete-v1"
const policyPhase2PredecessorManifestSHA256V1 = "c89a6be543ec35e68bef3cd6d5a91b685b1a05e523aca264faabc6d4933c398b"

var policyMaintenancePathsV1 = []string{
	"README.md", "ROADMAP.md", "docs/GOVERNANCE.md", "docs/safety.md",
	"internal/audit/security.go", "internal/audit/security_test.go",
	"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go",
	policyMaintenanceManifestPathV1,
}

var policyHelperPathsV1 = []string{"internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", "cmd/kgen/main_test.go"}
var policyHelperPreV1 = []string{"0874db08bb14f2d94b94b88171f1d78cd87dd34122e6ca39e3eb4ec9942a00ec", "9f1941a9ef49c70aedddddf11890ea97df0563c2b921c75a3300aee713faf9ac", "a80d10983b1e5684faf64011ee482a3a8216f2ab2393fbe9cd7570cbf4d5524d"}
var policyHelperV1PostV1 = []string{"5e7fff88d4e75aadf0b2306c9d9574b76e13a62c585deeebda53ba6a191832d1", "96e6e30ccfe131cfa0384fc4463ac2f75a4e9d0630179233dc40157f7839f30b", "bad5ffb692075048785a98b0c048761f06003462f1a202660b60bddf4c9103e4"}
var policyHelperV2PostV1 = []string{"7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0"}
var policyValidatorPathsV1 = []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go"}
var policyValidatorPreV1 = []string{"b5be3c78bf856be24b92751f21fe54c7cb4a197c9f68aa7bf10d1129e6ba5c17", "b7449bc1148e01edaadfffed21626f0acc45c1fd114d606bf9abe4275a5a56e3", "a799b17b7218f806217ca551bb8807d380d193206c7151dab96add53affe0136"}
var policyConvergencePathsV1 = []string{"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go"}
var policyConvergencePreV1 = []string{"aa0d56ec1b1ebeeab11c90497d1f252295682bfb4b9d0c096dcd5b0047558ac0", "7707d4faf66e9d20edbb157a3ad59d71c81d8d3b7f869d7529ff312f9fce073d", "985d46009b1ed6c0faade46de2574b940954de92ad6db8de3ddac0e29ea4a3ae", "f6b623b865407412856cbfc1c3748524b47ccae39ad3d33e40bd8977c9dbeab3", "abf9e52b55971aefb21dace2226dfe4b29c4b5b8478504f30868934af8d6b935", "53f9635f8761701cd2a9ce2762b3004ff3a0143097cb7334930e7b6f086e33b9", "81ae4a98530acc4a643fd824a939aa658eba6f8f6c4857b7978c1ebeb6853c9f"}
var policyPhase2CompletePathsV1 = []string{"README.md", "ROADMAP.md", "cmd/kgen/main_test.go", "docs/GOVERNANCE.md", "docs/KIP-0001-threat-model.md", "docs/KIP-0066-product-layer-scaffold.md", "docs/KIP-0068-product-governance-foundation.md", "docs/KIP-0069-product-contracts-v1.md", "docs/safety.md", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", policyMaintenanceManifestPathV1}

func validatePolicyMaintenanceStatusV1(root string, changed, historical map[string]bool) error {
	if len(changed) != 0 && exactPathSetV1(changed, historical) {
		return nil
	}
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyMaintenanceManifestPathV1)))
	if err != nil {
		return err
	}
	var manifest struct {
		MaintenanceOverlays         map[string]policyMaintenanceOverlayV1    `json:"maintenance_overlays"`
		HelperOwnerOverlays         map[string]policyLayeredOverlayV1        `json:"helper_owner_overlays"`
		ValidatorOverlays           map[string]policyLayeredOverlayV1        `json:"validator_overlays"`
		ValidatorConsumerOverlays   map[string]policyLayeredOverlayV1        `json:"validator_consumer_overlays"`
		EvidenceConvergenceOverlays map[string]policyLayeredOverlayV1        `json:"evidence_convergence_overlays"`
		Phase2CompleteOverlays      map[string]policyPhase2CompleteOverlayV1 `json:"phase2_complete_overlays"`
		Phase3ContractOverlays      map[string]policyPhase2CompleteOverlayV1 `json:"phase3_contract_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	candidate, err := policyPhase2CandidateInventoryV1(root)
	if err != nil {
		return err
	}
	if len(candidate) == 0 {
		return nil
	}
	return validatePolicyM2ComposedStateV1(root, candidate, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays)
}

func validatePolicyM2ComposedStateV1(root string, changed map[string]bool, maintenanceOverlays map[string]policyMaintenanceOverlayV1, helperOverlays, validatorOverlays, consumerOverlays, convergenceOverlays map[string]policyLayeredOverlayV1, phase3Overlays, phase2Overlays map[string]policyPhase2CompleteOverlayV1) error {
	currentAtM2, err := validatePolicyPhase3ContractV1(root, phase3Overlays)
	if err != nil {
		return err
	}
	currentAtPre, err := validatePolicyPhase2CompleteV1(root, currentAtM2, phase2Overlays)
	if err != nil {
		return err
	}
	currentAtPre, err = validatePolicyConvergenceV1(currentAtPre, convergenceOverlays)
	if err != nil {
		return err
	}
	maintenance, ok := maintenanceOverlays[policyMaintenanceOverlayNameV1]
	if len(maintenanceOverlays) != 1 || !ok || maintenance.Version != policyMaintenanceOverlayNameV1 || maintenance.SelfPath != policyMaintenanceManifestPathV1 || len(maintenance.Paths) != 9 || len(maintenance.Entries) != 8 || !validPolicySHA256V1(maintenance.SelfPreSHA256) {
		return fmt.Errorf("invalid M2 maintenance overlay")
	}
	want := map[string]bool{}
	for _, path := range policyPhase2CompletePathsV1 {
		want[path] = true
	}
	for _, path := range phase3Overlays["m3-profile-lifecycle-contract-v1"].Paths {
		want[path] = true
	}
	for i, path := range policyMaintenancePathsV1 {
		if maintenance.Paths[i] != path {
			return fmt.Errorf("M2 maintenance path[%d]=%q want %q", i, maintenance.Paths[i], path)
		}
	}
	if len(helperOverlays) != 2 {
		return fmt.Errorf("invalid M2 helper overlay count")
	}
	v1, ok1 := helperOverlays[policyHelperOverlayNameV1]
	v2, ok2 := helperOverlays[policyHelperOverlayNameV2]
	if !ok1 || v1.Version != policyHelperOverlayNameV1 || v1.PredecessorManifestSHA != "b2a95c93332afbc13c73a4bb08e92067db97e93e843cb55e1f191b9c398e3c7b" || len(v1.Entries) != 3 || !ok2 || v2.Version != policyHelperOverlayNameV2 || v2.PredecessorManifestSHA != "7258697b4806469afea99342d981e96b328114036668e874f7c0e5a597a94cc6" || len(v2.Entries) != 3 {
		return fmt.Errorf("invalid M2 helper overlay identity/cardinality")
	}
	for i, path := range policyHelperPathsV1 {
		oldEntry, newEntry := v1.Entries[i], v2.Entries[i]
		if oldEntry.Path != path || oldEntry.PreSHA256 != policyHelperPreV1[i] || oldEntry.PostSHA256 != policyHelperV1PostV1[i] || newEntry.Path != path || newEntry.PreSHA256 != oldEntry.PostSHA256 || newEntry.PostSHA256 != policyHelperV2PostV1[i] {
			return fmt.Errorf("invalid M2 helper overlay entry %d", i)
		}
		actual := currentAtPre[path]
		if actual != newEntry.PostSHA256 {
			return fmt.Errorf("M2 helper hash drift %s=%s want %s: %v", path, actual, newEntry.PostSHA256, err)
		}
	}
	validators, ok := validatorOverlays[policyValidatorOverlayNameV1]
	if len(validatorOverlays) != 1 || !ok || validators.Version != policyValidatorOverlayNameV1 || validators.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(validators.Entries) != 3 {
		return fmt.Errorf("invalid M2 validator overlay identity/cardinality")
	}
	validatorByPath := map[string]policyMaintenanceEntryV1{}
	for i, entry := range validators.Entries {
		if entry.Path != policyValidatorPathsV1[i] || entry.PreSHA256 != policyValidatorPreV1[i] || !validPolicySHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
			return fmt.Errorf("invalid M2 validator entry %d", i)
		}
		actual := currentAtPre[entry.Path]
		if actual != entry.PostSHA256 {
			return fmt.Errorf("M2 validator hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		validatorByPath[entry.Path] = entry
	}
	consumer, ok := consumerOverlays[policyValidatorConsumerOverlayNameV1]
	if len(consumerOverlays) != 1 || !ok || consumer.Version != policyValidatorConsumerOverlayNameV1 || consumer.PredecessorManifestSHA != "7924eff0ab8d66440bd370af1c6073ca9dc9beb320ac68acd82748b7f2d4f87b" || len(consumer.Entries) != 1 {
		return fmt.Errorf("invalid M2 validator-consumer overlay identity/cardinality")
	}
	consumerEntry := consumer.Entries[0]
	if consumerEntry.Path != "internal/testkit/importrules/importrules_test.go" || consumerEntry.PreSHA256 != "3a170c4752fea63a728d55abff9b0c8a7c91e25e0c98d14bdd4c401e3b56a178" || !validPolicySHA256V1(consumerEntry.PostSHA256) || consumerEntry.PostSHA256 == consumerEntry.PreSHA256 {
		return fmt.Errorf("invalid M2 validator-consumer entry")
	}
	actualConsumer := currentAtPre[consumerEntry.Path]
	if actualConsumer != consumerEntry.PostSHA256 {
		return fmt.Errorf("M2 validator-consumer hash drift %s=%s want %s: %v", consumerEntry.Path, actualConsumer, consumerEntry.PostSHA256, err)
	}
	if !exactPathSetV1(changed, want) {
		return fmt.Errorf("repository status matches neither historical M0 nor exact composed M2 state: paths=%d", len(changed))
	}
	for i, entry := range maintenance.Entries {
		if entry.Path != policyMaintenancePathsV1[i] || !validPolicySHA256V1(entry.PreSHA256) || !validPolicySHA256V1(entry.PostSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return fmt.Errorf("invalid M2 maintenance entry %d", i)
		}
		actual := currentAtPre[entry.Path]
		if actual == "" {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil {
			return err
		}
		if validator, layered := validatorByPath[entry.Path]; layered {
			if validator.PreSHA256 != entry.PostSHA256 || actual != validator.PostSHA256 {
				return fmt.Errorf("M2 validator chain drift %s", entry.Path)
			}
			actual = validator.PreSHA256
		}
		if entry.Path == consumerEntry.Path {
			if actual != consumerEntry.PostSHA256 {
				return fmt.Errorf("M2 validator-consumer chain drift %s", entry.Path)
			}
			actual = consumerEntry.PreSHA256
		}
		if actual != entry.PostSHA256 {
			return fmt.Errorf("M2 maintenance hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
	}
	return nil
}

func validatePolicyPhase2CompleteV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	overlay, ok := overlays[policyPhase2CompleteOverlayNameV1]
	if len(overlays) != 1 || !ok || overlay.Version != policyPhase2CompleteOverlayNameV1 || overlay.PredecessorManifestSHA256 != policyPhase2PredecessorManifestSHA256V1 || len(overlay.Paths) != len(policyPhase2CompletePathsV1) || len(overlay.Entries) != len(policyPhase2CompletePathsV1)-1 {
		return nil, fmt.Errorf("invalid phase2-complete overlay identity/cardinality")
	}
	for i, path := range policyPhase2CompletePathsV1 {
		if overlay.Paths[i] != path {
			return nil, fmt.Errorf("phase2-complete path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if entry.Path != policyPhase2CompletePathsV1[i] || entry.Path == policyMaintenanceManifestPathV1 || !validPolicySHA256V1(entry.PostSHA256) || (entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" && !validPolicySHA256V1(entry.PreEvidence)) {
			return nil, fmt.Errorf("invalid phase2-complete entry %d", i)
		}
		actual, ok := currentAtPost[entry.Path]
		var err error
		if !ok {
			actual, err = policyFileSHA256V1(root, entry.Path)
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

func validatePolicyPhase3ContractV1(root string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != policyMaintenanceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase3 contract overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase3 contract entry %d", i)
		}
		actual, err := policyFileSHA256V1(root, entry.Path)
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validPolicySHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePolicyConvergenceV1(currentAtPost map[string]string, overlays map[string]policyLayeredOverlayV1) (map[string]string, error) {
	convergence, ok := overlays[policyEvidenceConvergenceOverlayNameV1]
	if len(overlays) != 1 || !ok || convergence.Version != policyEvidenceConvergenceOverlayNameV1 || convergence.PredecessorManifestSHA != "1502ae4db6d151839f554e6becde9e81994286cbff378945282739015492bf1e" || len(convergence.Entries) != 7 {
		return nil, fmt.Errorf("invalid convergence overlay identity/cardinality")
	}
	result := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		result[path] = hash
	}
	for i, entry := range convergence.Entries {
		if entry.Path != policyConvergencePathsV1[i] || entry.PreSHA256 != policyConvergencePreV1[i] || !validPolicySHA256V1(entry.PostSHA256) || entry.PostSHA256 == entry.PreSHA256 {
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

func policyPhase2CandidateInventoryV1(root string) (map[string]bool, error) {
	result := map[string]bool{}
	commands := [][]string{{"diff", "--name-only", "0ab9f32", "--"}, {"ls-files", "--others", "--exclude-standard", "--"}}
	for _, args := range commands {
		command := exec.Command("git", args...)
		command.Dir = root
		output, err := command.Output()
		if err != nil {
			return nil, fmt.Errorf("git %s: %w", strings.Join(args, " "), err)
		}
		for _, line := range strings.Split(strings.TrimSpace(string(output)), "\n") {
			path := filepath.ToSlash(strings.TrimSpace(strings.TrimSuffix(line, "\r")))
			if path != "" {
				result[path] = true
			}
		}
	}
	return result, nil
}

func policyFileSHA256V1(root, path string) (string, error) {
	content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(path)))
	if err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", sha256.Sum256(content)), nil
}

func validatePolicyM2MaintenanceV1(root string, changed map[string]bool, overlay policyMaintenanceOverlayV1) error {
	if overlay.Version != policyMaintenanceOverlayNameV1 || overlay.SelfPath != policyMaintenanceManifestPathV1 || len(overlay.Paths) != 9 || len(overlay.Entries) != 8 || !validPolicySHA256V1(overlay.SelfPreSHA256) {
		return fmt.Errorf("invalid M2 maintenance identity/cardinality")
	}
	want := map[string]bool{}
	for i, path := range policyMaintenancePathsV1 {
		if overlay.Paths[i] != path {
			return fmt.Errorf("M2 maintenance path[%d]=%q want %q", i, overlay.Paths[i], path)
		}
		want[path] = true
	}
	if !exactPathSetV1(changed, want) {
		return fmt.Errorf("repository status matches neither historical M0 set nor exact M2 maintenance set: paths=%d", len(changed))
	}
	for i, entry := range overlay.Entries {
		if entry.Path != policyMaintenancePathsV1[i] || !validPolicySHA256V1(entry.PreSHA256) || !validPolicySHA256V1(entry.PostSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return fmt.Errorf("invalid M2 maintenance entry %d", i)
		}
		content, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(entry.Path)))
		if err != nil {
			return err
		}
		actual := fmt.Sprintf("%x", sha256.Sum256(content))
		if actual != entry.PostSHA256 {
			return fmt.Errorf("M2 maintenance hash drift %s=%s want %s", entry.Path, actual, entry.PostSHA256)
		}
	}
	return nil
}

func exactPathSetV1(got, want map[string]bool) bool {
	if len(got) != len(want) {
		return false
	}
	for path := range want {
		if !got[path] {
			return false
		}
	}
	return true
}

func validPolicySHA256V1(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size && value == strings.ToLower(value) && value != strings.Repeat("0", 64)
}

func TestPolicyMatrixMaintenanceExactStatesV1(t *testing.T) {
	root := t.TempDir()
	overlay := policyMaintenanceOverlayV1{
		Version: policyMaintenanceOverlayNameV1, SelfPath: policyMaintenanceManifestPathV1, SelfPreSHA256: strings.Repeat("1", 64),
		Paths: append([]string(nil), policyMaintenancePathsV1...),
	}
	changed := map[string]bool{}
	for _, path := range policyMaintenancePathsV1 {
		changed[path] = true
		if path == policyMaintenanceManifestPathV1 {
			continue
		}
		content := []byte("content:" + path)
		target := filepath.Join(root, filepath.FromSlash(path))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, content, 0o644); err != nil {
			t.Fatal(err)
		}
		overlay.Entries = append(overlay.Entries, policyMaintenanceEntryV1{Path: path, PreSHA256: strings.Repeat("2", 64), PostSHA256: fmt.Sprintf("%x", sha256.Sum256(content))})
	}
	if err := validatePolicyM2MaintenanceV1(root, changed, overlay); err != nil {
		t.Fatal(err)
	}
	partial := make(map[string]bool, len(changed)-1)
	for path := range changed {
		if path != "README.md" {
			partial[path] = true
		}
	}
	if err := validatePolicyM2MaintenanceV1(root, partial, overlay); err == nil {
		t.Fatal("partial M2 set accepted")
	}
	superset := make(map[string]bool, len(changed)+1)
	for path := range changed {
		superset[path] = true
	}
	superset["extra"] = true
	if err := validatePolicyM2MaintenanceV1(root, superset, overlay); err == nil {
		t.Fatal("M2 superset accepted")
	}
	drift := overlay
	drift.Entries = append([]policyMaintenanceEntryV1(nil), overlay.Entries...)
	drift.Entries[0].PostSHA256 = strings.Repeat("3", 64)
	if err := validatePolicyM2MaintenanceV1(root, changed, drift); err == nil || !strings.Contains(err.Error(), "hash drift") {
		t.Fatalf("M2 content drift error=%v", err)
	}
}

func TestPolicyMatrixComposedM2ExactStatesV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(policyMaintenanceManifestPathV1)))
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		MaintenanceOverlays         map[string]policyMaintenanceOverlayV1    `json:"maintenance_overlays"`
		HelperOwnerOverlays         map[string]policyLayeredOverlayV1        `json:"helper_owner_overlays"`
		ValidatorOverlays           map[string]policyLayeredOverlayV1        `json:"validator_overlays"`
		ValidatorConsumerOverlays   map[string]policyLayeredOverlayV1        `json:"validator_consumer_overlays"`
		EvidenceConvergenceOverlays map[string]policyLayeredOverlayV1        `json:"evidence_convergence_overlays"`
		Phase2CompleteOverlays      map[string]policyPhase2CompleteOverlayV1 `json:"phase2_complete_overlays"`
		Phase3ContractOverlays      map[string]policyPhase2CompleteOverlayV1 `json:"phase3_contract_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	changed := map[string]bool{}
	for _, path := range policyPhase2CompletePathsV1 {
		changed[path] = true
	}
	for _, path := range manifest.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"].Paths {
		changed[path] = true
	}
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err != nil {
		t.Fatal(err)
	}
	partial := clonePathSetV1(changed)
	delete(partial, policyHelperPathsV1[0])
	if err := validatePolicyM2ComposedStateV1(root, partial, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("composed M2 subset accepted")
	}
	superset := clonePathSetV1(changed)
	superset["extra"] = true
	if err := validatePolicyM2ComposedStateV1(root, superset, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("composed M2 superset accepted")
	}
	badHelpers := clonePolicyLayeredOverlaysV1(manifest.HelperOwnerOverlays)
	v2 := badHelpers[policyHelperOverlayNameV2]
	v2.Entries[0], v2.Entries[1] = v2.Entries[1], v2.Entries[0]
	badHelpers[policyHelperOverlayNameV2] = v2
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, badHelpers, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("reordered helper overlay accepted")
	}
	badValidators := clonePolicyLayeredOverlaysV1(manifest.ValidatorOverlays)
	validator := badValidators[policyValidatorOverlayNameV1]
	validator.Entries[0].PostSHA256 = strings.Repeat("3", 64)
	badValidators[policyValidatorOverlayNameV1] = validator
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, badValidators, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted validator overlay accepted")
	}
	badConsumers := clonePolicyLayeredOverlaysV1(manifest.ValidatorConsumerOverlays)
	consumer := badConsumers[policyValidatorConsumerOverlayNameV1]
	consumer.Entries[0].PreSHA256 = strings.Repeat("4", 64)
	badConsumers[policyValidatorConsumerOverlayNameV1] = consumer
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, badConsumers, manifest.EvidenceConvergenceOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted validator-consumer overlay accepted")
	}
}

func clonePathSetV1(source map[string]bool) map[string]bool {
	clone := make(map[string]bool, len(source))
	for path, present := range source {
		clone[path] = present
	}
	return clone
}

func clonePolicyLayeredOverlaysV1(source map[string]policyLayeredOverlayV1) map[string]policyLayeredOverlayV1 {
	clone := make(map[string]policyLayeredOverlayV1, len(source))
	for name, overlay := range source {
		overlay.Entries = append([]policyMaintenanceEntryV1(nil), overlay.Entries...)
		clone[name] = overlay
	}
	return clone
}
