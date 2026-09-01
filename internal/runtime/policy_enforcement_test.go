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
	"path/filepath"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/phase17evidence"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/testkit/evidenceoverlay"
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
	ownerHashes := map[string]string{"protected_channel.go": "4523d20b60fb9df4533c284386d359073de9c2b5745166b842ae42424aabded0", "trace.go": "4d53711a2c0a9d834b7c5024bc9e076e6b70215e19c496c1a3b3a52ae1dc9844", "link.go": "dae7aeb583ae7ec13433a1dc4ead2c2d20ab3d1e6713e82f1465070f913e0e02", "loopback_pair.go": "955557e2aeac18b5df08a391679ccfff1f07097ec754816c94889f354da09013"}
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
			if entry.Name() == ".git" || entry.Name() == ".claude" || entry.Name() == ".tools" || entry.Name() == "planning" {
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
		"internal/audit/status.go", "SZ-evidence-ref-070", "README.md", "docs/sb-evidence-ref-068",
		"docs/KZ-evidence-ref-012", "internal/runtime/policy_enforcement_test.go",
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
	wo044 := []string{"internal/testkit/importrules/importrules_test.go", "docs/KZ-evidence-ref-021", "docs/KZ-evidence-ref-013", "docs/KZ-evidence-ref-014", "README.md"}
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
	root := filepath.Join("..", "..")
	// The historical committed subject has no pending changes. Bind all thirteen
	// owner paths to its exact commit/tree/blob identities, not today's index or
	// status. The complete frozen overlay chain must still verify below.
	tracked := make(map[string]bool, len(manifestPaths))
	for _, path := range manifestPaths {
		if tracked[path] {
			t.Fatalf("duplicate historical WO-050 path: %s", path)
		}
		file, err := evidenceoverlay.ReadHistoricalFile(root, path)
		if err != nil {
			t.Fatalf("historical tracked WO-050 path missing: %s: %v", path, err)
		}
		if file.Path != path || file.Length != int64(len(file.Content)) || file.SHA256 != fmt.Sprintf("%x", sha256.Sum256(file.Content)) {
			t.Fatalf("historical WO-050 object binding mismatch: %s", path)
		}
		tracked[path] = true
	}
	if len(tracked) != 13 {
		t.Fatalf("historical tracked WO-050 paths=%d want 13", len(tracked))
	}
	if err := validatePolicyMaintenanceStatusV1(root, nil, allowed); err != nil {
		t.Fatal(err)
	}
	availability, err := phase17evidence.VerifyDevelopmentAvailability(root)
	if err != nil {
		t.Fatal(err)
	}
	if availability.HistoricalCommit != evidenceoverlay.HistoricalCommit || availability.HistoricalTree != evidenceoverlay.HistoricalTree || availability.HistoricalVerification != "VERIFIED" || availability.SuccessorEvidence != "NOT_AVAILABLE" {
		t.Fatalf("historical/current subject separation: %+v", availability)
	}
	for name, state := range map[string]string{"candidate": availability.Candidate, "readiness": availability.Readiness, "Stress": availability.Stress, "campaign": availability.Campaign, "soak": availability.Soak, "release": availability.Release} {
		if state != "BLOCKED" {
			t.Fatalf("historical verification opened current %s gate: %s", name, state)
		}
	}
	// These AST and API protections deliberately inspect live source. Historical
	// evidence verification must not hide a newly introduced runtime bypass.
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
	Path        string `json:"path"`
	PreEvidence string `json:"pre_evidence"`
	PreSHA256   string `json:"pre_sha256"`
	PostSHA256  string `json:"post_sha256"`
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

type policyPhase8WorkOrderOverlayV1 struct {
	Version                  string                               `json:"version"`
	WorkOrderPath            string                               `json:"work_order_path"`
	PredecessorOverlaySHA256 string                               `json:"predecessor_overlay_sha256"`
	Paths                    []string                             `json:"paths"`
	Entries                  []policyPhase2CompleteOverlayEntryV1 `json:"entries"`
	OverlaySHA256            string                               `json:"overlay_sha256"`
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
	"README.md", "RZ-evidence-ref-069", "docs/GZ-evidence-ref-001", "docs/sb-evidence-ref-068",
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
var policyPhase2CompletePathsV1 = []string{"README.md", "RZ-evidence-ref-069", "cmd/kgen/main_test.go", "docs/GZ-evidence-ref-001", "docs/KZ-evidence-ref-003", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023", "docs/sb-evidence-ref-068", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", policyMaintenanceManifestPathV1}
var policyStabilizationPathsV1 = []string{
	"SZ-evidence-ref-070", "go.mod", "internal/audit/audit_test.go", "internal/audit/status.go",
	"internal/codegen/generator_test.go", "internal/codegen/templates.go",
	"internal/crypto/auth/handshake_test.go", "internal/runtime/implementation_support_test.go",
}
var policyPhase8WO802PathsV1 = []string{
	"docs/KZ-evidence-ref-031",
	"docs/third-party/phase8-profile-cryptography.md",
	"go.mod",
	"go.sum",
	"internal/product/envelope/phase8_evidence_test.go",
	"internal/product/envelope/phase8_suite.go",
	"internal/product/envelope/phase8_suite_test.go",
	"testdata/evidence/independent/phase8_interop.py",
	"testdata/evidence/independent/regenerate_phase8_interop.ps1",
	"testdata/evidence/independent/requirements-win-amd64-py312.lock",
	"testdata/evidence/phase8-independent-interop-report.json",
	"testdata/evidence/phase8-prohibited-composition-report.json",
	"testdata/evidence/phase8-suite-decision-matrix.json",
	"testdata/evidence/phase8-toolchain-randomness-report.json",
}
var policyPhase8WO804PathsV1 = []string{
	"docs/KZ-evidence-ref-032",
	"internal/product/profile/phase8_providers.go",
	"internal/product/profile/phase8_providers_test.go",
	"internal/product/profile/testdata/delegation-negative-report.json",
	"internal/product/profile/testdata/emergency-authority-report.json",
	"internal/product/profile/testdata/recipient-registrar-negative-report.json",
	"internal/product/profile/testdata/role-confusion-report.json",
	"internal/product/profile/testdata/root-emergency-negative-report.json",
	"internal/product/profile/testdata/test-provider-hygiene-report.json",
}
var policyPhase8WO803PathsV1 = []string{
	"docs/KZ-evidence-ref-033",
	"internal/product/envelope/phase8_ingress.go",
	"internal/product/envelope/phase8_profile_codec.go",
	"internal/product/envelope/phase8_profile_codec_fuzz_test.go",
	"internal/product/envelope/phase8_profile_codec_test.go",
	"internal/product/envelope/testdata/phase8-codec/canonical-profile-v1.hex",
	"internal/product/envelope/testdata/phase8-codec/fuzz-profile.txt",
	"internal/product/envelope/testdata/phase8-codec/fuzz-qr.txt",
	"internal/product/envelope/testdata/phase8-codec/fuzz-sealed.txt",
	"internal/product/envelope/testdata/phase8-codec/fuzz-signed.txt",
	"internal/product/envelope/testdata/phase8-codec/fuzz-transcript.json",
	"internal/product/envelope/testdata/phase8-codec/fuzz-uri.txt",
	"internal/product/envelope/testdata/phase8-codec/ingress-normalization-report.json",
	"internal/product/envelope/testdata/phase8-codec/malformed-envelope-report.json",
	"internal/product/envelope/testdata/phase8-codec/reference-host-resource-raw.json",
	"internal/product/envelope/testdata/phase8-codec/reference-host-resource-report.json",
	"internal/testkit/phase8fixturegen/main.go",
	"internal/testkit/phase8resourcecapture/main.go",
}
var policyPhase8WO805PathsV1 = []string{
	"docs/KZ-evidence-ref-034",
	"internal/product/envelope/phase8_verified_headers.go",
	"internal/product/envelope/phase8_verified_headers_test.go",
	"internal/product/lifecycle/phase8_verified.go",
	"internal/product/lifecycle/phase8_verified_fuzz_test.go",
	"internal/product/lifecycle/phase8_verified_test.go",
	"internal/product/profile/phase8_activation.go",
	"internal/product/profile/phase8_activation_evidence_test.go",
	"internal/product/profile/phase8_activation_fuzz_test.go",
	"internal/product/profile/phase8_activation_test.go",
	"internal/product/profile/testdata/phase8-activation/activation-crash-report.json",
	"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
	"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json",
	"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json",
	"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
	"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json",
}
var policyPhase8WO806PathsV1 = []string{
	"cmd/kprofile/main.go",
	"cmd/kprofile/main_test.go",
	"cmd/kprofile/path_other.go",
	"cmd/kprofile/path_windows.go",
	"docs/KZ-evidence-ref-035",
	"internal/product/profile/phase8_tooling.go",
	"internal/product/profile/phase8_tooling_evidence_test.go",
	"internal/product/profile/phase8_tooling_external_test.go",
	"internal/product/profile/testdata/phase8-issuance/device-recipient.bin",
	"internal/product/profile/testdata/phase8-issuance/encrypted-backup.bin",
	"internal/product/profile/testdata/phase8-issuance/fixture-manifest.json",
	"internal/product/profile/testdata/phase8-issuance/fixture-reproduction-report.json",
	"internal/product/profile/testdata/phase8-issuance/invalid-generation.json",
	"internal/product/profile/testdata/phase8-issuance/invalid-tamper.bin",
	"internal/product/profile/testdata/phase8-issuance/invalid-truncation.bin",
	"internal/product/profile/testdata/phase8-issuance/invalid-wrong-header.json",
	"internal/product/profile/testdata/phase8-issuance/invalid-wrong-recipient.json",
	"internal/product/profile/testdata/phase8-issuance/invalid-wrong-role.json",
	"internal/product/profile/testdata/phase8-issuance/issuance-negative-report.json",
	"internal/product/profile/testdata/phase8-issuance/issuance-roundtrip-report.json",
	"internal/product/profile/testdata/phase8-issuance/offline-boundary-report.json",
	"internal/product/profile/testdata/phase8-issuance/production-wiring-negative-report.json",
	"internal/product/profile/testdata/phase8-issuance/provider-group-recipient.bin",
	"internal/product/profile/testdata/phase8-issuance/redacted-inspect-report.json",
	"internal/product/profile/testdata/phase8-issuance/signed-public.bin",
	"internal/testkit/phase8issuance/provider.go",
	"internal/testkit/phase8issuancefixture/cmd/main.go",
	"internal/testkit/phase8issuancefixture/generate.go",
	"internal/testkit/phase8issuancefixture/isolation_test.go",
}
var policyPhase8WO807PathsV1 = []string{
	"docs/KZ-evidence-ref-036",
	"docs/PZ-evidence-ref-064",
	"docs/PZ-evidence-ref-065",
	"internal/product/envelope/phase8_assurance_test.go",
	"internal/product/profile/phase8_local_activation.go",
	"internal/product/profile/phase8_recovery_test.go",
	"internal/product/profile/testdata/fuzz/FuzzActivateVerifiedProfileStateMachine/5c3e9efa06c432c0",
	"internal/testkit/phase8assurance/cmd/main.go",
	"internal/testkit/phase8assurance/manifest.go",
	"testdata/evidence/phase8-fuzz-campaign-report.json",
	"testdata/evidence/phase8-fuzz-command-manifest.json",
	"testdata/evidence/phase8-release-corpus-manifest.json",
	"testdata/evidence/phase8-wo807-recovery-report.json",
}
var policyPhase8WO808PathsV1 = []string{
	"README.md",
	"RZ-evidence-ref-069",
	"docs/GZ-evidence-ref-001",
	"docs/sb-evidence-ref-068",
	"cmd/gate/main.go",
	".github/workflows/ci.yml",
	"internal/product/envelope/phase8_suite_test.go",
	"testdata/evidence/independent/phase8_interop.py",
	"testdata/evidence/phase8-independent-interop-report.json",
	"internal/product/envelope/phase8_profile_codec.go",
	"internal/product/envelope/phase8_profile_codec_test.go",
	"cmd/kprofile/main.go",
	"cmd/kprofile/main_test.go",
	"internal/product/profile/testdata/phase8-issuance/offline-boundary-report.json",
	"internal/product/profile/testdata/phase8-issuance/redacted-inspect-report.json",
	"internal/audit/security.go",
	"internal/audit/security_test.go",
	"internal/runtime/policy_enforcement_test.go",
	"internal/testkit/importrules/importrules_test.go",
	"cmd/kgen/main_test.go",
	"internal/audit/codegen_test.go",
	"internal/codegen/authorization_v1_test.go",
	".gitignore",
	"internal/audit/status.go",
	"cmd/kprofile/path_other.go",
	"cmd/kprofile/path_unsupported.go",
	"cmd/kprofile/path_windows_test.go",
	"cmd/kprofile/path_windows.go",
	"cmd/kprofile/path.go",
	"docs/KZ-evidence-ref-036",
	"docs/PZ-evidence-ref-064",
	"docs/PZ-evidence-ref-065",
	"internal/product/envelope/phase8_evidence_test.go",
	"internal/product/envelope/phase8_suite.go",
	"internal/product/profile/phase8_activation_test.go",
	"internal/product/profile/phase8_activation.go",
	"internal/product/profile/phase8_providers.go",
	"internal/product/profile/phase8_tooling_evidence_test.go",
	"internal/product/profile/phase8_tooling_external_test.go",
	"internal/product/profile/phase8_tooling.go",
	"internal/product/profile/testdata/phase8-activation/activation-crash-report.json",
	"internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
	"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json",
	"internal/product/profile/testdata/phase8-activation/policy-bypass-report.json",
	"internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
	"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json",
	"internal/product/profile/testdata/phase8-issuance/fixture-manifest.json",
	"internal/product/profile/testdata/phase8-issuance/fixture-reproduction-report.json",
	"internal/product/profile/testdata/phase8-issuance/issuance-negative-report.json",
	"internal/product/profile/testdata/phase8-issuance/issuance-roundtrip-report.json",
	"internal/product/profile/testdata/phase8-issuance/production-wiring-negative-report.json",
	"internal/testkit/phase8fixturegen/main_test.go",
	"internal/testkit/phase8fixturegen/main.go",
	"internal/testkit/phase8issuancefixture/generate.go",
	"SZ-evidence-ref-070",
	"testdata/evidence/phase8-release-corpus-manifest.json",
	"testdata/evidence/phase8-wo807-recovery-report.json",
	"testdata/evidence/phase1-m0-committed-sha256.json",
}

func validatePolicyMaintenanceStatusV1(root string, changed, historical map[string]bool) error {
	if len(changed) != 0 && exactPathSetV1(changed, historical) {
		return nil
	}
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		return err
	}
	var manifest struct {
		MaintenanceOverlays                 map[string]policyMaintenanceOverlayV1    `json:"maintenance_overlays"`
		HelperOwnerOverlays                 map[string]policyLayeredOverlayV1        `json:"helper_owner_overlays"`
		ValidatorOverlays                   map[string]policyLayeredOverlayV1        `json:"validator_overlays"`
		ValidatorConsumerOverlays           map[string]policyLayeredOverlayV1        `json:"validator_consumer_overlays"`
		EvidenceConvergenceOverlays         map[string]policyLayeredOverlayV1        `json:"evidence_convergence_overlays"`
		Phase2CompleteOverlays              map[string]policyPhase2CompleteOverlayV1 `json:"phase2_complete_overlays"`
		Phase3ContractOverlays              map[string]policyPhase2CompleteOverlayV1 `json:"phase3_contract_overlays"`
		Phase4FallbackOverlays              map[string]policyPhase2CompleteOverlayV1 `json:"phase4_fallback_overlays"`
		Phase5RelayDescriptorOverlays       map[string]policyPhase2CompleteOverlayV1 `json:"phase5_relay_descriptor_overlays"`
		Phase6DiagnosticExportOverlays      map[string]policyPhase2CompleteOverlayV1 `json:"phase6_diagnostic_export_overlays"`
		Phase7AppRuntimeOverlays            map[string]policyPhase2CompleteOverlayV1 `json:"phase7_app_runtime_overlays"`
		BaselineStabilizationOverlays       map[string]policyPhase2CompleteOverlayV1 `json:"baseline_stabilization_overlays"`
		Phase8ProfileCryptographyOverlays   map[string]policyPhase2CompleteOverlayV1 `json:"phase8_profile_cryptography_overlays"`
		Phase8WO801ThreatModelOverlays      map[string]policyPhase2CompleteOverlayV1 `json:"phase8_wo801_threat_model_overlays"`
		Phase8WO801AdoptionOverlays         map[string]policyPhase2CompleteOverlayV1 `json:"phase8_wo801_adoption_overlays"`
		Phase9GuardMaintenanceOverlays      map[string]policyMaintenanceOverlayV1    `json:"phase9_guard_maintenance_overlays"`
		Phase10VPNRuntimeOverlays           map[string]policyMaintenanceOverlayV1    `json:"phase10_vpn_runtime_overlays"`
		Phase11LocalTransportOverlays       map[string]policyMaintenanceOverlayV1    `json:"phase11_local_transport_overlays"`
		Phase12OperatorControlPlaneOverlays map[string]policyMaintenanceOverlayV1    `json:"phase12_operator_control_plane_overlays"`
		Phase13AndroidProductOverlays       map[string]policyMaintenanceOverlayV1    `json:"phase13_android_product_overlays"`
		Phase14AssuranceOverlays            map[string]policyMaintenanceOverlayV1    `json:"phase14_assurance_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return err
	}
	phase14Pre, err := validatePolicyPhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		return err
	}
	phase13Pre, err := validatePolicyPhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		return err
	}
	phase12Pre, err := validatePolicyPhase12OperatorControlPlaneOverlayAtPostV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		return err
	}
	phase11Pre, err := validatePolicyPhase11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
	if err != nil {
		return err
	}
	phase10Pre, err := validatePolicyPhase10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
	if err != nil {
		return err
	}
	if _, err := validatePolicyPhase9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, manifest.Phase9GuardMaintenanceOverlays); err != nil {
		return err
	}
	phase11OverlayPaths := make(map[string]bool, len(phase11Pre))
	for path := range phase11Pre {
		phase11OverlayPaths[path] = true
		// The historical Phase 11-14 overlay chain has already verified the
		// exact current content above. Successor overlays may absorb most of a
		// dirty historical phase while leaving a smaller, still-valid subset in
		// git status, so remove those independently verified paths before the
		// physical-status shape check.
		delete(changed, path)
	}
	// A clean checkout is the committed Phase 10 state only after its complete
	// path and content overlay has validated above.
	if len(changed) == 0 {
		return nil
	}
	phase15Pre, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return err
	}
	phase15Changed := map[string]bool{evidenceoverlay.SuccessorPath: true}
	for path := range phase15Pre {
		phase15Changed[path] = true
	}
	if exactPathSetV1(changed, phase15Changed) {
		return nil
	}
	phase10Changed := map[string]bool{policyMaintenanceManifestPathV1: true}
	phase10OverlayPaths := make(map[string]bool)
	for _, overlay := range manifest.Phase10VPNRuntimeOverlays {
		for _, path := range overlay.Paths {
			phase10Changed[path] = true
			phase10OverlayPaths[path] = true
		}
	}
	if exactPathSetV1(changed, phase10Changed) || policyPhase9MaintenanceDirtyPathSetV1(changed, phase10OverlayPaths) {
		return nil
	}
	phase9Changed := map[string]bool{policyMaintenanceManifestPathV1: true}
	phase9OverlayPaths := make(map[string]bool)
	for _, overlay := range manifest.Phase9GuardMaintenanceOverlays {
		for _, path := range overlay.Paths {
			phase9Changed[path] = true
			phase9OverlayPaths[path] = true
		}
	}
	combinedChanged := make(map[string]bool, len(phase9Changed)+len(phase10Changed))
	for path := range phase9Changed {
		combinedChanged[path] = true
	}
	for path := range phase10Changed {
		combinedChanged[path] = true
	}
	for path := range phase11OverlayPaths {
		combinedChanged[path] = true
	}
	if exactPathSetV1(changed, combinedChanged) || policyPhase9MaintenanceDirtyPathSetV1(changed, combinedChanged) {
		return nil
	}
	if exactPathSetV1(changed, phase9Changed) || policyPhase9MaintenanceDirtyPathSetV1(changed, phase9OverlayPaths) {
		return nil
	}
	// Validate the explicit historical/fixture inventory, including unexpected
	// paths. A live diff or untracked-file scan must never substitute another
	// subject or turn an invalid supplied inventory into an empty accepted one.
	return validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays)
}

func validatePolicyPhase14AssuranceOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase14-assurance-v1"
	const predecessorBinding = "9a06e73ef9659dd10dd1c58c53955029b0116d7bd8c0ffa0856b0fa7c3ab230a"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.SelfPath != policyMaintenanceManifestPathV1 || !validPolicySHA256V1(overlay.SelfPreSHA256) || len(overlay.Paths) == 0 || len(overlay.Paths) > 256 || len(overlay.Paths) != len(overlay.Entries) {
		return nil, fmt.Errorf("invalid phase14 assurance overlay identity/cardinality")
	}
	successor, err := evidenceoverlay.LoadSuccessor(root, "phase15-production-contract-v1")
	if err != nil {
		return nil, fmt.Errorf("load Phase 15 successor overlay: %w", err)
	}
	pre := make(map[string]string, len(successor)+len(overlay.Paths))
	for path, hash := range successor {
		pre[path] = hash
	}
	binding := sha256.New()
	_, _ = fmt.Fprintln(binding, overlay.SelfPreSHA256)
	last := ""
	for index, path := range overlay.Paths {
		entry := overlay.Entries[index]
		if path != entry.Path || path <= last || path == overlay.SelfPath || strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase14 assurance overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase14 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validPolicySHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase14 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, found := successor[path]
		if !found {
			actual, err = policyFileSHA256V1(root, path)
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

func validatePolicyPhase13AndroidProductOverlayV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase13-android-product-v1"
	const predecessorBinding = "93020d6f615b9706dda3bf719ddbffeafa838837f0ec15d3e89ad395d1950c6c"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != policyMaintenanceManifestPathV1 || !validPolicySHA256V1(overlay.SelfPreSHA256) ||
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
			!validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase13 Android product overlay entry %d", index)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase13 absent predecessor %d", index)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validPolicySHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase13 predecessor %d", index)
		}
		_, _ = fmt.Fprintf(binding, "%s\x00%s\n", path, predecessor)
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, path)
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

func validatePolicyPhase12OperatorControlPlaneOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	return validatePolicyPhase12OperatorControlPlaneOverlayAtPostV1(root, nil, overlays)
}

func validatePolicyPhase12OperatorControlPlaneOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase12-operator-control-plane-v1"
	paths := []string{
		"RZ-evidence-ref-069",
		"cmd/gate/main.go",
		"cmd/gate/main_test.go",
		"cmd/kgen/main_test.go",
		"cmd/koperator/evidence_test.go",
		"cmd/koperator/main.go",
		"cmd/koperator/main_test.go",
		"cmd/phase9verify/phase11_overlay_test.go",
		"docs/KZ-evidence-ref-041",
		"docs/PZ-evidence-ref-049",
		"docs/sb-evidence-ref-068",
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
		"RZ-evidence-ref-069":                                                              "586a5e7f377c1809eb67cfe932d996ae81703bb562f52b539935e26ccdc93e8b",
		"cmd/gate/main.go":                                                                 "8f0e4e86384ea012ac54f1c9f795c3a4f760b5ab6c7f4b24f3ab553cad3c96c1",
		"cmd/gate/main_test.go":                                                            "c2b868ec7b155ed5ae95f667181284af9672722ceea8b3c018f4dd32df2d4fdd",
		"cmd/kgen/main_test.go":                                                            "2fabad2630c546749cde3c0c67dd9885ffa855230c298dacb741c65ef497c846",
		"cmd/phase9verify/phase11_overlay_test.go":                                         "95c7e090b93beab82e673513735e6725e1f636f10244a6b37b504adc91cb3a67",
		"docs/sb-evidence-ref-068":                                                         "2846c0453c9a20d8fee0a355d339ba70f658d3f064e2dcd6ddef693d7bbb50b0",
		"internal/audit/codegen_test.go":                                                   "c1896696926104de33e540f207c4cc3e7f477edfddc006cfc9f279dd34e5df94",
		"internal/audit/security.go":                                                       "a180d1b42b37ac390a1bdf718a4c8172cafc8f14b8afd9c46c24831fe461cbe9",
		"internal/audit/security_test.go":                                                  "b4674dd844d0f006fe83ced7fbd6855a309e1bbd76ac1cd2fb6c8a73711a5519",
		"internal/codegen/authorization_v1_test.go":                                        "e2d8caf8757c35bc9e1aea7ba6c5a129d328f507d9aa54889223b83e536e4c51",
		"internal/codegen/generator_templates.go":                                          "53651959c9fbc7a936c23d4ae6cf5e4821e2322befc38596cbf215f3f24ff643",
		"internal/codegen/generator_test.go":                                               "2a519ad4aaf1d0ba4e4f9cf6294dc0772059f677e82a113b81c3712ac2832f31",
		"internal/product/lifecycle/phase8_verified.go":                                    "e9fd50ec54dca326be6580815153a3983555f1b31ea028e4a3c052257e7e17c6",
		"internal/product/lifecycle/phase8_verified_test.go":                               "7e3aad03d9af6dcec588c37225c4791cce3d38c7d0b3dfb7c69218b3ae5e5769",
		"internal/product/profile/phase8_activation.go":                                    "3de078f241b4bd4da039891cf19db34f30eae083363cd23ea21b393d88a3a080",
		"internal/product/profile/phase8_providers.go":                                     "9bf824c879fc0186de623f4c6a589a0ef2dce0cefb33b6168397363cd0a5f33c",
		"internal/product/profile/testdata/phase8-activation/activation-crash-report.json": "4e710e1683d0e68274d1403443c342dacbbb1e67033ced503bc0d389165609f0",
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
		overlay.SelfPath != policyMaintenanceManifestPathV1 ||
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
		if overlay.Paths[i] != path || entry.Path != path || !validPolicySHA256V1(entry.PostSHA256) {
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
			actual, err = policyFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase12 operator control-plane hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
	}
	return pre, nil
}

func validatePolicyPhase11LocalTransportOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	return validatePolicyPhase11LocalTransportOverlayAtPostV1(root, nil, overlays)
}

func validatePolicyPhase11LocalTransportOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase11-local-transport-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != policyMaintenanceManifestPathV1 ||
		!validPolicySHA256V1(overlay.SelfPreSHA256) ||
		len(overlay.Paths) == 0 || len(overlay.Paths) > 128 ||
		len(overlay.Entries) != len(overlay.Paths) {
		return nil, fmt.Errorf("invalid phase11 local-transport overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost)+len(overlay.Paths))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	lastPath := ""
	for i, path := range overlay.Paths {
		entry := overlay.Entries[i]
		if entry.Path != path || path <= lastPath || path == policyMaintenanceManifestPathV1 ||
			strings.HasPrefix(path, ".tools/") || strings.HasPrefix(path, "planning/") ||
			!validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase11 local-transport entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase11 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validPolicySHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase11 existing predecessor %d", i)
		}
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase11 local-transport hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	return pre, nil
}

func policyPhase9MaintenanceDirtyPathSetV1(changed, overlayPaths map[string]bool) bool {
	if len(changed) < 2 || !changed[policyMaintenanceManifestPathV1] {
		return false
	}
	for path := range changed {
		if path != policyMaintenanceManifestPathV1 && !overlayPaths[path] {
			return false
		}
	}
	return true
}

func TestPolicyPhase9MaintenanceDirtyPathSetV1(t *testing.T) {
	overlayPaths := map[string]bool{"authorized.txt": true}
	for name, tc := range map[string]struct {
		changed map[string]bool
		want    bool
	}{
		"exact maintenance subset": {
			changed: map[string]bool{policyMaintenanceManifestPathV1: true, "authorized.txt": true},
			want:    true,
		},
		"manifest only": {
			changed: map[string]bool{policyMaintenanceManifestPathV1: true},
		},
		"missing manifest": {
			changed: map[string]bool{"authorized.txt": true},
		},
		"unauthorized path": {
			changed: map[string]bool{policyMaintenanceManifestPathV1: true, "other.txt": true},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := policyPhase9MaintenanceDirtyPathSetV1(tc.changed, overlayPaths); got != tc.want {
				t.Fatalf("policyPhase9MaintenanceDirtyPathSetV1()=%v want %v", got, tc.want)
			}
		})
	}
}

func validatePolicyM2ComposedStateV1(root string, changed map[string]bool, maintenanceOverlays map[string]policyMaintenanceOverlayV1, helperOverlays, validatorOverlays, consumerOverlays, convergenceOverlays map[string]policyLayeredOverlayV1, wo801Overlays, phase8Overlays, baselineOverlays, phase7Overlays, phase6Overlays, phase5Overlays, phase4Overlays, phase3Overlays, phase2Overlays map[string]policyPhase2CompleteOverlayV1) error {
	want, err := policyM2ComposedPathSetV1(wo801Overlays, phase8Overlays, phase7Overlays, phase6Overlays, phase5Overlays, phase4Overlays, phase3Overlays)
	if err != nil {
		return err
	}
	currentAtWO801, err := loadPolicyWO801AdoptionV1(root)
	if err != nil {
		return err
	}
	if !exactPathSetV1(changed, want) {
		return fmt.Errorf("repository status matches neither historical M0 nor exact composed M2 state: paths=%d", len(changed))
	}
	currentAtWO800, err := validatePolicyPhase8WO801ThreatModelAtPostV1(root, currentAtWO801, wo801Overlays)
	if err != nil {
		return err
	}
	for path, hash := range currentAtWO801 {
		if _, replaced := currentAtWO800[path]; !replaced {
			currentAtWO800[path] = hash
		}
	}
	currentAtPhase8, err := validatePolicyPhase8ProfileCryptographyAtPostV1(root, currentAtWO800, phase8Overlays)
	if err != nil {
		return err
	}
	for path, hash := range currentAtWO800 {
		if _, replaced := currentAtPhase8[path]; !replaced {
			currentAtPhase8[path] = hash
		}
	}
	currentAtM7, err := validatePolicyBaselineStabilizationV1(root, currentAtPhase8, baselineOverlays)
	if err != nil {
		return err
	}
	currentAtM6, err := validatePolicyPhase7AppRuntimeV1(root, currentAtM7, phase7Overlays)
	if err != nil {
		return err
	}
	currentAtM5, err := validatePolicyPhase6DiagnosticExportV1(root, currentAtM6, phase6Overlays)
	if err != nil {
		return err
	}
	currentAtM4, err := validatePolicyPhase5RelayDescriptorV1(root, currentAtM5, phase5Overlays)
	if err != nil {
		return err
	}
	currentAtM3, err := validatePolicyPhase4FallbackV1(root, currentAtM4, phase4Overlays)
	if err != nil {
		return err
	}
	currentAtM2, err := validatePolicyPhase3ContractV1(root, currentAtM3, phase3Overlays)
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

func policyM2ComposedPathSetV1(wo801Overlays, phase8Overlays, phase7Overlays, phase6Overlays, phase5Overlays, phase4Overlays, phase3Overlays map[string]policyPhase2CompleteOverlayV1) (map[string]bool, error) {
	want := map[string]bool{}
	pathGroups := [][]string{
		policyPhase2CompletePathsV1,
		phase3Overlays["m3-profile-lifecycle-contract-v1"].Paths,
		phase4Overlays["m4-permitted-fallback-contract-v1"].Paths,
		phase5Overlays["m5-offline-relay-descriptor-admission-v1"].Paths,
		phase6Overlays["m6-offline-diagnostic-export-contract-v1"].Paths,
		phase7Overlays["m7-offline-app-runtime-contract-v1"].Paths,
		phase8Overlays["phase8-profile-cryptography-authorization-v1"].Paths,
		wo801Overlays["phase8-wo801-threat-model-v1"].Paths,
		{"testdata/evidence/phase8-wo801-adoption-2026-07-17.json", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", policyMaintenanceManifestPathV1},
		policyStabilizationPathsV1,
	}
	for _, paths := range pathGroups {
		for _, path := range paths {
			want[path] = true
		}
	}
	if len(policyPhase8WO802PathsV1) != 14 {
		return nil, fmt.Errorf("invalid phase8 WO-802 path cardinality")
	}
	seen := map[string]bool{}
	for _, path := range policyPhase8WO802PathsV1 {
		if path == "" || seen[path] {
			return nil, fmt.Errorf("invalid phase8 WO-802 path %q", path)
		}
		seen[path] = true
		want[path] = true
	}
	if len(policyPhase8WO804PathsV1) != 9 {
		return nil, fmt.Errorf("invalid phase8 WO-804 path cardinality")
	}
	for _, path := range policyPhase8WO804PathsV1 {
		if path == "" || seen[path] {
			return nil, fmt.Errorf("invalid phase8 WO-804 path %q", path)
		}
		seen[path] = true
		want[path] = true
	}
	if len(policyPhase8WO803PathsV1) != 18 {
		return nil, fmt.Errorf("invalid phase8 WO-803 path cardinality")
	}
	for _, path := range policyPhase8WO803PathsV1 {
		if path == "" || seen[path] {
			return nil, fmt.Errorf("invalid phase8 WO-803 path %q", path)
		}
		seen[path] = true
		want[path] = true
	}
	if len(policyPhase8WO805PathsV1) != 16 {
		return nil, fmt.Errorf("invalid phase8 WO-805 path cardinality")
	}
	for _, path := range policyPhase8WO805PathsV1 {
		if path == "" || seen[path] {
			return nil, fmt.Errorf("invalid phase8 WO-805 path %q", path)
		}
		seen[path] = true
		want[path] = true
	}
	if len(policyPhase8WO806PathsV1) != 29 {
		return nil, fmt.Errorf("invalid phase8 WO-806 path cardinality")
	}
	for _, path := range policyPhase8WO806PathsV1 {
		if path == "" || seen[path] {
			return nil, fmt.Errorf("invalid phase8 WO-806 path %q", path)
		}
		seen[path] = true
		want[path] = true
	}
	if len(policyPhase8WO807PathsV1) != 13 {
		return nil, fmt.Errorf("invalid phase8 WO-807 path cardinality")
	}
	for _, path := range policyPhase8WO807PathsV1 {
		if path == "" || seen[path] {
			return nil, fmt.Errorf("invalid phase8 WO-807 path %q", path)
		}
		seen[path] = true
		want[path] = true
	}
	if len(policyPhase8WO808PathsV1) != 58 {
		return nil, fmt.Errorf("invalid phase8 WO-808 path cardinality")
	}
	for _, path := range policyPhase8WO808PathsV1 {
		if path == "" {
			return nil, fmt.Errorf("invalid phase8 WO-808 path")
		}
		want[path] = true
	}
	if len(want) != 166 {
		return nil, fmt.Errorf("invalid composed phase8 path cardinality: got %d want 166", len(want))
	}
	return want, nil
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

func validatePolicyPhase8ProfileCryptographyV1(root string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	return validatePolicyPhase8ProfileCryptographyAtPostV1(root, nil, overlays)
}

func validatePolicyPhase8ProfileCryptographyAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-profile-cryptography-authorization-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/GZ-evidence-ref-001", "docs/sb-evidence-ref-068", "docs/KZ-evidence-ref-020",
		"docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023", "docs/KZ-evidence-ref-024",
		"docs/KZ-evidence-ref-029", "testdata/evidence/phase8-stabilization-baseline-2026-07-17.json",
		"cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go",
		policyMaintenanceManifestPathV1,
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
		if entry.Path != wantPaths[i] || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography entry %d", i)
		}
		wantAbsent := i == 7 || i == 8
		if wantAbsent != (entry.PreEvidence == "ABSENT") {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor %d", i)
		}
		if !wantAbsent && !validPolicySHA256V1(entry.PreEvidence) {
			return nil, fmt.Errorf("invalid phase8 profile cryptography predecessor hash %d", i)
		}
		if want, guarded := wantStabilized[entry.Path]; guarded && entry.PreEvidence != want {
			return nil, fmt.Errorf("phase8 profile cryptography reconstruction drift %s", entry.Path)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
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

func validatePolicyPhase8WO801ThreatModelV1(root string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	return validatePolicyPhase8WO801ThreatModelAtPostV1(root, nil, overlays)
}

func validatePolicyPhase8WO801ThreatModelAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-threat-model-v1"
	wantPaths := []string{
		"docs/KZ-evidence-ref-030",
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
		policyMaintenanceManifestPathV1,
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
		if entry.Path != wantPaths[i] || !validPolicySHA256V1(entry.PostSHA256) {
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
			actual, err = policyFileSHA256V1(root, entry.Path)
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

type policyWO812ManifestV1 struct {
	Phase8WO801AdoptionOverlays         map[string]policyPhase2CompleteOverlayV1  `json:"phase8_wo801_adoption_overlays"`
	Phase8WorkOrderOverlays             map[string]policyPhase8WorkOrderOverlayV1 `json:"phase8_work_order_overlays"`
	Phase8GuardMaintenanceOverlays      map[string]policyMaintenanceOverlayV1     `json:"phase8_guard_maintenance_overlays"`
	Phase8FinalGuardMaintenanceOverlays map[string]policyMaintenanceOverlayV1     `json:"phase8_final_guard_maintenance_overlays"`
	Phase9GuardMaintenanceOverlays      map[string]policyMaintenanceOverlayV1     `json:"phase9_guard_maintenance_overlays"`
	Phase10VPNRuntimeOverlays           map[string]policyMaintenanceOverlayV1     `json:"phase10_vpn_runtime_overlays"`
}

func loadPolicyWO801AdoptionV1(root string) (map[string]string, error) {
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		return nil, err
	}
	var m policyWO812ManifestV1
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	phase9Pre, err := validatePolicyPhase9GuardMaintenanceOverlayV1(root, m.Phase9GuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	finalGuardPre, err := validatePolicyPhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, m.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	pre, err := validatePolicyPhase8WorkOrderOverlayChainAtPostV1(root, finalGuardPre, m.Phase8WorkOrderOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range finalGuardPre {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := pre[path]; !replaced {
			pre[path] = hash
		}
	}
	guardPre, err := validatePolicyPhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, m.Phase8GuardMaintenanceOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range guardPre {
		if hash == "ABSENT" {
			continue
		}
		pre[path] = hash
	}
	currentAtWO801, err := validatePolicyPhase8WO801AdoptionAtPostV1(root, pre, m.Phase8WO801AdoptionOverlays)
	if err != nil {
		return nil, err
	}
	for path, hash := range pre {
		if hash == "ABSENT" {
			continue
		}
		if _, replaced := currentAtWO801[path]; !replaced {
			currentAtWO801[path] = hash
		}
	}
	return currentAtWO801, nil
}
func validatePolicyPhase8WO801AdoptionV1(root string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	return validatePolicyPhase8WO801AdoptionAtPostV1(root, nil, overlays)
}

func policyPhase8WorkOrderOverlaySHA256V1(o policyPhase8WorkOrderOverlayV1) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", o.Version, o.PredecessorOverlaySHA256)
	for i, path := range o.Paths {
		fmt.Fprintf(h, "path:%s\n%s%c%s%c%s\n", path, o.Entries[i].Path, byte(0), o.Entries[i].PreEvidence, byte(0), o.Entries[i].PostSHA256)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func validatePolicyPhase8WorkOrderOverlayChainV1(root string, overlays map[string]policyPhase8WorkOrderOverlayV1) (map[string]string, error) {
	return validatePolicyPhase8WorkOrderOverlayChainAtPostV1(root, nil, overlays)
}

func validatePolicyPhase8WorkOrderOverlayChainAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase8WorkOrderOverlayV1) (map[string]string, error) {
	type expected struct {
		name, workOrder, predecessor, binding string
		cardinality                           int
	}
	want := []expected{
		{"phase8-wo802-standards-suite-v1", "evidence/publication-ref-802", "2a086c7cc686f4ff27e040684d9e5c33c7d0fc0cb6f9746bc0d637e41ccec6cf", "86ff9cc08f44e1313adc904901e4fc3ba5c40ec656beb29d2be2850118b5eb5a", 14},
		{"phase8-wo803-canonical-profile-codec-v1", "evidence/publication-ref-803", "86ff9cc08f44e1313adc904901e4fc3ba5c40ec656beb29d2be2850118b5eb5a", "ab4a13ecca60d4ad8eb8d091d915032a85130258eb11c721eaec93aaff033507", 18},
		{"phase8-wo804-trust-provider-boundaries-v1", "evidence/publication-ref-804", "ab4a13ecca60d4ad8eb8d091d915032a85130258eb11c721eaec93aaff033507", "07ea004c3e5edb52a20f030cdfb1352eb4e3ff54ed2a10acc6ff0998bb8b38bc", 9},
		{"phase8-wo805-verified-profile-activation-v1", "evidence/publication-ref-805", "07ea004c3e5edb52a20f030cdfb1352eb4e3ff54ed2a10acc6ff0998bb8b38bc", "62116f838e0ba5b01dd62be55d7eac84280cf8c6fd1bb392b4100104db4712e7", 16},
		{"phase8-wo806-offline-issuance-tooling-v1", "evidence/publication-ref-806", "62116f838e0ba5b01dd62be55d7eac84280cf8c6fd1bb392b4100104db4712e7", "acd3e082b430521ddcf1d077d34fa87d380ba385f5cc93b21117e1c3ef4e164c", 29},
		{"phase8-wo807-integrated-assurance-v1", "evidence/publication-ref-807", "acd3e082b430521ddcf1d077d34fa87d380ba385f5cc93b21117e1c3ef4e164c", "c6912fb21ef8c02585ccf63d4983896697a45396167b49566bd977eb35b9af7a", 13},
	}
	if len(overlays) != len(want) {
		return nil, fmt.Errorf("invalid phase8 work-order overlay cardinality")
	}
	pre := map[string]string{}
	for _, w := range want {
		o, ok := overlays[w.name]
		if !ok || o.Version != w.name || o.WorkOrderPath != w.workOrder || o.PredecessorOverlaySHA256 != w.predecessor || o.OverlaySHA256 != w.binding || len(o.Paths) != w.cardinality || len(o.Entries) != w.cardinality || policyPhase8WorkOrderOverlaySHA256V1(o) != w.binding {
			return nil, fmt.Errorf("invalid phase8 work-order overlay %s: version=%q work_order=%q predecessor=%q binding=%q computed=%q paths=%d entries=%d", w.name, o.Version, o.WorkOrderPath, o.PredecessorOverlaySHA256, o.OverlaySHA256, policyPhase8WorkOrderOverlaySHA256V1(o), len(o.Paths), len(o.Entries))
		}
		for i, entry := range o.Entries {
			if entry.Path != o.Paths[i] || (entry.PreEvidence != "ABSENT" && !validPolicySHA256V1(entry.PreEvidence)) || !validPolicySHA256V1(entry.PostSHA256) {
				return nil, fmt.Errorf("invalid phase8 work-order overlay entry %s[%d]", w.name, i)
			}
			actual, present := currentAtPost[entry.Path]
			var err error
			if !present {
				actual, err = policyFileSHA256V1(root, entry.Path)
			}
			if err != nil || actual != entry.PostSHA256 {
				return nil, fmt.Errorf("phase8 work-order hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePolicyPhase8GuardMaintenanceOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	return validatePolicyPhase8GuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validatePolicyPhase8GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase8-wo806-guard-convergence-v1"
	paths := []string{"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/codegen/authorization_v1_test.go", policyMaintenanceManifestPathV1}
	preHashes := []string{"10f4a412739c3896e88fb7b649774e0243ccfcfab2c77335b2e7ecaa8948f3ae", "8ed3f3c023baa71d60dbe81c94bb0e4254e8fcaf35b5c4b75d027b2c2290b15b", "1333f376b7ff19580719c40ec831a61ff6c66dd2ea90721a1d257370d698e45e", "4420c4c6582124b04c9330329bfedf213f2976f3c536cb2fa815ab28a28a1fb5", "c3fb2ce202af327107885f8a5866908cbd984aa74b09ee702514d6ed2442901d", "a7e40a30f7a30122bf23e538f8714890f3bba945799466cf378c3566160c4041", "a4664fe1fb3b6a6050af2c8e04eab51263ce32989e5d673c1ae35b97f7b8b79e"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != policyMaintenanceManifestPathV1 || o.SelfPreSHA256 != "37ece675df4e2f17bb253a3a5d648c3a7b6e62d9319fd27a138be00cedb3e77a" || len(o.Paths) != 8 || len(o.Entries) != 7 {
		return nil, fmt.Errorf("invalid phase8 guard-maintenance overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, path := range paths {
		if o.Paths[i] != path {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance path %d", i)
		}
	}
	for i, entry := range o.Entries {
		if entry.Path != paths[i] || entry.PreSHA256 != preHashes[i] || !validPolicySHA256V1(entry.PostSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase8 guard-maintenance entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreSHA256
	}
	return pre, nil
}

func validatePolicyPhase8FinalGuardMaintenanceOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	return validatePolicyPhase8FinalGuardMaintenanceOverlayAtPostV1(root, nil, overlays)
}

func validatePolicyPhase8FinalGuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase8-wo808-final-guard-convergence-v1"
	paths := []string{
		"README.md", "RZ-evidence-ref-069", "docs/GZ-evidence-ref-001",
		"docs/sb-evidence-ref-068", "cmd/gate/main.go", ".github/workflows/ci.yml",
		"internal/product/envelope/phase8_suite_test.go", "testdata/evidence/independent/phase8_interop.py", "testdata/evidence/phase8-independent-interop-report.json",
		"internal/product/envelope/phase8_profile_codec.go", "internal/product/envelope/phase8_profile_codec_test.go", "cmd/kprofile/main.go",
		"cmd/kprofile/main_test.go", "internal/product/profile/testdata/phase8-issuance/offline-boundary-report.json", "internal/product/profile/testdata/phase8-issuance/redacted-inspect-report.json",
		"internal/audit/security.go", "internal/audit/security_test.go", "internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go",
		"internal/codegen/authorization_v1_test.go", ".gitignore", "internal/audit/status.go",
		"cmd/kprofile/path_other.go", "cmd/kprofile/path_unsupported.go", "cmd/kprofile/path_windows_test.go",
		"cmd/kprofile/path_windows.go", "cmd/kprofile/path.go", "docs/KZ-evidence-ref-036",
		"docs/PZ-evidence-ref-064", "docs/PZ-evidence-ref-065", "internal/product/envelope/phase8_evidence_test.go",
		"internal/product/envelope/phase8_suite.go", "internal/product/profile/phase8_activation_test.go", "internal/product/profile/phase8_activation.go",
		"internal/product/profile/phase8_providers.go", "internal/product/profile/phase8_tooling_evidence_test.go", "internal/product/profile/phase8_tooling_external_test.go",
		"internal/product/profile/phase8_tooling.go", "internal/product/profile/testdata/phase8-activation/activation-crash-report.json", "internal/product/profile/testdata/phase8-activation/authenticated-hint-mismatch-report.json",
		"internal/product/profile/testdata/phase8-activation/last-known-good-negative-report.json", "internal/product/profile/testdata/phase8-activation/policy-bypass-report.json", "internal/product/profile/testdata/phase8-activation/revocation-generation-report.json",
		"internal/product/profile/testdata/phase8-activation/verify-before-semantics-report.json", "internal/product/profile/testdata/phase8-issuance/fixture-manifest.json", "internal/product/profile/testdata/phase8-issuance/fixture-reproduction-report.json",
		"internal/product/profile/testdata/phase8-issuance/issuance-negative-report.json", "internal/product/profile/testdata/phase8-issuance/issuance-roundtrip-report.json", "internal/product/profile/testdata/phase8-issuance/production-wiring-negative-report.json",
		"internal/testkit/phase8fixturegen/main_test.go", "internal/testkit/phase8fixturegen/main.go", "internal/testkit/phase8issuancefixture/generate.go",
		"SZ-evidence-ref-070", "testdata/evidence/phase8-release-corpus-manifest.json", "testdata/evidence/phase8-wo807-recovery-report.json",
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
	if len(overlays) != 1 || !ok || o.Version != name || o.SelfPath != policyMaintenanceManifestPathV1 || o.SelfPreSHA256 != "afcef52b1302379c2172815138219421e2dcf2b4e7280724f7c9ae4829d5f76a" || len(o.Paths) != len(paths) || len(o.Entries) != len(preHashes) {
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
		if entry.Path != paths[i] || !validPolicySHA256V1(entry.PostSHA256) {
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
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase8 final guard-maintenance hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = expectedPre
	}
	return pre, nil
}

func validatePolicyPhase10VPNRuntimeOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	return validatePolicyPhase10VPNRuntimeOverlayAtPostV1(root, nil, overlays)
}

func validatePolicyPhase10VPNRuntimeOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase10-local-vpn-runtime-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != policyMaintenanceManifestPathV1 ||
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
		if entry.Path != path || path <= lastPath || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase10 VPN runtime entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase10 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validPolicySHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase10 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase10 VPN runtime hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "a05d9436a931ac6286fa9c77f8d16cd24af6eb283c64168700de50dfb1278477" {
		return nil, fmt.Errorf("phase10 VPN runtime scope drift %s", got)
	}
	return pre, nil
}

func validatePolicyPhase9GuardMaintenanceOverlayV1(root string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		return nil, err
	}
	var manifest struct {
		Phase10VPNRuntimeOverlays           map[string]policyMaintenanceOverlayV1 `json:"phase10_vpn_runtime_overlays"`
		Phase11LocalTransportOverlays       map[string]policyMaintenanceOverlayV1 `json:"phase11_local_transport_overlays"`
		Phase12OperatorControlPlaneOverlays map[string]policyMaintenanceOverlayV1 `json:"phase12_operator_control_plane_overlays"`
		Phase13AndroidProductOverlays       map[string]policyMaintenanceOverlayV1 `json:"phase13_android_product_overlays"`
		Phase14AssuranceOverlays            map[string]policyMaintenanceOverlayV1 `json:"phase14_assurance_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return nil, err
	}
	phase14Pre, err := validatePolicyPhase14AssuranceOverlayV1(root, manifest.Phase14AssuranceOverlays)
	if err != nil {
		return nil, err
	}
	phase13Pre, err := validatePolicyPhase13AndroidProductOverlayV1(root, phase14Pre, manifest.Phase13AndroidProductOverlays)
	if err != nil {
		return nil, err
	}
	phase12Pre, err := validatePolicyPhase12OperatorControlPlaneOverlayAtPostV1(root, phase13Pre, manifest.Phase12OperatorControlPlaneOverlays)
	if err != nil {
		return nil, err
	}
	phase11Pre, err := validatePolicyPhase11LocalTransportOverlayAtPostV1(root, phase12Pre, manifest.Phase11LocalTransportOverlays)
	if err != nil {
		return nil, err
	}
	phase10Pre, err := validatePolicyPhase10VPNRuntimeOverlayAtPostV1(root, phase11Pre, manifest.Phase10VPNRuntimeOverlays)
	if err != nil {
		return nil, err
	}
	return validatePolicyPhase9GuardMaintenanceOverlayAtPostV1(root, phase10Pre, overlays)
}

func validatePolicyPhase9GuardMaintenanceOverlayAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyMaintenanceOverlayV1) (map[string]string, error) {
	const name = "phase9-wo909-final-guard-convergence-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name ||
		overlay.SelfPath != policyMaintenanceManifestPathV1 ||
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
		if entry.Path != path || path <= lastPath || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase9 guard-maintenance entry %d", i)
		}
		predecessor := entry.PreSHA256
		if entry.PreEvidence == "ABSENT" {
			if entry.PreSHA256 != "" {
				return nil, fmt.Errorf("invalid phase9 absent predecessor %d", i)
			}
			predecessor = "ABSENT"
		} else if entry.PreEvidence != "" || !validPolicySHA256V1(entry.PreSHA256) || entry.PreSHA256 == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid phase9 existing predecessor %d", i)
		}
		scope.Write([]byte(path))
		scope.Write([]byte{0})
		scope.Write([]byte(predecessor))
		scope.Write([]byte{'\n'})
		actual, present := currentAtPost[path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase9 guard-maintenance hash drift %s=%s want %s: %v", path, actual, entry.PostSHA256, err)
		}
		pre[path] = predecessor
		lastPath = path
	}
	if got := hex.EncodeToString(scope.Sum(nil)); got != "d7ea283af5423eef0dc6af53d6b3004b241ba1474b3f50a1899edfddc69c12a1" {
		return nil, fmt.Errorf("phase9 guard-maintenance scope drift %s", got)
	}
	return pre, nil
}

func validatePolicyPhase8WO801AdoptionAtPostV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "phase8-wo801-adoption-v1"
	paths := []string{"testdata/evidence/phase8-wo801-adoption-2026-07-17.json", "cmd/kgen/main_test.go", "internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go", "internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", policyMaintenanceManifestPathV1}
	want := map[string]string{"cmd/kgen/main_test.go": "f3756c80bd358535e929a8bffa4ef79129f346318fb6304fdd01abd6c915a846", "internal/audit/codegen_test.go": "00ac00353fda287944ba5fd1965a130830514b2807c5df1ea46eccbcc1299791", "internal/audit/security.go": "d71fc4a337b995790ee397b944e3d7cf47ba675dc9204eeb8b5f2c513250b73d", "internal/audit/security_test.go": "dba0df11ef69fa6364a262d2f3fdf4bb8046f089fa314148ed5a7ae13c4cf7d8", "internal/codegen/authorization_v1_test.go": "c9b8f29d924a37e1b2fbba5b6a69ef04fc6043e4c2e0f77aafd162edf66d5adc", "internal/runtime/policy_enforcement_test.go": "ab7ab4f454448750a82e5a50a8acfba96b08ca5c4c492539c371f4a6f9f49241", "internal/testkit/importrules/importrules_test.go": "1c465b2026c31246a3685f96849604d0879e0025e892fc6a4b3875bf0ef09a17"}
	o, ok := overlays[name]
	if len(overlays) != 1 || !ok || o.Version != name || o.PredecessorManifestSHA256 != "989df23699da6edfb8e5279752dbe66863a854b530a532119a2689320049c56f" || len(o.Paths) != 9 || len(o.Entries) != 8 {
		return nil, fmt.Errorf("invalid phase8 WO-801 adoption overlay identity/cardinality")
	}
	pre := map[string]string{}
	for i, p := range paths {
		if o.Paths[i] != p {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption path %d", i)
		}
	}
	for i, e := range o.Entries {
		if e.Path != paths[i] || !validPolicySHA256V1(e.PostSHA256) {
			return nil, fmt.Errorf("invalid phase8 WO-801 adoption entry %d", i)
		}
		if i == 0 {
			if e.PreEvidence != "ABSENT" {
				return nil, fmt.Errorf("invalid phase8 WO-801 adoption evidence predecessor")
			}
		} else if !validPolicySHA256V1(e.PreEvidence) || e.PreEvidence != want[e.Path] {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstruction drift %s", e.Path)
		}
		a, present := currentAtPost[e.Path]
		var err error
		if !present {
			a, err = policyFileSHA256V1(root, e.Path)
		}
		if err != nil || a != e.PostSHA256 {
			return nil, fmt.Errorf("phase8 WO-801 adoption current hash drift %s=%s want %s: %v", e.Path, a, e.PostSHA256, err)
		}
		if i > 0 {
			pre[e.Path] = e.PreEvidence
		}
	}
	for p, w := range want {
		if pre[p] != w {
			return nil, fmt.Errorf("phase8 WO-801 adoption reconstructed %s=%s want %s", p, pre[p], w)
		}
	}
	return pre, nil
}

func validatePolicyBaselineStabilizationV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "go126-clean-worktree-stabilization-v1"
	wantPaths := []string{
		"cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go",
		"internal/audit/security.go",
		"internal/audit/security_test.go",
		"internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go",
		"internal/testkit/importrules/importrules_test.go",
		policyMaintenanceManifestPathV1,
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
		if entry.Path != wantPaths[i] || !validPolicySHA256V1(entry.PreEvidence) || !validPolicySHA256V1(entry.PostSHA256) || entry.PreEvidence == entry.PostSHA256 {
			return nil, fmt.Errorf("invalid baseline stabilization entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("baseline stabilization hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		pre[entry.Path] = entry.PreEvidence
	}
	return pre, nil
}

func validatePolicyPhase7AppRuntimeV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m7-offline-app-runtime-contract-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-028", "internal/product/appruntime/appruntime.go", "internal/product/appruntime/appruntime_test.go",
		"testdata/consumer/m7-app-runtime-sdk/go.mod", "testdata/consumer/m7-app-runtime-sdk/app_runtime_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", policyMaintenanceManifestPathV1,
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
		if entry.Path != wantPaths[i] || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase7 app runtime entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase7 app runtime hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validPolicySHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase7 app runtime pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePolicyPhase6DiagnosticExportV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m6-offline-diagnostic-export-contract-v1"
	wantPaths := []string{
		"RZ-evidence-ref-069", "docs/KZ-evidence-ref-020", "docs/KZ-evidence-ref-022", "docs/KZ-evidence-ref-023",
		"docs/KZ-evidence-ref-027", "internal/product/diagnosticexport/diagnosticexport.go", "internal/product/diagnosticexport/diagnosticexport_test.go",
		"testdata/consumer/m6-diagnostic-export-sdk/go.mod", "testdata/consumer/m6-diagnostic-export-sdk/diagnostic_export_sdk_test.go", "cmd/kgen/main_test.go",
		"internal/audit/codegen_test.go", "internal/audit/security.go", "internal/audit/security_test.go", "internal/codegen/authorization_v1_test.go",
		"internal/runtime/policy_enforcement_test.go", "internal/testkit/importrules/importrules_test.go", policyMaintenanceManifestPathV1,
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
		if entry.Path != wantPaths[i] || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase6 diagnostic export entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase6 diagnostic export hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validPolicySHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase6 diagnostic export pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePolicyPhase5RelayDescriptorV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m5-offline-relay-descriptor-admission-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "709e4a5a7412ee115fc71c2d825ebe9ac4f167439b4861a1649dd63fcf0c150f" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != policyMaintenanceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase5 relay descriptor overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase5 relay descriptor entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase5 relay descriptor hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validPolicySHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase5 relay descriptor pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePolicyPhase4FallbackV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m4-permitted-fallback-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "772ae344c99edb21a4d04fadd77f51978a6e81aa4d555ec30190cb64e7a7c2d9" || len(overlay.Paths) != 17 || len(overlay.Entries) != 16 || overlay.Paths[16] != policyMaintenanceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase4 fallback overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase4 fallback entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase4 fallback hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence == "ABSENT" || entry.PreEvidence == "UNRECORDED" {
			delete(pre, entry.Path)
		} else {
			if !validPolicySHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase4 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		}
	}
	return pre, nil
}

func validatePolicyPhase3ContractV1(root string, currentAtPost map[string]string, overlays map[string]policyPhase2CompleteOverlayV1) (map[string]string, error) {
	const name = "m3-profile-lifecycle-contract-v1"
	overlay, ok := overlays[name]
	if len(overlays) != 1 || !ok || overlay.Version != name || overlay.PredecessorManifestSHA256 != "50fde6a39c0b5d987a16e370f2d10f0526759c03c0d5f73a316cffcc207e4d90" || len(overlay.Paths) != len(overlay.Entries)+1 || overlay.Paths[len(overlay.Paths)-1] != policyMaintenanceManifestPathV1 {
		return nil, fmt.Errorf("invalid phase3 contract overlay identity/cardinality")
	}
	pre := make(map[string]string, len(currentAtPost))
	for path, hash := range currentAtPost {
		pre[path] = hash
	}
	for i, entry := range overlay.Entries {
		if overlay.Paths[i] != entry.Path || !validPolicySHA256V1(entry.PostSHA256) {
			return nil, fmt.Errorf("invalid phase3 contract entry %d", i)
		}
		actual, present := currentAtPost[entry.Path]
		var err error
		if !present {
			actual, err = policyFileSHA256V1(root, entry.Path)
		}
		if err != nil || actual != entry.PostSHA256 {
			return nil, fmt.Errorf("phase3 contract hash drift %s=%s want %s: %v", entry.Path, actual, entry.PostSHA256, err)
		}
		if entry.PreEvidence != "ABSENT" && entry.PreEvidence != "UNRECORDED" {
			if !validPolicySHA256V1(entry.PreEvidence) {
				return nil, fmt.Errorf("invalid phase3 pre evidence %s", entry.Path)
			}
			pre[entry.Path] = entry.PreEvidence
		} else {
			delete(pre, entry.Path)
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

func policyFileSHA256V1(root, path string) (string, error) {
	return evidenceoverlay.ResolveCurrentSHA256(root, path)
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
		content, err := evidenceoverlay.ReadSubjectFile(root, entry.Path)
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

type policyWO801ManifestV1 struct {
	Phase8WO801ThreatModelOverlays map[string]policyPhase2CompleteOverlayV1 `json:"phase8_wo801_threat_model_overlays"`
	Phase8WO801AdoptionOverlays    map[string]policyPhase2CompleteOverlayV1 `json:"phase8_wo801_adoption_overlays"`
}

func TestPolicyPhase8WO801ThreatModelOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest policyWO801ManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	base := manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"]
	mutations := map[string]func(*policyPhase2CompleteOverlayV1){
		"missing-path":  func(v *policyPhase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":    func(v *policyPhase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing-entry": func(v *policyPhase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra-entry": func(v *policyPhase2CompleteOverlayV1) {
			v.Entries = append(v.Entries, policyPhase2CompleteOverlayEntryV1{})
		},
		"swapped":        func(v *policyPhase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"tampered":       func(v *policyPhase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"predecessor":    func(v *policyPhase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("3", 64) },
		"reconstruction": func(v *policyPhase2CompleteOverlayV1) { v.Entries[5].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range mutations {
		copyOverlay := base
		copyOverlay.Paths = append([]string(nil), base.Paths...)
		copyOverlay.Entries = append([]policyPhase2CompleteOverlayEntryV1(nil), base.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePolicyPhase8WO801ThreatModelV1(root, map[string]policyPhase2CompleteOverlayV1{"phase8-wo801-threat-model-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 WO-801 %s mutation", name)
		}
	}
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

func TestPolicyMatrixMaintenanceRejectsUnlistedHistoricalInventoryV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	for _, path := range []string{"unexpected/policy-bypass.go", "internal/runtime/undeclared_authority.go"} {
		t.Run(path, func(t *testing.T) {
			// An explicit unlisted path must not be replaced by an empty live
			// status or an unrelated working-tree inventory.
			err := validatePolicyMaintenanceStatusV1(root, map[string]bool{path: true}, nil)
			if err == nil || !strings.Contains(err.Error(), "neither historical M0 nor exact composed M2 state") {
				t.Fatalf("unlisted historical inventory %q error=%v", path, err)
			}
		})
	}
}

func TestPolicyMatrixComposedM2ExactStatesV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		MaintenanceOverlays               map[string]policyMaintenanceOverlayV1    `json:"maintenance_overlays"`
		HelperOwnerOverlays               map[string]policyLayeredOverlayV1        `json:"helper_owner_overlays"`
		ValidatorOverlays                 map[string]policyLayeredOverlayV1        `json:"validator_overlays"`
		ValidatorConsumerOverlays         map[string]policyLayeredOverlayV1        `json:"validator_consumer_overlays"`
		EvidenceConvergenceOverlays       map[string]policyLayeredOverlayV1        `json:"evidence_convergence_overlays"`
		Phase2CompleteOverlays            map[string]policyPhase2CompleteOverlayV1 `json:"phase2_complete_overlays"`
		Phase3ContractOverlays            map[string]policyPhase2CompleteOverlayV1 `json:"phase3_contract_overlays"`
		Phase4FallbackOverlays            map[string]policyPhase2CompleteOverlayV1 `json:"phase4_fallback_overlays"`
		Phase5RelayDescriptorOverlays     map[string]policyPhase2CompleteOverlayV1 `json:"phase5_relay_descriptor_overlays"`
		Phase6DiagnosticExportOverlays    map[string]policyPhase2CompleteOverlayV1 `json:"phase6_diagnostic_export_overlays"`
		Phase7AppRuntimeOverlays          map[string]policyPhase2CompleteOverlayV1 `json:"phase7_app_runtime_overlays"`
		BaselineStabilizationOverlays     map[string]policyPhase2CompleteOverlayV1 `json:"baseline_stabilization_overlays"`
		Phase8ProfileCryptographyOverlays map[string]policyPhase2CompleteOverlayV1 `json:"phase8_profile_cryptography_overlays"`
		Phase8WO801ThreatModelOverlays    map[string]policyPhase2CompleteOverlayV1 `json:"phase8_wo801_threat_model_overlays"`
		Phase8WO801AdoptionOverlays       map[string]policyPhase2CompleteOverlayV1 `json:"phase8_wo801_adoption_overlays"`
	}
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	basePhase8 := manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"]
	phase8Mutations := map[string]func(*policyPhase2CompleteOverlayV1){
		"missing-path": func(v *policyPhase2CompleteOverlayV1) { v.Paths = v.Paths[:len(v.Paths)-1] },
		"extra-path":   func(v *policyPhase2CompleteOverlayV1) { v.Paths = append(v.Paths, "extra") },
		"missing":      func(v *policyPhase2CompleteOverlayV1) { v.Entries = v.Entries[:len(v.Entries)-1] },
		"extra": func(v *policyPhase2CompleteOverlayV1) {
			v.Entries = append(v.Entries, policyPhase2CompleteOverlayEntryV1{})
		},
		"swapped":        func(v *policyPhase2CompleteOverlayV1) { v.Paths[0], v.Paths[1] = v.Paths[1], v.Paths[0] },
		"predecessor":    func(v *policyPhase2CompleteOverlayV1) { v.PredecessorManifestSHA256 = strings.Repeat("1", 64) },
		"entry-hash":     func(v *policyPhase2CompleteOverlayV1) { v.Entries[0].PostSHA256 = strings.Repeat("2", 64) },
		"invalid-absent": func(v *policyPhase2CompleteOverlayV1) { v.Entries[7].PreEvidence = strings.Repeat("3", 64) },
		"reconstruction": func(v *policyPhase2CompleteOverlayV1) { v.Entries[9].PreEvidence = strings.Repeat("4", 64) },
	}
	for name, mutate := range phase8Mutations {
		copyOverlay := basePhase8
		copyOverlay.Paths = append([]string(nil), basePhase8.Paths...)
		copyOverlay.Entries = append([]policyPhase2CompleteOverlayEntryV1(nil), basePhase8.Entries...)
		mutate(&copyOverlay)
		if _, err := validatePolicyPhase8ProfileCryptographyV1(root, map[string]policyPhase2CompleteOverlayV1{"phase8-profile-cryptography-authorization-v1": copyOverlay}); err == nil {
			t.Fatalf("accepted phase8 profile cryptography %s mutation", name)
		}
	}
	changed := map[string]bool{}
	for _, path := range policyPhase2CompletePathsV1 {
		changed[path] = true
	}
	for _, path := range manifest.Phase3ContractOverlays["m3-profile-lifecycle-contract-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase4FallbackOverlays["m4-permitted-fallback-contract-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase5RelayDescriptorOverlays["m5-offline-relay-descriptor-admission-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase6DiagnosticExportOverlays["m6-offline-diagnostic-export-contract-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase7AppRuntimeOverlays["m7-offline-app-runtime-contract-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase8ProfileCryptographyOverlays["phase8-profile-cryptography-authorization-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase8WO801ThreatModelOverlays["phase8-wo801-threat-model-v1"].Paths {
		changed[path] = true
	}
	for _, path := range manifest.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"].Paths {
		changed[path] = true
	}
	for _, path := range policyStabilizationPathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO802PathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO804PathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO803PathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO805PathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO806PathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO807PathsV1 {
		changed[path] = true
	}
	for _, path := range policyPhase8WO808PathsV1 {
		changed[path] = true
	}
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err != nil {
		t.Fatal(err)
	}
	missingWO807 := clonePathSetV1(changed)
	delete(missingWO807, "testdata/evidence/phase8-wo807-recovery-report.json")
	if err := validatePolicyM2ComposedStateV1(root, missingWO807, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("composed state accepted without WO-807 evidence")
	}
	missingWO808 := clonePathSetV1(changed)
	delete(missingWO808, ".github/workflows/ci.yml")
	if err := validatePolicyM2ComposedStateV1(root, missingWO808, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("composed state accepted without WO-808 CI guard")
	}
	partial := clonePathSetV1(changed)
	delete(partial, policyHelperPathsV1[0])
	if err := validatePolicyM2ComposedStateV1(root, partial, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("composed M2 subset accepted")
	}
	superset := clonePathSetV1(changed)
	superset["extra"] = true
	if err := validatePolicyM2ComposedStateV1(root, superset, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("composed M2 superset accepted")
	}
	badHelpers := clonePolicyLayeredOverlaysV1(manifest.HelperOwnerOverlays)
	v2 := badHelpers[policyHelperOverlayNameV2]
	v2.Entries[0], v2.Entries[1] = v2.Entries[1], v2.Entries[0]
	badHelpers[policyHelperOverlayNameV2] = v2
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, badHelpers, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("reordered helper overlay accepted")
	}
	badValidators := clonePolicyLayeredOverlaysV1(manifest.ValidatorOverlays)
	validator := badValidators[policyValidatorOverlayNameV1]
	validator.Entries[0].PostSHA256 = strings.Repeat("3", 64)
	badValidators[policyValidatorOverlayNameV1] = validator
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, badValidators, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted validator overlay accepted")
	}
	badConsumers := clonePolicyLayeredOverlaysV1(manifest.ValidatorConsumerOverlays)
	consumer := badConsumers[policyValidatorConsumerOverlayNameV1]
	consumer.Entries[0].PreSHA256 = strings.Repeat("4", 64)
	badConsumers[policyValidatorConsumerOverlayNameV1] = consumer
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, badConsumers, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted validator-consumer overlay accepted")
	}
	badM5 := map[string]policyPhase2CompleteOverlayV1{}
	m5 := manifest.Phase5RelayDescriptorOverlays["m5-offline-relay-descriptor-admission-v1"]
	m5.PredecessorManifestSHA256 = strings.Repeat("5", 64)
	badM5["m5-offline-relay-descriptor-admission-v1"] = m5
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, manifest.Phase6DiagnosticExportOverlays, badM5, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted M5 predecessor accepted")
	}
	badM6 := map[string]policyPhase2CompleteOverlayV1{}
	m6 := manifest.Phase6DiagnosticExportOverlays["m6-offline-diagnostic-export-contract-v1"]
	m6.PredecessorManifestSHA256 = strings.Repeat("6", 64)
	badM6["m6-offline-diagnostic-export-contract-v1"] = m6
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, manifest.Phase7AppRuntimeOverlays, badM6, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted M6 predecessor accepted")
	}
	badM7 := map[string]policyPhase2CompleteOverlayV1{}
	m7 := manifest.Phase7AppRuntimeOverlays["m7-offline-app-runtime-contract-v1"]
	m7.PredecessorManifestSHA256 = strings.Repeat("7", 64)
	badM7["m7-offline-app-runtime-contract-v1"] = m7
	if err := validatePolicyM2ComposedStateV1(root, changed, manifest.MaintenanceOverlays, manifest.HelperOwnerOverlays, manifest.ValidatorOverlays, manifest.ValidatorConsumerOverlays, manifest.EvidenceConvergenceOverlays, manifest.Phase8WO801ThreatModelOverlays, manifest.Phase8ProfileCryptographyOverlays, manifest.BaselineStabilizationOverlays, badM7, manifest.Phase6DiagnosticExportOverlays, manifest.Phase5RelayDescriptorOverlays, manifest.Phase4FallbackOverlays, manifest.Phase3ContractOverlays, manifest.Phase2CompleteOverlays); err == nil {
		t.Fatal("drifted M7 predecessor accepted")
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
func TestPolicyPhase8WO801AdoptionOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var m policyWO801ManifestV1
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	base := m.Phase8WO801AdoptionOverlays["phase8-wo801-adoption-v1"]
	muts := map[string]func(map[string]policyPhase2CompleteOverlayV1){"missing-map": func(v map[string]policyPhase2CompleteOverlayV1) { delete(v, "phase8-wo801-adoption-v1") }, "extra-map": func(v map[string]policyPhase2CompleteOverlayV1) { v["extra"] = base }, "wrong-version": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Version = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-predecessor": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.PredecessorManifestSHA256 = strings.Repeat("1", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-path": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = x.Paths[:8]
		v["phase8-wo801-adoption-v1"] = x
	}, "extra-path": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths = append(x.Paths, "x")
		v["phase8-wo801-adoption-v1"] = x
	}, "reordered": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[0], x.Paths[1] = x.Paths[1], x.Paths[0]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-not-last": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Paths[7], x.Paths[8] = x.Paths[8], x.Paths[7]
		v["phase8-wo801-adoption-v1"] = x
	}, "missing-entry": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = x.Entries[:7]
		v["phase8-wo801-adoption-v1"] = x
	}, "self-entry": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries = append(x.Entries, policyPhase2CompleteOverlayEntryV1{})
		v["phase8-wo801-adoption-v1"] = x
	}, "entry-path": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].Path = "wrong"
		v["phase8-wo801-adoption-v1"] = x
	}, "malformed": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PostSHA256 = "bad"
		v["phase8-wo801-adoption-v1"] = x
	}, "evidence-pre": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[0].PreEvidence = strings.Repeat("2", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "consumer-absent": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = "ABSENT"
		v["phase8-wo801-adoption-v1"] = x
	}, "wrong-pre": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PreEvidence = strings.Repeat("3", 64)
		v["phase8-wo801-adoption-v1"] = x
	}, "current-drift": func(v map[string]policyPhase2CompleteOverlayV1) {
		x := v["phase8-wo801-adoption-v1"]
		x.Entries[1].PostSHA256 = strings.Repeat("4", 64)
		v["phase8-wo801-adoption-v1"] = x
	}}
	for name, mut := range muts {
		t.Run(name, func(t *testing.T) {
			x := base
			x.Paths = append([]string(nil), base.Paths...)
			x.Entries = append([]policyPhase2CompleteOverlayEntryV1(nil), base.Entries...)
			v := map[string]policyPhase2CompleteOverlayV1{"phase8-wo801-adoption-v1": x}
			mut(v)
			if _, err := validatePolicyPhase8WO801AdoptionV1(root, v); err == nil {
				t.Fatalf("accepted %s", name)
			}
		})
	}
}

func TestPolicyPhase8GuardMaintenanceOverlayMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest policyWO812ManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]policyMaintenanceOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase8GuardMaintenanceOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]policyMaintenanceOverlayV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase9Pre, err := validatePolicyPhase9GuardMaintenanceOverlayV1(root, manifest.Phase9GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	finalGuardPre, err := validatePolicyPhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePolicyPhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, clone()); err != nil {
		t.Fatal(err)
	}
	mutations := map[string]func(map[string]policyMaintenanceOverlayV1){
		"missing-overlay": func(v map[string]policyMaintenanceOverlayV1) { delete(v, "phase8-wo806-guard-convergence-v1") },
		"extra-overlay":   func(v map[string]policyMaintenanceOverlayV1) { v["extra"] = v["phase8-wo806-guard-convergence-v1"] },
		"missing-path": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = o.Paths[:len(o.Paths)-1]
			v[o.Version] = o
		},
		"extra-path": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths = append(o.Paths, "README.md")
			v[o.Version] = o
		},
		"reordered-path": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Paths[1] = o.Paths[1], o.Paths[0]
			v[o.Version] = o
		},
		"self-pre": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.SelfPreSHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"pre-hash": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PreSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
		"post-hash": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("3", 64)
			v[o.Version] = o
		},
		"path-substitution": func(v map[string]policyMaintenanceOverlayV1) {
			o := v["phase8-wo806-guard-convergence-v1"]
			o.Paths[0], o.Entries[0].Path = "README.md", "README.md"
			v[o.Version] = o
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			v := clone()
			mutate(v)
			if _, err := validatePolicyPhase8GuardMaintenanceOverlayAtPostV1(root, finalGuardPre, v); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}

func TestPolicyPhase8WorkOrderOverlayChainMutationsV1(t *testing.T) {
	root := filepath.Clean(filepath.Join("..", ".."))
	raw, err := evidenceoverlay.ReadSubjectFile(root, policyMaintenanceManifestPathV1)
	if err != nil {
		t.Fatal(err)
	}
	var manifest policyWO812ManifestV1
	if err := json.Unmarshal(raw, &manifest); err != nil {
		t.Fatal(err)
	}
	clone := func() map[string]policyPhase8WorkOrderOverlayV1 {
		encoded, err := json.Marshal(manifest.Phase8WorkOrderOverlays)
		if err != nil {
			t.Fatal(err)
		}
		var out map[string]policyPhase8WorkOrderOverlayV1
		if err := json.Unmarshal(encoded, &out); err != nil {
			t.Fatal(err)
		}
		return out
	}
	phase9Pre, err := validatePolicyPhase9GuardMaintenanceOverlayV1(root, manifest.Phase9GuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	finalGuardPre, err := validatePolicyPhase8FinalGuardMaintenanceOverlayAtPostV1(root, phase9Pre, manifest.Phase8FinalGuardMaintenanceOverlays)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validatePolicyPhase8WorkOrderOverlayChainAtPostV1(root, finalGuardPre, clone()); err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(map[string]policyPhase8WorkOrderOverlayV1){
		"missing": func(v map[string]policyPhase8WorkOrderOverlayV1) {
			delete(v, "phase8-wo803-canonical-profile-codec-v1")
		},
		"extra": func(v map[string]policyPhase8WorkOrderOverlayV1) { v["extra"] = v["phase8-wo802-standards-suite-v1"] },
		"reordered": func(v map[string]policyPhase8WorkOrderOverlayV1) {
			v["phase8-wo803-canonical-profile-codec-v1"], v["phase8-wo804-trust-provider-boundaries-v1"] = v["phase8-wo804-trust-provider-boundaries-v1"], v["phase8-wo803-canonical-profile-codec-v1"]
		},
		"path-substitution": func(v map[string]policyPhase8WorkOrderOverlayV1) {
			o := v["phase8-wo805-verified-profile-activation-v1"]
			o.Paths[0], o.Entries[0].Path = "README.md", "README.md"
			v[o.Version] = o
		},
		"predecessor": func(v map[string]policyPhase8WorkOrderOverlayV1) {
			o := v["phase8-wo807-integrated-assurance-v1"]
			o.PredecessorOverlaySHA256 = strings.Repeat("1", 64)
			v[o.Version] = o
		},
		"content-drift": func(v map[string]policyPhase8WorkOrderOverlayV1) {
			o := v["phase8-wo802-standards-suite-v1"]
			o.Entries[0].PostSHA256 = strings.Repeat("2", 64)
			v[o.Version] = o
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			v := clone()
			mutate(v)
			if _, err := validatePolicyPhase8WorkOrderOverlayChainAtPostV1(root, finalGuardPre, v); err == nil {
				t.Fatal("mutation accepted")
			}
		})
	}
}
