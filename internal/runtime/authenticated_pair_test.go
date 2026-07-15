// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"reflect"
	gort "runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
)

func TestPairInputV1ExactFiveRoleFixedFields(t *testing.T) {
	typeOf := reflect.TypeOf(PairInputV1{})
	if typeOf.NumField() != 5 {
		t.Fatalf("PairInputV1 has %d fields, want 5", typeOf.NumField())
	}
	want := []reflect.Type{
		reflect.TypeOf(auth.FirstContactInput{}),
		reflect.TypeOf(ClientStrictSessionConfigV1{}),
		reflect.TypeOf(RelayStrictSessionConfigV1{}),
		reflect.TypeOf(ClientLocalRuntimeControlsV1{}),
		reflect.TypeOf(RelayLocalRuntimeControlsV1{}),
	}
	for i := range want {
		if typeOf.Field(i).Type != want[i] {
			t.Fatalf("field %d has type %v, want %v", i, typeOf.Field(i).Type, want[i])
		}
	}
}

func TestPairAPISurfaceV1(t *testing.T) {
	runtimeType := reflect.TypeOf((*HandshakeRuntime)(nil))
	method, ok := runtimeType.MethodByName("NewAuthenticatedChannelPair")
	if !ok || method.Type.NumIn() != 2 || method.Type.In(1) != reflect.TypeOf(PairInputV1{}) || method.Type.NumOut() != 3 ||
		method.Type.Out(0) != reflect.TypeOf((*ClientAuthenticatedEndpointV1)(nil)) ||
		method.Type.Out(1) != reflect.TypeOf((*RelayAuthenticatedEndpointV1)(nil)) ||
		method.Type.Out(2) != reflect.TypeOf((*error)(nil)).Elem() {
		t.Fatalf("unexpected strict pair method signature: %v", method.Type)
	}
	for _, value := range []any{
		ClientStrictSessionConfigV1{}, RelayStrictSessionConfigV1{},
		ClientAuthenticatedEndpointV1{}, RelayAuthenticatedEndpointV1{},
	} {
		typeOf := reflect.TypeOf(value)
		for i := range typeOf.NumField() {
			if typeOf.Field(i).IsExported() {
				t.Fatalf("%s exposes field %s", typeOf, typeOf.Field(i).Name)
			}
		}
	}
	for _, endpoint := range []reflect.Type{reflect.TypeOf((*ClientAuthenticatedEndpointV1)(nil)), reflect.TypeOf((*RelayAuthenticatedEndpointV1)(nil))} {
		if endpoint.NumMethod() != 2 {
			t.Fatalf("%s exposes %d methods, want only State and Close", endpoint, endpoint.NumMethod())
		}
		for _, name := range []string{"State", "Close"} {
			if _, ok := endpoint.MethodByName(name); !ok {
				t.Fatalf("%s is missing %s", endpoint, name)
			}
		}
	}
	coordinator := reflect.TypeOf(pairTerminalCoordinatorV1{})
	for i := range coordinator.NumField() {
		field := coordinator.Field(i)
		lower := strings.ToLower(field.Name + field.Type.String())
		for _, forbidden := range []string{"schedule", "key", "peer", "endpointstate"} {
			if strings.Contains(lower, forbidden) {
				t.Fatalf("coordinator exposes peer material field %s %s", field.Name, field.Type)
			}
		}
	}
	for _, state := range []reflect.Type{reflect.TypeOf(clientAuthenticatedEndpointStateV1{}), reflect.TypeOf(relayAuthenticatedEndpointStateV1{})} {
		schedules := 0
		for i := range state.NumField() {
			if state.Field(i).Type == reflect.TypeOf(security.KeySchedule{}) {
				schedules++
			}
		}
		if schedules != 1 {
			t.Fatalf("%s owns %d schedules, want exactly one", state, schedules)
		}
	}
}

func TestPairAPIRouteAndStaticBoundaryV1(t *testing.T) {
	_, thisFile, _, ok := gort.Caller(0)
	if !ok {
		t.Fatal("caller unavailable")
	}
	dir := filepath.Dir(thisFile)
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
	raw, err := os.ReadFile(filepath.Join(dir, "handshake.go"))
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "handshake.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"SnapshotFirstContactInputV1", "verifySupportAndAuthorizationPreflightV1", "FirstContact", "AuthenticatedContextSnapshotV1", "verifySupportAndAuthorizationContextV1"}
	var got []string
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "strictFirstContactWithContextV1" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				name := callName(call)
				for _, expected := range want {
					if name == expected {
						got = append(got, name)
					}
				}
			}
			return true
		})
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("pair route calls=%v want=%v", got, want)
	}
	pairRaw, err := os.ReadFile(filepath.Join(dir, "authenticated_pair.go"))
	if err != nil {
		t.Fatal(err)
	}
	pairFile, err := parser.ParseFile(token.NewFileSet(), "authenticated_pair.go", pairRaw, 0)
	if err != nil {
		t.Fatal(err)
	}
	var pairCalls []string
	for _, decl := range pairFile.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "NewAuthenticatedChannelPair" {
			continue
		}
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			if call, ok := node.(*ast.CallExpr); ok {
				name := callName(call)
				for _, expected := range []string{"strictFirstContactWithContextV1", "registerPairMaterialV1", "consumePairMaterialV1"} {
					if name == expected {
						pairCalls = append(pairCalls, name)
					}
				}
			}
			return true
		})
	}
	if !reflect.DeepEqual(pairCalls, []string{"strictFirstContactWithContextV1", "registerPairMaterialV1", "consumePairMaterialV1"}) {
		t.Fatalf("public pair route=%v", pairCalls)
	}
	for _, name := range []string{"authenticated_pair.go", "authenticated_pair_test.go", "handshake.go", "config.go", "config_v1_test.go"} {
		raw, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{string([]byte{'"', 'n', 'e', 't'}), "internal/" + "testkit", "internal/" + "lab", "internal/" + "generated", "internal/" + "codegen"} {
			if bytes.Contains(raw, []byte(forbidden)) {
				t.Fatalf("%s contains forbidden dependency %q", name, forbidden)
			}
		}
	}
	for _, typ := range []reflect.Type{reflect.TypeOf(pairTerminalCoordinatorV1{}), reflect.TypeOf(clientAuthenticatedEndpointStateV1{}), reflect.TypeOf(relayAuthenticatedEndpointStateV1{})} {
		for i := range typ.NumField() {
			lower := strings.ToLower(typ.Field(i).Name)
			for _, forbidden := range []string{"counter", "replay", "ratchet", "operation", "ack", "transition"} {
				if strings.Contains(lower, forbidden) {
					t.Fatalf("%s contains active-state field %s", typ, typ.Field(i).Name)
				}
			}
		}
	}
}

func TestAuthenticatedChannelPairSuccessAndTerminalOwnershipV1(t *testing.T) {
	fixture, input, _ := authenticatedPairFixtureV1(t)
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{2}, 32)))
	calls := 0
	runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
		calls++
		return security.DeriveKeyScheduleV1(input)
	}
	client, relay, err := runtime.NewAuthenticatedChannelPair(input)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 2 {
		t.Fatalf("derived %d schedules, want exactly 2", calls)
	}
	if client.State() != auth.StateEstablished || relay.State() != auth.StateAuthenticating {
		t.Fatalf("unexpected initial states: client=%s relay=%s", client.State(), relay.State())
	}
	clientSlices := [][]byte{client.state.schedule.ClientWriteKey, client.state.schedule.ServerWriteKey, client.state.schedule.ClientNonceBase, client.state.schedule.ServerNonceBase, client.state.schedule.ExporterSecret}
	relaySlices := [][]byte{relay.state.schedule.ClientWriteKey, relay.state.schedule.ServerWriteKey, relay.state.schedule.ClientNonceBase, relay.state.schedule.ServerNonceBase, relay.state.schedule.ExporterSecret}
	for i := range clientSlices {
		if len(clientSlices[i]) == 0 || len(relaySlices[i]) == 0 || &clientSlices[i][0] == &relaySlices[i][0] {
			t.Fatalf("endpoint public schedule slice %d aliases or is empty", i)
		}
	}
	clientCopy := *client
	relayCopy := *relay
	client.Close()
	client.Close()
	relay.Close()
	if clientCopy.State() != auth.StateClosed || relayCopy.State() != auth.StateClosed {
		t.Fatal("copied endpoint view survived terminal pair close")
	}
	for i := range clientSlices {
		if !zeroRuntimeSliceV1(clientSlices[i]) || !zeroRuntimeSliceV1(relaySlices[i]) {
			t.Fatalf("terminal close retained public schedule slice %d", i)
		}
	}
	if client.state.coordinator.destroy != nil {
		t.Fatal("terminal destroy closure was not cleared")
	}
}

func TestAuthenticatedChannelPairConfigAndControlsV1(t *testing.T) {
	fixture, base, context := authenticatedPairFixtureV1(t)
	tests := map[string]func(*PairInputV1){
		"client config":      func(input *PairInputV1) { input.ClientConfig.value.MaxFrameBytes-- },
		"relay config":       func(input *PairInputV1) { input.RelayConfig.value.ConfigPolicyHash[0] ^= 1 },
		"client queue below": func(input *PairInputV1) { input.ClientControls.QueueCeiling = 0 },
		"relay queue below":  func(input *PairInputV1) { input.RelayControls.QueueCeiling = 0 },
		"client queue above": func(input *PairInputV1) {
			input.ClientControls.QueueCeiling = context.ClientLimitBlock.CarrierMaxQueueDepth + 1
		},
		"relay queue above": func(input *PairInputV1) {
			input.RelayControls.QueueCeiling = context.ServerLimitBlock.CarrierMaxQueueDepth + 1
		},
		"client event zero":  func(input *PairInputV1) { input.ClientControls.EventCapacity = 0 },
		"relay event zero":   func(input *PairInputV1) { input.RelayControls.EventCapacity = 0 },
		"client event above": func(input *PairInputV1) { input.ClientControls.EventCapacity = 1<<20 + 1 },
		"relay event above":  func(input *PairInputV1) { input.RelayControls.EventCapacity = 1<<20 + 1 },
		"client runtime id":  func(input *PairInputV1) { input.ClientControls.RuntimeID = "" },
		"relay runtime id":   func(input *PairInputV1) { input.RelayControls.RuntimeID = "" },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			input := base
			mutate(&input)
			runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{3}, 32)))
			kdf := 0
			runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
				kdf++
				return security.DeriveKeyScheduleV1(input)
			}
			client, relay, err := runtime.NewAuthenticatedChannelPair(input)
			if client != nil || relay != nil || !errors.Is(err, ErrConfigInvalid) || kdf != 0 {
				t.Fatalf("got client=%v relay=%v err=%v, want nil/nil/config_invalid", client, relay, err)
			}
			if bytes.Contains([]byte(err.Error()), []byte(base.ClientControls.RuntimeID)) {
				t.Fatal("error exposed RuntimeID")
			}
		})
	}
	for _, queue := range []uint32{1, context.ClientLimitBlock.CarrierMaxQueueDepth} {
		input := base
		input.ClientControls.QueueCeiling = queue
		input.RelayControls.QueueCeiling = queue
		runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{4}, 32)))
		client, relay, err := runtime.NewAuthenticatedChannelPair(input)
		if err != nil {
			t.Fatalf("queue %d: %v", queue, err)
		}
		client.Close()
		relay.Close()
	}
	for _, capacity := range []uint32{1, 1 << 20} {
		input := base
		input.ClientControls.EventCapacity, input.RelayControls.EventCapacity = capacity, capacity
		input.ClientControls.RuntimeID, input.RelayControls.RuntimeID = "different-client-id", "different-relay-id"
		runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{5}, 32)))
		client, relay, err := runtime.NewAuthenticatedChannelPair(input)
		if err != nil {
			t.Fatal(err)
		}
		client.Close()
		relay.Close()
	}
}

func TestAuthenticatedChannelPairRejectsRehashedContextMismatchV1(t *testing.T) {
	fixture, base, _ := authenticatedPairFixtureV1(t)
	mutations := map[string]func(*StrictSessionConfigV1){
		"profile id":       func(v *StrictSessionConfigV1) { v.ProfileID = "other-profile" },
		"profile hash":     func(v *StrictSessionConfigV1) { v.ProfileHash[0] ^= 1 },
		"policy hash":      func(v *StrictSessionConfigV1) { v.EffectivePolicyHash[0] ^= 1 },
		"capability hash":  func(v *StrictSessionConfigV1) { v.SelectedCapabilityHash[0] ^= 1 },
		"selected suite":   func(v *StrictSessionConfigV1) { v.SelectedSuite.KDFSuite = "alternate-kdf" },
		"replay":           func(v *StrictSessionConfigV1) { v.ReplayWindowSize-- },
		"session messages": func(v *StrictSessionConfigV1) { v.MaxSessionMessages-- },
		"key messages":     func(v *StrictSessionConfigV1) { v.MaxKeyLifetimeMessages-- },
		"streams":          func(v *StrictSessionConfigV1) { v.MaxConcurrentStreams-- },
		"frame":            func(v *StrictSessionConfigV1) { v.MaxFrameBytes-- },
		"envelope":         func(v *StrictSessionConfigV1) { v.MaxEnvelopeBytes-- },
	}
	for _, role := range []string{"client", "relay"} {
		for name, mutate := range mutations {
			t.Run(role+" "+name, func(t *testing.T) {
				input := base
				value := input.ClientConfig.value
				mutate(&value)
				hash, err := ConfigPolicyHashV1(value)
				if err != nil {
					t.Fatal(err)
				}
				value.ConfigPolicyHash = hash
				if role == "client" {
					input.ClientConfig = ClientStrictSessionConfigV1{value: value}
				} else {
					input.RelayConfig = RelayStrictSessionConfigV1{value: value}
				}
				runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{13}, 32)))
				calls := 0
				runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
					calls++
					return security.DeriveKeyScheduleV1(input)
				}
				client, relay, err := runtime.NewAuthenticatedChannelPair(input)
				if client != nil || relay != nil || !errors.Is(err, ErrConfigInvalid) || calls != 0 {
					t.Fatalf("got client=%v relay=%v err=%v KDF calls=%d", client, relay, err, calls)
				}
			})
		}
	}
}

func TestStrictSessionConfigIndependentSourceMappingAndCeilingsV1(t *testing.T) {
	fixture := newHigherCeilingStrictFixtureV1(t)
	base, context := pairInputForStrictFixtureV1(t, fixture)
	if !reflect.DeepEqual(context.ClientCompatibilityBlock, context.ServerCompatibilityBlock) {
		t.Fatal("fixture bilateral compatibility blocks differ")
	}
	compatibility := context.ClientCompatibilityBlock
	policy := context.EffectivePolicy
	limits := context.ClientLimitBlock
	if compatibility.MaxReplayWindow <= uint32(policy.ReplayWindowSize) || compatibility.MaxStreamCount <= limits.SessionMaxConcurrentStreams || compatibility.MaxEnvelopeBytes <= limits.CarrierMaxEnvelopeBytes {
		t.Fatalf("fixture does not provide deliberately higher ceilings: replay=%d/%d stream=%d/%d envelope=%d/%d", policy.ReplayWindowSize, compatibility.MaxReplayWindow, limits.SessionMaxConcurrentStreams, compatibility.MaxStreamCount, limits.CarrierMaxEnvelopeBytes, compatibility.MaxEnvelopeBytes)
	}
	expected := StrictSessionConfigV1{
		ProfileID: policy.ProfileID, ProfileHash: context.ClientProfileHash, SelectedSuite: context.SelectedSuite,
		EffectivePolicyHash: context.EffectivePolicyHash, SelectedCapabilityHash: context.SelectedCapabilityHash,
		ReplayWindowSize: uint32(policy.ReplayWindowSize), MaxSessionMessages: uint64(policy.MaxSessionMessages), MaxKeyLifetimeMessages: uint64(policy.MaxKeyLifetimeMessages),
		MaxConcurrentStreams: limits.SessionMaxConcurrentStreams, MaxFrameBytes: limits.MaxFrameBytes, MaxEnvelopeBytes: limits.CarrierMaxEnvelopeBytes,
	}
	expected.ConfigPolicyHash = independentConfigPolicyHashV1(expected)
	clientMapped, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	relayMapped, err := strictConfigFromContextV1(context, false)
	if err != nil {
		t.Fatal(err)
	}
	if clientMapped != expected || relayMapped != expected {
		t.Fatalf("source mapping drifted: client=%#v relay=%#v expected=%#v", clientMapped, relayMapped, expected)
	}
	ceiling := expected
	ceiling.ReplayWindowSize = compatibility.MaxReplayWindow
	ceiling.MaxConcurrentStreams = compatibility.MaxStreamCount
	ceiling.MaxEnvelopeBytes = compatibility.MaxEnvelopeBytes
	hash, err := ConfigPolicyHashV1(ceiling)
	if err != nil {
		t.Fatal(err)
	}
	ceiling.ConfigPolicyHash = hash
	base.ClientConfig = ClientStrictSessionConfigV1{value: ceiling}
	base.RelayConfig = RelayStrictSessionConfigV1{value: ceiling}
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{22}, 32)))
	kdf := 0
	runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
		kdf++
		return security.DeriveKeyScheduleV1(input)
	}
	client, relay, err := runtime.NewAuthenticatedChannelPair(base)
	if client != nil || relay != nil || !errors.Is(err, ErrConfigInvalid) || kdf != 0 {
		t.Fatalf("client=%v relay=%v err=%v kdf=%d", client, relay, err, kdf)
	}
}

func TestAuthenticatedContextPairAdmissionRejectsDetachedBlockMutationV1(t *testing.T) {
	_, _, base := authenticatedPairFixtureV1(t)
	mutations := map[string]func(*auth.AuthenticatedContextSnapshotV1){
		"context hash":             func(v *auth.AuthenticatedContextSnapshotV1) { v.ContextHash[0] ^= 1 },
		"client compatibility":     func(v *auth.AuthenticatedContextSnapshotV1) { v.ClientCompatibilityBlock.MaxReplayWindow++ },
		"relay compatibility hash": func(v *auth.AuthenticatedContextSnapshotV1) { v.ServerCompatibilityBlockHash[0] ^= 1 },
		"client limit":             func(v *auth.AuthenticatedContextSnapshotV1) { v.ClientLimitBlock.MaxFrameBytes++ },
		"relay limit hash":         func(v *auth.AuthenticatedContextSnapshotV1) { v.ServerLimitBlockHash[0] ^= 1 },
		"client config source":     func(v *auth.AuthenticatedContextSnapshotV1) { v.ClientConfigSourceBlock.ProfileID = "detached" },
		"relay config source hash": func(v *auth.AuthenticatedContextSnapshotV1) { v.ServerConfigSourceBlockHash[0] ^= 1 },
		"compatibility policy": func(v *auth.AuthenticatedContextSnapshotV1) {
			v.EffectivePolicy.ProfileCompatibilityPolicy = "schema_and_feature"
		},
		"config policy": func(v *auth.AuthenticatedContextSnapshotV1) {
			v.EffectivePolicy.ConfigValidationPolicy = "strict_profile_bound"
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			context := cloneAuthenticatedContextSnapshotV1(base)
			mutate(&context)
			if err := validateAuthenticatedContextForPairV1(context); !errors.Is(err, ErrProfileIncompatible) {
				t.Fatalf("got %v, want profile_incompatible", err)
			}
		})
	}
}

func TestAuthenticatedContextPairAdmissionRejectsConsistentlyRehashedUnsupportedModesV1(t *testing.T) {
	_, _, base := authenticatedPairFixtureV1(t)
	tests := map[string]func() auth.AuthenticatedContextSnapshotV1{
		"schema and feature": func() auth.AuthenticatedContextSnapshotV1 {
			return authenticatedContextWithPoliciesV1(t, "schema_and_feature", "strict_required")
		},
		"strict profile bound": func() auth.AuthenticatedContextSnapshotV1 {
			return authenticatedContextWithPoliciesV1(t, "strict_schema", "strict_profile_bound")
		},
		"unequal peer ceiling": func() auth.AuthenticatedContextSnapshotV1 {
			context := cloneAuthenticatedContextSnapshotV1(base)
			context.ServerCompatibilityBlock.MaxReplayWindow++
			if err := rehashAuthenticatedContextForPairTestV1(&context); err != nil {
				t.Fatal(err)
			}
			return context
		},
	}
	for name, makeContext := range tests {
		t.Run(name, func(t *testing.T) {
			context := makeContext()
			recomputed, err := security.ContextHashV1(contextHashInputForPairTestV1(context))
			if err != nil {
				t.Fatalf("security DTO rejected internally consistent context: %v", err)
			}
			if recomputed != context.ContextHash {
				t.Fatalf("stored context hash %x differs from independently recomputed %x", context.ContextHash, recomputed)
			}
			if err := validateAuthenticatedContextForPairV1(context); !errors.Is(err, ErrProfileIncompatible) {
				t.Fatalf("got %v", err)
			}
		})
	}
}

func TestAuthenticatedChannelPairOwnerPreflightAndRepeatV1(t *testing.T) {
	fixture, base, _ := authenticatedPairFixtureV1(t)
	tests := map[string]func(*HandshakeRuntime){
		"client missing profile":           func(r *HandshakeRuntime) { r.clientRegistry.entries = nil },
		"relay missing profile":            func(r *HandshakeRuntime) { r.relayRegistry.entries = nil },
		"client stale policy":              func(r *HandshakeRuntime) { r.clientRegistry.entries[0].effectivePolicyHash[0] ^= 1 },
		"relay stale policy":               func(r *HandshakeRuntime) { r.relayRegistry.entries[0].effectivePolicyHash[0] ^= 1 },
		"client stale profile":             func(r *HandshakeRuntime) { r.clientRegistry.entries[0].profileHash[0] ^= 1 },
		"relay stale profile":              func(r *HandshakeRuntime) { r.relayRegistry.entries[0].profileHash[0] ^= 1 },
		"client strict schema missing":     func(r *HandshakeRuntime) { r.clientSupport.schemaVersions = nil },
		"relay strict schema missing":      func(r *HandshakeRuntime) { r.relaySupport.schemaVersions = nil },
		"client compiler security missing": func(r *HandshakeRuntime) { r.clientSupport.compilerSecurityVersions = nil },
		"relay compiler security missing":  func(r *HandshakeRuntime) { r.relaySupport.compilerSecurityVersions = nil },
		"client selected suite missing":    func(r *HandshakeRuntime) { r.clientSupport.suites = nil },
		"relay selected suite missing":     func(r *HandshakeRuntime) { r.relaySupport.suites = nil },
		"client current suite missing":     func(r *HandshakeRuntime) { r.clientSupport.securitySuiteIDs = nil },
		"relay current suite missing":      func(r *HandshakeRuntime) { r.relaySupport.securitySuiteIDs = nil },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			entropy := &countingEntropyV1{fail: true}
			runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, entropy)
			mutate(runtime)
			kdf := 0
			runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
				kdf++
				return security.DeriveKeyScheduleV1(input)
			}
			client, relay, err := runtime.NewAuthenticatedChannelPair(base)
			if err == nil || client != nil || relay != nil || entropy.reads != 0 || kdf != 0 {
				t.Fatalf("client=%v relay=%v err=%v entropy=%d kdf=%d", client, relay, err, entropy.reads, kdf)
			}
		})
	}

	t.Run("post success owner mutation", func(t *testing.T) {
		runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{19}, 32)))
		runtime.clientDependencies.Identity = &callbackIdentityV1{base: runtime.clientDependencies.Identity, call: func() { runtime.clientRegistry.entries[0].effectivePolicyHash[0] ^= 1 }}
		kdf := 0
		runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
			kdf++
			return security.DeriveKeyScheduleV1(input)
		}
		client, relay, err := runtime.NewAuthenticatedChannelPair(base)
		if err == nil || client != nil || relay != nil || kdf != 0 {
			t.Fatalf("client=%v relay=%v err=%v kdf=%d", client, relay, err, kdf)
		}
	})

	t.Run("caller source mutation after snapshot", func(t *testing.T) {
		input := base
		runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{20}, 32)))
		runtime.clientDependencies.Identity = &callbackIdentityV1{base: runtime.clientDependencies.Identity, call: func() { input.FirstContactInput.SelectedCapabilities[0] = "caller-mutated" }}
		client, relay, err := runtime.NewAuthenticatedChannelPair(input)
		if err != nil {
			t.Fatal(err)
		}
		client.Close()
		relay.Close()
	})
}

func TestPairMaterialSingleUseForgeryAndCrossRuntimeV1(t *testing.T) {
	fixture, _, context := authenticatedPairFixtureV1(t)
	newRuntime := func(fill byte) *HandshakeRuntime {
		return strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{fill}, 32)))
	}
	makeMaterial := func(runtime *HandshakeRuntime) pairMaterialHandleV1 {
		if err := runtime.ensureStrictEpochV1(); err != nil {
			t.Fatal(err)
		}
		config, err := strictConfigFromContextV1(context, true)
		if err != nil {
			t.Fatal(err)
		}
		handle, err := runtime.registerPairMaterialV1(context, bytes.Repeat([]byte{9}, 32), config, config,
			ClientLocalRuntimeControlsV1{RuntimeID: "client", EventCapacity: 1, QueueCeiling: 1},
			RelayLocalRuntimeControlsV1{RuntimeID: "relay", EventCapacity: 1, QueueCeiling: 1})
		if err != nil {
			t.Fatal(err)
		}
		return handle
	}

	runtime := newRuntime(5)
	if err := runtime.ensureStrictEpochV1(); err != nil {
		t.Fatal(err)
	}
	config, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	if handle, err := runtime.registerPairMaterialV1(context, make([]byte, 32), config, config, ClientLocalRuntimeControlsV1{}, RelayLocalRuntimeControlsV1{}); err == nil || handle.state != nil {
		t.Fatal("all-zero transfer secret was registered")
	}
	forgedClient := bytes.Repeat([]byte{0x31}, 32)
	forgedRelay := bytes.Repeat([]byte{0x32}, 32)
	forgedState := &pairMaterialStateV1{clientSecret: forgedClient, relaySecret: forgedRelay}
	if client, relay, err := runtime.consumePairMaterialV1(pairMaterialHandleV1{state: forgedState}); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) || !zeroRuntimeSliceV1(forgedClient) || !zeroRuntimeSliceV1(forgedRelay) {
		t.Fatal("unregistered forged state was not rejected and cleaned")
	}
	if client, relay, err := runtime.consumePairMaterialV1(pairMaterialHandleV1{}); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("zero material got client=%v relay=%v err=%v", client, relay, err)
	}
	handle := makeMaterial(runtime)
	client, relay, err := runtime.consumePairMaterialV1(handle)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	relay.Close()
	if client, relay, err = runtime.consumePairMaterialV1(handle); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("reuse got client=%v relay=%v err=%v", client, relay, err)
	}

	forged := makeMaterial(runtime)
	forged.epoch[0] ^= 1
	if client, relay, err = runtime.consumePairMaterialV1(forged); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("forgery got client=%v relay=%v err=%v", client, relay, err)
	}
	if client, relay, err = runtime.consumePairMaterialV1(forged); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatal("forged attempt did not burn material")
	}
	other := newRuntime(6)
	if err := other.ensureStrictEpochV1(); err != nil {
		t.Fatal(err)
	}
	handleOwnerMismatch := makeMaterial(runtime)
	handleOwnerMismatch.owner = other
	if client, relay, err = runtime.consumePairMaterialV1(handleOwnerMismatch); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatal("handle-owner mismatch accepted")
	}
	stateOwnerMismatch := makeMaterial(runtime)
	stateOwnerMismatch.state.owner = other
	if client, relay, err = runtime.consumePairMaterialV1(stateOwnerMismatch); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatal("state-owner mismatch accepted")
	}
	deepSource := makeMaterial(runtime)
	sourceState := deepSource.state
	deepState := pairMaterialStateV1{
		owner: sourceState.owner, epoch: sourceState.epoch, context: cloneAuthenticatedContextSnapshotV1(sourceState.context),
		clientSecret: append([]byte(nil), sourceState.clientSecret...), relaySecret: append([]byte(nil), sourceState.relaySecret...),
		clientTranscript: sourceState.clientTranscript, relayTranscript: sourceState.relayTranscript,
		clientSuite: sourceState.clientSuite, relaySuite: sourceState.relaySuite,
		clientConfig: sourceState.clientConfig, relayConfig: sourceState.relayConfig,
		clientControls: sourceState.clientControls, relayControls: sourceState.relayControls,
	}
	deepClient, deepRelay := deepState.clientSecret, deepState.relaySecret
	if client, relay, err = runtime.consumePairMaterialV1(pairMaterialHandleV1{state: &deepState, owner: runtime, epoch: runtime.epoch}); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) || !zeroRuntimeSliceV1(deepClient) || !zeroRuntimeSliceV1(deepRelay) {
		t.Fatal("deep-copy forgery accepted or retained secrets")
	}
	client, relay, err = runtime.consumePairMaterialV1(deepSource)
	if err != nil {
		t.Fatal("deep-copy forgery invalidated original registration")
	}
	client.Close()
	relay.Close()

	cross := makeMaterial(runtime)
	if client, relay, err = other.consumePairMaterialV1(cross); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("cross-runtime got client=%v relay=%v err=%v", client, relay, err)
	}
	if client, relay, err = runtime.consumePairMaterialV1(cross); client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatal("cross-runtime attempt did not burn owner material")
	}
}

func TestPairMaterialConcurrentReuseV1(t *testing.T) {
	fixture, _, context := authenticatedPairFixtureV1(t)
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{7}, 32)))
	if err := runtime.ensureStrictEpochV1(); err != nil {
		t.Fatal(err)
	}
	config, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := runtime.registerPairMaterialV1(context, bytes.Repeat([]byte{8}, 32), config, config,
		ClientLocalRuntimeControlsV1{RuntimeID: "client", EventCapacity: 1, QueueCeiling: 1},
		RelayLocalRuntimeControlsV1{RuntimeID: "relay", EventCapacity: 1, QueueCeiling: 1})
	if err != nil {
		t.Fatal(err)
	}
	const attempts = 16
	var wg sync.WaitGroup
	var mu sync.Mutex
	successes := 0
	failures := 0
	for range attempts {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client, relay, err := runtime.consumePairMaterialV1(handle)
			if err == nil {
				client.Close()
				relay.Close()
				mu.Lock()
				successes++
				mu.Unlock()
			} else {
				if client != nil || relay != nil {
					t.Errorf("loser returned an endpoint")
				}
				mu.Lock()
				failures++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if successes != 1 || failures != attempts-1 {
		t.Fatalf("got successes=%d failures=%d", successes, failures)
	}
}

func TestPairMaterialTranscriptAndSecretIsolationV1(t *testing.T) {
	fixture, _, context := authenticatedPairFixtureV1(t)
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{17}, 32)))
	if err := runtime.ensureStrictEpochV1(); err != nil {
		t.Fatal(err)
	}
	config, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := runtime.registerPairMaterialV1(context, bytes.Repeat([]byte{0x71}, 32), config, config,
		ClientLocalRuntimeControlsV1{RuntimeID: "client", EventCapacity: 1, QueueCeiling: 1}, RelayLocalRuntimeControlsV1{RuntimeID: "relay", EventCapacity: 1, QueueCeiling: 1})
	if err != nil {
		t.Fatal(err)
	}
	clientSecretAlias, relaySecretAlias := handle.state.clientSecret, handle.state.relaySecret
	if &clientSecretAlias[0] == &relaySecretAlias[0] {
		t.Fatal("transfer secrets alias before consume")
	}
	wantTranscript := context.TranscriptHash
	calls := 0
	runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
		calls++
		if calls == 1 {
			input.TranscriptHash[0] ^= 0xff
		}
		if calls == 2 && !bytes.Equal(input.TranscriptHash, wantTranscript[:]) {
			t.Fatal("client transcript mutation reached relay KDF")
		}
		return security.DeriveKeyScheduleV1(input)
	}
	client, relay, err := runtime.consumePairMaterialV1(handle)
	if err != nil {
		t.Fatal(err)
	}
	client.Close()
	relay.Close()
	if !zeroRuntimeSliceV1(clientSecretAlias) || !zeroRuntimeSliceV1(relaySecretAlias) {
		t.Fatal("transfer secret aliases retained bytes")
	}
}

func TestPairOwnershipRegisteredFailureWipesAliasesV1(t *testing.T) {
	fixture, _, context := authenticatedPairFixtureV1(t)
	tests := map[string]func(*pairMaterialHandleV1, *HandshakeRuntime, *HandshakeRuntime) *HandshakeRuntime{
		"handle epoch": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.epoch[0] ^= 1
			return owner
		},
		"state epoch": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.epoch[0] ^= 1
			return owner
		},
		"handle owner": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.owner = other
			return owner
		},
		"state owner": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.owner = other
			return owner
		},
		"cross runtime": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime { return other },
		"client transcript": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.clientTranscript[0] ^= 1
			return owner
		},
		"relay transcript": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.relayTranscript[0] ^= 1
			return owner
		},
		"client suite": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.clientSuite.KDF = "forged"
			return owner
		},
		"relay suite": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.relaySuite.AEAD = "forged"
			return owner
		},
		"context integrity": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.context.ContextHash[0] ^= 1
			return owner
		},
		"config integrity": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.clientConfig.ConfigPolicyHash[0] ^= 1
			return owner
		},
		"control integrity": func(h *pairMaterialHandleV1, owner, other *HandshakeRuntime) *HandshakeRuntime {
			h.state.relayControls.QueueCeiling = 0
			return owner
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			owner, handle, clientSecret, relaySecret := registeredPairMaterialForFailureV1(t, fixture, context, 30)
			other := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{31}, 32)))
			if err := other.ensureStrictEpochV1(); err != nil {
				t.Fatal(err)
			}
			receiver := mutate(&handle, owner, other)
			kdf := 0
			receiver.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
				kdf++
				return security.DeriveKeyScheduleV1(input)
			}
			client, relay, err := receiver.consumePairMaterialV1(handle)
			if err == nil || client != nil || relay != nil || kdf != 0 || !zeroRuntimeSliceV1(clientSecret) || !zeroRuntimeSliceV1(relaySecret) {
				t.Fatalf("client=%v relay=%v err=%v kdf=%d clientSecretZero=%v relaySecretZero=%v", client, relay, err, kdf, zeroRuntimeSliceV1(clientSecret), zeroRuntimeSliceV1(relaySecret))
			}
		})
	}
}

func TestPairOwnershipCoordinatorDestroyExactlyOnceV1(t *testing.T) {
	var calls atomic.Int32
	coordinator := &pairTerminalCoordinatorV1{destroy: func() { calls.Add(1) }}
	client := &ClientAuthenticatedEndpointV1{state: &clientAuthenticatedEndpointStateV1{coordinator: coordinator}}
	relay := &RelayAuthenticatedEndpointV1{state: &relayAuthenticatedEndpointStateV1{coordinator: coordinator}}
	var wg sync.WaitGroup
	for i := 0; i < 64; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if i%2 == 0 {
				client.Close()
			} else {
				relay.Close()
			}
		}(i)
	}
	wg.Wait()
	client.Close()
	relay.Close()
	if calls.Load() != 1 || !coordinator.closed || coordinator.destroy != nil {
		t.Fatalf("calls=%d closed=%v destroyNil=%v", calls.Load(), coordinator.closed, coordinator.destroy == nil)
	}
}

func TestPairFailureDestroysSecretsAndPartialSchedulesV1(t *testing.T) {
	fixture, _, context := authenticatedPairFixtureV1(t)
	t.Run("first kdf", func(t *testing.T) {
		runtime, handle, clientSecret, relaySecret := registeredPairMaterialForFailureV1(t, fixture, context, 10)
		var observed []byte
		var partialAliases [][]byte
		runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
			observed = input.ApplicationSecret
			partial, aliases := hostilePublicScheduleV1(0x41)
			partialAliases = aliases
			return partial, errors.New("injected")
		}
		client, relay, err := runtime.consumePairMaterialV1(handle)
		if err == nil || client != nil || relay != nil || !zeroRuntimeSliceV1(observed) || !allRuntimeSlicesZeroV1(partialAliases) || !zeroRuntimeSliceV1(clientSecret) || !zeroRuntimeSliceV1(relaySecret) {
			t.Fatalf("first KDF cleanup failed: client=%v relay=%v err=%v secret=%x", client, relay, err, observed)
		}
	})
	t.Run("second kdf", func(t *testing.T) {
		runtime, handle, clientSecret, relaySecret := registeredPairMaterialForFailureV1(t, fixture, context, 11)
		calls := 0
		var firstAliases, partialSecondAliases [][]byte
		runtime.pairDeriveScheduleV1 = func(input security.KeyScheduleInput) (security.KeySchedule, error) {
			calls++
			if calls == 2 {
				partial, aliases := hostilePublicScheduleV1(0x42)
				partialSecondAliases = aliases
				return partial, errors.New("injected")
			}
			schedule, err := security.DeriveKeyScheduleV1(input)
			firstAliases = publicScheduleAliasesV1(schedule)
			return schedule, err
		}
		client, relay, err := runtime.consumePairMaterialV1(handle)
		if err == nil || client != nil || relay != nil || !allRuntimeSlicesZeroV1(firstAliases) || !allRuntimeSlicesZeroV1(partialSecondAliases) || !zeroRuntimeSliceV1(clientSecret) || !zeroRuntimeSliceV1(relaySecret) {
			t.Fatalf("second KDF cleanup failed: client=%v relay=%v err=%v", client, relay, err)
		}
	})
	t.Run("construction", func(t *testing.T) {
		runtime, handle, clientSecret, relaySecret := registeredPairMaterialForFailureV1(t, fixture, context, 12)
		var clientAliases, relayAliases [][]byte
		runtime.pairConstructV1 = func(input pairConstructionInputV1) (*ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1, error) {
			clientAliases = publicScheduleAliasesV1(input.clientSchedule)
			relayAliases = publicScheduleAliasesV1(input.relaySchedule)
			return nil, nil, errors.New("injected")
		}
		client, relay, err := runtime.consumePairMaterialV1(handle)
		if err == nil || client != nil || relay != nil || !allRuntimeSlicesZeroV1(clientAliases) || !allRuntimeSlicesZeroV1(relayAliases) || !zeroRuntimeSliceV1(clientSecret) || !zeroRuntimeSliceV1(relaySecret) {
			t.Fatalf("construction cleanup failed: client=%v relay=%v err=%v", client, relay, err)
		}
	})
}

func TestPairFailureInvalidConstructionOwnerV1(t *testing.T) {
	for _, input := range []pairConstructionInputV1{{}, {owner: &HandshakeRuntime{}, epoch: [32]byte{1}}} {
		client, relay, err := constructAuthenticatedPairV1(input)
		if client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
			t.Fatalf("client=%v relay=%v err=%v", client, relay, err)
		}
	}
}

func TestPairAPILegacyRuntimeRejectedV1(t *testing.T) {
	dependencies := runtimeDependenciesFixture(t)
	runtime, err := NewHandshakeRuntime(dependencies.client, dependencies.server)
	if err != nil {
		t.Fatal(err)
	}
	client, relay, err := runtime.NewAuthenticatedChannelPair(PairInputV1{})
	if client != nil || relay != nil || !errors.Is(err, ErrProfileIncompatible) {
		t.Fatalf("legacy pair got client=%v relay=%v err=%v", client, relay, err)
	}
}

func authenticatedPairFixtureV1(t *testing.T) (strictSupportFixtureV1, PairInputV1, auth.AuthenticatedContextSnapshotV1) {
	t.Helper()
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	input, context := pairInputForStrictFixtureV1(t, fixture)
	return fixture, input, context
}

func pairInputForStrictFixtureV1(t *testing.T, fixture strictSupportFixtureV1) (PairInputV1, auth.AuthenticatedContextSnapshotV1) {
	t.Helper()
	probe := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{1}, 32)))
	result, context, err := probe.strictFirstContactWithContextV1(fixture.input)
	if err != nil {
		t.Fatal(err)
	}
	wipeRuntimeBytesV1(result.ChannelSecret)
	clientValue, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	relayValue, err := strictConfigFromContextV1(context, false)
	if err != nil {
		t.Fatal(err)
	}
	clientConfig, err := NewClientStrictSessionConfigV1(clientValue)
	if err != nil {
		t.Fatal(err)
	}
	relayConfig, err := NewRelayStrictSessionConfigV1(relayValue)
	if err != nil {
		t.Fatal(err)
	}
	return PairInputV1{
		FirstContactInput: fixture.input,
		ClientConfig:      clientConfig,
		RelayConfig:       relayConfig,
		ClientControls:    ClientLocalRuntimeControlsV1{RuntimeID: "client-runtime", EventCapacity: 128, QueueCeiling: 1},
		RelayControls:     RelayLocalRuntimeControlsV1{RuntimeID: "relay-runtime", EventCapacity: 128, QueueCeiling: 1},
	}, context
}

func zeroRuntimeSliceV1(value []byte) bool {
	for _, b := range value {
		if b != 0 {
			return false
		}
	}
	return true
}

func registeredPairMaterialForFailureV1(t *testing.T, fixture strictSupportFixtureV1, context auth.AuthenticatedContextSnapshotV1, fill byte) (*HandshakeRuntime, pairMaterialHandleV1, []byte, []byte) {
	t.Helper()
	runtime := strictRuntimeForFixtureV1(t, fixture, reviewedClientImplementationSupportV1, reviewedRelayImplementationSupportV1, bytes.NewReader(bytes.Repeat([]byte{fill}, 32)))
	if err := runtime.ensureStrictEpochV1(); err != nil {
		t.Fatal(err)
	}
	config, err := strictConfigFromContextV1(context, true)
	if err != nil {
		t.Fatal(err)
	}
	handle, err := runtime.registerPairMaterialV1(context, bytes.Repeat([]byte{fill + 1}, 32), config, config,
		ClientLocalRuntimeControlsV1{RuntimeID: "client", EventCapacity: 1, QueueCeiling: 1}, RelayLocalRuntimeControlsV1{RuntimeID: "relay", EventCapacity: 1, QueueCeiling: 1})
	if err != nil {
		t.Fatal(err)
	}
	return runtime, handle, handle.state.clientSecret, handle.state.relaySecret
}

func hostilePublicScheduleV1(fill byte) (security.KeySchedule, [][]byte) {
	schedule := security.KeySchedule{
		ClientWriteKey: bytes.Repeat([]byte{fill}, 32), ServerWriteKey: bytes.Repeat([]byte{fill + 1}, 32),
		ClientNonceBase: bytes.Repeat([]byte{fill + 2}, 12), ServerNonceBase: bytes.Repeat([]byte{fill + 3}, 12),
		ExporterSecret: bytes.Repeat([]byte{fill + 4}, 32),
	}
	return schedule, publicScheduleAliasesV1(schedule)
}

func publicScheduleAliasesV1(schedule security.KeySchedule) [][]byte {
	return [][]byte{schedule.ClientWriteKey, schedule.ServerWriteKey, schedule.ClientNonceBase, schedule.ServerNonceBase, schedule.ExporterSecret}
}

func allRuntimeSlicesZeroV1(values [][]byte) bool {
	if len(values) == 0 {
		return false
	}
	for _, value := range values {
		if !zeroRuntimeSliceV1(value) {
			return false
		}
	}
	return true
}

func newHigherCeilingStrictFixtureV1(t *testing.T) strictSupportFixtureV1 {
	t.Helper()
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = "strict_suite_and_capabilities"
	p.Security.CapabilityNegotiationPolicy = "strict_required"
	p.Security.ProfileCompatibilityPolicy = "strict_schema"
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = "strict_required"
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.Compatibility.MaxReplayWindow = p.Security.ReplayWindowSize + 7
	p.Compatibility.MaxStreamCount = p.Stream.MaxConcurrentStreams + 5
	p.Compatibility.MaxEnvelopeBytes = p.CarrierPolicy.MaxEnvelopeBytes + 1024
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	client, err := auth.NewPeerParameters("runtime-client", p, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := auth.NewPeerParameters("runtime-server", p, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	input := auth.FirstContactInput{Client: client, Server: relay, SelectedPolicy: policy, SelectedCapabilities: append([]string(nil), floor...), ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay}
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
	clientRegistry := mustSingletonPairRegistryV1(t, clientEntry, NewClientProfileAuthorizationRegistryV1)
	relayRegistry := mustSingletonPairRegistryV1(t, relayEntry, NewRelayProfileAuthorizationRegistryV1)
	return strictSupportFixtureV1{input: input, snapshot: snapshot, view: view, dependencies: dependencies, clientEntry: clientEntry, relayEntry: relayEntry, clientRegistry: clientRegistry, relayRegistry: relayRegistry}
}

func mustSingletonPairRegistryV1[Entry any, Registry any](t *testing.T, entry Entry, constructor func([]Entry) (Registry, error)) Registry {
	t.Helper()
	registry, err := constructor([]Entry{entry})
	if err != nil {
		t.Fatal(err)
	}
	return registry
}

func authenticatedContextWithPoliciesV1(t *testing.T, profilePolicy, configPolicy string) auth.AuthenticatedContextSnapshotV1 {
	t.Helper()
	p, err := compiler.Generate(6201)
	if err != nil {
		t.Fatal(err)
	}
	p.Security.TranscriptMode = security.TranscriptCanonicalV1
	p.Security.NonceMode = "counter_xor_base"
	p.Security.ReplayPolicy = "ordered_only"
	p.Security.DowngradePolicy = "strict_suite_and_capabilities"
	p.Security.CapabilityNegotiationPolicy = "strict_required"
	p.Security.ProfileCompatibilityPolicy = profilePolicy
	p.Security.KeyRotationPolicy = "session_only"
	p.Security.ConfigValidationPolicy = configPolicy
	p.Security.SecureEnvelopeMode = "metadata_authenticated"
	p.GenerationHash = ""
	p.GenerationHash, err = ir.CanonicalHash(p)
	if err != nil {
		t.Fatal(err)
	}
	known := sortedStringsV1(ir.SecurityCapabilities())
	floor := append([]string(nil), known[:2]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(p, floor, floor, floor)
	if err != nil {
		t.Fatal(err)
	}
	clientPeer, err := auth.NewPeerParameters("runtime-client", p, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	relayPeer, err := auth.NewPeerParameters("runtime-server", p, policy, policy, known, floor)
	if err != nil {
		t.Fatal(err)
	}
	dependencies := runtimeDependenciesFixture(t)
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	result, err := auth.FirstContact(auth.FirstContactInput{Client: clientPeer, Server: relayPeer, SelectedPolicy: policy, SelectedCapabilities: floor, ClientDependencies: dependencies.client, ServerDependencies: dependencies.server, Replay: replay})
	if err != nil {
		t.Fatal(err)
	}
	defer wipeRuntimeBytesV1(result.ChannelSecret)
	context, ok := result.AuthenticatedContextSnapshotV1()
	if !ok {
		t.Fatal("missing authenticated context")
	}
	return context
}

func contextHashInputForPairTestV1(context auth.AuthenticatedContextSnapshotV1) security.AuthenticatedContextHashInputV1 {
	return security.AuthenticatedContextHashInputV1{EffectivePolicy: context.EffectivePolicy, EffectivePolicyHash: context.EffectivePolicyHash, TranscriptHash: context.TranscriptHash, SelectedSuite: context.SelectedSuite, SelectedCapabilityHash: context.SelectedCapabilityHash, ClientProfileHash: context.ClientProfileHash, ServerProfileHash: context.ServerProfileHash, ClientModeBinding: context.ClientModeBinding, ServerModeBinding: context.ServerModeBinding}
}

func rehashAuthenticatedContextForPairTestV1(context *auth.AuthenticatedContextSnapshotV1) error {
	roles := []struct {
		compatibility     *security.CompatibilityBlockV1
		compatibilityHash *[32]byte
		limits            *security.LimitBlockV1
		limitHash         *[32]byte
		source            *security.ConfigSourceBlockV1
		sourceHash        *[32]byte
		binding           *security.HandshakeModeBinding
	}{
		{&context.ClientCompatibilityBlock, &context.ClientCompatibilityBlockHash, &context.ClientLimitBlock, &context.ClientLimitBlockHash, &context.ClientConfigSourceBlock, &context.ClientConfigSourceBlockHash, &context.ClientModeBinding},
		{&context.ServerCompatibilityBlock, &context.ServerCompatibilityBlockHash, &context.ServerLimitBlock, &context.ServerLimitBlockHash, &context.ServerConfigSourceBlock, &context.ServerConfigSourceBlockHash, &context.ServerModeBinding},
	}
	for _, role := range roles {
		compatibilityHash, err := security.CompatibilityBlockHashV1(*role.compatibility)
		if err != nil {
			return err
		}
		limitHash, err := security.LimitBlockHashV1(*role.limits)
		if err != nil {
			return err
		}
		*role.compatibilityHash, *role.limitHash = compatibilityHash, limitHash
		role.source.CompatibilityBlockHash, role.source.LimitBlockHash = compatibilityHash, limitHash
		sourceHash, err := security.ConfigSourceBlockHashV1(*role.source)
		if err != nil {
			return err
		}
		*role.sourceHash = sourceHash
		role.binding.CompatibilityBlock, role.binding.CompatibilityBlockHash = role.compatibility.Clone(), compatibilityHash
		role.binding.LimitBlock, role.binding.LimitBlockHash = *role.limits, limitHash
		role.binding.ConfigSourceBlock, role.binding.ConfigSourceBlockHash = *role.source, sourceHash
	}
	hash, err := security.ContextHashV1(contextHashInputForPairTestV1(*context))
	if err != nil {
		return err
	}
	context.ContextHash = hash
	return nil
}
