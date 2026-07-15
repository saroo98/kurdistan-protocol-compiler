// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"errors"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/runtime/labfault"
	"reflect"
	"testing"
)

type runtimeLabExecutorOwnerRowV1 struct {
	Name, Category, Shape, Seam string
	Mode                        runtimeLabFaultModeV1
	Count                       uint32
}

var runtimeLabExecutorOwnerTableV1 = []runtimeLabExecutorOwnerRowV1{
	{"reused_nonce", "nonce", "pair", "newStrictProtectedChannelWithLabFaultV1", runtimeLabReusedNonceV1, 1}, {"accepts_replay", "security_replay", "pair", "openClientApplicationV1", runtimeLabAcceptsReplayV1, 1}, {"runtime_accepts_replay", "runtime_replay", "pair", "retryClientApplicationV1", runtimeLabAcceptsRuntimeReplayV1, 1}, {"runtime_no_state_validation", "state", "pair", "openRelayApplicationV1", runtimeLabNoStateValidationV1, 1}, {"secret_trace_leak", "trace", "nil", "newRuntimeTraceFaultObservationV1", runtimeLabSecretTraceV1, 1}, {"runtime_leaks_secret_trace", "trace", "nil", "newRuntimeTraceFaultObservationV1", runtimeLabRuntimeSecretTraceV1, 1}, {"runtime_leaks_payload_trace", "trace", "nil", "newRuntimeTraceFaultObservationV1", runtimeLabRuntimePayloadTraceV1, 1}, {"runtime_ignores_backpressure", "backpressure", "nil", "newMemoryLinkWithLabFaultV1", runtimeLabIgnoresBackpressureV1, 2}, {"runtime_padding_only_diversity", "padding", "pair", "newInProcessProtectedRelayWithLabFaultV1", runtimeLabPaddingDiversityV1, 2},
}

func TestRuntimeLabExecutorCausalOwnerTableV1(t *testing.T) {
	for i, row := range runtimeLabExecutorOwnerTableV1 {
		t.Run(row.Name, func(t *testing.T) {
			token, _ := labfault.NewTokenV1(row.Name)
			var client *ClientAuthenticatedEndpointV1
			var relay *RelayAuthenticatedEndpointV1
			if row.Shape == "pair" {
				_, client, relay = newAuthenticatingFirstRecordPairV1(t, int64(9000+i), "message_lifetime_bound", 32, 32)
			}
			got, err := ExecuteRuntimeLabFaultV1(token, client, relay)
			if classified, ok := classifyRuntimeLabFaultV1(token); !ok || classified != row.Mode {
				t.Fatalf("classification=%d/%v want %d", classified, ok, row.Mode)
			}
			if err != nil || !got.UnsafeObserved || got.Count != row.Count || got.Category != row.Category {
				t.Fatalf("observation=%+v err=%v", got, err)
			}
		})
	}
}

func TestRuntimeLabExecutorObservationV1(t *testing.T) {
	typ := reflect.TypeOf(RuntimeLabFaultObservationV1{})
	if typ.NumField() != 3 {
		t.Fatal("observation surface changed")
	}
	want := []struct {
		name string
		kind reflect.Kind
	}{{"UnsafeObserved", reflect.Bool}, {"Count", reflect.Uint32}, {"Category", reflect.String}}
	for i, item := range want {
		field := typ.Field(i)
		if field.Name != item.name || field.Type.Kind() != item.kind || field.Tag != "" {
			t.Fatalf("field %d=%s %s tag=%q", i, field.Name, field.Type, field.Tag)
		}
	}
}

func TestRuntimeLabExecutorAuthorityV1(t *testing.T) {
	if got, err := ExecuteRuntimeLabFaultV1(labfault.Token{}, nil, nil); err == nil || got != (RuntimeLabFaultObservationV1{}) {
		t.Fatalf("zero authority=%+v err=%v", got, err)
	}
	token, _ := labfault.NewTokenV1("runtime_ignores_backpressure")
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, 9100, "message_lifetime_bound", 32, 32)
	if got, err := ExecuteRuntimeLabFaultV1(token, client, relay); err == nil || got != (RuntimeLabFaultObservationV1{}) {
		t.Fatal("endpoint-free mode accepted endpoints")
	}
}

func TestRuntimeLabExecutorIsolationV1(t *testing.T) {
	token, _ := labfault.NewTokenV1("secret_trace_leak")
	got, err := ExecuteRuntimeLabFaultV1(token, nil, nil)
	if err != nil || got.Category != "trace" || got.Count != 1 {
		t.Fatalf("got=%+v err=%v", got, err)
	}
}

func TestRuntimeLabExecutorAllowlistV1(t *testing.T) {
	if len(runtimeLabExecutorOwnerTableV1) != 9 {
		t.Fatalf("rows=%d", len(runtimeLabExecutorOwnerTableV1))
	}
	seen := map[string]bool{}
	categories := map[string]bool{"nonce": true, "security_replay": true, "runtime_replay": true, "state": true, "trace": true, "backpressure": true, "padding": true}
	for _, row := range runtimeLabExecutorOwnerTableV1 {
		if seen[row.Name] || !categories[row.Category] || row.Count < 1 || row.Count > 2 || row.Seam == "" || row.Shape == "" || row.Mode == 0 {
			t.Fatalf("row=%+v", row)
		}
		seen[row.Name] = true
		if _, err := labfault.NewTokenV1(row.Name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestRuntimeLabExecutorZeroOnErrorV1(t *testing.T) {
	assertZero := func(got RuntimeLabFaultObservationV1, err error) {
		t.Helper()
		if err == nil || got != (RuntimeLabFaultObservationV1{}) {
			t.Fatalf("got=%+v err=%v", got, err)
		}
	}
	for _, name := range []string{"reused_nonce", "accepts_replay", "runtime_accepts_replay", "runtime_no_state_validation", "runtime_padding_only_diversity"} {
		token, _ := labfault.NewTokenV1(name)
		got, err := ExecuteRuntimeLabFaultV1(token, nil, nil)
		assertZero(got, err)
	}
	_, c1, r1 := newAuthenticatingFirstRecordPairV1(t, 9200, "message_lifetime_bound", 32, 32)
	_, c2, r2 := newAuthenticatingFirstRecordPairV1(t, 9201, "message_lifetime_bound", 32, 32)
	token, _ := labfault.NewTokenV1("reused_nonce")
	got, err := ExecuteRuntimeLabFaultV1(token, c1, r2)
	assertZero(got, err)
	closeEndpointPairV1(c1, r1)
	closeEndpointPairV1(c2, r2)
	_, closedClient, closedRelay := newAuthenticatingFirstRecordPairV1(t, 9202, "message_lifetime_bound", 32, 32)
	closeEndpointPairV1(closedClient, closedRelay)
	got, err = ExecuteRuntimeLabFaultV1(token, closedClient, closedRelay)
	assertZero(got, err)
	free, _ := labfault.NewTokenV1("runtime_ignores_backpressure")
	_, c3, r3 := newAuthenticatingFirstRecordPairV1(t, 9203, "message_lifetime_bound", 32, 32)
	got, err = ExecuteRuntimeLabFaultV1(free, c3, r3)
	assertZero(got, err)
	closeEndpointPairV1(c3, r3)
	got, err = ExecuteRuntimeLabFaultV1(labfault.Token{}, nil, nil)
	assertZero(got, err)
	if !errors.Is(err, errRuntimeTraceFaultInvalidV1) {
		t.Fatalf("sentinel=%v", err)
	}
}

func TestRuntimeLabExecutorCleanupV1(t *testing.T) {
	forced := errors.New("forced_late_error")
	for _, item := range []struct {
		name  string
		seed  int64
		field string
	}{{"reused_nonce", 9300, "protected"}, {"runtime_padding_only_diversity", 9301, "padding"}} {
		t.Run(item.field, func(t *testing.T) {
			_, client, relay := newAuthenticatingFirstRecordPairV1(t, item.seed, "message_lifetime_bound", 32, 32)
			ops := realRuntimeLabExecutorOpsV1()
			if item.field == "protected" {
				ops.afterProtectedProgress = func() error { return forced }
			} else {
				ops.afterPaddingProgress = func() error { return forced }
			}
			token, _ := labfault.NewTokenV1(item.name)
			got, err := executeRuntimeLabFaultWithOpsV1(token, client, relay, ops)
			if !errors.Is(err, forced) || got != (RuntimeLabFaultObservationV1{}) || client.State() != auth.StateClosed || relay.State() != auth.StateClosed {
				t.Fatalf("got=%+v states=%s/%s err=%v", got, client.State(), relay.State(), err)
			}
		})
	}
	ops := realRuntimeLabExecutorOpsV1()
	ops.afterBackpressureProgress = func() error { return forced }
	token, _ := labfault.NewTokenV1("runtime_ignores_backpressure")
	got, err := executeRuntimeLabFaultWithOpsV1(token, nil, nil, ops)
	if !errors.Is(err, forced) || got != (RuntimeLabFaultObservationV1{}) {
		t.Fatalf("backpressure got=%+v err=%v", got, err)
	}
}
