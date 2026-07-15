// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package runtime

import (
	"reflect"
	"testing"

	"kurdistan/internal/runtime/labfault"
)

func TestRuntimeLabEndpointPairConstructionV1(t *testing.T) {
	client, relay, err := NewRuntimeLabEndpointPairV1(9551)
	if err != nil || client == nil || relay == nil || client.State() == "closed" || relay.State() == "closed" {
		t.Fatalf("pair=%v/%v err=%v", client, relay, err)
	}
	closeEndpointPairV1(client, relay)
}
func TestRuntimeLabEndpointPairFreshnessV1(t *testing.T) {
	c1, r1, e1 := NewRuntimeLabEndpointPairV1(9552)
	c2, r2, e2 := NewRuntimeLabEndpointPairV1(9552)
	if e1 != nil || e2 != nil || c1 == c2 || r1 == r2 || c1.state.coordinator == c2.state.coordinator || c1.state.life.owner == c2.state.life.owner {
		t.Fatal("factory reused pair state")
	}
	if !strictPairOwnedByRuntimeV1(c1.state.life.owner, c1, r1) || !strictPairOwnedByRuntimeV1(c2.state.life.owner, c2, r2) {
		t.Fatal("factory returned a cross-owner or role-invalid pair")
	}
	closeEndpointPairV1(c1, r1)
	closeEndpointPairV1(c2, r2)
}
func TestRuntimeLabEndpointPairFailureV1(t *testing.T) {
	if c, r, err := NewRuntimeLabEndpointPairV1(0); err == nil || c != nil || r != nil {
		t.Fatalf("zero pair=%v/%v err=%v", c, r, err)
	}
}
func TestRuntimeLabEndpointPairAllowlistV1(t *testing.T) {
	typ := reflect.TypeOf(NewRuntimeLabEndpointPairV1)
	if typ.NumIn() != 1 || typ.In(0).Kind() != reflect.Int64 || typ.NumOut() != 3 {
		t.Fatalf("signature=%v", typ)
	}
}
func TestRuntimeLabEndpointPairStrictPathV1(t *testing.T) {
	pairModes := []string{"reused_nonce", "accepts_replay", "runtime_accepts_replay", "runtime_no_state_validation", "runtime_padding_only_diversity"}
	for i, name := range pairModes {
		client, relay, err := NewRuntimeLabEndpointPairV1(9553 + int64(i))
		if err != nil {
			t.Fatalf("%s factory: %v", name, err)
		}
		if !strictPairOwnedByRuntimeV1(client.state.life.owner, client, relay) {
			t.Fatalf("%s pair not strict-runtime owned", name)
		}
		token, err := labfault.NewTokenV1(name)
		if err != nil {
			t.Fatal(err)
		}
		observation, err := executeRuntimeLabFaultWithOpsV1(token, client, relay, realRuntimeLabExecutorOpsV1())
		if err != nil || !observation.UnsafeObserved || observation.Count == 0 {
			t.Fatalf("%s observation=%+v err=%v", name, observation, err)
		}
	}
}
