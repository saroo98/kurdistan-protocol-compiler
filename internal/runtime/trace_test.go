// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	ktrace "kurdistan/internal/observe/trace"
	"kurdistan/internal/runtime/labfault"
)

func TestTraceDiagnosticFaultCausalRedGreenV1(t *testing.T) {
	secret := []byte("synthetic-secret-canary")
	payload := []byte("synthetic-payload-canary")
	cases := []struct {
		name, owner string
		expected    []byte
	}{
		{"secret_trace_leak", runtimeTraceWrapperOwnerV1, secret},
		{"runtime_leaks_secret_trace", runtimeTraceEventOwnerV1, secret},
		{"runtime_leaks_payload_trace", runtimeTraceEventOwnerV1, payload},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			want := append([]byte(nil), item.expected...)
			token, _ := labfault.NewTokenV1(item.name)
			observation, err := newRuntimeTraceFaultObservationV1(token, secret, payload)
			if err != nil {
				t.Fatal(err)
			}
			secret[0] ^= 1
			payload[0] ^= 1
			if !observation.detectAndClearV1(item.owner, want) {
				t.Fatal("fault detector stayed green")
			}
			if observation.owned != nil || observation.owner != "" || !observation.used || observation.detectAndClearV1(item.owner, want) {
				t.Fatal("terminal carrier retained or reused")
			}
			secret[0] ^= 1
			payload[0] ^= 1
		})
	}
}

func TestRuntimeStrictTraceSequenceV1(t *testing.T) {
	session, err := NewSession("secret-session-id", "secret-runtime-id", RoleClient)
	if err != nil {
		t.Fatal(err)
	}
	session.State = SessionOpen
	runtimeEvent, err := RuntimeDiagnosticEventV1(session, "runtime")
	if err != nil {
		t.Fatal(err)
	}
	linkEvent, err := LinkDiagnosticEventV1(LinkFrame{Direction: "client_to_server"})
	if err != nil {
		t.Fatal(err)
	}
	sequence := []ktrace.DiagnosticEventV1{runtimeEvent, linkEvent}
	if err := ktrace.ValidateDiagnosticSequenceV1(sequence); err != nil {
		t.Fatal(err)
	}
	if ktrace.ContainsSensitiveValue(sequence, []byte(session.ID), []byte(session.RuntimeID)) {
		t.Fatal("strict runtime diagnostics retained identifiers")
	}
	raw, _ := json.Marshal(sequence)
	for _, forbidden := range []string{"TimeUnixNano", "ProfileID", "StreamLabel", "RelayFleetID", "RelayIDBucket", "Note"} {
		if _, ok := reflect.TypeOf(ktrace.DiagnosticEventV1{}).FieldByName(forbidden); ok || bytes.Contains(raw, []byte(forbidden)) {
			t.Fatalf("strict runtime diagnostic exposes %s", forbidden)
		}
	}
}

func TestCanaryOverwriteTerminalPathsV1(t *testing.T) {
	secret, payload := []byte("distinct-secret"), []byte("distinct-payload")
	token, _ := labfault.NewTokenV1("secret_trace_leak")
	for _, item := range []struct {
		owner    string
		expected []byte
	}{{"wrong", secret}, {runtimeTraceWrapperOwnerV1, []byte("wrong")}} {
		observation, err := newRuntimeTraceFaultObservationV1(token, secret, payload)
		if err != nil {
			t.Fatal(err)
		}
		owned := observation.owned
		if observation.detectAndClearV1(item.owner, item.expected) {
			t.Fatal("wrong detector matched")
		}
		if observation.owned != nil || !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatal("owned carrier not overwritten and nilled")
		}
	}
	invalid := []struct{ secret, payload []byte }{{nil, payload}, {secret, nil}, {secret, secret}, {make([]byte, 65), payload}}
	for _, item := range invalid {
		if observation, err := newRuntimeTraceFaultObservationV1(token, item.secret, item.payload); !errors.Is(err, errRuntimeTraceFaultInvalidV1) || observation != nil {
			t.Fatalf("invalid observation=%v err=%v", observation, err)
		}
	}
	backing := []byte("abcdef")
	if observation, err := newRuntimeTraceFaultObservationV1(token, backing[:3], backing[2:]); !errors.Is(err, errRuntimeTraceFaultInvalidV1) || observation != nil {
		t.Fatal("alias accepted")
	}
}

func TestNormalTraceNoFaultV1(t *testing.T) {
	if TraceHasSensitive(nil, []byte("synthetic-secret-canary")) {
		t.Fatal("normal empty trace reported canary")
	}
}
