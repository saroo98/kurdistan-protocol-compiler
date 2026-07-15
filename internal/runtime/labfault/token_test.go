// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package labfault

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"testing"
)

func TestRuntimeLabFaultTokenV1(t *testing.T) {
	for _, name := range []string{"reused_nonce", "accepts_replay", "runtime_accepts_replay", "runtime_no_state_validation", "secret_trace_leak", "runtime_leaks_secret_trace", "runtime_leaks_payload_trace", "runtime_ignores_backpressure", "runtime_padding_only_diversity"} {
		token, err := NewTokenV1(name)
		if err != nil || token.mode == 0 || !hmacEqualV1(token) {
			t.Fatalf("mint %s: %v", name, err)
		}
		copyToken := token
		if copyToken != token {
			t.Fatal("copy lost authority")
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%20.10v", "%-#40v"} {
			if got := fmt.Sprintf(format, token); got != redactedV1 {
				t.Fatalf("format %s=%q", format, got)
			}
		}
		if _, err := json.Marshal(token); !errors.Is(err, errInvalidV1) {
			t.Fatalf("json=%v", err)
		}
		if _, err := token.MarshalText(); !errors.Is(err, errInvalidV1) {
			t.Fatalf("text=%v", err)
		}
		if _, err := token.MarshalBinary(); !errors.Is(err, errInvalidV1) {
			t.Fatalf("binary=%v", err)
		}
		var out bytes.Buffer
		if err := gob.NewEncoder(&out).Encode(token); !errors.Is(err, errInvalidV1) {
			t.Fatalf("gob=%v", err)
		}
		forged := token
		forged.seal[0] ^= 1
		if hmacEqualV1(forged) {
			t.Fatal("forged token validated")
		}
	}
	if hmacEqualV1(Token{}) {
		t.Fatal("zero validated")
	}
	if _, err := NewTokenV1("unknown"); !errors.Is(err, errInvalidV1) {
		t.Fatalf("unknown=%v", err)
	}
	var reconstructed Token
	for _, err := range []error{json.Unmarshal([]byte(`{}`), &reconstructed), reconstructed.UnmarshalText(nil), reconstructed.UnmarshalBinary(nil), reconstructed.GobDecode(nil)} {
		if !errors.Is(err, errInvalidV1) {
			t.Fatalf("reconstruct=%v", err)
		}
	}
	typ := reflect.TypeOf(Token{})
	if typ.NumField() != 2 || typ.Field(0).PkgPath == "" || typ.Field(1).PkgPath == "" {
		t.Fatal("token exposes state")
	}
}

func hmacEqualV1(token Token) bool {
	if token.mode < modeReusedNonceV1 || token.mode > modeRuntimePaddingOnlyDiversityV1 {
		return false
	}
	want := sealV1(token.mode)
	return token.seal == want
}
