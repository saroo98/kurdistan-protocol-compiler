// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"encoding/gob"
	"encoding/json"
	"errors"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"reflect"
	"strings"
	"testing"
)

var authLabFaultNamesV1 = []string{"no_transcript_binding", "accepts_downgrade", "capability_mismatch_accepted", "profile_mismatch_accepted", "runtime_accepts_capability_downgrade", "runtime_accepts_profile_mismatch", "unsafe_config_allowed"}

func assertAuthLabNormalSentinelV1(t *testing.T, err error, code FailureCode) {
	t.Helper()
	var typed *HandshakeError
	if !errors.Is(err, ErrHandshake) || !errors.As(err, &typed) || typed.Code != code {
		t.Fatalf("normal sentinel=%v want %s", err, code)
	}
}

func TestAuthLabFaultTokenSealedSerializationAndFormatV1(t *testing.T) {
	for _, name := range authLabFaultNamesV1 {
		token, err := NewAuthLabFaultTokenV1(name)
		if err != nil || !validAuthLabFaultV1(token) {
			t.Fatalf("mint %s: %v", name, err)
		}
		copyToken := token
		if !validAuthLabFaultV1(copyToken) {
			t.Fatalf("ordinary copy lost authority: %s", name)
		}
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%20.10v", "%-#40v"} {
			if got := fmt.Sprintf(format, token); got != authLabFaultRedactedV1 {
				t.Fatalf("format %s=%q", format, got)
			}
		}
		if _, err := json.Marshal(token); !errors.Is(err, errAuthLabFaultInvalidV1) {
			t.Fatalf("json marshal=%v", err)
		}
		if _, err := token.MarshalText(); !errors.Is(err, errAuthLabFaultInvalidV1) {
			t.Fatalf("text marshal=%v", err)
		}
		if _, err := token.MarshalBinary(); !errors.Is(err, errAuthLabFaultInvalidV1) {
			t.Fatalf("binary marshal=%v", err)
		}
		var encoded bytes.Buffer
		if err := gob.NewEncoder(&encoded).Encode(token); !errors.Is(err, errAuthLabFaultInvalidV1) {
			t.Fatalf("gob encode=%v", err)
		}
		forged := token
		forged.seal[0] ^= 1
		if validAuthLabFaultV1(forged) {
			t.Fatal("forged token validated")
		}
	}
	if validAuthLabFaultV1(AuthLabFaultToken{}) {
		t.Fatal("zero token validated")
	}
	if _, err := NewAuthLabFaultTokenV1("unknown"); !errors.Is(err, errAuthLabFaultInvalidV1) {
		t.Fatalf("unknown mint=%v", err)
	}
	var reconstructed AuthLabFaultToken
	for _, err := range []error{json.Unmarshal([]byte(`{}`), &reconstructed), reconstructed.UnmarshalText(nil), reconstructed.UnmarshalBinary(nil), reconstructed.GobDecode(nil)} {
		if !errors.Is(err, errAuthLabFaultInvalidV1) {
			t.Fatalf("reconstruction=%v", err)
		}
	}
}

func TestTranscriptOmissionFaultCausalRedGreenV1(t *testing.T) {
	control := newFirstContactFixture(t, "canonical_full_binding_v1")
	green, err := FirstContact(control.input)
	if err != nil {
		t.Fatal(err)
	}
	greenContext, ok := green.AuthenticatedContextSnapshotV1()
	if !ok {
		t.Fatal("green context missing")
	}
	token, _ := NewAuthLabFaultTokenV1("no_transcript_binding")
	red := newFirstContactFixture(t, "canonical_full_binding_v1")
	unsafe, err := FirstContactWithAuthLabFaultV1(red.input, token)
	if err != nil {
		t.Fatal(err)
	}
	unsafeContext, ok := unsafe.AuthenticatedContextSnapshotV1()
	if !ok || unsafeContext.TranscriptHash == greenContext.TranscriptHash {
		t.Fatal("transcript omission detector stayed green")
	}
}

func TestDowngradeFaultCausalRedGreenV1(t *testing.T) {
	fixture := newFirstContactFixture(t, "canonical_v1")
	fixture.input.Client.OfferPolicy.NonceMode = "directional_counter"
	_, normalErr := FirstContact(fixture.input)
	assertAuthLabNormalSentinelV1(t, normalErr, FailureProfileMismatch)
	token, _ := NewAuthLabFaultTokenV1("accepts_downgrade")
	if result, err := FirstContactWithAuthLabFaultV1(fixture.input, token); err != nil || result.ClientState != StateEstablished {
		t.Fatalf("fault did not accept downgrade: %v", err)
	}
}

func TestCapabilityMismatchFaultCausalRedGreenV1(t *testing.T) {
	fixture := newFirstContactFixture(t, "canonical_v1")
	fixture.input.SelectedCapabilities = append(fixture.input.SelectedCapabilities, "transcript_binding")
	_, normalErr := FirstContact(fixture.input)
	assertAuthLabNormalSentinelV1(t, normalErr, FailurePolicyFloorRejected)
	token, _ := NewAuthLabFaultTokenV1("capability_mismatch_accepted")
	if _, err := FirstContactWithAuthLabFaultV1(fixture.input, token); err != nil {
		t.Fatalf("fault did not accept capability mismatch: %v", err)
	}
}

func TestProfileMismatchFaultCausalRedGreenV1(t *testing.T) {
	fixture := newFirstContactFixture(t, "canonical_v1")
	fixture.input.Server.ProfileHash[0] ^= 1
	_, normalErr := FirstContact(fixture.input)
	assertAuthLabNormalSentinelV1(t, normalErr, FailureProfileMismatch)
	token, _ := NewAuthLabFaultTokenV1("profile_mismatch_accepted")
	if _, err := FirstContactWithAuthLabFaultV1(fixture.input, token); err != nil {
		t.Fatalf("fault did not accept profile mismatch: %v", err)
	}
}

func TestNormalAPINoFaultReachabilityV1(t *testing.T) {
	raw, err := os.ReadFile("handshake.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "handshake.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, decl := range file.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "FirstContact" {
			continue
		}
		if len(fn.Type.Params.List) != 1 || strings.Contains(string(raw[fn.Pos()-1:fn.End()-1]), "AuthLabFault") {
			t.Fatal("normal FirstContact reaches fault authority")
		}
	}
	typ := reflect.TypeOf(AuthLabFaultToken{})
	if typ.NumField() != 2 || typ.Field(0).PkgPath == "" || typ.Field(1).PkgPath == "" {
		t.Fatal("fault token exposes state")
	}
}
