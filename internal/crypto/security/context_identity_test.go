// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"errors"
	"strings"
	"testing"
)

func TestContextIdentityRejectsInvalidFields(t *testing.T) {
	ctx, keys := validContextIdentityFixture(t)

	tests := []struct {
		name   string
		field  ContextIdentityField
		raw    string
		mutate func(*SecurityContext)
	}{
		{name: "empty profile id", field: ContextIdentityProfileID, mutate: func(v *SecurityContext) { v.ProfileID = "" }},
		{name: "empty profile hash", field: ContextIdentityProfileHash, mutate: func(v *SecurityContext) { v.ProfileHash = "" }},
		{name: "short profile hash", field: ContextIdentityProfileHash, raw: "abcd", mutate: func(v *SecurityContext) { v.ProfileHash = "abcd" }},
		{name: "malformed profile hash", field: ContextIdentityProfileHash, raw: strings.Repeat("z", 64), mutate: func(v *SecurityContext) { v.ProfileHash = strings.Repeat("z", 64) }},
		{name: "zero profile hash", field: ContextIdentityProfileHash, raw: strings.Repeat("0", 64), mutate: func(v *SecurityContext) { v.ProfileHash = strings.Repeat("0", 64) }},
		{name: "short session id", field: ContextIdentitySessionID, raw: "abcd", mutate: func(v *SecurityContext) { v.SessionID = "abcd" }},
		{name: "malformed transcript hash", field: ContextIdentityTranscriptHash, raw: strings.Repeat("g", 64), mutate: func(v *SecurityContext) { v.TranscriptHash = strings.Repeat("g", 64) }},
		{name: "long transcript hash", field: ContextIdentityTranscriptHash, raw: strings.Repeat("a", 66), mutate: func(v *SecurityContext) { v.TranscriptHash = strings.Repeat("a", 66) }},
		{name: "empty capability hash", field: ContextIdentityCapabilityHash, mutate: func(v *SecurityContext) { v.CapabilityHash = "" }},
		{name: "zero capability hash", field: ContextIdentityCapabilityHash, raw: strings.Repeat("0", 64), mutate: func(v *SecurityContext) { v.CapabilityHash = strings.Repeat("0", 64) }},
		{name: "empty carrier policy identity", field: ContextIdentityCarrier, mutate: func(v *SecurityContext) { v.CarrierBinding = "" }},
		{name: "empty stream policy identity", field: ContextIdentityStream, mutate: func(v *SecurityContext) { v.StreamBinding = "" }},
		{name: "empty proxy policy identity", field: ContextIdentityProxy, mutate: func(v *SecurityContext) { v.ProxyBinding = "" }},
		{name: "unknown suite", field: ContextIdentitySuite, mutate: func(v *SecurityContext) { v.Suite.KDF = "unknown" }},
		{name: "inconsistent profile identity", field: ContextIdentitySessionID, raw: strings.Repeat("f", 64), mutate: func(v *SecurityContext) { v.ProfileHash = strings.Repeat("f", 64) }},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := ctx
			tt.mutate(&bad)
			_, err := NewEnvelopeCodec(bad, keys, "client")
			assertContextIdentityError(t, err, tt.field, tt.raw)
		})
	}
}

func TestContextIdentityCoversBuilderDirectionAndSemanticBypasses(t *testing.T) {
	in := sampleTranscriptInput(t)
	in.ProfileHash = strings.Repeat("z", 64)
	_, err := BuildContext(in)
	assertContextIdentityError(t, err, ContextIdentityProfileHash, in.ProfileHash)

	ctx, keys := validContextIdentityFixture(t)
	_, err = NewEnvelopeCodec(ctx, keys, "unexpected-direction")
	assertContextIdentityError(t, err, ContextIdentityDirection, "unexpected-direction")

	codec, err := NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		t.Fatal(err)
	}
	_, err = codec.Seal(EnvelopeMetadata{Semantic: "data\x00hidden", CarrierFamily: "stream_carrier"}, []byte("payload"))
	assertContextIdentityError(t, err, ContextIdentitySemantic, "data\x00hidden")

	env, err := codec.Seal(EnvelopeMetadata{Semantic: "data", CarrierFamily: "stream_carrier"}, []byte("payload"))
	if err != nil {
		t.Fatal(err)
	}
	env.TranscriptHash = strings.Repeat("z", 64)
	_, err = codec.Open(env)
	assertContextIdentityError(t, err, ContextIdentityTranscriptHash, env.TranscriptHash)
}

func TestContextIdentityValidContextAuthenticatesEnvelope(t *testing.T) {
	ctx, keys := validContextIdentityFixture(t)
	codec, err := NewEnvelopeCodec(ctx, keys, "client")
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("context identity valid record")
	env, err := codec.Seal(EnvelopeMetadata{StreamID: 7, Semantic: "data", CarrierFamily: "stream_carrier"}, payload)
	if err != nil {
		t.Fatal(err)
	}
	got, err := codec.Open(env)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("authenticated envelope changed the valid payload")
	}
}

func validContextIdentityFixture(t *testing.T) (SecurityContext, KeySchedule) {
	t.Helper()
	ctx, err := BuildContext(sampleTranscriptInput(t))
	if err != nil {
		t.Fatal(err)
	}
	keys, err := DeriveKeySchedule([]byte("context identity test secret"), ctx.TranscriptHash, ctx.Suite)
	if err != nil {
		t.Fatal(err)
	}
	return ctx, keys
}

func assertContextIdentityError(t *testing.T, err error, field ContextIdentityField, raw string) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s identity rejection", field)
	}
	if !errors.Is(err, ErrInvalidContextIdentity) {
		t.Fatalf("error %v does not match ErrInvalidContextIdentity", err)
	}
	var identityErr *ContextIdentityError
	if !errors.As(err, &identityErr) {
		t.Fatalf("error %T is not a *ContextIdentityError", err)
	}
	if identityErr.Field != field {
		t.Fatalf("identity error field = %q, want %q", identityErr.Field, field)
	}
	if raw != "" && strings.Contains(err.Error(), raw) {
		t.Fatal("identity error echoed the rejected value")
	}
}
