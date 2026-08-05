// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authn

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

type fixedClock struct{ at time.Time }

func (clock fixedClock) Now() time.Time { return clock.at }

type fixedValidator struct {
	payload Payload
	err     error
}

func (validator fixedValidator) Validate(context.Context, string, string) (Payload, error) {
	return validator.payload, validator.err
}

type fixedEntitlements struct{ value Entitlement }

func (resolver fixedEntitlements) Resolve(context.Context, string) (Entitlement, error) {
	return resolver.value, nil
}

func TestAuthenticateRequestValidatesClaimsAndProducesOpaqueActor(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	payload := validPayload(now)
	authenticator := newTestAuthenticator(t, now, payload)
	request := bearerRequest("signed-token")
	identity, err := authenticator.AuthenticateRequest(context.Background(), request, true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(identity.ActorID, "actor-") || strings.Contains(identity.ActorID, payload.Subject) ||
		identity.EntitlementVersion != "entitlement-v7" || len(identity.Roles) != 1 {
		t.Fatalf("unexpected identity: %+v", identity)
	}
	if _, err := authenticator.AuthenticateRequest(context.Background(), bearerRequest("signed-token"), true); !errors.Is(err, ErrReplay) {
		t.Fatalf("privileged replay = %v", err)
	}
}

func TestAuthenticateRequestRejectsCredentialConfusion(t *testing.T) {
	now := time.Unix(2_000_000_000, 0).UTC()
	tests := []struct {
		name    string
		mutate  func(*Payload)
		request func() *http.Request
	}{
		{"wrong issuer", func(value *Payload) { value.Issuer = "https://untrusted.invalid" }, func() *http.Request { return bearerRequest("token-issuer") }},
		{"wrong audience", func(value *Payload) { value.Audience = "other-audience" }, func() *http.Request { return bearerRequest("token-audience") }},
		{"wrong authorized party", func(value *Payload) { value.Claims["azp"] = "other-party" }, func() *http.Request { return bearerRequest("token-azp") }},
		{"expired", func(value *Payload) { value.Expires = now.Unix() }, func() *http.Request { return bearerRequest("token-expired") }},
		{"future issued at", func(value *Payload) { value.IssuedAt = now.Unix() + 61 }, func() *http.Request { return bearerRequest("token-future") }},
		{"stale privileged authentication", func(value *Payload) { value.Claims["auth_time"] = float64(now.Unix() - 901) }, func() *http.Request { return bearerRequest("token-stale") }},
		{"missing token id", func(value *Payload) { delete(value.Claims, "jti") }, func() *http.Request { return bearerRequest("token-jti") }},
		{"query token", func(*Payload) {}, func() *http.Request {
			r := bearerRequest("token-query")
			r.URL.RawQuery = "access_token=forbidden"
			return r
		}},
		{"cookie token", func(*Payload) {}, func() *http.Request {
			r := bearerRequest("token-cookie")
			r.AddCookie(&http.Cookie{Name: "access_token", Value: "forbidden"})
			return r
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			payload := validPayload(now)
			test.mutate(&payload)
			authenticator := newTestAuthenticator(t, now, payload)
			if _, err := authenticator.AuthenticateRequest(context.Background(), test.request(), true); err == nil {
				t.Fatal("credential confusion accepted")
			}
		})
	}
}

func validPayload(now time.Time) Payload {
	return Payload{
		Issuer: "https://cloud.google.com/iap", Audience: "phase16-api", Expires: now.Unix() + 300,
		IssuedAt: now.Unix() - 10, Subject: "opaque-external-subject-123",
		Claims: map[string]any{"azp": "iap-client", "auth_time": float64(now.Unix() - 10), "jti": "token-id-0001", "email": "must-not-enter-state@example.invalid"},
	}
}

func newTestAuthenticator(t *testing.T, now time.Time, payload Payload) *Authenticator {
	t.Helper()
	clock := fixedClock{at: now}
	authenticator, err := New(Config{
		Audience: "phase16-api", Issuers: []string{"https://cloud.google.com/iap"},
		AuthorizedParties: []string{"iap-client"}, Environment: "qualification",
		ActorKey: []byte("0123456789abcdef0123456789abcdef"), PrivilegedMaximumAgeSeconds: 900,
		Clock: clock, Replay: NewMemoryReplayGuard(clock),
		Entitlements: fixedEntitlements{value: Entitlement{Version: "entitlement-v7", Roles: []string{"requester"}}},
	}, fixedValidator{payload: payload})
	if err != nil {
		t.Fatal(err)
	}
	return authenticator
}

func bearerRequest(token string) *http.Request {
	return &http.Request{
		Method: http.MethodPost, URL: &url.URL{Path: "/v1/operations"},
		Header: http.Header{"Authorization": []string{"Bearer " + token}},
	}
}
