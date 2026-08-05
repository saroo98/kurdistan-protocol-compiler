// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"kurdistan/production/internal/authn"
	"kurdistan/production/internal/authz"
)

type testClock struct{ at time.Time }

func (clock testClock) Now() time.Time { return clock.at }

type testLimiter struct{}

func (testLimiter) Allow(string, string) bool { return true }

type testValidator struct{ payload authn.Payload }

func (validator testValidator) Validate(context.Context, string, string) (authn.Payload, error) {
	return validator.payload, nil
}

type testEntitlements struct{ roles []string }

func (resolver testEntitlements) Resolve(context.Context, string) (authn.Entitlement, error) {
	return authn.Entitlement{Version: "entitlement-v1", Roles: append([]string(nil), resolver.roles...)}, nil
}

type testBackend struct {
	operation OperationView
	err       error
}

func (backend *testBackend) Ready(context.Context) error { return backend.err }
func (backend *testBackend) CreateOperation(_ context.Context, identity authn.Identity, request MutationRequest) (OperationView, error) {
	if backend.err != nil {
		return OperationView{}, backend.err
	}
	backend.operation = OperationView{OperationID: request.TargetID + "-operation", Action: request.Action, State: "PENDING", Revision: request.ExpectedRevision + 1, Epoch: request.ResultEpoch, Requester: identity.ActorID}
	return backend.operation, nil
}
func (backend *testBackend) GetOperation(context.Context, string) (OperationView, error) {
	return backend.operation, backend.err
}
func (backend *testBackend) ApproveOperation(_ context.Context, identity authn.Identity, _ string, request DecisionRequest) (OperationView, error) {
	backend.operation.Approvers = append(backend.operation.Approvers, identity.ActorID)
	backend.operation.Approvals++
	backend.operation.Revision = request.ExpectedRevision + 1
	return backend.operation, backend.err
}
func (backend *testBackend) RejectOperation(context.Context, authn.Identity, string, DecisionRequest) (OperationView, error) {
	backend.operation.State = "REJECTED"
	return backend.operation, backend.err
}
func (backend *testBackend) ExecuteOperation(context.Context, authn.Identity, string, DecisionRequest) (OperationView, error) {
	backend.operation.State = "COMMITTED"
	return backend.operation, backend.err
}
func (backend *testBackend) GetProfile(context.Context, string) (ProfileView, error) {
	return ProfileView{ProfileID: "profile-alpha", State: "ISSUED", Generation: 1}, backend.err
}
func (backend *testBackend) CurrentPublication(context.Context) (PublicationView, error) {
	return PublicationView{Version: 1}, backend.err
}
func (backend *testBackend) CurrentRevocation(context.Context) (PublicationView, error) {
	return PublicationView{Version: 1}, backend.err
}

func TestHandlerHealthAndMutationBoundary(t *testing.T) {
	backend := &testBackend{}
	handler := newTestHandler(t, backend, []string{"requester"})

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	if health.Code != http.StatusOK {
		t.Fatalf("ready status=%d body=%s", health.Code, health.Body.String())
	}

	body := `{"action":"profile.issue","target_id":"profile-alpha","subject_digest":"` + strings.Repeat("a", 64) + `","scope_digest":"` + strings.Repeat("b", 64) + `","expected_revision":1,"expected_epoch":0,"result_epoch":1,"expires_at":2000000300}`
	request := authenticatedRequest(http.MethodPost, "/v1/operations", body)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusAccepted {
		t.Fatalf("mutation status=%d body=%s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "external-subject") || strings.Contains(response.Body.String(), "@") {
		t.Fatal("identity material leaked")
	}
}

func TestHandlerRejectsAmbiguousAndUnboundedInput(t *testing.T) {
	tests := []struct{ name, body, contentType, idempotency string }{
		{"duplicate key", `{"action":"profile.issue","action":"profile.rotate"}`, "application/json", "idempotency-001"},
		{"unknown field", `{"unknown":true}`, "application/json", "idempotency-002"},
		{"wrong content type", `{}`, "application/json; charset=utf-8", "idempotency-003"},
		{"bad idempotency", `{}`, "application/json", "bad key"},
		{"oversized", strings.Repeat("x", MaxRequestBody+1), "application/json", "idempotency-004"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			handler := newTestHandler(t, &testBackend{}, []string{"requester"})
			request := authenticatedRequest(http.MethodPost, "/v1/operations", test.body)
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set("Idempotency-Key", test.idempotency)
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
		})
	}
}

func TestHandlerAcceptsExplicitZeroRevision(t *testing.T) {
	handler := newTestHandler(t, &testBackend{}, []string{"requester"})
	body := `{"action":"profile.issue","target_id":"profile-alpha","subject_digest":"` + strings.Repeat("a", 64) + `","scope_digest":"` + strings.Repeat("b", 64) + `","expected_revision":0,"expected_epoch":0,"result_epoch":1,"expires_at":2000000300}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost, "/v1/operations", body))
	if response.Code != http.StatusAccepted {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRejectsMissingExplicitRevision(t *testing.T) {
	handler := newTestHandler(t, &testBackend{}, []string{"requester"})
	body := `{"action":"profile.issue","target_id":"profile-alpha","subject_digest":"` + strings.Repeat("a", 64) + `","scope_digest":"` + strings.Repeat("b", 64) + `","expected_epoch":0,"result_epoch":1,"expires_at":2000000300}`
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, authenticatedRequest(http.MethodPost, "/v1/operations", body))
	if response.Code != http.StatusBadRequest {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestHandlerRedactsBackendErrors(t *testing.T) {
	backend := &testBackend{err: errors.New("provider stack trace and private endpoint")}
	handler := newTestHandler(t, backend, []string{"requester"})
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/v1/health/ready", nil))
	if response.Code != http.StatusServiceUnavailable || strings.Contains(response.Body.String(), "provider") || strings.Contains(response.Body.String(), "endpoint") {
		t.Fatalf("backend error leaked: %s", response.Body.String())
	}
}

func newTestHandler(t *testing.T, backend Backend, roles []string) *Handler {
	t.Helper()
	now := time.Unix(2_000_000_000, 0).UTC()
	clock := testClock{at: now}
	authenticator, err := authn.New(authn.Config{
		Audience: "phase16-api", Issuers: []string{"https://cloud.google.com/iap"}, AuthorizedParties: []string{"iap-client"},
		Environment: "qualification", ActorKey: []byte("0123456789abcdef0123456789abcdef"), PrivilegedMaximumAgeSeconds: 900,
		Clock: clock, Replay: authn.NewMemoryReplayGuard(clock), Entitlements: testEntitlements{roles: roles},
	}, testValidator{payload: authn.Payload{Issuer: "https://cloud.google.com/iap", Audience: "phase16-api", Expires: now.Unix() + 300, IssuedAt: now.Unix() - 10, Subject: "external-subject", Claims: map[string]any{"azp": "iap-client", "auth_time": float64(now.Unix() - 10), "jti": "server-token-id"}}})
	if err != nil {
		t.Fatal(err)
	}
	authorizer, err := authz.New(map[string]map[authz.Phase][]string{
		"profile.issue":    {authz.PhaseRequest: {"requester"}, authz.PhaseApprove: {"approver"}, authz.PhaseExecute: {"executor"}},
		"operation.read":   {authz.PhaseRead: {"viewer", "requester", "approver", "executor"}},
		"profile.read":     {authz.PhaseRead: {"viewer", "requester"}},
		"publication.read": {authz.PhaseRead: {"viewer", "requester"}},
		"revocation.read":  {authz.PhaseRead: {"viewer", "requester"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	handler, err := NewHandler(authenticator, authorizer, backend, testLimiter{})
	if err != nil {
		t.Fatal(err)
	}
	return handler
}

func authenticatedRequest(method, path, body string) *http.Request {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer signed-token")
	request.Header.Set("Kurdistan-API-Version", APIVersion)
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Idempotency-Key", "idempotency-001")
	return request
}

func decodeResponse[T any](t *testing.T, response *httptest.ResponseRecorder) T {
	t.Helper()
	var value T
	if err := json.Unmarshal(response.Body.Bytes(), &value); err != nil {
		t.Fatal(err)
	}
	return value
}
