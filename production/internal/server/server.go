// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"sync/atomic"

	"kurdistan/production/internal/authn"
	"kurdistan/production/internal/authz"
)

var (
	ErrNotFound    = errors.New("server: not found")
	ErrConflict    = errors.New("server: conflict")
	ErrUnavailable = errors.New("server: unavailable")
	identifierRE   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
	digestRE       = regexp.MustCompile(`^[0-9a-f]{64}$`)
)

type Handler struct {
	authenticator *authn.Authenticator
	authorizer    *authz.Authorizer
	backend       Backend
	limiter       RateLimiter
	sequence      atomic.Uint64
}

func NewHandler(authenticator *authn.Authenticator, authorizer *authz.Authorizer, backend Backend, limiter RateLimiter) (*Handler, error) {
	if authenticator == nil || authorizer == nil || backend == nil || limiter == nil {
		return nil, ErrUnavailable
	}
	return &Handler{authenticator: authenticator, authorizer: authorizer, backend: backend, limiter: limiter}, nil
}

func (handler *Handler) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	response.Header().Set("Content-Type", "application/json")
	response.Header().Set("Cache-Control", "no-store")
	response.Header().Set("X-Content-Type-Options", "nosniff")
	correlation := handler.correlationAlias()
	response.Header().Set("Kurdistan-Correlation-Alias", correlation)

	if request.Method == http.MethodGet && request.URL.Path == "/v1/version" {
		handler.writeJSON(response, http.StatusOK, map[string]string{"api_version": APIVersion})
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/v1/health/live" {
		handler.writeJSON(response, http.StatusOK, map[string]string{"status": "live"})
		return
	}
	if request.Method == http.MethodGet && request.URL.Path == "/v1/health/ready" {
		if err := handler.backend.Ready(request.Context()); err != nil {
			handler.writeError(response, http.StatusServiceUnavailable, "UNAVAILABLE", correlation)
			return
		}
		handler.writeJSON(response, http.StatusOK, map[string]string{"status": "ready"})
		return
	}

	privileged := request.Method != http.MethodGet
	identity, err := handler.authenticator.AuthenticateRequest(request.Context(), request, privileged)
	if err != nil {
		handler.writeError(response, http.StatusUnauthorized, "UNAUTHENTICATED", correlation)
		return
	}
	if !handler.limiter.Allow(identity.ActorID, request.Method+" "+request.URL.Path) {
		handler.writeError(response, http.StatusTooManyRequests, "RATE_LIMITED", correlation)
		return
	}
	if privileged && request.Header.Get("Kurdistan-API-Version") != APIVersion {
		handler.writeError(response, http.StatusBadRequest, "API_VERSION_REQUIRED", correlation)
		return
	}

	switch {
	case request.Method == http.MethodPost && request.URL.Path == "/v1/operations":
		handler.createOperation(response, request, identity, correlation)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/operations/"):
		handler.getOperation(response, request, identity, correlation)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, ":approve"):
		handler.decideOperation(response, request, identity, correlation, authz.PhaseApprove)
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, ":reject"):
		handler.decideOperation(response, request, identity, correlation, "reject")
	case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, ":execute"):
		handler.decideOperation(response, request, identity, correlation, authz.PhaseExecute)
	case request.Method == http.MethodGet && strings.HasPrefix(request.URL.Path, "/v1/profiles/"):
		handler.getProfile(response, request, identity, correlation)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/publications/current":
		handler.getPublication(response, request, identity, correlation, false)
	case request.Method == http.MethodGet && request.URL.Path == "/v1/revocations/current":
		handler.getPublication(response, request, identity, correlation, true)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/emergency:deny":
		handler.createNamedOperation(response, request, identity, correlation, "emergency.deny", "")
	case request.Method == http.MethodPost && strings.HasPrefix(request.URL.Path, "/v1/keys/") && strings.HasSuffix(request.URL.Path, ":rotate"):
		keyID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/keys/"), ":rotate")
		handler.createNamedOperation(response, request, identity, correlation, "key.issuer.rotate", keyID)
	case request.Method == http.MethodPost && request.URL.Path == "/v1/recovery:prepare":
		handler.createNamedOperation(response, request, identity, correlation, "recovery.prepare", "")
	default:
		handler.writeError(response, http.StatusNotFound, "NOT_FOUND", correlation)
	}
}

func (handler *Handler) createOperation(response http.ResponseWriter, request *http.Request, identity authn.Identity, correlation string) {
	var input MutationRequest
	if err := decodeMutation(request, &input); err != nil {
		handler.writeError(response, http.StatusBadRequest, "INVALID_REQUEST", correlation)
		return
	}
	if err := handler.authorizer.Authorize(identity, input.Action, authz.PhaseRequest, authz.OperationContext{}); err != nil {
		handler.writeError(response, http.StatusForbidden, "FORBIDDEN", correlation)
		return
	}
	result, err := handler.backend.CreateOperation(request.Context(), identity, input)
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	handler.writeJSON(response, http.StatusAccepted, result)
}

func (handler *Handler) createNamedOperation(response http.ResponseWriter, request *http.Request, identity authn.Identity, correlation, action, pathTarget string) {
	var input MutationRequest
	if err := decodeMutation(request, &input); err != nil || (input.Action != "" && input.Action != action) {
		handler.writeError(response, http.StatusBadRequest, "INVALID_REQUEST", correlation)
		return
	}
	input.Action = action
	if pathTarget != "" && (!identifierRE.MatchString(pathTarget) || input.TargetID != pathTarget) {
		handler.writeError(response, http.StatusBadRequest, "INVALID_REQUEST", correlation)
		return
	}
	if err := handler.authorizer.Authorize(identity, action, authz.PhaseRequest, authz.OperationContext{}); err != nil {
		handler.writeError(response, http.StatusForbidden, "FORBIDDEN", correlation)
		return
	}
	result, err := handler.backend.CreateOperation(request.Context(), identity, input)
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	handler.writeJSON(response, http.StatusAccepted, result)
}

func (handler *Handler) getOperation(response http.ResponseWriter, request *http.Request, identity authn.Identity, correlation string) {
	operationID := strings.TrimPrefix(request.URL.Path, "/v1/operations/")
	if strings.Contains(operationID, ":") || !identifierRE.MatchString(operationID) ||
		handler.authorizer.Authorize(identity, "operation.read", authz.PhaseRead, authz.OperationContext{}) != nil {
		handler.writeError(response, http.StatusForbidden, "FORBIDDEN", correlation)
		return
	}
	result, err := handler.backend.GetOperation(request.Context(), operationID)
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) decideOperation(response http.ResponseWriter, request *http.Request, identity authn.Identity, correlation string, phase authz.Phase) {
	suffix := ":" + string(phase)
	if phase == "reject" {
		suffix = ":reject"
	}
	operationID := strings.TrimSuffix(strings.TrimPrefix(request.URL.Path, "/v1/operations/"), suffix)
	if !identifierRE.MatchString(operationID) {
		handler.writeError(response, http.StatusBadRequest, "INVALID_REQUEST", correlation)
		return
	}
	current, err := handler.backend.GetOperation(request.Context(), operationID)
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	authorizationPhase := phase
	if phase == "reject" {
		authorizationPhase = authz.PhaseApprove
	}
	if err := handler.authorizer.Authorize(identity, current.Action, authorizationPhase, authz.OperationContext{
		RequesterActorID: current.Requester, ApproverActorIDs: current.Approvers,
	}); err != nil {
		handler.writeError(response, http.StatusForbidden, "FORBIDDEN", correlation)
		return
	}
	var input DecisionRequest
	if err := decodeMutation(request, &input); err != nil {
		handler.writeError(response, http.StatusBadRequest, "INVALID_REQUEST", correlation)
		return
	}
	switch phase {
	case authz.PhaseApprove:
		current, err = handler.backend.ApproveOperation(request.Context(), identity, operationID, input)
	case "reject":
		current, err = handler.backend.RejectOperation(request.Context(), identity, operationID, input)
	case authz.PhaseExecute:
		current, err = handler.backend.ExecuteOperation(request.Context(), identity, operationID, input)
	default:
		err = ErrUnavailable
	}
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	handler.writeJSON(response, http.StatusOK, current)
}

func (handler *Handler) getProfile(response http.ResponseWriter, request *http.Request, identity authn.Identity, correlation string) {
	profileID := strings.TrimPrefix(request.URL.Path, "/v1/profiles/")
	if !identifierRE.MatchString(profileID) || handler.authorizer.Authorize(identity, "profile.read", authz.PhaseRead, authz.OperationContext{}) != nil {
		handler.writeError(response, http.StatusForbidden, "FORBIDDEN", correlation)
		return
	}
	result, err := handler.backend.GetProfile(request.Context(), profileID)
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func (handler *Handler) getPublication(response http.ResponseWriter, request *http.Request, identity authn.Identity, correlation string, revocation bool) {
	action := "publication.read"
	if revocation {
		action = "revocation.read"
	}
	if handler.authorizer.Authorize(identity, action, authz.PhaseRead, authz.OperationContext{}) != nil {
		handler.writeError(response, http.StatusForbidden, "FORBIDDEN", correlation)
		return
	}
	var result PublicationView
	var err error
	if revocation {
		result, err = handler.backend.CurrentRevocation(request.Context())
	} else {
		result, err = handler.backend.CurrentPublication(request.Context())
	}
	if err != nil {
		handler.backendError(response, err, correlation)
		return
	}
	handler.writeJSON(response, http.StatusOK, result)
}

func decodeMutation[T any](request *http.Request, destination *T) error {
	if request.Header.Get("Content-Type") != "application/json" {
		return errors.New("content type")
	}
	idempotency := request.Header.Get("Idempotency-Key")
	if !identifierRE.MatchString(idempotency) || len(idempotency) > MaxIdempotencySize {
		return errors.New("idempotency")
	}
	limited := io.LimitReader(request.Body, MaxRequestBody+1)
	raw, err := io.ReadAll(limited)
	if err != nil || len(raw) == 0 || len(raw) > MaxRequestBody || !uniqueJSONKeys(raw) {
		return errors.New("body")
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil {
		return errors.New("body")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing json")
	}
	switch value := any(destination).(type) {
	case *MutationRequest:
		if !hasExactFields(fields, "action", "target_id", "subject_digest", "scope_digest", "expected_revision", "expected_epoch", "result_epoch", "expires_at") {
			return errors.New("missing mutation field")
		}
		value.IdempotencyKey = idempotency
		if value.ResultEpoch < value.ExpectedEpoch || value.ExpiresAt <= 0 ||
			!identifierRE.MatchString(value.Action) || !identifierRE.MatchString(value.TargetID) ||
			!digestRE.MatchString(value.SubjectDigest) || !digestRE.MatchString(value.ScopeDigest) {
			return errors.New("invalid mutation")
		}
	case *DecisionRequest:
		if !hasExactFields(fields, "expected_revision", "expected_epoch") {
			return errors.New("missing decision field")
		}
		value.IdempotencyKey = idempotency
	}
	return nil
}

func hasExactFields(fields map[string]json.RawMessage, required ...string) bool {
	if len(fields) != len(required) {
		return false
	}
	for _, field := range required {
		if _, ok := fields[field]; !ok {
			return false
		}
	}
	return true
}

func uniqueJSONKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var stack []map[string]struct{}
	expectingKey := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, make(map[string]struct{}))
				expectingKey = true
			case '}':
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				expectingKey = len(stack) > 0
			}
		case string:
			if expectingKey && len(stack) > 0 {
				if _, duplicate := stack[len(stack)-1][value]; duplicate {
					return false
				}
				stack[len(stack)-1][value] = struct{}{}
				expectingKey = false
			} else if len(stack) > 0 {
				expectingKey = true
			}
		default:
			if len(stack) > 0 {
				expectingKey = true
			}
		}
	}
}

func (handler *Handler) backendError(response http.ResponseWriter, err error, correlation string) {
	switch {
	case errors.Is(err, ErrNotFound):
		handler.writeError(response, http.StatusNotFound, "NOT_FOUND", correlation)
	case errors.Is(err, ErrConflict):
		handler.writeError(response, http.StatusConflict, "CONFLICT", correlation)
	default:
		handler.writeError(response, http.StatusServiceUnavailable, "UNAVAILABLE", correlation)
	}
}

func (handler *Handler) writeError(response http.ResponseWriter, status int, code, correlation string) {
	handler.writeJSONStatus(response, status, map[string]string{"code": code, "correlation_alias": correlation})
}

func (handler *Handler) writeJSON(response http.ResponseWriter, status int, value any) {
	handler.writeJSONStatus(response, status, value)
}

func (handler *Handler) writeJSONStatus(response http.ResponseWriter, status int, value any) {
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(value)
}

func (handler *Handler) correlationAlias() string {
	sequence := handler.sequence.Add(1)
	digest := sha256.Sum256([]byte(fmt.Sprintf("phase16-correlation-%d", sequence)))
	return "corr-" + hex.EncodeToString(digest[:8])
}

var _ http.Handler = (*Handler)(nil)
