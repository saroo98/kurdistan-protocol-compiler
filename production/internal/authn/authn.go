// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authn

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"cloud.google.com/go/auth/credentials/idtoken"
)

const (
	MaxTokenBytes       = 16 << 10
	MaxSubjectBytes     = 256
	MaxClaimStringBytes = 512
)

var (
	ErrMissingCredential = errors.New("authn: missing credential")
	ErrInvalidCredential = errors.New("authn: invalid credential")
	ErrExpiredCredential = errors.New("authn: expired credential")
	ErrReplay            = errors.New("authn: credential replay")
)

type Payload struct {
	Issuer   string
	Audience string
	Expires  int64
	IssuedAt int64
	Subject  string
	Claims   map[string]any
}

type TokenValidator interface {
	Validate(ctx context.Context, token, audience string) (Payload, error)
}

type GoogleTokenValidator struct {
	validator *idtoken.Validator
}

func NewGoogleTokenValidator(client *http.Client) (*GoogleTokenValidator, error) {
	validator, err := idtoken.NewValidator(&idtoken.ValidatorOptions{Client: client})
	if err != nil {
		return nil, fmt.Errorf("authn validator: %w", err)
	}
	return &GoogleTokenValidator{validator: validator}, nil
}

func (validator *GoogleTokenValidator) Validate(ctx context.Context, token, audience string) (Payload, error) {
	payload, err := validator.validator.Validate(ctx, token, audience)
	if err != nil {
		return Payload{}, fmt.Errorf("%w: token validation", ErrInvalidCredential)
	}
	return Payload{
		Issuer: payload.Issuer, Audience: payload.Audience, Expires: payload.Expires,
		IssuedAt: payload.IssuedAt, Subject: payload.Subject, Claims: payload.Claims,
	}, nil
}

type Clock interface {
	Now() time.Time
}

type SystemClock struct{}

func (SystemClock) Now() time.Time { return time.Now().UTC() }

type ReplayGuard interface {
	UseOnce(actorID, tokenID string, expiresAt int64) error
}

type Entitlement struct {
	Version string
	Roles   []string
}

type EntitlementResolver interface {
	Resolve(ctx context.Context, opaqueActorID string) (Entitlement, error)
}

type Config struct {
	Audience                    string
	Issuers                     []string
	AuthorizedParties           []string
	Environment                 string
	ActorKey                    []byte
	PrivilegedMaximumAgeSeconds int64
	Clock                       Clock
	Replay                      ReplayGuard
	Entitlements                EntitlementResolver
}

type Authenticator struct {
	config    Config
	validator TokenValidator
}

type Identity struct {
	ActorID            string
	Roles              []string
	EntitlementVersion string
	AuthenticatedAt    int64
	ExpiresAt          int64
}

func New(config Config, validator TokenValidator) (*Authenticator, error) {
	if validator == nil || config.Clock == nil || config.Replay == nil || config.Entitlements == nil ||
		len(config.Audience) == 0 || len(config.Audience) > MaxClaimStringBytes ||
		len(config.Environment) < 3 || len(config.Environment) > 64 ||
		len(config.ActorKey) < 32 || config.PrivilegedMaximumAgeSeconds <= 0 ||
		config.PrivilegedMaximumAgeSeconds > 900 || len(config.Issuers) == 0 || len(config.AuthorizedParties) == 0 {
		return nil, ErrInvalidCredential
	}
	return &Authenticator{config: config, validator: validator}, nil
}

func (authenticator *Authenticator) AuthenticateRequest(ctx context.Context, request *http.Request, privileged bool) (Identity, error) {
	if request == nil || request.URL == nil || request.URL.Query().Has("access_token") || request.URL.Query().Has("id_token") {
		return Identity{}, ErrInvalidCredential
	}
	if _, err := request.Cookie("access_token"); err == nil {
		return Identity{}, ErrInvalidCredential
	}
	header := request.Header.Get("Authorization")
	if header == "" {
		return Identity{}, ErrMissingCredential
	}
	if len(header) > MaxTokenBytes+7 || !strings.HasPrefix(header, "Bearer ") || strings.Count(header, " ") != 1 {
		return Identity{}, ErrInvalidCredential
	}
	token := strings.TrimPrefix(header, "Bearer ")
	if len(token) == 0 || len(token) > MaxTokenBytes {
		return Identity{}, ErrInvalidCredential
	}
	payload, err := authenticator.validator.Validate(ctx, token, authenticator.config.Audience)
	if err != nil {
		return Identity{}, err
	}
	return authenticator.authenticatePayload(ctx, payload, privileged)
}

func (authenticator *Authenticator) authenticatePayload(ctx context.Context, payload Payload, privileged bool) (Identity, error) {
	now := authenticator.config.Clock.Now().Unix()
	if !contains(authenticator.config.Issuers, payload.Issuer) || payload.Audience != authenticator.config.Audience ||
		payload.Expires <= now || payload.IssuedAt <= 0 || payload.IssuedAt > now+60 ||
		len(payload.Subject) == 0 || len(payload.Subject) > MaxSubjectBytes {
		return Identity{}, ErrInvalidCredential
	}
	authorizedParty, ok := claimString(payload.Claims, "azp")
	if !ok || !contains(authenticator.config.AuthorizedParties, authorizedParty) {
		return Identity{}, ErrInvalidCredential
	}
	authenticatedAt := payload.IssuedAt
	if value, ok := claimInt64(payload.Claims, "auth_time"); ok {
		authenticatedAt = value
	}
	if authenticatedAt <= 0 || authenticatedAt > now+60 ||
		(privileged && now-authenticatedAt > authenticator.config.PrivilegedMaximumAgeSeconds) {
		return Identity{}, ErrExpiredCredential
	}
	actorID := authenticator.opaqueActorID(payload.Subject)
	if privileged {
		tokenID, ok := claimString(payload.Claims, "jti")
		if !ok || len(tokenID) < 8 || len(tokenID) > MaxClaimStringBytes {
			return Identity{}, ErrInvalidCredential
		}
		if err := authenticator.config.Replay.UseOnce(actorID, tokenID, payload.Expires); err != nil {
			return Identity{}, ErrReplay
		}
	}
	entitlement, err := authenticator.config.Entitlements.Resolve(ctx, actorID)
	if err != nil || len(entitlement.Version) == 0 || len(entitlement.Version) > 128 || len(entitlement.Roles) == 0 || len(entitlement.Roles) > 9 {
		return Identity{}, ErrInvalidCredential
	}
	roles := append([]string(nil), entitlement.Roles...)
	for _, role := range roles {
		if len(role) == 0 || len(role) > 32 {
			return Identity{}, ErrInvalidCredential
		}
	}
	return Identity{
		ActorID: actorID, Roles: roles, EntitlementVersion: entitlement.Version,
		AuthenticatedAt: authenticatedAt, ExpiresAt: payload.Expires,
	}, nil
}

func (authenticator *Authenticator) opaqueActorID(subject string) string {
	mac := hmac.New(sha256.New, authenticator.config.ActorKey)
	mac.Write([]byte("kurdistan-operator-actor-v1\x00"))
	mac.Write([]byte(authenticator.config.Environment))
	mac.Write([]byte{0})
	mac.Write([]byte(subject))
	return "actor-" + hex.EncodeToString(mac.Sum(nil)[:16])
}

func claimString(claims map[string]any, key string) (string, bool) {
	value, ok := claims[key].(string)
	return value, ok && len(value) > 0 && len(value) <= MaxClaimStringBytes
}

func claimInt64(claims map[string]any, key string) (int64, bool) {
	switch value := claims[key].(type) {
	case float64:
		converted := int64(value)
		return converted, float64(converted) == value
	case int64:
		return value, true
	case int:
		return int64(value), true
	default:
		return 0, false
	}
}

func contains(values []string, target string) bool {
	for _, value := range values {
		if hmac.Equal([]byte(value), []byte(target)) {
			return true
		}
	}
	return false
}
