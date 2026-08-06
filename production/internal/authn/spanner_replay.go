// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package authn

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"time"

	"cloud.google.com/go/spanner"
)

var replayEnvironmentRE = regexp.MustCompile(`^[a-z][a-z0-9-]{2,31}$`)

// SpannerReplayGuard provides cross-instance single-use enforcement for
// privileged identity tokens. It persists only an opaque actor alias and a
// domain-separated token digest, never the raw token identifier.
type SpannerReplayGuard struct {
	client      *spanner.Client
	environment string
	clock       Clock
	timeout     time.Duration
}

func NewSpannerReplayGuard(client *spanner.Client, environment string, clock Clock, timeout time.Duration) (*SpannerReplayGuard, error) {
	if client == nil || clock == nil || !replayEnvironmentRE.MatchString(environment) || timeout < time.Second || timeout > 10*time.Second {
		return nil, ErrInvalidCredential
	}
	return &SpannerReplayGuard{client: client, environment: environment, clock: clock, timeout: timeout}, nil
}

func (guard *SpannerReplayGuard) UseOnce(parent context.Context, actorID, tokenID string, expiresAt int64) error {
	if parent == nil || len(actorID) < 3 || len(actorID) > 128 || len(tokenID) < 8 || len(tokenID) > MaxClaimStringBytes {
		return ErrReplay
	}
	now := guard.clock.Now().UTC()
	if expiresAt <= now.Unix() {
		return ErrReplay
	}
	digest := sha256.Sum256(append([]byte("kurdistan-operator-token-replay-v1\x00"), []byte(tokenID)...))
	tokenDigest := hex.EncodeToString(digest[:])
	ctx, cancel := context.WithTimeout(parent, guard.timeout)
	defer cancel()
	_, err := guard.client.ReadWriteTransaction(ctx, func(tx context.Context, transaction *spanner.ReadWriteTransaction) error {
		row, err := transaction.ReadRow(tx, "TokenReplay", spanner.Key{guard.environment, actorID, tokenDigest}, []string{"ExpiresAt"})
		switch {
		case err == nil:
			var existing time.Time
			if row.Columns(&existing) != nil || existing.After(now) {
				return ErrReplay
			}
			return transaction.BufferWrite([]*spanner.Mutation{spanner.UpdateMap("TokenReplay", map[string]any{
				"Environment": guard.environment, "ActorID": actorID, "TokenDigest": tokenDigest,
				"ExpiresAt": time.Unix(expiresAt, 0).UTC(), "CreatedAt": spanner.CommitTimestamp,
			})})
		case errors.Is(err, spanner.ErrRowNotFound):
			return transaction.BufferWrite([]*spanner.Mutation{spanner.InsertMap("TokenReplay", map[string]any{
				"Environment": guard.environment, "ActorID": actorID, "TokenDigest": tokenDigest,
				"ExpiresAt": time.Unix(expiresAt, 0).UTC(), "CreatedAt": spanner.CommitTimestamp,
			})})
		default:
			return err
		}
	})
	if err != nil {
		return ErrReplay
	}
	return nil
}

var _ ReplayGuard = (*SpannerReplayGuard)(nil)
