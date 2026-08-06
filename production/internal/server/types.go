// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"context"
	"encoding/json"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/production/internal/authn"
	"kurdistan/production/internal/authoritysource"
)

const (
	APIVersion         = "v1"
	MaxRequestBody     = 64 << 10
	MaxIdempotencySize = 128
)

type MutationRequest struct {
	Action           string          `json:"action"`
	OperationID      string          `json:"operation_id"`
	AuthoritySource  json.RawMessage `json:"authority_source"`
	ExpectedRevision uint64          `json:"expected_revision"`
	ExpectedEpoch    uint64          `json:"expected_epoch"`
	IdempotencyKey   string          `json:"-"`
	PathTarget       string          `json:"-"`
}

type DecisionRequest struct {
	ExpectedRevision uint64 `json:"expected_revision"`
	ExpectedEpoch    uint64 `json:"expected_epoch"`
	IdempotencyKey   string `json:"-"`
}

type OperationView struct {
	OperationID string   `json:"operation_id"`
	Action      string   `json:"action"`
	State       string   `json:"state"`
	Revision    uint64   `json:"revision"`
	Epoch       uint64   `json:"epoch"`
	Approvals   int      `json:"approvals"`
	Requester   string   `json:"requester_actor_alias,omitempty"`
	Approvers   []string `json:"approver_actor_aliases,omitempty"`
}

type ProfileView struct {
	ProfileID       string `json:"profile_id"`
	State           string `json:"state"`
	Generation      uint64 `json:"generation"`
	ArtifactDigest  string `json:"artifact_digest"`
	ExpirationClass string `json:"expiration_class"`
}

type PublicationView struct {
	Version        uint64 `json:"version"`
	RootVersion    uint64 `json:"root_version"`
	SnapshotDigest string `json:"snapshot_digest"`
	TargetsDigest  string `json:"targets_digest"`
}

type Backend interface {
	Ready(ctx context.Context) error
	CreateOperation(ctx context.Context, identity authn.Identity, request MutationRequest) (OperationView, error)
	GetOperation(ctx context.Context, operationID string) (OperationView, error)
	ApproveOperation(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest) (OperationView, error)
	RejectOperation(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest) (OperationView, error)
	ExecuteOperation(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest) (OperationView, error)
	GetProfile(ctx context.Context, profileID string) (ProfileView, error)
	CurrentPublication(ctx context.Context) (PublicationView, error)
	CurrentRevocation(ctx context.Context) (PublicationView, error)
}

// AuthorityAdmitter must rerun the authoritative Phase 8 or Phase 11 verifier
// over the complete bounded source. Its output is a proof-sealed RequestInput;
// caller-provided digests can never cross this boundary.
type AuthorityAdmitter interface {
	Admit(ctx context.Context, request MutationRequest, snapshot controlplane.State, trusted controlplane.TrustedInstant) (controlplane.RequestInput, error)
}

type AuthorityExecutionStore interface {
	controlplane.ProductionTransactionStore
	ExecuteAdmitted(context.Context, controlplane.Command, authoritysource.Protected) (controlplane.TransactionResult, error)
	ReadAuthoritySource(context.Context, string) (authoritysource.Protected, error)
}

type AuthoritySourceProtector interface {
	Protect(context.Context, string, string, []byte) (authoritysource.Protected, error)
}

type RateLimiter interface {
	Allow(actorID, action string) bool
}
