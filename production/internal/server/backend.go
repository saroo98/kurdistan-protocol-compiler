// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"

	"kurdistan/internal/operator/controlplane"
	"kurdistan/internal/product/profile"
	"kurdistan/production/internal/authn"
)

// ProductionBackend is the only runtime path from authenticated operator input
// into the serializable authority store. It reserves trusted time, asks the
// verifier-backed admitter to produce a proof-sealed request, and executes that
// exact request in the external transaction store.
type ProductionBackend struct {
	store     AuthorityExecutionStore
	clock     controlplane.TrustedTimeSource
	admitter  AuthorityAdmitter
	protector AuthoritySourceProtector
}

func NewProductionBackend(store AuthorityExecutionStore, clock controlplane.TrustedTimeSource, admitter AuthorityAdmitter, protector AuthoritySourceProtector) (*ProductionBackend, error) {
	if store == nil || clock == nil || admitter == nil || protector == nil {
		return nil, ErrUnavailable
	}
	return &ProductionBackend{store: store, clock: clock, admitter: admitter, protector: protector}, nil
}

func (backend *ProductionBackend) Ready(ctx context.Context) error {
	state, err := backend.store.Snapshot(ctx)
	if err != nil {
		return ErrUnavailable
	}
	if err := state.Validate(); err != nil {
		return ErrUnavailable
	}
	return nil
}

func (backend *ProductionBackend) CreateOperation(ctx context.Context, identity authn.Identity, request MutationRequest) (OperationView, error) {
	snapshot, err := backend.store.Snapshot(ctx)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	if receipt, exists := snapshot.Idempotency[request.IdempotencyKey]; exists {
		operation, ok := snapshot.Operations[receipt.OperationID]
		if !ok || operation.ID != request.OperationID || externalAction(operation.Action) != request.Action ||
			operation.ExpectedRevision != request.ExpectedRevision || operation.ExpectedEpoch != request.ExpectedEpoch {
			return OperationView{}, ErrConflict
		}
		protected, err := backend.store.ReadAuthoritySource(ctx, operation.ID)
		digest := sha256.Sum256(request.AuthoritySource)
		if err != nil || protected.PlaintextSHA256 != hex.EncodeToString(digest[:]) {
			return OperationView{}, ErrConflict
		}
		return operationView(snapshot, operation)
	}
	trusted, err := backend.clock.Reserve(ctx, 0)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	snapshot, err = backend.store.Snapshot(ctx)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	verified, err := backend.admitter.Admit(ctx, request, snapshot, trusted)
	if err != nil {
		return OperationView{}, ErrConflict
	}
	actor := controlplane.Actor{ID: identity.ActorID, AuthorityRole: profile.RoleOperator, Duties: []controlplane.Duty{controlplane.DutyRequest}}
	command, err := controlplane.NewRequestCommand(actor, verified, trusted)
	if err != nil {
		return OperationView{}, ErrConflict
	}
	protected, err := backend.protector.Protect(ctx, verified.ID, verified.SubjectDigest, request.AuthoritySource)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	if _, err := backend.store.ExecuteAdmitted(ctx, command, protected); err != nil {
		return OperationView{}, mapAuthorityError(err)
	}
	return backend.GetOperation(ctx, verified.ID)
}

func (backend *ProductionBackend) GetOperation(ctx context.Context, operationID string) (OperationView, error) {
	state, err := backend.store.Snapshot(ctx)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	operation, ok := state.Operations[operationID]
	if !ok {
		return OperationView{}, ErrNotFound
	}
	return operationView(state, operation)
}

func (backend *ProductionBackend) ApproveOperation(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest) (OperationView, error) {
	return backend.decide(ctx, identity, operationID, request, controlplane.CommandApprove)
}

func (backend *ProductionBackend) RejectOperation(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest) (OperationView, error) {
	return backend.decide(ctx, identity, operationID, request, controlplane.CommandReject)
}

func (backend *ProductionBackend) ExecuteOperation(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest) (OperationView, error) {
	return backend.decide(ctx, identity, operationID, request, controlplane.CommandExecute)
}

func (backend *ProductionBackend) decide(ctx context.Context, identity authn.Identity, operationID string, request DecisionRequest, kind controlplane.CommandKind) (OperationView, error) {
	trusted, err := backend.clock.Reserve(ctx, 0)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	state, err := backend.store.Snapshot(ctx)
	if err != nil {
		return OperationView{}, ErrUnavailable
	}
	operation, ok := state.Operations[operationID]
	if !ok {
		return OperationView{}, ErrNotFound
	}
	if request.ExpectedEpoch != operation.ResultEpoch {
		return OperationView{}, ErrConflict
	}
	actor, err := decisionActor(identity, operation.Action, kind)
	if err != nil {
		return OperationView{}, ErrConflict
	}
	var command controlplane.Command
	switch kind {
	case controlplane.CommandApprove:
		command, err = controlplane.NewApproveCommand(actor, operationID, request.IdempotencyKey, request.ExpectedRevision, trusted)
	case controlplane.CommandReject:
		command, err = controlplane.NewRejectCommand(actor, operationID, request.IdempotencyKey, request.ExpectedRevision, trusted)
	case controlplane.CommandExecute:
		command, err = controlplane.NewExecuteCommand(actor, operationID, request.IdempotencyKey, request.ExpectedRevision, trusted)
	default:
		err = controlplane.ErrInvalidInput
	}
	if err != nil {
		return OperationView{}, ErrConflict
	}
	if _, err := backend.store.Execute(ctx, command); err != nil {
		return OperationView{}, mapAuthorityError(err)
	}
	return backend.GetOperation(ctx, operationID)
}

func (backend *ProductionBackend) GetProfile(ctx context.Context, profileID string) (ProfileView, error) {
	state, err := backend.store.Snapshot(ctx)
	if err != nil {
		return ProfileView{}, ErrUnavailable
	}
	record, ok := state.Profiles[profileID]
	if !ok {
		return ProfileView{}, ErrNotFound
	}
	operation, effect, ok := finalizedProfileEffect(state, record)
	if !ok || effect.DeliveredAt == 0 || effect.FailedAt != 0 {
		return ProfileView{}, ErrUnavailable
	}
	trusted, err := backend.clock.Reserve(ctx, 0)
	if err != nil {
		return ProfileView{}, ErrUnavailable
	}
	profileState := "ISSUED"
	expirationClass := "CURRENT"
	if record.State == controlplane.ProfileRevoked {
		profileState = "REVOKED"
	} else if trusted.UnixSeconds >= operation.ExpiresAt {
		profileState = "EXPIRED"
		expirationClass = "EXPIRED"
	}
	return ProfileView{ProfileID: record.ID, State: profileState, Generation: record.Generation, ArtifactDigest: record.ArtifactDigest, ExpirationClass: expirationClass}, nil
}

func (backend *ProductionBackend) CurrentPublication(ctx context.Context) (PublicationView, error) {
	state, err := backend.store.Snapshot(ctx)
	if err != nil {
		return PublicationView{}, ErrUnavailable
	}
	if len(state.Publications) == 0 {
		return PublicationView{}, ErrNotFound
	}
	publication := state.Publications[len(state.Publications)-1]
	return PublicationView{Version: publication.Version, RootVersion: publication.RootVersion, SnapshotDigest: publication.SnapshotDigest, TargetsDigest: publication.TargetsDigest}, nil
}

func (backend *ProductionBackend) CurrentRevocation(ctx context.Context) (PublicationView, error) {
	return backend.CurrentPublication(ctx)
}

func decisionActor(identity authn.Identity, action controlplane.Action, kind controlplane.CommandKind) (controlplane.Actor, error) {
	actor := controlplane.Actor{ID: identity.ActorID, AuthorityRole: profile.RoleOperator}
	switch kind {
	case controlplane.CommandApprove, controlplane.CommandReject:
		actor.Duties = []controlplane.Duty{controlplane.DutyApprove}
	case controlplane.CommandExecute:
		actor.Duties = []controlplane.Duty{controlplane.DutyExecute}
	default:
		return controlplane.Actor{}, controlplane.ErrInvalidInput
	}
	switch action {
	case controlplane.ActionPrepareProfileIssue, controlplane.ActionPrepareProfileRotate, controlplane.ActionIssueProfile, controlplane.ActionRotateProfile:
		actor.AuthorityRole = profile.RoleIssuer
	case controlplane.ActionRevokeProfile:
		actor.AuthorityRole = profile.RoleProvider
	case controlplane.ActionPublishSnapshot:
		actor.AuthorityRole = profile.RoleOperator
		actor.Duties = append(actor.Duties, controlplane.DutyPublish)
	case controlplane.ActionEnrollRelay, controlplane.ActionPromoteRelay, controlplane.ActionDrainRelay,
		controlplane.ActionRetireRelay, controlplane.ActionQuarantineRelay, controlplane.ActionRevokeRelay:
		actor.AuthorityRole = profile.RoleRelay
	case controlplane.ActionEmergencyDeny, controlplane.ActionEmergencyNarrow:
		actor.AuthorityRole = profile.RoleEmergency
	default:
		return controlplane.Actor{}, controlplane.ErrInvalidInput
	}
	return actor, nil
}

func operationView(state controlplane.State, operation controlplane.Operation) (OperationView, error) {
	productionState, err := productionOperationState(state, operation)
	if err != nil {
		return OperationView{}, err
	}
	return OperationView{
		OperationID: operation.ID, Action: externalAction(operation.Action), State: string(productionState),
		Revision: state.Revision, Epoch: operation.ResultEpoch, Approvals: len(operation.ApproverIDs),
		Requester: operation.RequesterID, Approvers: append([]string(nil), operation.ApproverIDs...),
	}, nil
}

func productionOperationState(state controlplane.State, operation controlplane.Operation) (controlplane.ProductionOperationState, error) {
	switch operation.State {
	case controlplane.OperationPending:
		return controlplane.ProductionPending, nil
	case controlplane.OperationApproved:
		return controlplane.ProductionApproved, nil
	case controlplane.OperationRejected:
		return controlplane.ProductionRejected, nil
	case controlplane.OperationExecuted:
	default:
		return "", ErrUnavailable
	}
	effect, ok := operationEffect(state, operation.ID)
	if !ok || effect.Kind != string(operation.Action) || effect.SubjectDigest != operation.SubjectDigest {
		return "", ErrUnavailable
	}
	if effect.FailedAt != 0 {
		return controlplane.ProductionFailedTerminal, nil
	}
	if effect.DeliveredAt == 0 {
		if effect.Attempts != 0 {
			return controlplane.ProductionFailedRetryable, nil
		}
		return controlplane.ProductionEffectPending, nil
	}
	switch operation.Action {
	case controlplane.ActionPrepareProfileIssue, controlplane.ActionPrepareProfileRotate:
		return controlplane.ProductionAnchored, nil
	case controlplane.ActionPublishSnapshot:
		return controlplane.ProductionPublished, nil
	default:
		return controlplane.ProductionFinalized, nil
	}
}

func operationEffect(state controlplane.State, operationID string) (controlplane.OutboxEvent, bool) {
	for _, event := range state.Outbox {
		if event.OperationID == operationID {
			return event, true
		}
	}
	return controlplane.OutboxEvent{}, false
}

func finalizedProfileEffect(state controlplane.State, record controlplane.ProfileRecord) (controlplane.Operation, controlplane.OutboxEvent, bool) {
	for _, operation := range state.Operations {
		matchesIssued := record.State == controlplane.ProfileIssued &&
			(operation.Action == controlplane.ActionIssueProfile || operation.Action == controlplane.ActionRotateProfile) &&
			operation.SubjectDigest == record.ArtifactDigest
		matchesRevoked := record.State == controlplane.ProfileRevoked &&
			operation.Action == controlplane.ActionRevokeProfile &&
			operation.SubjectDigest == record.RevocationDigest
		if operation.TargetID != record.ID || operation.ResultEpoch != record.Generation || operation.State != controlplane.OperationExecuted ||
			(!matchesIssued && !matchesRevoked) {
			continue
		}
		effect, ok := operationEffect(state, operation.ID)
		if ok && effect.Kind == string(operation.Action) && effect.SubjectDigest == operation.SubjectDigest {
			return operation, effect, true
		}
	}
	return controlplane.Operation{}, controlplane.OutboxEvent{}, false
}

func externalAction(action controlplane.Action) string {
	switch action {
	case controlplane.ActionPrepareProfileIssue, controlplane.ActionIssueProfile:
		return "profile.issue"
	case controlplane.ActionPrepareProfileRotate, controlplane.ActionRotateProfile:
		return "profile.rotate"
	case controlplane.ActionRevokeProfile:
		return "profile.revoke"
	case controlplane.ActionPublishSnapshot:
		return "publication.publish"
	case controlplane.ActionEmergencyDeny:
		return "emergency.deny"
	case controlplane.ActionEmergencyNarrow:
		return "emergency.narrow"
	default:
		return string(action)
	}
}

func mapAuthorityError(err error) error {
	switch {
	case errors.Is(err, controlplane.ErrConflict), errors.Is(err, controlplane.ErrIdempotency),
		errors.Is(err, controlplane.ErrExpired), errors.Is(err, controlplane.ErrInsufficientQuorum),
		errors.Is(err, controlplane.ErrUnauthorized), errors.Is(err, controlplane.ErrInvalidInput):
		return ErrConflict
	default:
		return ErrUnavailable
	}
}

var _ Backend = (*ProductionBackend)(nil)
