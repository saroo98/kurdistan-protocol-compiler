// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sort"

	"kurdistan/internal/product/profile"
)

type RequestInput struct {
	ID                     string
	Action                 Action
	TargetID               string
	ParentOperationID      string
	SubjectDigest          string
	ScopeDigest            string
	AuthorityScopeDigest   string
	AuthorityRootDigest    string
	ExpectedArtifactDigest string
	ExpectedRevision       uint64
	ExpectedEpoch          uint64
	ResultEpoch            uint64
	CreatedAt              int64
	ExpiresAt              int64
	IdempotencyKey         string
	Publication            *PublicationInput
	proof                  requestProof
}

type Service struct {
	store            Store
	effectOutcomeKey [32]byte
}

func NewService(store Store) (*Service, error) {
	if store == nil {
		return nil, ErrInvalidInput
	}
	if err := store.Snapshot().Validate(); err != nil {
		return nil, err
	}
	service := &Service{store: store}
	if _, err := rand.Read(service.effectOutcomeKey[:]); err != nil {
		return nil, fmt.Errorf("effect outcome key: %w", err)
	}
	return service, nil
}

func (service *Service) State() State {
	return service.store.Snapshot()
}

func (service *Service) Request(actor Actor, input RequestInput) (Receipt, error) {
	trusted, err := NewTrustedInstant(input.CreatedAt, "phase12-compatibility", input.ExpectedRevision+1)
	if err != nil {
		return Receipt{}, err
	}
	command, err := NewRequestCommand(actor, input, trusted)
	if err != nil {
		return Receipt{}, err
	}
	if result, replay, err := commandReplay(service.store.Snapshot(), command); err != nil {
		return Receipt{}, err
	} else if replay {
		return result.Receipt, nil
	}
	var result CommandResult
	next, err := service.store.Update(input.ExpectedRevision, func(state *State) error {
		result, err = applyCommandMutation(state, command)
		return err
	})
	if err != nil {
		return Receipt{}, err
	}
	result.Receipt.Revision = next.Revision
	return result.Receipt, nil
}

func sameRequestIntent(existing, requested Operation) bool {
	if existing.ID != requested.ID || existing.Action != requested.Action ||
		existing.TargetID != requested.TargetID ||
		existing.ParentOperationID != requested.ParentOperationID ||
		existing.SubjectDigest != requested.SubjectDigest ||
		existing.ScopeDigest != requested.ScopeDigest ||
		existing.AuthorityScopeDigest != requested.AuthorityScopeDigest ||
		existing.AuthorityRootDigest != requested.AuthorityRootDigest ||
		existing.ExpectedArtifactDigest != requested.ExpectedArtifactDigest ||
		existing.RequesterID != requested.RequesterID ||
		existing.ExpectedRevision != requested.ExpectedRevision ||
		existing.ExpectedEpoch != requested.ExpectedEpoch ||
		existing.ResultEpoch != requested.ResultEpoch ||
		existing.CreatedAt != requested.CreatedAt ||
		existing.ExpiresAt != requested.ExpiresAt {
		return false
	}
	if existing.Publication == nil || requested.Publication == nil {
		return existing.Publication == nil && requested.Publication == nil
	}
	return *existing.Publication == *requested.Publication
}

func (service *Service) Approve(actor Actor, operationID, idempotencyKey string, expectedRevision uint64, now int64) (Receipt, error) {
	trusted, err := NewTrustedInstant(now, "phase12-compatibility", expectedRevision+1)
	if err != nil {
		return Receipt{}, err
	}
	command, err := NewApproveCommand(actor, operationID, idempotencyKey, expectedRevision, trusted)
	if err != nil {
		return Receipt{}, err
	}
	if result, replay, err := commandReplay(service.store.Snapshot(), command); err != nil {
		return Receipt{}, err
	} else if replay {
		return result.Receipt, nil
	}
	var result CommandResult
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		result, err = applyCommandMutation(state, command)
		return err
	})
	if err != nil {
		return Receipt{}, err
	}
	result.Receipt.Revision = next.Revision
	return result.Receipt, nil
}

func (service *Service) Reject(actor Actor, operationID, idempotencyKey string, expectedRevision uint64, now int64) (Receipt, error) {
	trusted, err := NewTrustedInstant(now, "phase12-compatibility", expectedRevision+1)
	if err != nil {
		return Receipt{}, err
	}
	command, err := NewRejectCommand(actor, operationID, idempotencyKey, expectedRevision, trusted)
	if err != nil {
		return Receipt{}, err
	}
	if result, replay, err := commandReplay(service.store.Snapshot(), command); err != nil {
		return Receipt{}, err
	} else if replay {
		return result.Receipt, nil
	}
	var result CommandResult
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		result, err = applyCommandMutation(state, command)
		return err
	})
	if err != nil {
		return Receipt{}, err
	}
	result.Receipt.Revision = next.Revision
	return result.Receipt, nil
}

func (service *Service) Execute(actor Actor, operationID, idempotencyKey string, expectedRevision uint64, now int64) (Receipt, error) {
	trusted, err := NewTrustedInstant(now, "phase12-compatibility", expectedRevision+1)
	if err != nil {
		return Receipt{}, err
	}
	command, err := NewExecuteCommand(actor, operationID, idempotencyKey, expectedRevision, trusted)
	if err != nil {
		return Receipt{}, err
	}
	if result, replay, err := commandReplay(service.store.Snapshot(), command); err != nil {
		return Receipt{}, err
	} else if replay {
		return result.Receipt, nil
	}
	var result CommandResult
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		result, err = applyCommandMutation(state, command)
		return err
	})
	if err != nil {
		return Receipt{}, err
	}
	result.Receipt.Revision = next.Revision
	return result.Receipt, nil
}

func (service *Service) markDelivered(actor Actor, capability effectOutcomeCapability, expectedRevision uint64, now int64) (Receipt, error) {
	if err := ValidateActor(actor); err != nil || !actor.has(DutyRecover) || now <= 0 {
		return Receipt{}, ErrUnauthorized
	}
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		index, operation, err := service.validateEffectOutcome(*state, capability, effectOutcomeDelivered)
		if err != nil {
			return err
		}
		idempotencyKey := "ack-" + capability.eventID
		if _, exists := state.Idempotency[idempotencyKey]; exists {
			return ErrConflict
		}
		event := &state.Outbox[index]
		if event.DeliveredAt != 0 || event.FailedAt != 0 {
			return ErrConflict
		}
		remainingObligations := MaxEffectAttempts - int(event.Attempts)
		if !mutationCapacityAvailable(*state, operation.Action, 0, 1, 1, 0, -remainingObligations) {
			return ErrConflict
		}
		event.DeliveredAt = now
		event.OutcomeDigest = hex.EncodeToString(capability.effectDigest[:])
		if err := appendAudit(state, now, actor.ID, "acknowledge-outbox", event.ID, "delivered"); err != nil {
			return err
		}
		receipt := Receipt{OperationID: event.ID, State: OperationExecuted, Revision: state.Revision + 1, Sequence: state.NextSequence - 1}
		state.Idempotency[idempotencyKey] = receipt
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	return next.Idempotency["ack-"+capability.eventID], nil
}

func (service *Service) markEffectFailed(actor Actor, capability effectOutcomeCapability, expectedRevision uint64, now int64) (Receipt, error) {
	if err := ValidateActor(actor); err != nil || !actor.has(DutyRecover) || now <= 0 {
		return Receipt{}, ErrUnauthorized
	}
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		if capability.outcome != effectOutcomeFailed && capability.outcome != effectOutcomeExpired {
			return ErrUnauthorized
		}
		index, operation, err := service.validateEffectOutcome(*state, capability, capability.outcome)
		if err != nil {
			return err
		}
		event := &state.Outbox[index]
		if event.DeliveredAt != 0 || event.FailedAt != 0 || event.Attempts >= MaxEffectAttempts {
			return ErrConflict
		}
		if !mutationCapacityAvailable(*state, operation.Action, 0, 1, 1, 0, -1) {
			return ErrConflict
		}
		idempotencyKey := fmt.Sprintf("fail-%s-%d", event.ID, event.Attempts+1)
		if _, exists := state.Idempotency[idempotencyKey]; exists {
			return ErrConflict
		}
		event.Attempts++
		event.LastAttemptAt = now
		result := "retry"
		if event.Attempts == MaxEffectAttempts {
			event.FailedAt = now
			result = "terminal"
		}
		if err := appendAudit(state, now, actor.ID, "record-outbox-failure", event.ID, result); err != nil {
			return err
		}
		receipt := Receipt{OperationID: event.ID, State: OperationExecuted, Revision: state.Revision + 1, Sequence: state.NextSequence - 1}
		state.Idempotency[idempotencyKey] = receipt
		return nil
	})
	if err != nil {
		return Receipt{}, err
	}
	key := fmt.Sprintf("fail-%s-%d", capability.eventID, capability.attempt+1)
	return next.Idempotency[key], nil
}

func authorizeExecution(actor Actor, action Action) error {
	var operation profile.AuthorityOperation
	switch action {
	case ActionPrepareProfileIssue, ActionPrepareProfileRotate, ActionIssueProfile, ActionRotateProfile:
		operation = profile.OperationIssueProfile
	case ActionRevokeProfile:
		operation = profile.OperationRevokeGroup
	case ActionPublishSnapshot:
		if !actor.has(DutyPublish) {
			return ErrUnauthorized
		}
		operation = profile.OperationExecuteCeremony
	case ActionEnrollRelay, ActionPromoteRelay, ActionDrainRelay,
		ActionRetireRelay, ActionQuarantineRelay, ActionRevokeRelay:
		operation = profile.OperationAuthenticateRelay
	case ActionEmergencyDeny:
		operation = profile.OperationEmergencyDeny
	case ActionEmergencyNarrow:
		operation = profile.OperationEmergencyNarrow
	default:
		return ErrUnauthorized
	}
	if err := profile.AuthorizeRoleOperation(actor.AuthorityRole, operation); err != nil {
		return fmt.Errorf("%w: %v", ErrUnauthorized, err)
	}
	return nil
}

func applyOperation(state *State, operation Operation, now int64) error {
	switch operation.Action {
	case ActionPrepareProfileIssue, ActionPrepareProfileRotate:
		return applyProfileIssuanceIntent(state, operation)
	case ActionIssueProfile, ActionRotateProfile, ActionRevokeProfile:
		return applyProfile(state, operation, now)
	case ActionPublishSnapshot:
		return applyPublication(state, *operation.Publication, now)
	case ActionEnrollRelay, ActionPromoteRelay, ActionDrainRelay,
		ActionRetireRelay, ActionQuarantineRelay, ActionRevokeRelay:
		return applyRelay(state, operation, now)
	case ActionEmergencyDeny, ActionEmergencyNarrow:
		return applyEmergency(state, operation, now)
	default:
		return ErrInvalidInput
	}
}

func applyProfileIssuanceIntent(state *State, operation Operation) error {
	current, exists := state.Profiles[operation.TargetID]
	switch operation.Action {
	case ActionPrepareProfileIssue:
		if exists || operation.ExpectedEpoch != 0 || operation.ResultEpoch == 0 ||
			operation.ExpectedArtifactDigest != "" {
			return ErrConflict
		}
	case ActionPrepareProfileRotate:
		if !exists || current.State != ProfileIssued ||
			current.Generation != operation.ExpectedEpoch ||
			operation.ResultEpoch != current.Generation+1 ||
			current.ArtifactDigest != operation.ExpectedArtifactDigest ||
			current.ScopeDigest != operation.ScopeDigest {
			return ErrConflict
		}
	default:
		return ErrInvalidInput
	}
	return nil
}

func applyProfile(state *State, operation Operation, now int64) error {
	current, exists := state.Profiles[operation.TargetID]
	switch operation.Action {
	case ActionIssueProfile:
		if exists || operation.ExpectedEpoch != 0 || operation.ResultEpoch == 0 ||
			operation.ExpectedArtifactDigest != "" {
			return ErrConflict
		}
		if operation.ParentOperationID != "" {
			parent, ok := state.Operations[operation.ParentOperationID]
			if !ok || parent.Action != ActionPrepareProfileIssue ||
				parent.State != OperationExecuted || parent.TargetID != operation.TargetID ||
				parent.SubjectDigest == operation.SubjectDigest ||
				parent.ScopeDigest != operation.ScopeDigest ||
				parent.ResultEpoch != operation.ResultEpoch ||
				parent.ExpiresAt < operation.ExpiresAt ||
				!operationEffectDelivered(*state, parent.ID, string(ActionPrepareProfileIssue), parent.SubjectDigest) {
				return ErrConflict
			}
		}
		state.Profiles[operation.TargetID] = ProfileRecord{
			ID: operation.TargetID, State: ProfileIssued, Generation: operation.ResultEpoch,
			ArtifactDigest: operation.SubjectDigest, ScopeDigest: operation.ScopeDigest,
			UpdatedAt: now,
		}
		return nil
	case ActionRotateProfile:
		if !exists || current.State != ProfileIssued ||
			current.Generation != operation.ExpectedEpoch ||
			operation.ResultEpoch != current.Generation+1 ||
			current.ArtifactDigest != operation.ExpectedArtifactDigest ||
			current.ArtifactDigest == operation.SubjectDigest ||
			current.ScopeDigest != operation.ScopeDigest {
			return ErrConflict
		}
		if operation.ParentOperationID != "" {
			parent, ok := state.Operations[operation.ParentOperationID]
			if !ok || parent.Action != ActionPrepareProfileRotate ||
				parent.State != OperationExecuted || parent.TargetID != operation.TargetID ||
				parent.SubjectDigest == operation.SubjectDigest ||
				parent.ScopeDigest != operation.ScopeDigest ||
				parent.ExpectedArtifactDigest != operation.ExpectedArtifactDigest ||
				parent.ExpectedEpoch != operation.ExpectedEpoch ||
				parent.ResultEpoch != operation.ResultEpoch ||
				parent.ExpiresAt < operation.ExpiresAt ||
				!operationEffectDelivered(*state, parent.ID, string(ActionPrepareProfileRotate), parent.SubjectDigest) {
				return ErrConflict
			}
		}
		current.Generation = operation.ResultEpoch
		current.ArtifactDigest = operation.SubjectDigest
		current.UpdatedAt = now
		state.Profiles[current.ID] = current
		return nil
	case ActionRevokeProfile:
		if !exists || current.State != ProfileIssued ||
			current.Generation != operation.ExpectedEpoch ||
			operation.ResultEpoch != current.Generation+1 ||
			current.ArtifactDigest != operation.ExpectedArtifactDigest ||
			current.ScopeDigest != operation.ScopeDigest {
			return ErrConflict
		}
		current.Generation = operation.ResultEpoch
		current.State = ProfileRevoked
		current.RevocationDigest = operation.SubjectDigest
		current.UpdatedAt = now
		state.Profiles[current.ID] = current
		return nil
	default:
		return ErrInvalidInput
	}
}

func operationEffectDelivered(state State, operationID, kind, subjectDigest string) bool {
	for _, event := range state.Outbox {
		if event.OperationID == operationID && event.Kind == kind &&
			event.SubjectDigest == subjectDigest && event.DeliveredAt != 0 && event.FailedAt == 0 {
			return true
		}
	}
	return false
}

func applyPublication(state *State, input PublicationInput, now int64) error {
	if input.ValidUntil <= now {
		return ErrExpired
	}
	if len(state.Publications) > 0 {
		last := state.Publications[len(state.Publications)-1]
		if input.Version != last.Version+1 || input.RootVersion < last.RootVersion ||
			input.SnapshotDigest == last.SnapshotDigest ||
			input.TargetsDigest == last.TargetsDigest {
			return ErrConflict
		}
	} else if input.Version != 1 {
		return ErrConflict
	}
	state.Publications = append(state.Publications, Publication{
		Version:        input.Version,
		RootVersion:    input.RootVersion,
		SnapshotDigest: input.SnapshotDigest,
		TargetsDigest:  input.TargetsDigest,
		ValidUntil:     input.ValidUntil,
		PublishedAt:    now,
	})
	return nil
}

func applyRelay(state *State, operation Operation, now int64) error {
	current, exists := state.Relays[operation.TargetID]
	switch operation.Action {
	case ActionEnrollRelay:
		if exists || operation.ExpectedEpoch != 0 || operation.ResultEpoch != 1 {
			return ErrConflict
		}
		state.Relays[operation.TargetID] = RelayRecord{
			ID: operation.TargetID, State: RelayEnrolled, Epoch: operation.ResultEpoch,
			IdentityDigest: operation.SubjectDigest, PlanDigest: operation.ScopeDigest,
			UpdatedAt: now,
		}
		return nil
	default:
		if !exists || current.Epoch != operation.ExpectedEpoch ||
			operation.ResultEpoch != current.Epoch+1 ||
			current.IdentityDigest != operation.SubjectDigest ||
			current.PlanDigest != operation.ScopeDigest ||
			current.State == RelayRevoked || current.State == RelayRetired {
			return ErrConflict
		}
	}
	next, ok := relayTransition(current.State, operation.Action)
	if !ok {
		return ErrConflict
	}
	current.State = next
	current.Epoch = operation.ResultEpoch
	current.UpdatedAt = now
	state.Relays[current.ID] = current
	return nil
}

func relayTransition(current RelayState, action Action) (RelayState, bool) {
	switch action {
	case ActionPromoteRelay:
		if current == RelayEnrolled {
			return RelayCanary, true
		}
		if current == RelayCanary {
			return RelayActive, true
		}
	case ActionDrainRelay:
		if current == RelayActive {
			return RelayDraining, true
		}
	case ActionRetireRelay:
		if current == RelayDraining || current == RelayQuarantined {
			return RelayRetired, true
		}
	case ActionQuarantineRelay:
		if current == RelayEnrolled || current == RelayCanary ||
			current == RelayActive || current == RelayDraining {
			return RelayQuarantined, true
		}
	case ActionRevokeRelay:
		if current != RelayRevoked && current != RelayRetired {
			return RelayRevoked, true
		}
	}
	return "", false
}

func applyEmergency(state *State, operation Operation, now int64) error {
	authority, exists := state.EmergencyAuthorities[operation.AuthorityScopeDigest]
	if !exists || authority.Revoked ||
		authority.ScopeDigest != operation.AuthorityScopeDigest ||
		authority.RootSetDigest != operation.AuthorityRootDigest ||
		authority.DelegationDigest != operation.ExpectedArtifactDigest ||
		now < authority.ValidFrom || now >= authority.ValidUntil {
		return ErrConflict
	}
	current, exists := state.Restrictions[operation.ScopeDigest]
	expected := uint64(0)
	if exists {
		expected = current.Epoch
	}
	if operation.ExpectedEpoch != expected || operation.ResultEpoch != expected+1 ||
		operation.ExpiresAt <= now {
		return ErrConflict
	}
	state.Restrictions[operation.ScopeDigest] = EmergencyRestriction{
		ScopeDigest: operation.ScopeDigest,
		Epoch:       operation.ResultEpoch,
		Narrowed:    operation.Action == ActionEmergencyNarrow,
		ValidUntil:  operation.ExpiresAt,
		AppliedAt:   now,
	}
	return nil
}

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}

func mutationCapacityAvailable(
	state State,
	action Action,
	operations, idempotency, audit, outbox, pendingEffectObligationDelta int,
) bool {
	operationLimit := MaxOperations
	idempotencyLimit := MaxIdempotencyKeys
	auditLimit := MaxAuditEntries
	outboxLimit := MaxOutboxEvents
	if !isSafetyAction(action) {
		operationLimit -= ReservedSafetyOperations
		idempotencyLimit -= ReservedSafetyIdempotencyKeys
		auditLimit -= ReservedSafetyAuditEntries
		outboxLimit -= ReservedSafetyOutboxEvents
	}
	pendingEffectObligations := pendingEffectObligations(state) + pendingEffectObligationDelta
	if pendingEffectObligations < 0 {
		return false
	}
	return len(state.Operations)+operations <= operationLimit &&
		len(state.Idempotency)+idempotency+pendingEffectObligations <= idempotencyLimit &&
		len(state.Audit)+audit+pendingEffectObligations <= auditLimit &&
		len(state.Outbox)+outbox <= outboxLimit
}

func pendingEffectObligations(state State) int {
	obligations := 0
	for _, event := range PendingOutbox(state) {
		obligations += MaxEffectAttempts - int(event.Attempts)
	}
	return obligations
}
