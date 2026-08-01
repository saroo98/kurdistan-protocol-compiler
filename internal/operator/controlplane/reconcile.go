// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
)

const maxAcknowledgeAttempts = 8

// Effect is a value-only, redacted adapter command. EventID is the mandatory
// provider-side idempotency key. The DTO intentionally excludes raw actor,
// approver, target, and operation identifiers.
type Effect struct {
	EventID                string
	Action                 Action
	TargetDigest           string
	SubjectDigest          string
	ScopeDigest            string
	ExpectedArtifactDigest string
	ExpectedEpoch          uint64
	ResultEpoch            uint64
	ValidUntil             int64
	Publication            PublicationEffect
}

type effectOutcome uint8

const (
	effectOutcomeDelivered effectOutcome = iota + 1
	effectOutcomeFailed
	effectOutcomeExpired
)

type effectOutcomeCapability struct {
	eventID       string
	eventSequence uint64
	attempt       uint32
	effectDigest  [sha256.Size]byte
	outcome       effectOutcome
	mac           [sha256.Size]byte
}

type PublicationEffect struct {
	Version        uint64
	RootVersion    uint64
	SnapshotDigest string
	TargetsDigest  string
	ValidUntil     int64
}

// EffectHandler is an idempotent adapter boundary. Implementations receive
// only a redacted value snapshot and must use effect.EventID as their
// provider-side idempotency key.
type EffectHandler interface {
	Apply(context.Context, Effect) error
}

func ReconcileNext(ctx context.Context, service *Service, recoverer Actor, handler EffectHandler, now int64) (bool, error) {
	if service == nil || handler == nil || ctx == nil || now <= 0 {
		return false, ErrInvalidInput
	}
	if err := ValidateActor(recoverer); err != nil || !recoverer.has(DutyRecover) {
		return false, ErrUnauthorized
	}
	state := service.State()
	event, found := nextOutbox(state)
	if !found {
		return false, nil
	}
	operation, found := state.Operations[event.OperationID]
	if !found || operation.State != OperationExecuted ||
		string(operation.Action) != event.Kind ||
		operation.SubjectDigest != event.SubjectDigest {
		return false, ErrConflict
	}
	// Every effect in this control plane is lease-bounded, including safety
	// effects. Expired intent is never dispatched to an external adapter.
	if now >= operation.ExpiresAt {
		capability, capabilityErr := service.mintEffectOutcome(event, operation, effectOutcomeExpired)
		if capabilityErr != nil {
			return false, capabilityErr
		}
		if recordErr := recordEffectFailure(service, recoverer, capability, now); recordErr != nil {
			return false, fmt.Errorf("%w: record expired effect: %v", ErrExpired, recordErr)
		}
		return false, ErrExpired
	}
	if !mutationCapacityAvailable(state, operation.Action, 0, 1, 1, 0, -1) {
		return false, ErrConflict
	}
	if applyErr := handler.Apply(ctx, newEffect(event, operation)); applyErr != nil {
		capability, capabilityErr := service.mintEffectOutcome(event, operation, effectOutcomeFailed)
		if capabilityErr != nil {
			return false, capabilityErr
		}
		if recordErr := recordEffectFailure(service, recoverer, capability, now); recordErr != nil {
			return false, fmt.Errorf("%w: record effect failure: %v", applyErr, recordErr)
		}
		return false, applyErr
	}
	capability, err := service.mintEffectOutcome(event, operation, effectOutcomeDelivered)
	if err != nil {
		return false, err
	}
	for attempt := 0; attempt < maxAcknowledgeAttempts; attempt++ {
		current := service.State()
		delivered, terminal, found := outboxStatus(current, event.ID)
		if !found {
			return false, ErrConflict
		}
		if delivered {
			return true, nil
		}
		if terminal {
			return false, ErrConflict
		}
		if _, err := service.markDelivered(recoverer, capability, current.Revision, now); err == nil {
			return true, nil
		} else if !errors.Is(err, ErrConflict) {
			return false, err
		}
	}
	return false, ErrConflict
}

func nextOutbox(state State) (OutboxEvent, bool) {
	pending := PendingOutbox(state)
	if len(pending) == 0 {
		return OutboxEvent{}, false
	}
	for index, event := range pending {
		operation, exists := state.Operations[event.OperationID]
		if !exists || !isSafetyAction(operation.Action) {
			continue
		}
		blockedByTargetPredecessor := false
		for predecessor := 0; predecessor < index; predecessor++ {
			earlier, exists := state.Operations[pending[predecessor].OperationID]
			if exists && earlier.TargetID == operation.TargetID {
				blockedByTargetPredecessor = true
				break
			}
		}
		if !blockedByTargetPredecessor {
			return event, true
		}
	}
	return pending[0], true
}

func recordEffectFailure(service *Service, recoverer Actor, capability effectOutcomeCapability, now int64) error {
	for attempt := 0; attempt < maxAcknowledgeAttempts; attempt++ {
		current := service.State()
		delivered, terminal, found := outboxStatus(current, capability.eventID)
		if !found {
			return ErrConflict
		}
		if delivered || terminal {
			return nil
		}
		if _, err := service.markEffectFailed(recoverer, capability, current.Revision, now); err == nil {
			return nil
		} else if !errors.Is(err, ErrConflict) {
			return err
		}
	}
	return ErrConflict
}

func newEffect(event OutboxEvent, operation Operation) Effect {
	effect := Effect{
		EventID:                event.ID,
		Action:                 operation.Action,
		TargetDigest:           DigestLabel(operation.TargetID),
		SubjectDigest:          operation.SubjectDigest,
		ScopeDigest:            operation.ScopeDigest,
		ExpectedArtifactDigest: operation.ExpectedArtifactDigest,
		ExpectedEpoch:          operation.ExpectedEpoch,
		ResultEpoch:            operation.ResultEpoch,
		ValidUntil:             operation.ExpiresAt,
	}
	if operation.Publication != nil {
		effect.Publication = PublicationEffect{
			Version:        operation.Publication.Version,
			RootVersion:    operation.Publication.RootVersion,
			SnapshotDigest: operation.Publication.SnapshotDigest,
			TargetsDigest:  operation.Publication.TargetsDigest,
			ValidUntil:     operation.Publication.ValidUntil,
		}
	}
	return effect
}

func (service *Service) mintEffectOutcome(event OutboxEvent, operation Operation, outcome effectOutcome) (effectOutcomeCapability, error) {
	if service == nil || (outcome != effectOutcomeDelivered && outcome != effectOutcomeFailed && outcome != effectOutcomeExpired) ||
		event.ID == "" || event.OperationID != operation.ID || event.Kind != string(operation.Action) ||
		event.SubjectDigest != operation.SubjectDigest {
		return effectOutcomeCapability{}, ErrInvalidInput
	}
	digest, err := effectDigest(newEffect(event, operation))
	if err != nil {
		return effectOutcomeCapability{}, err
	}
	capability := effectOutcomeCapability{
		eventID: event.ID, eventSequence: event.Sequence, attempt: event.Attempts,
		effectDigest: digest, outcome: outcome,
	}
	capability.mac = service.effectOutcomeMAC(capability)
	return capability, nil
}

func (service *Service) validateEffectOutcome(state State, capability effectOutcomeCapability, expected effectOutcome) (int, Operation, error) {
	if service == nil || capability.outcome != expected {
		return 0, Operation{}, ErrUnauthorized
	}
	expectedMAC := service.effectOutcomeMAC(capability)
	if !hmac.Equal(capability.mac[:], expectedMAC[:]) {
		return 0, Operation{}, ErrUnauthorized
	}
	for index, event := range state.Outbox {
		if event.ID != capability.eventID {
			continue
		}
		operation, exists := state.Operations[event.OperationID]
		if !exists || event.Sequence != capability.eventSequence || event.Attempts != capability.attempt {
			return 0, Operation{}, ErrUnauthorized
		}
		digest, err := effectDigest(newEffect(event, operation))
		if err != nil || !hmac.Equal(digest[:], capability.effectDigest[:]) {
			return 0, Operation{}, ErrUnauthorized
		}
		return index, operation, nil
	}
	return 0, Operation{}, ErrUnauthorized
}

func (service *Service) effectOutcomeMAC(capability effectOutcomeCapability) [sha256.Size]byte {
	hash := hmac.New(sha256.New, service.effectOutcomeKey[:])
	writeOutcomeString(hash, capability.eventID)
	var scalar [8]byte
	binary.BigEndian.PutUint64(scalar[:], capability.eventSequence)
	_, _ = hash.Write(scalar[:])
	binary.BigEndian.PutUint32(scalar[:4], capability.attempt)
	_, _ = hash.Write(scalar[:4])
	_, _ = hash.Write(capability.effectDigest[:])
	_, _ = hash.Write([]byte{byte(capability.outcome)})
	var result [sha256.Size]byte
	copy(result[:], hash.Sum(nil))
	return result
}

func writeOutcomeString(hash interface{ Write([]byte) (int, error) }, value string) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(value)))
	_, _ = hash.Write(size[:])
	_, _ = hash.Write([]byte(value))
}

func effectDigest(effect Effect) ([sha256.Size]byte, error) {
	raw, err := json.Marshal(effect)
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	return sha256.Sum256(raw), nil
}

func outboxStatus(state State, eventID string) (bool, bool, bool) {
	for _, event := range state.Outbox {
		if event.ID == eventID {
			return event.DeliveredAt != 0, event.FailedAt != 0, true
		}
	}
	return false, false, false
}

type HealthSummary struct {
	Schema              string `json:"schema"`
	Revision            uint64 `json:"revision"`
	PendingOperations   int    `json:"pending_operations"`
	ApprovedOperations  int    `json:"approved_operations"`
	ExecutedOperations  int    `json:"executed_operations"`
	IssuedProfiles      int    `json:"issued_profiles"`
	RevokedProfiles     int    `json:"revoked_profiles"`
	PendingEffects      int    `json:"pending_effects"`
	FailedEffects       int    `json:"failed_effects"`
	ActiveRelays        int    `json:"active_relays"`
	RestrictedScopes    int    `json:"restricted_scopes"`
	PublicationVersion  uint64 `json:"publication_version"`
	AuditEntries        int    `json:"audit_entries"`
	ContainsUserData    bool   `json:"contains_user_data"`
	ContainsPayloadData bool   `json:"contains_payload_data"`
}

func SummarizeHealth(state State) (HealthSummary, error) {
	if err := state.Validate(); err != nil {
		return HealthSummary{}, err
	}
	summary := HealthSummary{
		Schema:           "kurdistan-control-plane-health-v1",
		Revision:         state.Revision,
		PendingEffects:   len(PendingOutbox(state)),
		RestrictedScopes: len(state.Restrictions),
		AuditEntries:     len(state.Audit),
	}
	for _, operation := range state.Operations {
		switch operation.State {
		case OperationPending:
			summary.PendingOperations++
		case OperationApproved:
			summary.ApprovedOperations++
		case OperationExecuted:
			summary.ExecutedOperations++
		}
	}
	for _, relay := range state.Relays {
		if relay.State == RelayActive {
			summary.ActiveRelays++
		}
	}
	for _, record := range state.Profiles {
		if record.State == ProfileIssued {
			summary.IssuedProfiles++
		} else if record.State == ProfileRevoked {
			summary.RevokedProfiles++
		}
	}
	for _, event := range state.Outbox {
		if event.FailedAt != 0 {
			summary.FailedEffects++
		}
	}
	if len(state.Publications) > 0 {
		summary.PublicationVersion = state.Publications[len(state.Publications)-1].Version
	}
	return summary, nil
}
