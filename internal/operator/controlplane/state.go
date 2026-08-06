// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"

	"kurdistan/internal/product/envelope"
)

func (state State) Validate() error {
	if state.Version != StateVersion || state.NextSequence == 0 ||
		len(state.Operations) > MaxOperations || len(state.Profiles) > MaxProfiles ||
		len(state.Relays) > MaxRelays ||
		len(state.EmergencyAuthorities) > MaxEmergencyAuthorities ||
		len(state.Publications) > MaxPublications || len(state.Audit) > MaxAuditEntries ||
		len(state.Outbox) > MaxOutboxEvents || len(state.Idempotency) > MaxIdempotencyKeys {
		return ErrInvalidInput
	}
	if state.NextSequence != uint64(len(state.Audit))+1 {
		return ErrInvalidInput
	}
	for id, operation := range state.Operations {
		if id != operation.ID {
			return ErrInvalidInput
		}
		if err := ValidateOperation(operation); err != nil {
			return err
		}
	}
	for id, record := range state.Profiles {
		if id != record.ID || !validID(record.ID) ||
			!validDigest(record.ArtifactDigest) || !validDigest(record.ScopeDigest) ||
			record.Generation == 0 || record.UpdatedAt <= 0 {
			return ErrInvalidInput
		}
		if record.State != ProfileIssued && record.State != ProfileRevoked {
			return ErrInvalidInput
		}
		if record.State == ProfileIssued && record.RevocationDigest != "" {
			return ErrInvalidInput
		}
		if record.State == ProfileRevoked && !validDigest(record.RevocationDigest) {
			return ErrInvalidInput
		}
	}
	for id, relay := range state.Relays {
		if id != relay.ID || !validID(relay.ID) || !validDigest(relay.IdentityDigest) ||
			!validDigest(relay.PlanDigest) || relay.Epoch == 0 || relay.UpdatedAt <= 0 {
			return ErrInvalidInput
		}
		switch relay.State {
		case RelayEnrolled, RelayCanary, RelayActive, RelayDraining,
			RelayRetired, RelayQuarantined, RelayRevoked:
		default:
			return ErrInvalidInput
		}
	}
	for scope, authority := range state.EmergencyAuthorities {
		if scope != authority.ScopeDigest || !validDigest(scope) ||
			!validDigest(authority.RootSetDigest) ||
			authority.RootEpoch == 0 || !validID(authority.RootKeyID) ||
			authority.RootKeySuiteID != uint16(envelope.SuiteClassicalV1) ||
			authority.AuthorizationEpoch == 0 ||
			!validDigest(authority.DelegationDigest) ||
			!validID(authority.KeyID) ||
			authority.KeySuiteID != uint16(envelope.SuiteClassicalV1) ||
			authority.ValidFrom <= 0 || authority.ValidUntil <= authority.ValidFrom ||
			authority.UpdatedAt <= 0 {
			return ErrInvalidInput
		}
		if authority.Revoked {
			if !validDigest(authority.RevocationDigest) {
				return ErrInvalidInput
			}
		} else if authority.RevocationDigest != "" {
			return ErrInvalidInput
		}
	}
	for index, publication := range state.Publications {
		if err := ValidatePublicationInput(PublicationInput{
			Version:        publication.Version,
			RootVersion:    publication.RootVersion,
			SnapshotDigest: publication.SnapshotDigest,
			TargetsDigest:  publication.TargetsDigest,
			ValidUntil:     publication.ValidUntil,
		}); err != nil {
			return err
		}
		if publication.PublishedAt <= 0 ||
			publication.ValidUntil <= publication.PublishedAt ||
			(index > 0 && publication.Version <= state.Publications[index-1].Version) {
			return ErrInvalidInput
		}
	}
	for scope, restriction := range state.Restrictions {
		if scope != restriction.ScopeDigest || !validDigest(scope) ||
			restriction.Epoch == 0 || restriction.ValidUntil <= restriction.AppliedAt {
			return ErrInvalidInput
		}
	}
	if err := ValidateAuditChain(state.Audit); err != nil {
		return err
	}
	seenOutbox := make(map[string]struct{}, len(state.Outbox))
	outboxByOperation := make(map[string]OutboxEvent, len(state.Outbox))
	outboxByID := make(map[string]OutboxEvent, len(state.Outbox))
	pendingObligations := 0
	for _, event := range state.Outbox {
		if !validID(event.ID) || event.Sequence == 0 ||
			!validID(event.OperationID) ||
			!validDigest(event.SubjectDigest) || event.CreatedAt <= 0 ||
			event.DeliveredAt < 0 || event.LastAttemptAt < 0 || event.FailedAt < 0 ||
			event.Attempts > MaxEffectAttempts ||
			(event.Attempts == MaxEffectAttempts && event.FailedAt == 0) ||
			(event.DeliveredAt != 0 && event.FailedAt != 0) ||
			(event.DeliveredAt != 0 && !validDigest(event.OutcomeDigest)) ||
			(event.DeliveredAt == 0 && event.OutcomeDigest != "") ||
			(event.DeliveredAt != 0 && event.DeliveredAt < event.CreatedAt) ||
			(event.Attempts == 0 && (event.LastAttemptAt != 0 || event.FailedAt != 0)) ||
			(event.Attempts != 0 && event.LastAttemptAt < event.CreatedAt) ||
			(event.DeliveredAt != 0 && event.LastAttemptAt > event.DeliveredAt) ||
			(event.FailedAt != 0 &&
				(event.Attempts != MaxEffectAttempts || event.FailedAt != event.LastAttemptAt)) ||
			containsForbiddenText(event.Kind) ||
			event.ID != fmt.Sprintf("evt-%016x", event.Sequence) {
			return ErrInvalidInput
		}
		if _, duplicate := seenOutbox[event.ID]; duplicate {
			return ErrInvalidInput
		}
		if _, namespaceCollision := state.Operations[event.ID]; namespaceCollision {
			return ErrInvalidInput
		}
		if _, duplicate := outboxByOperation[event.OperationID]; duplicate {
			return ErrInvalidInput
		}
		operation, exists := state.Operations[event.OperationID]
		if !exists || operation.State != OperationExecuted ||
			string(operation.Action) != event.Kind ||
			operation.SubjectDigest != event.SubjectDigest ||
			operation.ExecutedAt != event.CreatedAt ||
			event.Sequence > uint64(len(state.Audit)) {
			return ErrInvalidInput
		}
		execution := state.Audit[event.Sequence-1]
		if execution.At != event.CreatedAt ||
			execution.Action != "execute-"+event.Kind ||
			execution.TargetDigest != DigestLabel(event.OperationID) ||
			execution.Result != "executed" {
			return ErrInvalidInput
		}
		acknowledgements := 0
		failures := uint32(0)
		terminals := 0
		var lastFailureAt int64
		for _, entry := range state.Audit {
			if entry.TargetDigest != DigestLabel(event.ID) {
				continue
			}
			switch entry.Action {
			case "acknowledge-outbox":
				acknowledgements++
				if event.DeliveredAt == 0 || entry.At != event.DeliveredAt ||
					entry.Result != "delivered" {
					return ErrInvalidInput
				}
			case "record-outbox-failure":
				failures++
				if entry.Result == "terminal" {
					terminals++
				}
				if acknowledgements != 0 || failures > event.Attempts ||
					entry.At < event.CreatedAt || entry.At > event.LastAttemptAt ||
					entry.At < lastFailureAt ||
					(entry.Result != "retry" && entry.Result != "terminal") ||
					(entry.Result == "terminal" &&
						(event.FailedAt == 0 || entry.At != event.FailedAt ||
							failures != event.Attempts)) {
					return ErrInvalidInput
				}
				lastFailureAt = entry.At
			default:
				return ErrInvalidInput
			}
		}
		if failures != event.Attempts ||
			(event.Attempts != 0 && lastFailureAt != event.LastAttemptAt) ||
			(event.FailedAt == 0 && terminals != 0) ||
			(event.FailedAt != 0 && terminals != 1) {
			return ErrInvalidInput
		}
		if (event.DeliveredAt == 0 && acknowledgements != 0) ||
			(event.DeliveredAt != 0 && acknowledgements != 1) {
			return ErrInvalidInput
		}
		seenOutbox[event.ID] = struct{}{}
		outboxByOperation[event.OperationID] = event
		outboxByID[event.ID] = event
		if event.DeliveredAt == 0 && event.FailedAt == 0 {
			pendingObligations += MaxEffectAttempts - int(event.Attempts)
		}
	}
	if len(state.Idempotency)+pendingObligations > MaxIdempotencyKeys ||
		len(state.Audit)+pendingObligations > MaxAuditEntries {
		return ErrInvalidInput
	}
	for _, operation := range state.Operations {
		if err := validateOperationAuditLinks(state.Audit, operation); err != nil {
			return err
		}
		if operation.ParentOperationID != "" {
			parent, exists := state.Operations[operation.ParentOperationID]
			expectedParentAction := ActionPrepareProfileIssue
			if operation.Action == ActionRotateProfile {
				expectedParentAction = ActionPrepareProfileRotate
			}
			if !exists || parent.Action != expectedParentAction ||
				parent.State != OperationExecuted || parent.TargetID != operation.TargetID ||
				parent.ScopeDigest != operation.ScopeDigest ||
				parent.ResultEpoch != operation.ResultEpoch ||
				parent.SubjectDigest == operation.SubjectDigest ||
				parent.ExpiresAt < operation.ExpiresAt ||
				parent.ExpectedEpoch != operation.ExpectedEpoch ||
				parent.ExpectedArtifactDigest != operation.ExpectedArtifactDigest {
				return ErrInvalidInput
			}
			if operation.State == OperationExecuted &&
				!operationEffectDelivered(state, parent.ID, string(expectedParentAction), parent.SubjectDigest) {
				return ErrInvalidInput
			}
		}
		_, hasOutbox := outboxByOperation[operation.ID]
		if (operation.State == OperationExecuted) != hasOutbox {
			return ErrInvalidInput
		}
	}
	for key, receipt := range state.Idempotency {
		if !validID(key) || !validID(receipt.OperationID) ||
			receipt.Revision == 0 || receipt.Revision > state.Revision ||
			receipt.Sequence == 0 || receipt.Sequence > uint64(len(state.Audit)) {
			return ErrInvalidInput
		}
		audit := state.Audit[receipt.Sequence-1]
		if audit.TargetDigest != DigestLabel(receipt.OperationID) {
			return ErrInvalidInput
		}
		if operation, exists := state.Operations[receipt.OperationID]; exists {
			if !validReceiptStateForOperation(receipt.State, operation.State) {
				return ErrInvalidInput
			}
			continue
		}
		event, exists := outboxByID[receipt.OperationID]
		if !exists || receipt.State != OperationExecuted {
			return ErrInvalidInput
		}
		validAcknowledgement := event.DeliveredAt != 0 &&
			audit.Action == "acknowledge-outbox" &&
			audit.Result == "delivered"
		validFailure := event.Attempts != 0 &&
			audit.Action == "record-outbox-failure" &&
			(audit.Result == "retry" || audit.Result == "terminal")
		if !validAcknowledgement && !validFailure {
			return ErrInvalidInput
		}
	}
	return nil
}

func validateOperationAuditLinks(entries []AuditEntry, operation Operation) error {
	target := DigestLabel(operation.ID)
	requests := 0
	executions := 0
	rejections := 0
	approvals := make(map[string]int, len(operation.ApproverIDs))
	for _, approver := range operation.ApproverIDs {
		approvals[DigestLabel(approver)] = 0
	}
	for _, entry := range entries {
		if entry.TargetDigest != target {
			continue
		}
		switch entry.Action {
		case "request-" + string(operation.Action):
			requests++
			if requests != 1 || entry.At != operation.CreatedAt ||
				entry.ActorDigest != DigestLabel(operation.RequesterID) ||
				entry.Result != "accepted" {
				return ErrInvalidInput
			}
		case "approve-" + string(operation.Action):
			count, exists := approvals[entry.ActorDigest]
			if !exists || count != 0 ||
				entry.At < operation.CreatedAt || entry.At >= operation.ExpiresAt ||
				(entry.Result != string(OperationPending) &&
					entry.Result != string(OperationApproved)) {
				return ErrInvalidInput
			}
			approvals[entry.ActorDigest] = 1
		case "execute-" + string(operation.Action):
			executions++
			if executions != 1 || operation.State != OperationExecuted ||
				entry.At != operation.ExecutedAt || entry.Result != "executed" {
				return ErrInvalidInput
			}
		case "reject-" + string(operation.Action):
			rejections++
			count, exists := approvals[entry.ActorDigest]
			if rejections != 1 || operation.State != OperationRejected || !exists || count != 0 ||
				entry.At < operation.CreatedAt || entry.At >= operation.ExpiresAt || entry.Result != string(OperationRejected) {
				return ErrInvalidInput
			}
			approvals[entry.ActorDigest] = 1
		default:
			return ErrInvalidInput
		}
	}
	if requests != 1 {
		return ErrInvalidInput
	}
	for _, count := range approvals {
		if count != 1 {
			return ErrInvalidInput
		}
	}
	if (operation.State == OperationExecuted && executions != 1) ||
		(operation.State != OperationExecuted && executions != 0) ||
		(operation.State == OperationRejected && rejections != 1) ||
		(operation.State != OperationRejected && rejections != 0) {
		return ErrInvalidInput
	}
	return nil
}

func validReceiptStateForOperation(receipt, current OperationState) bool {
	switch current {
	case OperationPending:
		return receipt == OperationPending
	case OperationApproved:
		return receipt == OperationPending || receipt == OperationApproved
	case OperationExecuted:
		return receipt == OperationPending || receipt == OperationApproved ||
			receipt == OperationExecuted
	case OperationRejected:
		return receipt == OperationPending || receipt == OperationRejected
	default:
		return false
	}
}

func appendAudit(state *State, at int64, actorID, action, targetID, result string) error {
	if len(state.Audit) >= MaxAuditEntries ||
		!validID(actorID) || !validID(targetID) ||
		containsForbiddenText(action) || containsForbiddenText(result) {
		return ErrInvalidInput
	}
	previous := ""
	if len(state.Audit) > 0 {
		previous = state.Audit[len(state.Audit)-1].Hash
	}
	entry := AuditEntry{
		Sequence:     state.NextSequence,
		At:           at,
		ActorDigest:  DigestLabel(actorID),
		Action:       action,
		TargetDigest: DigestLabel(targetID),
		Result:       result,
		PreviousHash: previous,
	}
	hash, err := auditHash(entry)
	if err != nil {
		return err
	}
	entry.Hash = hash
	state.Audit = append(state.Audit, entry)
	state.NextSequence++
	return nil
}

func auditHash(entry AuditEntry) (string, error) {
	entry.Hash = ""
	raw, err := json.Marshal(entry)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

func ValidateAuditChain(entries []AuditEntry) error {
	if len(entries) > MaxAuditEntries {
		return ErrAuditChain
	}
	previous := ""
	for index, entry := range entries {
		if entry.Sequence != uint64(index+1) || entry.At <= 0 ||
			!validDigest(entry.ActorDigest) || !validDigest(entry.TargetDigest) ||
			containsForbiddenText(entry.Action) || containsForbiddenText(entry.Result) ||
			entry.PreviousHash != previous {
			return ErrAuditChain
		}
		expected, err := auditHash(entry)
		if err != nil || expected != entry.Hash {
			return ErrAuditChain
		}
		previous = entry.Hash
	}
	return nil
}

func appendOutbox(state *State, at int64, operationID, kind, subjectDigest string) error {
	if len(state.Outbox) >= MaxOutboxEvents || containsForbiddenText(kind) ||
		!validID(operationID) || !validDigest(subjectDigest) {
		return ErrInvalidInput
	}
	sequence := state.NextSequence
	state.Outbox = append(state.Outbox, OutboxEvent{
		ID:            fmt.Sprintf("evt-%016x", sequence),
		Sequence:      sequence,
		OperationID:   operationID,
		Kind:          kind,
		SubjectDigest: subjectDigest,
		CreatedAt:     at,
	})
	return nil
}

func PendingOutbox(state State) []OutboxEvent {
	pending := make([]OutboxEvent, 0, len(state.Outbox))
	for _, event := range state.Outbox {
		if event.DeliveredAt == 0 && event.FailedAt == 0 {
			pending = append(pending, event)
		}
	}
	sort.Slice(pending, func(i, j int) bool {
		return pending[i].Sequence < pending[j].Sequence
	})
	return pending
}

func VerifyPublication(lastTrusted *Publication, observed Publication, now int64) error {
	if err := ValidatePublicationInput(PublicationInput{
		Version:        observed.Version,
		RootVersion:    observed.RootVersion,
		SnapshotDigest: observed.SnapshotDigest,
		TargetsDigest:  observed.TargetsDigest,
		ValidUntil:     observed.ValidUntil,
	}); err != nil {
		return err
	}
	if observed.PublishedAt <= 0 || now <= 0 {
		return ErrInvalidInput
	}
	if observed.PublishedAt > now || observed.ValidUntil <= observed.PublishedAt {
		return ErrInvalidInput
	}
	if observed.ValidUntil <= now {
		return ErrExpired
	}
	if lastTrusted == nil {
		return nil
	}
	if observed.Version < lastTrusted.Version ||
		observed.RootVersion < lastTrusted.RootVersion {
		return ErrConflict
	}
	if observed.Version == lastTrusted.Version {
		if observed != *lastTrusted {
			return ErrConflict
		}
		return nil
	}
	if observed.SnapshotDigest == lastTrusted.SnapshotDigest ||
		observed.TargetsDigest == lastTrusted.TargetsDigest {
		return ErrConflict
	}
	return nil
}

func canonicalApprovers(ids []string) []string {
	result := append([]string(nil), ids...)
	sort.Strings(result)
	return result
}
