// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"bytes"

	"kurdistan/internal/product/lifecycle"
)

// ActivationCommandKind identifies one durable operation requested by the
// stepwise activation state machine. The caller owns persistence; the session
// owns verification, ordering, recovery decisions, and terminal outcomes.
type ActivationCommandKind string

const (
	ActivationCommandSnapshot           ActivationCommandKind = "snapshot"
	ActivationCommandStageCandidate     ActivationCommandKind = "stage-candidate"
	ActivationCommandReopenCandidate    ActivationCommandKind = "reopen-candidate"
	ActivationCommandMarkActivation     ActivationCommandKind = "mark-activation"
	ActivationCommandCommitMarked       ActivationCommandKind = "commit-marked"
	ActivationCommandFinalizeActivation ActivationCommandKind = "finalize-activation"
	ActivationCommandRecover            ActivationCommandKind = "recover"
	ActivationCommandQuarantine         ActivationCommandKind = "quarantine"
)

// ActivationCommand is immutable caller work. Record is populated only for
// ActivationCommandStageCandidate and is always a defensive copy.
type ActivationCommand struct {
	Sequence uint64
	Kind     ActivationCommandKind
	Record   ActivationRecord
}

// ActivationCommandResult carries only the bounded result shape allowed for a
// command. Snapshot uses Active and LastKnownGood; reopen uses Record; other
// commands use only Err.
type ActivationCommandResult struct {
	Active        ActivationRecord
	LastKnownGood ActivationRecord
	Record        ActivationRecord
	Err           error
}

type activationSessionPhase uint8

const (
	activationNeedInitialSnapshot activationSessionPhase = iota + 1
	activationNeedStage
	activationNeedReopen
	activationNeedMark
	activationNeedCommit
	activationNeedFinalize
	activationNeedRecover
	activationNeedRecoverySnapshot
	activationNeedQuarantine
	activationTerminal
)

// ActivationSession is a single-use, strictly ordered activation transaction.
// It contains exact artifact bytes and must be closed by reaching Result.
// It is not safe for concurrent use.
type ActivationSession struct {
	request                   ActivationRequest
	phase                     activationSessionPhase
	sequence                  uint64
	outstanding               bool
	priorActive               ActivationRecord
	priorLastKnownGood        ActivationRecord
	candidate                 ActivationRecord
	committedCandidateAllowed bool
	record                    ActivationRecord
	err                       error
}

// NewActivationSession creates a stepwise equivalent of
// ActivateVerifiedProfile. Persistence is supplied through command results, so
// request.Storage is intentionally ignored by the session.
func NewActivationSession(request ActivationRequest) *ActivationSession {
	request.Artifact = bytes.Clone(request.Artifact)
	request.Storage = nil
	return &ActivationSession{
		request:  request,
		phase:    activationNeedInitialSnapshot,
		sequence: 1,
	}
}

// Next returns the current command. Callers must submit exactly this command
// once before asking for another command.
func (s *ActivationSession) Next() (ActivationCommand, bool) {
	if s == nil || s.phase == activationTerminal || s.outstanding {
		return ActivationCommand{}, false
	}
	command := ActivationCommand{
		Sequence: s.sequence,
		Kind:     s.commandKind(),
	}
	if command.Kind == ActivationCommandStageCandidate {
		command.Record = cloneActivationRecord(s.candidate)
	}
	s.outstanding = true
	return command, true
}

// Submit advances the state machine only when command is the exact outstanding
// command. A protocol misuse is terminal and fail-closed.
func (s *ActivationSession) Submit(command ActivationCommand, result ActivationCommandResult) error {
	if s == nil || !s.outstanding || s.phase == activationTerminal ||
		command.Sequence != s.sequence || command.Kind != s.commandKind() {
		return activationFailure(ActivationPolicyRejected)
	}
	s.outstanding = false
	s.sequence++

	switch s.phase {
	case activationNeedInitialSnapshot:
		s.submitInitialSnapshot(result)
	case activationNeedStage:
		s.submitStage(result)
	case activationNeedReopen:
		s.submitReopen(result)
	case activationNeedMark:
		s.submitMark(result)
	case activationNeedCommit:
		s.submitCommit(result)
	case activationNeedFinalize:
		s.submitFinalize(result)
	case activationNeedRecover:
		s.submitRecover(result)
	case activationNeedRecoverySnapshot:
		s.submitRecoverySnapshot(result)
	case activationNeedQuarantine:
		s.submitQuarantine(result)
	default:
		s.finish(ActivationRecord{}, activationFailure(ActivationPolicyRejected))
	}
	return nil
}

// Result is available only after the session has reached a terminal state.
func (s *ActivationSession) Result() (ActivationRecord, error) {
	if s == nil || s.phase != activationTerminal || s.outstanding {
		return ActivationRecord{}, activationFailure(ActivationPolicyRejected)
	}
	return cloneActivationRecord(s.record), s.err
}

// Destroy clears exact artifacts retained by a completed, cancelled, or
// abandoned bridge session.
func (s *ActivationSession) Destroy() {
	if s == nil {
		return
	}
	clear(s.request.Artifact)
	clear(s.request.Delegation.Payload)
	clear(s.request.Delegation.Signature)
	clear(s.request.Revocations.Payload)
	clear(s.request.Revocations.Signature)
	if destroyer, ok := s.request.OfflineOpener.(interface{ Destroy() }); ok {
		destroyer.Destroy()
	}
	destroyActivationRecord(&s.priorActive)
	destroyActivationRecord(&s.priorLastKnownGood)
	destroyActivationRecord(&s.candidate)
	destroyActivationRecord(&s.record)
	s.request = ActivationRequest{}
	s.err = nil
	s.phase = activationTerminal
	s.outstanding = false
}

func destroyActivationRecord(record *ActivationRecord) {
	if record == nil {
		return
	}
	clear(record.Artifact)
	clear(record.SignedObject)
	clear(record.Profile.Policy)
	*record = ActivationRecord{}
}

func (s *ActivationSession) commandKind() ActivationCommandKind {
	switch s.phase {
	case activationNeedInitialSnapshot, activationNeedRecoverySnapshot:
		return ActivationCommandSnapshot
	case activationNeedStage:
		return ActivationCommandStageCandidate
	case activationNeedReopen:
		return ActivationCommandReopenCandidate
	case activationNeedMark:
		return ActivationCommandMarkActivation
	case activationNeedCommit:
		return ActivationCommandCommitMarked
	case activationNeedFinalize:
		return ActivationCommandFinalizeActivation
	case activationNeedRecover:
		return ActivationCommandRecover
	case activationNeedQuarantine:
		return ActivationCommandQuarantine
	default:
		return ""
	}
}

func (s *ActivationSession) submitInitialSnapshot(result ActivationCommandResult) {
	if result.Err != nil {
		s.finish(ActivationRecord{}, activationFailure(ActivationStorageFailure))
		return
	}
	active := cloneActivationRecord(result.Active)
	lastKnownGood := cloneActivationRecord(result.LastKnownGood)
	if active.State.Status == "" {
		if s.request.Current.Status != "" && s.request.Current.Status != lifecycle.Absent {
			s.finish(ActivationRecord{}, activationFailure(ActivationPolicyRejected))
			return
		}
	} else if active.State != s.request.Current {
		s.finish(ActivationRecord{}, activationFailure(ActivationPolicyRejected))
		return
	}
	candidate, err := verifyActivationCandidate(s.request, s.request.Artifact)
	if err != nil {
		s.finish(ActivationRecord{}, err)
		return
	}
	s.priorActive = active
	s.priorLastKnownGood = lastKnownGood
	s.candidate = cloneActivationRecord(candidate.record)
	s.phase = activationNeedStage
}

func (s *ActivationSession) submitStage(result ActivationCommandResult) {
	if result.Err != nil {
		s.beginRecovery(false)
		return
	}
	observe(s.request, StageCandidateStored)
	s.phase = activationNeedReopen
}

func (s *ActivationSession) submitReopen(result ActivationCommandResult) {
	reopened := cloneActivationRecord(result.Record)
	if result.Err != nil ||
		!bytes.Equal(reopened.Artifact, s.candidate.Artifact) ||
		!bytes.Equal(reopened.SignedObject, s.candidate.SignedObject) {
		s.beginRecovery(false)
		return
	}
	observe(s.request, StageCandidateReopened)
	reverified, err := verifyActivationCandidate(s.request, reopened.Artifact)
	if err != nil || !activationRecordEqual(reverified.record, reopened) {
		s.beginRecovery(false)
		return
	}
	s.candidate = cloneActivationRecord(reverified.record)
	s.phase = activationNeedMark
}

func (s *ActivationSession) submitMark(result ActivationCommandResult) {
	if result.Err != nil {
		s.beginRecovery(false)
		return
	}
	observe(s.request, StageActivationMarked)
	s.phase = activationNeedCommit
}

func (s *ActivationSession) submitCommit(result ActivationCommandResult) {
	if result.Err != nil {
		s.beginRecovery(true)
		return
	}
	observe(s.request, StageActivationCommitted)
	s.phase = activationNeedFinalize
}

func (s *ActivationSession) submitFinalize(result ActivationCommandResult) {
	if result.Err != nil {
		s.beginRecovery(true)
		return
	}
	observe(s.request, StageActivationFinalized)
	s.finish(s.candidate, nil)
}

func (s *ActivationSession) beginRecovery(committedCandidateAllowed bool) {
	s.committedCandidateAllowed = committedCandidateAllowed
	s.phase = activationNeedRecover
}

func (s *ActivationSession) submitRecover(result ActivationCommandResult) {
	if result.Err != nil {
		s.phase = activationNeedQuarantine
		return
	}
	s.phase = activationNeedRecoverySnapshot
}

func (s *ActivationSession) submitRecoverySnapshot(result ActivationCommandResult) {
	if result.Err != nil {
		s.phase = activationNeedQuarantine
		return
	}
	active := cloneActivationRecord(result.Active)
	lastKnownGood := cloneActivationRecord(result.LastKnownGood)
	restoredPrior := activationRecordEqual(active, s.priorActive) &&
		activationRecordEqual(lastKnownGood, s.priorLastKnownGood)
	committedCandidate := s.committedCandidateAllowed &&
		activationRecordEqual(active, s.candidate) &&
		activationRecordEqual(lastKnownGood, s.priorActive)
	if !restoredPrior && !committedCandidate {
		s.phase = activationNeedQuarantine
		return
	}
	s.finish(ActivationRecord{}, activationFailure(ActivationStorageFailure))
}

func (s *ActivationSession) submitQuarantine(result ActivationCommandResult) {
	if result.Err != nil {
		s.finish(ActivationRecord{}, activationFailure(ActivationQuarantineFailure))
		return
	}
	s.finish(ActivationRecord{}, activationFailure(ActivationRecoveryFailure))
}

func (s *ActivationSession) finish(record ActivationRecord, err error) {
	s.record = cloneActivationRecord(record)
	s.err = err
	s.phase = activationTerminal
	s.outstanding = false
}
