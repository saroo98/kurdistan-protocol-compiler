// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
)

func (s *Session) transition(to SessionState, reason string) error {
	if s == nil {
		return fmt.Errorf("%w: nil session", ErrLifecycle)
	}
	if terminalState(s.State) {
		if s.State == SessionClosed && to == SessionClosed {
			return nil
		}
		return fmt.Errorf("%w: terminal state %s", ErrLifecycle, s.State)
	}
	if !validTransition(s.State, to) {
		return fmt.Errorf("%w: %s to %s", ErrLifecycle, s.State, to)
	}
	from := s.State
	s.State = to
	if to == SessionFailed {
		s.FailureReason = reason
	}
	if to == SessionClosed || to == SessionDraining {
		s.CloseReason = reason
	}
	s.Events = append(s.Events, Event{
		RuntimeRole:   s.Role,
		RuntimeID:     s.RuntimeID,
		SessionID:     s.ID,
		State:         s.State,
		Transition:    string(from) + "->" + string(to),
		FailureReason: safeReason(s.FailureReason),
		CloseReason:   safeReason(s.CloseReason),
	})
	return nil
}

func validTransition(from, to SessionState) bool {
	switch from {
	case SessionNew:
		return to == SessionNegotiating || to == SessionFailed
	case SessionNegotiating:
		return to == SessionSecuring || to == SessionFailed
	case SessionSecuring:
		return to == SessionOpen || to == SessionFailed
	case SessionOpen:
		return to == SessionDraining || to == SessionClosed || to == SessionFailed
	case SessionDraining:
		return to == SessionClosed || to == SessionFailed
	default:
		return false
	}
}

func safeReason(reason string) string {
	if reason == "" {
		return ""
	}
	if len(reason) > 64 {
		return reason[:64]
	}
	return reason
}

type lifecycleRoleV1 uint8

const (
	lifecycleRoleClientV1 lifecycleRoleV1 = iota + 1
	lifecycleRoleRelayV1
	lifecycleTransmissionLimitV1 = 3
)

type endpointLifecycleV1 struct {
	self                   *endpointLifecycleV1
	coordinator            *pairTerminalCoordinatorV1
	owner                  *HandshakeRuntime
	runtimeEpoch           [32]byte
	schedule               *security.KeySchedule
	config                 StrictSessionConfigV1
	role                   lifecycleRoleV1
	state                  auth.State
	rotation               string
	nonceMode              string
	replayPolicy           string
	th4                    [32]byte
	generation             uint64
	keyEpoch               uint64
	outSequence            uint64
	outSequenceEnd         bool
	operationSequence      uint64
	operationSequenceEnd   bool
	inOperationSequence    uint64
	inOperationSequenceEnd bool
	outKeyAttempts         uint64
	inKeyAttempts          uint64
	sendCompleted          uint64
	receiveCompleted       uint64
	replay                 *security.ReplayWindowV1
	outStreams             map[uint16]outboundSequenceStateV1
	replayStreams          map[uint16]*security.ReplayWindowV1
	outstanding            map[[32]byte]*outstandingOperationV1
	completed              map[[32]byte]*completedOperationV1
	acknowledged           map[[32]byte]uint64
	issuedOperations       map[recordReservationKeyV1]operationTransmissionV1
	issuedAcks             map[recordReservationKeyV1]acknowledgementTransmissionV1
	destroySchedule        func(*security.KeySchedule)
	commitReplay           func(*security.ReplayWindowV1, uint64) error
	beforeRatchetInstall   func()
	beforeReceiveCommit    func()
	labAcceptCompleted     bool
	labSkipStateValidation bool
	lastCommitDeliver      bool
	// beforeProfileCommitObserver is an unexported test synchronization seam,
	// nil in production. It may block while the coordinator is held, is invoked
	// before profileMu, and has no behavior-selecting return value.
	beforeProfileCommitObserver func()
}

type outboundSequenceStateV1 struct {
	sequence uint64
	ended    bool
}

type recordReservationKeyV1 struct {
	streamSlot uint16
	epoch      uint64
	sequence   uint64
}

type outstandingOperationV1 struct {
	id                [32]byte
	originDirection   uint16
	originEpoch       uint64
	streamSlot        uint16
	operationSequence uint64
	expectedCompleted uint64
	attempts          uint8
}

type completedOperationV1 struct {
	originDirection   uint16
	originEpoch       uint64
	streamSlot        uint16
	operationSequence uint64
	ack               OperationAckV1
	ackAttempts       uint8
}

type operationTransmissionV1 struct {
	owner             *endpointLifecycleV1
	coordinator       *pairTerminalCoordinatorV1
	operationID       [32]byte
	originDirection   uint16
	originEpoch       uint64
	streamSlot        uint16
	operationSequence uint64
	recordEpoch       uint64
	recordSequence    uint64
	attempt           uint8
}

func (life *endpointLifecycleV1) labReuseIssuedCoordinatesV1(transmission operationTransmissionV1, epoch uint64, slot uint16, sequence uint64) (operationTransmissionV1, error) {
	if !life.lockV1() {
		return operationTransmissionV1{}, ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if !life.validIssuedOperationLockedV1(transmission) || transmission.streamSlot != slot || transmission.recordEpoch != epoch || transmission.recordSequence == sequence {
		return operationTransmissionV1{}, ErrLifecycle
	}
	delete(life.issuedOperations, operationReservationKeyV1(transmission))
	transmission.recordEpoch = epoch
	transmission.recordSequence = sequence
	life.issuedOperations[operationReservationKeyV1(transmission)] = transmission
	return transmission, nil
}

type acknowledgementTransmissionV1 struct {
	owner          *endpointLifecycleV1
	coordinator    *pairTerminalCoordinatorV1
	ack            OperationAckV1
	recordEpoch    uint64
	recordSequence uint64
	attempt        uint8
}

type receiveEpochCandidateV1 struct {
	replay     *security.ReplayWindowV1
	pending    security.KeySchedule
	next       bool
	attachSlot bool
	epoch      uint64
	streamSlot uint16
	sequence   uint64
}

// strictReceiveEpochCandidateV1 deliberately contains no replay state. The
// strict protected-channel path has exactly one replay owner: the authenticated
// envelope capability committed by commitFirstAuthenticatedOperationV1.
type strictReceiveEpochCandidateV1 struct {
	pending security.KeySchedule
	next    bool
	epoch   uint64
}

type outboundRecordCandidateV1 struct {
	ratchet bool
	pending security.KeySchedule
	replay  *security.ReplayWindowV1
}

func newEndpointLifecycleV1(coordinator *pairTerminalCoordinatorV1, owner *HandshakeRuntime, schedule *security.KeySchedule, config StrictSessionConfigV1, context auth.AuthenticatedContextSnapshotV1, role lifecycleRoleV1, state auth.State) (*endpointLifecycleV1, error) {
	if coordinator == nil || owner == nil || schedule == nil || schedule.Epoch != 0 || zeroRuntimeEpoch(owner.epoch) ||
		(role != lifecycleRoleClientV1 && role != lifecycleRoleRelayV1) ||
		(state != auth.StateEstablished && state != auth.StateAuthenticating) {
		return nil, ErrProfileIncompatible
	}
	var replay *security.ReplayWindowV1
	replayStreams := make(map[uint16]*security.ReplayWindowV1)
	if context.EffectivePolicy.NonceMode != security.NonceModeStreamPartitionedCounterV1 {
		var err error
		replay, err = security.NewReplayWindowV1(context.EffectivePolicy.ReplayPolicy, int(config.ReplayWindowSize))
		if err != nil {
			return nil, ErrProfileIncompatible
		}
	}
	generation, overflow := owner.currentProfileGenerationV1()
	if overflow {
		return nil, ErrProfileRotationRequired
	}
	life := &endpointLifecycleV1{
		coordinator: coordinator, owner: owner, runtimeEpoch: owner.epoch,
		schedule: schedule, config: config, role: role, state: state,
		rotation:     context.EffectivePolicy.KeyRotationPolicy,
		nonceMode:    context.EffectivePolicy.NonceMode,
		replayPolicy: context.EffectivePolicy.ReplayPolicy,
		th4:          context.TranscriptHash, generation: generation, keyEpoch: schedule.Epoch,
		replay:           replay,
		outStreams:       make(map[uint16]outboundSequenceStateV1),
		replayStreams:    replayStreams,
		outstanding:      make(map[[32]byte]*outstandingOperationV1),
		completed:        make(map[[32]byte]*completedOperationV1),
		acknowledged:     make(map[[32]byte]uint64),
		issuedOperations: make(map[recordReservationKeyV1]operationTransmissionV1),
		issuedAcks:       make(map[recordReservationKeyV1]acknowledgementTransmissionV1),
		destroySchedule: func(schedule *security.KeySchedule) {
			if schedule != nil {
				schedule.Destroy()
			}
		},
		commitReplay: func(replay *security.ReplayWindowV1, sequence uint64) error {
			return replay.CommitAuthenticated(sequence)
		},
	}
	life.self = life
	return life, nil
}

func (life *endpointLifecycleV1) stateLockedV1() auth.State {
	if !life.validLockedV1() {
		if life != nil && life.coordinator != nil {
			life.coordinator.closeLockedV1()
		}
		return auth.StateClosed
	}
	return life.state
}

func (life *endpointLifecycleV1) validLockedV1() bool {
	if life == nil || life.self != life || life.coordinator == nil || life.owner == nil || life.schedule == nil ||
		life.owner.epoch != life.runtimeEpoch || zeroRuntimeEpoch(life.runtimeEpoch) ||
		life.schedule.Epoch != life.keyEpoch || life.outStreams == nil || life.replayStreams == nil ||
		life.outstanding == nil || life.completed == nil || life.acknowledged == nil ||
		life.issuedOperations == nil || life.issuedAcks == nil || life.destroySchedule == nil || life.commitReplay == nil {
		return false
	}
	switch life.nonceMode {
	case security.NonceModeCounterXORBaseV1, security.NonceModeCounterAppendBaseV1,
		security.NonceModeDirectionalCounterV1, security.NonceModeStreamPartitionedCounterV1:
	default:
		return false
	}
	if life.nonceMode == security.NonceModeStreamPartitionedCounterV1 {
		if life.replay != nil {
			return false
		}
	} else if life.replay == nil {
		return false
	}
	return life.role == lifecycleRoleClientV1 || life.role == lifecycleRoleRelayV1
}

func (life *endpointLifecycleV1) destroyLockedV1() {
	if life == nil {
		return
	}
	life.state = auth.StateClosed
	if life.schedule != nil {
		life.destroyScheduleLockedV1(life.schedule)
	}
	life.replay = nil
	life.outStreams = nil
	life.replayStreams = nil
	life.outstanding = nil
	life.completed = nil
	life.acknowledged = nil
	life.issuedOperations = nil
	life.issuedAcks = nil
	life.schedule = nil
	life.owner = nil
	life.runtimeEpoch = [32]byte{}
	life.th4 = [32]byte{}
	life.config = StrictSessionConfigV1{}
	life.role = 0
	life.rotation = ""
	life.nonceMode = ""
	life.replayPolicy = ""
	life.generation = 0
	life.keyEpoch = 0
	life.outSequence = 0
	life.outSequenceEnd = false
	life.operationSequence = 0
	life.operationSequenceEnd = false
	life.inOperationSequence = 0
	life.inOperationSequenceEnd = false
	life.outKeyAttempts = 0
	life.inKeyAttempts = 0
	life.sendCompleted = 0
	life.receiveCompleted = 0
	life.destroySchedule = nil
	life.commitReplay = nil
	life.beforeRatchetInstall = nil
	life.beforeReceiveCommit = nil
	life.beforeProfileCommitObserver = nil
}

func (life *endpointLifecycleV1) destroyScheduleLockedV1(schedule *security.KeySchedule) {
	if schedule == nil || !scheduleMaterialPresentV1(schedule) {
		return
	}
	if life != nil && life.destroySchedule != nil {
		life.destroySchedule(schedule)
		return
	}
	schedule.Destroy()
}

func scheduleMaterialPresentV1(schedule *security.KeySchedule) bool {
	return schedule != nil && (schedule.Epoch != 0 || schedule.Suite != (security.Suite{}) ||
		len(schedule.ClientWriteKey) != 0 || len(schedule.ServerWriteKey) != 0 ||
		len(schedule.ClientNonceBase) != 0 || len(schedule.ServerNonceBase) != 0 || len(schedule.ExporterSecret) != 0)
}

func (life *endpointLifecycleV1) failLockedV1(err error) error {
	if life != nil && life.coordinator != nil {
		life.coordinator.closeLockedV1()
	}
	return err
}

func (life *endpointLifecycleV1) lockV1() bool {
	if life == nil || life.coordinator == nil {
		return false
	}
	life.coordinator.mu.Lock()
	return true
}

func (life *endpointLifecycleV1) readyLockedV1() error {
	if !life.validLockedV1() || life.coordinator.closed || life.state != auth.StateEstablished {
		return life.failLockedV1(ErrLifecycle)
	}
	return life.checkProfileGenerationLockedV1()
}

func (life *endpointLifecycleV1) checkProfileGenerationLockedV1() error {
	if err := life.profileGenerationValueLockedV1(); err != nil {
		return life.failLockedV1(err)
	}
	return nil
}

func (life *endpointLifecycleV1) profileGenerationValueLockedV1() error {
	if life.rotation != "profile_lifetime_bound" {
		return nil
	}
	owner := life.owner
	if owner == nil {
		return ErrProfileRotationRequired
	}
	owner.profileMu.Lock()
	defer owner.profileMu.Unlock()
	return life.profileGenerationValueWithProfileMuHeldV1()
}

func (life *endpointLifecycleV1) profileGenerationValueWithProfileMuHeldV1() error {
	if life.rotation != "profile_lifetime_bound" {
		return nil
	}
	if life.owner == nil || life.owner.profileOverflow || life.owner.profileGeneration != life.generation {
		return ErrProfileRotationRequired
	}
	return nil
}

// lockProfileCommitGuardLockedV1 is entered only while the pair coordinator is
// already held. A non-nil return value owns profileMu until explicitly
// unlocked, making profile validation and the associated lifecycle mutation a
// single coordinator -> profileMu critical section.
func (life *endpointLifecycleV1) lockProfileCommitGuardLockedV1() (*HandshakeRuntime, error) {
	if life.rotation != "profile_lifetime_bound" {
		return nil, nil
	}
	owner := life.owner
	if owner == nil {
		return nil, ErrProfileRotationRequired
	}
	owner.profileMu.Lock()
	if err := life.profileGenerationValueWithProfileMuHeldV1(); err != nil {
		owner.profileMu.Unlock()
		return nil, err
	}
	return owner, nil
}

func unlockProfileCommitGuardV1(owner *HandshakeRuntime) {
	if owner != nil {
		owner.profileMu.Unlock()
	}
}

func (life *endpointLifecycleV1) postAuthenticationCommitV1() error {
	if !life.lockV1() {
		return ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if !life.validLockedV1() || life.coordinator.closed || life.role != lifecycleRoleRelayV1 || life.state != auth.StateAuthenticating {
		return life.failLockedV1(ErrLifecycle)
	}
	if err := life.checkProfileGenerationLockedV1(); err != nil {
		return err
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		return life.failLockedV1(err)
	}
	life.state = auth.StateEstablished
	unlockProfileCommitGuardV1(profileOwner)
	return nil
}

func (life *endpointLifecycleV1) beginOperationV1(streamSlot uint16) (operationTransmissionV1, error) {
	if !life.lockV1() {
		return operationTransmissionV1{}, ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if err := life.readyLockedV1(); err != nil {
		return operationTransmissionV1{}, err
	}
	if streamSlot == 0 || life.operationSequenceEnd {
		return operationTransmissionV1{}, life.failLockedV1(ErrLifecycle)
	}
	if life.sendCompleted+uint64(len(life.outstanding)) >= life.config.MaxSessionMessages {
		return operationTransmissionV1{}, life.failLockedV1(ErrSessionMessageLimit)
	}
	candidate, err := life.prepareOutboundRecordLockedV1(streamSlot)
	if err != nil {
		return operationTransmissionV1{}, err
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return operationTransmissionV1{}, life.failLockedV1(err)
	}
	recordEpoch, recordSequence, oldSchedule, err := life.commitOutboundRecordLockedV1(streamSlot, &candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return operationTransmissionV1{}, life.failLockedV1(err)
	}
	direction := life.outboundDirectionV1()
	originEpoch := recordEpoch
	operationSequence := life.operationSequence
	id := operationIDV1(life.th4, direction, originEpoch, streamSlot, operationSequence)
	expectedCompleted := life.sendCompleted + uint64(len(life.outstanding)) + 1
	operation := &outstandingOperationV1{
		id: id, originDirection: direction, originEpoch: originEpoch, streamSlot: streamSlot,
		operationSequence: operationSequence, expectedCompleted: expectedCompleted, attempts: 1,
	}
	life.outstanding[id] = operation
	if life.operationSequence == math.MaxUint64 {
		life.operationSequenceEnd = true
	} else {
		life.operationSequence++
	}
	transmission := life.operationTransmissionLockedV1(operation, recordEpoch, recordSequence)
	life.issuedOperations[operationReservationKeyV1(transmission)] = transmission
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return transmission, nil
}

func (life *endpointLifecycleV1) retryOperationV1(operationID [32]byte) (operationTransmissionV1, error) {
	if !life.lockV1() {
		return operationTransmissionV1{}, ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if err := life.readyLockedV1(); err != nil {
		return operationTransmissionV1{}, err
	}
	operation := life.outstanding[operationID]
	if operation == nil || operation.attempts >= lifecycleTransmissionLimitV1 {
		return operationTransmissionV1{}, life.failLockedV1(ErrLifecycle)
	}
	candidate, err := life.prepareOutboundRecordLockedV1(operation.streamSlot)
	if err != nil {
		return operationTransmissionV1{}, err
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return operationTransmissionV1{}, life.failLockedV1(err)
	}
	recordEpoch, recordSequence, oldSchedule, err := life.commitOutboundRecordLockedV1(operation.streamSlot, &candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return operationTransmissionV1{}, life.failLockedV1(err)
	}
	operation.attempts++
	transmission := life.operationTransmissionLockedV1(operation, recordEpoch, recordSequence)
	life.issuedOperations[operationReservationKeyV1(transmission)] = transmission
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return transmission, nil
}

func (life *endpointLifecycleV1) operationTransmissionLockedV1(operation *outstandingOperationV1, recordEpoch, recordSequence uint64) operationTransmissionV1 {
	return operationTransmissionV1{
		owner: life, coordinator: life.coordinator, operationID: operation.id,
		originDirection: operation.originDirection, originEpoch: operation.originEpoch,
		streamSlot: operation.streamSlot, operationSequence: operation.operationSequence,
		recordEpoch: recordEpoch, recordSequence: recordSequence, attempt: operation.attempts,
	}
}

func (life *endpointLifecycleV1) commitAuthenticatedOperationV1(transmission operationTransmissionV1) (OperationAckV1, error) {
	if !life.lockV1() {
		return OperationAckV1{}, ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if err := life.readyLockedV1(); err != nil {
		return OperationAckV1{}, err
	}
	if !life.validOperationOwnerLockedV1(transmission) || !life.validIssuedOperationLockedV1(transmission) || transmission.streamSlot == 0 ||
		operationIDV1(life.th4, transmission.originDirection, transmission.originEpoch, transmission.streamSlot, transmission.operationSequence) != transmission.operationID {
		return OperationAckV1{}, life.failLockedV1(ErrLifecycle)
	}
	completed := life.completed[transmission.operationID]
	if completed != nil {
		if completed.originDirection != transmission.originDirection || completed.originEpoch != transmission.originEpoch ||
			completed.streamSlot != transmission.streamSlot || completed.operationSequence != transmission.operationSequence {
			return OperationAckV1{}, life.failLockedV1(ErrLifecycle)
		}
		candidate, err := life.prepareReceiveEpochLockedV1(transmission.streamSlot, transmission.recordEpoch, transmission.recordSequence)
		if err != nil {
			return OperationAckV1{}, life.failLockedV1(err)
		}
		if life.beforeReceiveCommit != nil {
			life.beforeReceiveCommit()
		}
		if life.beforeProfileCommitObserver != nil {
			life.beforeProfileCommitObserver()
		}
		profileOwner, err := life.lockProfileCommitGuardLockedV1()
		if err != nil {
			life.destroyPendingReceiveLockedV1(&candidate)
			return OperationAckV1{}, life.failLockedV1(err)
		}
		oldSchedule, err := life.commitReceiveEpochLockedV1(&candidate)
		if err != nil {
			unlockProfileCommitGuardV1(profileOwner)
			life.destroyPendingReceiveLockedV1(&candidate)
			return OperationAckV1{}, life.failLockedV1(err)
		}
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyScheduleLockedV1(&oldSchedule)
		return completed.ack, nil
	}
	if life.inOperationSequenceEnd || transmission.operationSequence != life.inOperationSequence {
		return OperationAckV1{}, life.failLockedV1(ErrLifecycle)
	}
	if life.receiveCompleted >= life.config.MaxSessionMessages {
		return OperationAckV1{}, life.failLockedV1(ErrSessionMessageLimit)
	}
	candidate, err := life.prepareReceiveEpochLockedV1(transmission.streamSlot, transmission.recordEpoch, transmission.recordSequence)
	if err != nil {
		return OperationAckV1{}, life.failLockedV1(err)
	}
	if life.beforeReceiveCommit != nil {
		life.beforeReceiveCommit()
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyPendingReceiveLockedV1(&candidate)
		return OperationAckV1{}, life.failLockedV1(err)
	}
	oldSchedule, err := life.commitReceiveEpochLockedV1(&candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyPendingReceiveLockedV1(&candidate)
		return OperationAckV1{}, life.failLockedV1(err)
	}
	life.receiveCompleted++
	ack := OperationAckV1{OperationID: transmission.operationID, CompletedCount: life.receiveCompleted}
	life.completed[transmission.operationID] = &completedOperationV1{
		originDirection: transmission.originDirection, originEpoch: transmission.originEpoch,
		streamSlot: transmission.streamSlot, operationSequence: transmission.operationSequence, ack: ack,
	}
	if life.inOperationSequence == math.MaxUint64 {
		life.inOperationSequenceEnd = true
	} else {
		life.inOperationSequence++
	}
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return ack, nil
}

// commitFirstAuthenticatedOperationV1 is the strict protected-channel receive
// transaction. replayCommit must be the non-retained one-shot closure over the
// exact prepared envelope capability. Every fallible lifecycle operation occurs
// before that closure; after it succeeds, only assignments are performed while
// the coordinator and profile-generation guards remain held.
func (life *endpointLifecycleV1) commitFirstAuthenticatedOperationV1(transmission operationTransmissionV1, replayCommit func() error) (OperationAckV1, error) {
	if !life.lockV1() {
		return OperationAckV1{}, ErrLifecycle
	}
	coordinator := life.coordinator
	if !life.validStrictCandidateLockedV1() || coordinator.closed || replayCommit == nil ||
		(life.state != auth.StateEstablished && (life.state != auth.StateAuthenticating || (life.role != lifecycleRoleRelayV1 && !life.labSkipStateValidation))) {
		coordinator.mu.Unlock()
		return OperationAckV1{}, ErrLifecycle
	}
	if err := life.profileGenerationValueLockedV1(); err != nil {
		coordinator.mu.Unlock()
		return OperationAckV1{}, err
	}
	if !life.validStrictOperationOwnerLockedV1(transmission) || !life.validIssuedOperationLockedV1(transmission) || transmission.streamSlot == 0 ||
		operationIDV1(life.th4, transmission.originDirection, transmission.originEpoch, transmission.streamSlot, transmission.operationSequence) != transmission.operationID {
		coordinator.mu.Unlock()
		return OperationAckV1{}, ErrLifecycle
	}
	completed := life.completed[transmission.operationID]
	unique := completed == nil
	var ack OperationAckV1
	if !unique {
		if completed.originDirection != transmission.originDirection || completed.originEpoch != transmission.originEpoch ||
			completed.streamSlot != transmission.streamSlot || completed.operationSequence != transmission.operationSequence {
			coordinator.mu.Unlock()
			return OperationAckV1{}, ErrLifecycle
		}
		ack = completed.ack
	} else {
		if life.inOperationSequenceEnd || transmission.operationSequence != life.inOperationSequence {
			coordinator.mu.Unlock()
			return OperationAckV1{}, ErrLifecycle
		}
		if life.receiveCompleted >= life.config.MaxSessionMessages {
			coordinator.mu.Unlock()
			return OperationAckV1{}, ErrSessionMessageLimit
		}
		ack = OperationAckV1{OperationID: transmission.operationID, CompletedCount: life.receiveCompleted + 1}
	}
	candidate, err := life.prepareStrictReceiveEpochLockedV1(transmission.recordEpoch)
	if err != nil {
		coordinator.mu.Unlock()
		return OperationAckV1{}, err
	}
	destroySchedule := life.destroySchedule
	if life.beforeReceiveCommit != nil {
		life.beforeReceiveCommit()
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyStrictReceiveEpochCandidateLockedV1(&candidate)
		coordinator.mu.Unlock()
		return OperationAckV1{}, err
	}
	if err := replayCommit(); err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyStrictReceiveEpochCandidateLockedV1(&candidate)
		coordinator.mu.Unlock()
		return OperationAckV1{}, err
	}
	oldSchedule := life.applyStrictReceiveEpochLockedV1(&candidate)
	if unique {
		life.receiveCompleted++
		life.completed[transmission.operationID] = &completedOperationV1{
			originDirection: transmission.originDirection, originEpoch: transmission.originEpoch,
			streamSlot: transmission.streamSlot, operationSequence: transmission.operationSequence, ack: ack,
		}
		if life.inOperationSequence == math.MaxUint64 {
			life.inOperationSequenceEnd = true
		} else {
			life.inOperationSequence++
		}
	}
	if life.state == auth.StateAuthenticating {
		life.state = auth.StateEstablished
	}
	unlockProfileCommitGuardV1(profileOwner)
	coordinator.mu.Unlock()
	if scheduleMaterialPresentV1(&oldSchedule) {
		if destroySchedule != nil {
			destroySchedule(&oldSchedule)
		} else {
			oldSchedule.Destroy()
		}
	}
	life.lastCommitDeliver = unique || life.labAcceptCompleted
	return ack, nil
}

func (life *endpointLifecycleV1) validStrictCandidateLockedV1() bool {
	if life == nil || life.self != life || life.coordinator == nil || life.owner == nil || life.schedule == nil ||
		life.owner.epoch != life.runtimeEpoch || zeroRuntimeEpoch(life.runtimeEpoch) || life.schedule.Epoch != life.keyEpoch ||
		life.outStreams == nil || life.outstanding == nil || life.completed == nil || life.acknowledged == nil ||
		life.issuedOperations == nil || life.issuedAcks == nil || life.destroySchedule == nil {
		return false
	}
	switch life.nonceMode {
	case security.NonceModeCounterXORBaseV1, security.NonceModeCounterAppendBaseV1,
		security.NonceModeDirectionalCounterV1, security.NonceModeStreamPartitionedCounterV1:
	default:
		return false
	}
	return life.role == lifecycleRoleClientV1 || life.role == lifecycleRoleRelayV1
}

func (life *endpointLifecycleV1) validStrictOperationOwnerLockedV1(transmission operationTransmissionV1) bool {
	return transmission.coordinator == life.coordinator && transmission.owner != nil && transmission.owner.coordinator == life.coordinator &&
		transmission.owner.validStrictCandidateLockedV1() && transmission.owner.owner == life.owner &&
		transmission.owner.runtimeEpoch == life.runtimeEpoch && transmission.owner.role != life.role &&
		transmission.originDirection == transmission.owner.outboundDirectionV1()
}

func (life *endpointLifecycleV1) prepareStrictReceiveEpochLockedV1(epoch uint64) (strictReceiveEpochCandidateV1, error) {
	if life.inKeyAttempts >= life.config.MaxKeyLifetimeMessages && epoch == life.keyEpoch {
		if life.rotation == "session_only" {
			return strictReceiveEpochCandidateV1{}, ErrKeyLifetimeExhausted
		}
		return strictReceiveEpochCandidateV1{}, ErrRekeyFailed
	}
	if epoch == life.keyEpoch {
		return strictReceiveEpochCandidateV1{epoch: epoch}, nil
	}
	if life.keyEpoch == math.MaxUint64 || epoch != life.keyEpoch+1 || life.rotation == "session_only" {
		if life.rotation == "session_only" {
			return strictReceiveEpochCandidateV1{}, ErrKeyLifetimeExhausted
		}
		return strictReceiveEpochCandidateV1{}, ErrRekeyFailed
	}
	if life.rotation != "message_lifetime_bound" && life.rotation != "profile_lifetime_bound" {
		return strictReceiveEpochCandidateV1{}, ErrRekeyFailed
	}
	pending, err := security.RatchetKeyScheduleV1(*life.schedule)
	if err != nil || pending.Epoch != epoch {
		pending.Destroy()
		return strictReceiveEpochCandidateV1{}, ErrRekeyFailed
	}
	return strictReceiveEpochCandidateV1{pending: pending, next: true, epoch: epoch}, nil
}

func (life *endpointLifecycleV1) applyStrictReceiveEpochLockedV1(candidate *strictReceiveEpochCandidateV1) security.KeySchedule {
	var oldSchedule security.KeySchedule
	if candidate.next {
		oldSchedule = *life.schedule
		*life.schedule = candidate.pending
		life.keyEpoch = candidate.epoch
		life.outSequence = 0
		life.outSequenceEnd = false
		life.outStreams = make(map[uint16]outboundSequenceStateV1)
		life.outKeyAttempts = 0
		life.inKeyAttempts = 0
		candidate.pending = security.KeySchedule{}
		candidate.next = false
	}
	life.inKeyAttempts++
	return oldSchedule
}

func (life *endpointLifecycleV1) destroyStrictReceiveEpochCandidateLockedV1(candidate *strictReceiveEpochCandidateV1) {
	if candidate != nil && candidate.next {
		life.destroyScheduleLockedV1(&candidate.pending)
		candidate.pending = security.KeySchedule{}
		candidate.next = false
	}
}

func (life *endpointLifecycleV1) beginOperationAckV1(operationID [32]byte) (acknowledgementTransmissionV1, error) {
	return life.reserveOperationAckV1(operationID, false)
}

func (life *endpointLifecycleV1) retryOperationAckV1(operationID [32]byte) (acknowledgementTransmissionV1, error) {
	return life.reserveOperationAckV1(operationID, true)
}

func (life *endpointLifecycleV1) reserveOperationAckV1(operationID [32]byte, retry bool) (acknowledgementTransmissionV1, error) {
	if !life.lockV1() {
		return acknowledgementTransmissionV1{}, ErrOperationAckInvalid
	}
	defer life.coordinator.mu.Unlock()
	if !life.validLockedV1() || life.coordinator.closed || life.state != auth.StateEstablished {
		return acknowledgementTransmissionV1{}, life.failLockedV1(ErrOperationAckInvalid)
	}
	if err := life.checkProfileGenerationLockedV1(); err != nil {
		return acknowledgementTransmissionV1{}, err
	}
	completed := life.completed[operationID]
	if completed == nil || (!retry && completed.ackAttempts != 0) || (retry && completed.ackAttempts == 0) || completed.ackAttempts >= lifecycleTransmissionLimitV1 {
		return acknowledgementTransmissionV1{}, life.failLockedV1(ErrOperationAckInvalid)
	}
	candidate, err := life.prepareOutboundRecordLockedV1(0)
	if err != nil {
		return acknowledgementTransmissionV1{}, err
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return acknowledgementTransmissionV1{}, life.failLockedV1(err)
	}
	recordEpoch, recordSequence, oldSchedule, err := life.commitOutboundRecordLockedV1(0, &candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return acknowledgementTransmissionV1{}, life.failLockedV1(err)
	}
	completed.ackAttempts++
	transmission := acknowledgementTransmissionV1{
		owner: life, coordinator: life.coordinator, ack: completed.ack,
		recordEpoch: recordEpoch, recordSequence: recordSequence, attempt: completed.ackAttempts,
	}
	life.issuedAcks[ackReservationKeyV1(transmission)] = transmission
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return transmission, nil
}

func (life *endpointLifecycleV1) commitAuthenticatedOperationAckV1(transmission acknowledgementTransmissionV1) error {
	if !life.lockV1() {
		return ErrOperationAckInvalid
	}
	defer life.coordinator.mu.Unlock()
	if !life.validLockedV1() || life.coordinator.closed || life.state != auth.StateEstablished {
		return life.failLockedV1(ErrOperationAckInvalid)
	}
	if err := life.checkProfileGenerationLockedV1(); err != nil {
		return err
	}
	if !life.validAckOwnerLockedV1(transmission) || !life.validIssuedAckLockedV1(transmission) {
		return life.failLockedV1(ErrOperationAckInvalid)
	}
	operation := life.outstanding[transmission.ack.OperationID]
	if operation != nil {
		if transmission.ack.CompletedCount != operation.expectedCompleted || transmission.ack.CompletedCount != life.sendCompleted+1 {
			return life.failLockedV1(ErrOperationAckInvalid)
		}
	} else {
		count, ok := life.acknowledged[transmission.ack.OperationID]
		if !ok || count != transmission.ack.CompletedCount {
			return life.failLockedV1(ErrOperationAckInvalid)
		}
	}
	candidate, err := life.prepareReceiveEpochLockedV1(0, transmission.recordEpoch, transmission.recordSequence)
	if err != nil {
		if err == ErrProfileRotationRequired {
			return err
		}
		return life.failLockedV1(ErrOperationAckInvalid)
	}
	if life.beforeReceiveCommit != nil {
		life.beforeReceiveCommit()
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyPendingReceiveLockedV1(&candidate)
		return life.failLockedV1(err)
	}
	oldSchedule, err := life.commitReceiveEpochLockedV1(&candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyPendingReceiveLockedV1(&candidate)
		return life.failLockedV1(ErrOperationAckInvalid)
	}
	if operation != nil {
		delete(life.outstanding, transmission.ack.OperationID)
		life.sendCompleted++
		life.acknowledged[transmission.ack.OperationID] = transmission.ack.CompletedCount
	}
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return nil
}

// commitStrictAuthenticatedOperationAckV1 is the protected-channel Ack
// transaction. The decoded Ack and clear role-fixed header fields identify an
// exact peer-issued reservation. replayCommit is the sole replay authority;
// every fallible lifecycle check and ratchet preparation precedes it.
func (life *endpointLifecycleV1) commitStrictAuthenticatedOperationAckV1(sender *endpointLifecycleV1, direction uint16, epoch, sequence uint64, ack OperationAckV1, replayCommit func() error) error {
	if !life.lockV1() {
		return ErrOperationAckInvalid
	}
	coordinator := life.coordinator
	if !life.validStrictCandidateLockedV1() || coordinator.closed || life.state != auth.StateEstablished || replayCommit == nil ||
		sender == nil || sender.coordinator != coordinator || !sender.validStrictCandidateLockedV1() || sender.state != auth.StateEstablished ||
		sender.owner != life.owner || sender.runtimeEpoch != life.runtimeEpoch || sender.role == life.role || direction != sender.outboundDirectionV1() {
		coordinator.mu.Unlock()
		return ErrOperationAckInvalid
	}
	if err := life.profileGenerationValueLockedV1(); err != nil {
		coordinator.mu.Unlock()
		return err
	}
	if err := sender.profileGenerationValueLockedV1(); err != nil {
		coordinator.mu.Unlock()
		return err
	}
	key := recordReservationKeyV1{streamSlot: 0, epoch: epoch, sequence: sequence}
	transmission, ok := sender.issuedAcks[key]
	if !ok || transmission.owner != sender || transmission.coordinator != coordinator || transmission.recordEpoch != epoch ||
		transmission.recordSequence != sequence || transmission.ack != ack || transmission.attempt == 0 {
		coordinator.mu.Unlock()
		return ErrOperationAckInvalid
	}
	completed := sender.completed[ack.OperationID]
	if completed == nil || completed.ack != ack || transmission.attempt > completed.ackAttempts {
		coordinator.mu.Unlock()
		return ErrOperationAckInvalid
	}
	operation := life.outstanding[ack.OperationID]
	if operation == nil || ack.CompletedCount != operation.expectedCompleted || ack.CompletedCount != life.sendCompleted+1 {
		coordinator.mu.Unlock()
		return ErrOperationAckInvalid
	}
	candidate, err := life.prepareStrictReceiveEpochLockedV1(epoch)
	if err != nil {
		coordinator.mu.Unlock()
		return ErrOperationAckInvalid
	}
	destroySchedule := life.destroySchedule
	if life.beforeReceiveCommit != nil {
		life.beforeReceiveCommit()
	}
	if life.beforeProfileCommitObserver != nil {
		life.beforeProfileCommitObserver()
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyStrictReceiveEpochCandidateLockedV1(&candidate)
		coordinator.mu.Unlock()
		return err
	}
	if err := replayCommit(); err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyStrictReceiveEpochCandidateLockedV1(&candidate)
		coordinator.mu.Unlock()
		return err
	}
	oldSchedule := life.applyStrictReceiveEpochLockedV1(&candidate)
	delete(life.outstanding, ack.OperationID)
	life.sendCompleted++
	life.acknowledged[ack.OperationID] = ack.CompletedCount
	unlockProfileCommitGuardV1(profileOwner)
	coordinator.mu.Unlock()
	if scheduleMaterialPresentV1(&oldSchedule) {
		if destroySchedule != nil {
			destroySchedule(&oldSchedule)
		} else {
			oldSchedule.Destroy()
		}
	}
	return nil
}

func (life *endpointLifecycleV1) validOperationOwnerLockedV1(transmission operationTransmissionV1) bool {
	if transmission.coordinator != life.coordinator || transmission.owner == nil || transmission.owner.coordinator != life.coordinator ||
		!transmission.owner.validLockedV1() || transmission.owner.owner != life.owner ||
		transmission.owner.runtimeEpoch != life.runtimeEpoch || transmission.owner.role == life.role ||
		transmission.originDirection != transmission.owner.outboundDirectionV1() {
		return false
	}
	return true
}

func operationReservationKeyV1(transmission operationTransmissionV1) recordReservationKeyV1 {
	return recordReservationKeyV1{streamSlot: transmission.streamSlot, epoch: transmission.recordEpoch, sequence: transmission.recordSequence}
}

func ackReservationKeyV1(transmission acknowledgementTransmissionV1) recordReservationKeyV1 {
	return recordReservationKeyV1{streamSlot: 0, epoch: transmission.recordEpoch, sequence: transmission.recordSequence}
}

func (life *endpointLifecycleV1) validIssuedOperationLockedV1(transmission operationTransmissionV1) bool {
	if transmission.owner == nil || transmission.owner.issuedOperations == nil {
		return false
	}
	issued, ok := transmission.owner.issuedOperations[operationReservationKeyV1(transmission)]
	return ok && issued == transmission
}

func (life *endpointLifecycleV1) validAckOwnerLockedV1(transmission acknowledgementTransmissionV1) bool {
	if transmission.coordinator != life.coordinator || transmission.owner == nil || transmission.owner.coordinator != life.coordinator ||
		!transmission.owner.validLockedV1() || transmission.owner.owner != life.owner ||
		transmission.owner.runtimeEpoch != life.runtimeEpoch || transmission.owner.role == life.role {
		return false
	}
	return true
}

func (life *endpointLifecycleV1) validIssuedAckLockedV1(transmission acknowledgementTransmissionV1) bool {
	if transmission.owner == nil || transmission.owner.issuedAcks == nil {
		return false
	}
	issued, ok := transmission.owner.issuedAcks[ackReservationKeyV1(transmission)]
	if !ok || issued != transmission {
		return false
	}
	completed := transmission.owner.completed[transmission.ack.OperationID]
	return completed != nil && completed.ack == transmission.ack && transmission.attempt > 0 && transmission.attempt <= completed.ackAttempts
}

func (life *endpointLifecycleV1) outboundDirectionV1() uint16 {
	if life.role == lifecycleRoleClientV1 {
		return controlDirectionClientV1
	}
	return controlDirectionRelayV1
}

func (life *endpointLifecycleV1) prepareOutboundRecordLockedV1(streamSlot uint16) (outboundRecordCandidateV1, error) {
	if err := life.readyLockedV1(); err != nil {
		return outboundRecordCandidateV1{}, err
	}
	streamState := life.outStreams[streamSlot]
	streamEnded := life.nonceMode == security.NonceModeStreamPartitionedCounterV1 && streamState.ended
	if life.outKeyAttempts < life.config.MaxKeyLifetimeMessages && !life.outSequenceEnd && !streamEnded {
		return outboundRecordCandidateV1{}, nil
	}
	if life.rotation == "session_only" {
		return outboundRecordCandidateV1{}, life.failLockedV1(ErrKeyLifetimeExhausted)
	}
	if life.rotation != "message_lifetime_bound" && life.rotation != "profile_lifetime_bound" {
		return outboundRecordCandidateV1{}, life.failLockedV1(ErrRekeyFailed)
	}
	pending, err := security.RatchetKeyScheduleV1(*life.schedule)
	if err != nil || pending.Epoch != life.keyEpoch+1 || pending.Epoch == 0 {
		life.destroyScheduleLockedV1(&pending)
		return outboundRecordCandidateV1{}, life.failLockedV1(ErrRekeyFailed)
	}
	var replay *security.ReplayWindowV1
	if life.nonceMode != security.NonceModeStreamPartitionedCounterV1 {
		replay, err = security.NewReplayWindowV1(life.replayPolicy, int(life.config.ReplayWindowSize))
		if err != nil {
			life.destroyScheduleLockedV1(&pending)
			return outboundRecordCandidateV1{}, life.failLockedV1(ErrRekeyFailed)
		}
	}
	if life.beforeRatchetInstall != nil {
		life.beforeRatchetInstall()
	}
	return outboundRecordCandidateV1{ratchet: true, pending: pending, replay: replay}, nil
}

func (life *endpointLifecycleV1) commitOutboundRecordLockedV1(streamSlot uint16, candidate *outboundRecordCandidateV1) (uint64, uint64, security.KeySchedule, error) {
	if candidate == nil {
		return 0, 0, security.KeySchedule{}, ErrRekeyFailed
	}
	streamState := life.outStreams[streamSlot]
	streamEnded := life.nonceMode == security.NonceModeStreamPartitionedCounterV1 && streamState.ended
	requiresRatchet := life.outKeyAttempts >= life.config.MaxKeyLifetimeMessages || life.outSequenceEnd || streamEnded
	if requiresRatchet != candidate.ratchet {
		return 0, 0, security.KeySchedule{}, ErrRekeyFailed
	}
	var oldSchedule security.KeySchedule
	if candidate.ratchet {
		if life.keyEpoch == math.MaxUint64 || candidate.pending.Epoch != life.keyEpoch+1 || candidate.pending.Epoch == 0 ||
			(life.nonceMode == security.NonceModeStreamPartitionedCounterV1) != (candidate.replay == nil) {
			return 0, 0, security.KeySchedule{}, ErrRekeyFailed
		}
		oldSchedule = *life.schedule
		*life.schedule = candidate.pending
		life.keyEpoch = candidate.pending.Epoch
		life.outSequence = 0
		life.outSequenceEnd = false
		life.outStreams = make(map[uint16]outboundSequenceStateV1)
		life.outKeyAttempts = 0
		life.inKeyAttempts = 0
		life.replay = candidate.replay
		life.replayStreams = make(map[uint16]*security.ReplayWindowV1)
		candidate.pending = security.KeySchedule{}
		candidate.replay = nil
		candidate.ratchet = false
		streamState = outboundSequenceStateV1{}
	}
	var sequence uint64
	if life.nonceMode == security.NonceModeStreamPartitionedCounterV1 {
		sequence = streamState.sequence
		if sequence == math.MaxUint64 {
			streamState.ended = true
		} else {
			streamState.sequence++
		}
		life.outStreams[streamSlot] = streamState
	} else {
		sequence = life.outSequence
		if sequence == math.MaxUint64 {
			life.outSequenceEnd = true
		} else {
			life.outSequence++
		}
	}
	life.outKeyAttempts++
	return life.keyEpoch, sequence, oldSchedule, nil
}

func (life *endpointLifecycleV1) destroyOutboundRecordCandidateLockedV1(candidate *outboundRecordCandidateV1) {
	if candidate == nil || !candidate.ratchet {
		return
	}
	life.destroyScheduleLockedV1(&candidate.pending)
	candidate.pending = security.KeySchedule{}
	candidate.replay = nil
	candidate.ratchet = false
}

func (life *endpointLifecycleV1) prepareReceiveEpochLockedV1(streamSlot uint16, epoch, sequence uint64) (receiveEpochCandidateV1, error) {
	if err := life.checkProfileGenerationLockedV1(); err != nil {
		return receiveEpochCandidateV1{}, err
	}
	if epoch == life.keyEpoch {
		if life.inKeyAttempts >= life.config.MaxKeyLifetimeMessages {
			if life.rotation == "session_only" {
				return receiveEpochCandidateV1{}, ErrKeyLifetimeExhausted
			}
			return receiveEpochCandidateV1{}, ErrRekeyFailed
		}
		replay, attach, err := life.receiveReplayCandidateLockedV1(streamSlot)
		if err != nil || replay.Plausible(sequence) != nil {
			return receiveEpochCandidateV1{}, ErrLifecycle
		}
		return receiveEpochCandidateV1{replay: replay, attachSlot: attach, epoch: epoch, streamSlot: streamSlot, sequence: sequence}, nil
	}
	if life.keyEpoch == math.MaxUint64 || epoch != life.keyEpoch+1 || life.rotation == "session_only" {
		if life.rotation == "session_only" {
			return receiveEpochCandidateV1{}, ErrKeyLifetimeExhausted
		}
		return receiveEpochCandidateV1{}, ErrRekeyFailed
	}
	if life.rotation != "message_lifetime_bound" && life.rotation != "profile_lifetime_bound" {
		return receiveEpochCandidateV1{}, ErrRekeyFailed
	}
	pending, err := security.RatchetKeyScheduleV1(*life.schedule)
	if err != nil || pending.Epoch != epoch {
		life.destroyScheduleLockedV1(&pending)
		return receiveEpochCandidateV1{}, ErrRekeyFailed
	}
	replay, err := security.NewReplayWindowV1(life.replayPolicy, int(life.config.ReplayWindowSize))
	if err != nil || replay.Plausible(sequence) != nil {
		life.destroyScheduleLockedV1(&pending)
		return receiveEpochCandidateV1{}, ErrRekeyFailed
	}
	return receiveEpochCandidateV1{
		replay: replay, pending: pending, next: true,
		attachSlot: life.nonceMode == security.NonceModeStreamPartitionedCounterV1,
		epoch:      epoch, streamSlot: streamSlot, sequence: sequence,
	}, nil
}

func (life *endpointLifecycleV1) receiveReplayCandidateLockedV1(streamSlot uint16) (*security.ReplayWindowV1, bool, error) {
	if life.nonceMode != security.NonceModeStreamPartitionedCounterV1 {
		if life.replay == nil {
			return nil, false, ErrRekeyFailed
		}
		return life.replay, false, nil
	}
	if replay := life.replayStreams[streamSlot]; replay != nil {
		return replay, false, nil
	}
	replay, err := security.NewReplayWindowV1(life.replayPolicy, int(life.config.ReplayWindowSize))
	if err != nil {
		return nil, false, ErrRekeyFailed
	}
	return replay, true, nil
}

func (life *endpointLifecycleV1) commitReceiveEpochLockedV1(candidate *receiveEpochCandidateV1) (security.KeySchedule, error) {
	if candidate == nil || candidate.replay == nil {
		return security.KeySchedule{}, ErrRekeyFailed
	}
	if candidate.next {
		if life.keyEpoch == math.MaxUint64 || candidate.pending.Epoch != life.keyEpoch+1 || candidate.epoch != candidate.pending.Epoch {
			return security.KeySchedule{}, ErrRekeyFailed
		}
		if (life.nonceMode == security.NonceModeStreamPartitionedCounterV1) != candidate.attachSlot {
			return security.KeySchedule{}, ErrRekeyFailed
		}
	} else if candidate.epoch != life.keyEpoch {
		return security.KeySchedule{}, ErrRekeyFailed
	} else if life.nonceMode == security.NonceModeStreamPartitionedCounterV1 {
		current := life.replayStreams[candidate.streamSlot]
		if (candidate.attachSlot && current != nil) || (!candidate.attachSlot && current != candidate.replay) {
			return security.KeySchedule{}, ErrRekeyFailed
		}
	} else if candidate.replay != life.replay || candidate.attachSlot {
		return security.KeySchedule{}, ErrRekeyFailed
	}
	commitReplay := life.commitReplay
	if commitReplay == nil || commitReplay(candidate.replay, candidate.sequence) != nil {
		return security.KeySchedule{}, ErrRekeyFailed
	}
	var oldSchedule security.KeySchedule
	if candidate.next {
		oldSchedule = *life.schedule
		*life.schedule = candidate.pending
		life.keyEpoch = candidate.pending.Epoch
		life.outSequence = 0
		life.outSequenceEnd = false
		life.outStreams = make(map[uint16]outboundSequenceStateV1)
		life.outKeyAttempts = 0
		life.inKeyAttempts = 0
		if life.nonceMode == security.NonceModeStreamPartitionedCounterV1 {
			life.replay = nil
			life.replayStreams = map[uint16]*security.ReplayWindowV1{candidate.streamSlot: candidate.replay}
		} else {
			life.replay = candidate.replay
			life.replayStreams = make(map[uint16]*security.ReplayWindowV1)
		}
		candidate.pending = security.KeySchedule{}
		candidate.next = false
	} else if candidate.attachSlot {
		life.replayStreams[candidate.streamSlot] = candidate.replay
	}
	life.inKeyAttempts++
	return oldSchedule, nil
}

func (life *endpointLifecycleV1) destroyPendingReceiveLockedV1(candidate *receiveEpochCandidateV1) {
	if candidate != nil && candidate.next {
		life.destroyScheduleLockedV1(&candidate.pending)
		candidate.pending = security.KeySchedule{}
		candidate.next = false
	}
}

func operationIDV1(th4 [32]byte, direction uint16, epoch uint64, streamSlot uint16, operationSequence uint64) [32]byte {
	var directionRaw, slotRaw [2]byte
	var epochRaw, sequenceRaw [8]byte
	binary.BigEndian.PutUint16(directionRaw[:], direction)
	binary.BigEndian.PutUint64(epochRaw[:], epoch)
	binary.BigEndian.PutUint16(slotRaw[:], streamSlot)
	binary.BigEndian.PutUint64(sequenceRaw[:], operationSequence)
	var input bytes.Buffer
	writeLifecycleLPV1(&input, []byte("kurdistan/operation/v1/id"))
	writeLifecycleLPV1(&input, th4[:])
	writeLifecycleLPV1(&input, directionRaw[:])
	writeLifecycleLPV1(&input, epochRaw[:])
	writeLifecycleLPV1(&input, slotRaw[:])
	writeLifecycleLPV1(&input, sequenceRaw[:])
	return sha256.Sum256(input.Bytes())
}

func writeLifecycleLPV1(out *bytes.Buffer, value []byte) {
	var length [4]byte
	binary.BigEndian.PutUint32(length[:], uint32(len(value)))
	out.Write(length[:])
	out.Write(value)
}

// commitPairProfileGenerationV1 commits the runtime profile transition and
// captures that exact generation on both role lifecycles as one critical
// section. The lock order is coordinator then profileMu.
func commitPairProfileGenerationV1(owner *HandshakeRuntime, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, profileID string, profileHash [32]byte) error {
	profile := pairProfileBindingV1{profileID: profileID, profileHash: profileHash}
	if !validHandshakeRuntimeIdentityV1(owner) || !validPairProfileBindingV1(profile) ||
		client == nil || relay == nil || client.state == nil || relay.state == nil ||
		client.state.coordinator == nil || client.state.coordinator != relay.state.coordinator ||
		client.state.life == nil || relay.state.life == nil {
		return ErrProfileRotationRequired
	}
	coordinator := client.state.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	clientLife := client.state.life
	relayLife := relay.state.life
	contextProfile, contextOK := authenticatedPairProfileBindingV1(coordinator.context, client.state.config, relay.state.config)
	if coordinator.closed || coordinator.owner != owner || coordinator.ownerTag != owner.instanceTag ||
		coordinator.runtimeEpoch != owner.epoch || coordinator.retiredProfile != profile || !contextOK || contextProfile != profile ||
		!pairRolesMatchProfileBindingLockedV1(client, relay, profile) ||
		!clientLife.validLockedV1() || !relayLife.validLockedV1() ||
		clientLife.role != lifecycleRoleClientV1 || relayLife.role != lifecycleRoleRelayV1 ||
		clientLife.state != auth.StateEstablished || relayLife.state != auth.StateAuthenticating ||
		clientLife.owner != owner || relayLife.owner != owner ||
		clientLife.runtimeEpoch != coordinator.runtimeEpoch || relayLife.runtimeEpoch != coordinator.runtimeEpoch {
		return ErrProfileRotationRequired
	}

	owner.profileMu.Lock()
	defer owner.profileMu.Unlock()
	if owner.profileOverflow ||
		(!owner.profileSeen && (owner.profileGeneration != 0 || owner.profileID != "" || !zeroRuntimeEpoch(owner.profileHash))) ||
		(owner.profileSeen && (!validPairProfileBindingV1(pairProfileBindingV1{profileID: owner.profileID, profileHash: owner.profileHash}))) {
		return ErrProfileRotationRequired
	}
	generation := owner.profileGeneration
	if !owner.profileSeen {
		owner.profileSeen = true
		owner.profileID = profile.profileID
		owner.profileHash = profile.profileHash
	} else if owner.profileID != profile.profileID || owner.profileHash != profile.profileHash {
		if owner.profileGeneration == math.MaxUint64 {
			// The overflow marker is the sole intentional failure-path mutation:
			// it permanently fails closed without advancing the generation,
			// rebinding the profile, or capturing either candidate lifecycle.
			owner.profileOverflow = true
			return ErrProfileRotationRequired
		}
		generation++
		owner.profileGeneration = generation
		owner.profileID = profile.profileID
		owner.profileHash = profile.profileHash
	}
	clientLife.generation = generation
	relayLife.generation = generation
	return nil
}

func strictPairOwnedByRuntimeV1(owner *HandshakeRuntime, client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) bool {
	if !validHandshakeRuntimeIdentityV1(owner) || client == nil || relay == nil || client.state == nil || relay.state == nil ||
		client.state.coordinator == nil || client.state.coordinator != relay.state.coordinator ||
		client.state.life == nil || relay.state.life == nil {
		return false
	}
	coordinator := client.state.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	clientLife := client.state.life
	relayLife := relay.state.life
	return !coordinator.closed && coordinator.owner == owner && coordinator.ownerTag == owner.instanceTag && clientLife.validLockedV1() && relayLife.validLockedV1() &&
		clientLife.role == lifecycleRoleClientV1 && relayLife.role == lifecycleRoleRelayV1 &&
		clientLife.owner == owner && relayLife.owner == owner &&
		clientLife.runtimeEpoch == owner.epoch && relayLife.runtimeEpoch == owner.epoch
}

func closeEndpointPairV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) {
	if client != nil {
		client.Close()
	}
	if relay != nil {
		relay.Close()
	}
}
