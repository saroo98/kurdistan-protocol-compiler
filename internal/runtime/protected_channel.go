// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"errors"
	"sort"
	"sync"
	"sync/atomic"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/runtime/labfault"
)

// strictProtectedChannelV1 is a local-only composition over one configured,
// runtime-owned authenticated pair. It exposes complete protected records to
// its transport seam and never exposes a codec, key, nonce, or prepared replay
// capability.
type strictProtectedChannelV1 struct {
	mu sync.Mutex

	client  *ClientAuthenticatedEndpointV1
	relay   *RelayAuthenticatedEndpointV1
	context security.EnvelopeContextV1
	control ControlContextV1

	clientEnvelope *security.EnvelopeCodecV1
	relayEnvelope  *security.EnvelopeCodecV1
	clientEpoch    uint64
	relayEpoch     uint64

	observer             *strictNonceObserverV1
	clientKey, relayKey  uint64
	afterSeal            func() error // package-private deterministic burn-after-seal test seam
	beforePublish        func()       // package-private close/restart publication test seam
	beforeFragmentCommit func()       // package-private prepared replay race test seam
	reassembly           *strictFragmentReassemblyV1
	labReusedNonce       bool
	labAcceptsReplay     bool
	labSealCount         uint64
	labFirstNonce        strictNonceObservationV1
}

func (channel *strictProtectedChannelV1) retainedPolicyTupleV1() policyMatrixTupleV1 {
	if channel == nil {
		return policyMatrixTupleV1{}
	}
	policy := channel.context.EffectivePolicy
	return policyMatrixTupleFromPolicyV1(irSecurityPolicyProjectionV1(policy))
}

func irSecurityPolicyProjectionV1(policy ir.EffectiveSecurityPolicy) ir.SecurityPolicy {
	return ir.SecurityPolicy{TranscriptMode: policy.TranscriptMode, NonceMode: policy.NonceMode, ReplayPolicy: policy.ReplayPolicy,
		ReplayWindowSize: policy.ReplayWindowSize, DowngradePolicy: policy.DowngradePolicy,
		CapabilityNegotiationPolicy: policy.CapabilityNegotiationPolicy, ProfileCompatibilityPolicy: policy.ProfileCompatibilityPolicy,
		KeyRotationPolicy: policy.KeyRotationPolicy, ConfigValidationPolicy: policy.ConfigValidationPolicy,
		SecureEnvelopeMode: policy.SecureEnvelopeMode, MaxSessionMessages: policy.MaxSessionMessages, MaxKeyLifetimeMessages: policy.MaxKeyLifetimeMessages}
}

const (
	strictFragmentMaxOperationsV1 = 8
	strictFragmentMaxCountV1      = 16
	strictFragmentLifetimeTicksV1 = 32
)

type strictFragmentReassemblyV1 struct {
	mu           sync.Mutex
	entries      map[[32]byte]*strictFragmentEntryV1
	pendingBytes uint64
	tick         uint64
	tickStep     uint64
	maxBytes     uint64
	maxOperation uint32
	destroyed    bool
}

type strictFragmentEntryV1 struct {
	operationID [32]byte
	streamSlot  uint16
	direction   uint16
	epoch       uint64
	count       uint16
	length      uint32
	createdTick uint64
	fragments   map[uint16]strictStoredFragmentV1
	finalizing  bool
}

type strictStoredFragmentV1 struct {
	offset uint32
	data   []byte
}

type strictNonceObservationV1 struct {
	key      uint64
	class    uint8
	epoch    uint64
	slot     uint16
	sequence uint64
}

type strictNonceObserverV1 struct {
	mu         sync.Mutex
	seen       map[strictNonceObservationV1]struct{}
	domains    map[uint8]struct{}
	collisions uint64
}

type strictNonceObservationSummaryV1 struct {
	Domains, Allocations int
	Collisions           uint64
}

func newStrictProtectedChannelV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1) (*strictProtectedChannelV1, error) {
	return newStrictProtectedChannelWithObserverV1(client, relay, nil)
}

func newStrictProtectedChannelWithLabFaultV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, token labfault.Token) (*strictProtectedChannelV1, error) {
	channel, err := newStrictProtectedChannelWithObserverV1(client, relay, nil)
	if err != nil {
		return nil, err
	}
	reused, _ := labfault.NewTokenV1("reused_nonce")
	securityReplay, _ := labfault.NewTokenV1("accepts_replay")
	runtimeReplay, _ := labfault.NewTokenV1("runtime_accepts_replay")
	noState, _ := labfault.NewTokenV1("runtime_no_state_validation")
	switch token {
	case reused:
		channel.labReusedNonce = true
	case securityReplay:
		channel.labAcceptsReplay = true
	case runtimeReplay:
		channel.client.state.life.labAcceptCompleted = true
		channel.relay.state.life.labAcceptCompleted = true
	case noState:
		channel.client.state.life.labSkipStateValidation = true
	default:
		channel.client.Close()
		channel.relay.Close()
		return nil, ErrSecureChannel
	}
	return channel, nil
}

var strictProtectedChannelOrdinalV1 atomic.Uint64

func newStrictProtectedChannelWithObserverV1(client *ClientAuthenticatedEndpointV1, relay *RelayAuthenticatedEndpointV1, observer *strictNonceObserverV1) (*strictProtectedChannelV1, error) {
	if client == nil || relay == nil || client.state == nil || relay.state == nil || client.state.coordinator == nil ||
		client.state.coordinator != relay.state.coordinator || client.state.life == nil || relay.state.life == nil {
		return nil, ErrSecureChannel
	}
	coordinator := client.state.coordinator
	coordinator.mu.Lock()
	defer coordinator.mu.Unlock()
	if coordinator.closed || !client.state.life.validStrictCandidateLockedV1() || !relay.state.life.validStrictCandidateLockedV1() ||
		client.state.life.role != lifecycleRoleClientV1 || relay.state.life.role != lifecycleRoleRelayV1 ||
		client.state.life.owner != relay.state.life.owner || client.state.life.runtimeEpoch != relay.state.life.runtimeEpoch {
		return nil, ErrSecureChannel
	}
	snapshot := cloneAuthenticatedContextSnapshotV1(coordinator.context)
	context := security.EnvelopeContextV1{
		EffectivePolicy: snapshot.EffectivePolicy, MaxEnvelopeBytes: client.state.config.MaxEnvelopeBytes,
		EffectivePolicyHash: snapshot.EffectivePolicyHash, TranscriptHash: snapshot.TranscriptHash,
		CapabilityHash: snapshot.SelectedCapabilityHash, ProfileHash: snapshot.ClientProfileHash,
		FramingHash: snapshot.ClientModeBinding.FramingPolicyHash, CarrierContextHash: snapshot.ClientModeBinding.CarrierContextHash,
	}
	clientEnvelope, err := security.NewClientEnvelopeV1(client.state.schedule, context)
	if err != nil {
		return nil, err
	}
	relayEnvelope, err := security.NewRelayEnvelopeV1(relay.state.schedule, context)
	if err != nil {
		return nil, err
	}
	if observer == nil {
		observer = &strictNonceObserverV1{seen: make(map[strictNonceObservationV1]struct{}), domains: make(map[uint8]struct{})}
	}
	ordinal := strictProtectedChannelOrdinalV1.Add(1) * 2
	reassembly := &strictFragmentReassemblyV1{
		entries: make(map[[32]byte]*strictFragmentEntryV1), tickStep: 1,
		maxBytes:     uint64(client.state.config.MaxFrameBytes) * strictFragmentMaxOperationsV1,
		maxOperation: client.state.config.MaxFrameBytes,
	}
	channel := &strictProtectedChannelV1{
		client: client, relay: relay, context: context,
		control:        ControlContextV1{EffectivePolicyHash: snapshot.EffectivePolicyHash, TH4: snapshot.TranscriptHash},
		clientEnvelope: clientEnvelope, relayEnvelope: relayEnvelope,
		clientEpoch: client.state.schedule.Epoch, relayEpoch: relay.state.schedule.Epoch,
		observer: observer, clientKey: ordinal - 1, relayKey: ordinal, reassembly: reassembly,
	}
	previousDestroy := coordinator.destroy
	coordinator.destroy = func() {
		if previousDestroy != nil {
			previousDestroy()
		}
		reassembly.destroyV1()
	}
	return channel, nil
}

func (state *strictFragmentReassemblyV1) destroyV1() {
	if state == nil {
		return
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	for id, entry := range state.entries {
		clearStrictFragmentEntryV1(entry)
		delete(state.entries, id)
	}
	state.pendingBytes = 0
	state.destroyed = true
}

func clearStrictFragmentEntryV1(entry *strictFragmentEntryV1) {
	if entry == nil {
		return
	}
	for index, fragment := range entry.fragments {
		clear(fragment.data)
		delete(entry.fragments, index)
	}
}

func (channel *strictProtectedChannelV1) rejectAfterSealV1(envelope security.EnvelopeRecordV1, err error) (security.EnvelopeRecordV1, error) {
	if err != nil || channel.afterSeal == nil {
		return envelope, err
	}
	if failure := channel.afterSeal(); failure != nil {
		clear(envelope.Ciphertext)
		return security.EnvelopeRecordV1{}, security.ErrAEADInvalid
	}
	return envelope, nil
}

func (channel *strictProtectedChannelV1) observeAllocationV1(key uint64, class uint8, epoch uint64, slot uint16, sequence uint64) {
	if channel.labReusedNonce && class == 1 {
		channel.labSealCount++
		if channel.labSealCount == 1 {
			channel.labFirstNonce = strictNonceObservationV1{key: key, class: class, epoch: epoch, slot: slot, sequence: sequence}
		} else if channel.labSealCount == 2 {
			key, class, epoch, slot, sequence = channel.labFirstNonce.key, channel.labFirstNonce.class, channel.labFirstNonce.epoch, channel.labFirstNonce.slot, channel.labFirstNonce.sequence
		}
	}
	channel.observer.mu.Lock()
	defer channel.observer.mu.Unlock()
	value := strictNonceObservationV1{key: key, class: class, epoch: epoch, slot: slot, sequence: sequence}
	if _, exists := channel.observer.seen[value]; exists {
		channel.observer.collisions++
	} else {
		channel.observer.seen[value] = struct{}{}
	}
	channel.observer.domains[class] = struct{}{}
}

func (channel *strictProtectedChannelV1) nonceSummaryV1() strictNonceObservationSummaryV1 {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	channel.observer.mu.Lock()
	defer channel.observer.mu.Unlock()
	return strictNonceObservationSummaryV1{Domains: len(channel.observer.domains), Allocations: len(channel.observer.seen), Collisions: channel.observer.collisions}
}

func (channel *strictProtectedChannelV1) guardOpenV1(life *endpointLifecycleV1) error {
	if life == nil || !life.lockV1() {
		return ErrSecureChannel
	}
	coordinator := life.coordinator
	if !life.validStrictCandidateLockedV1() || coordinator.closed {
		coordinator.mu.Unlock()
		return ErrSecureChannel
	}
	if err := life.profileGenerationValueLockedV1(); err != nil {
		coordinator.closeLockedV1()
		coordinator.mu.Unlock()
		return ErrProfileRotationRequired
	}
	coordinator.mu.Unlock()
	return nil
}

func (channel *strictProtectedChannelV1) publishRecordV1(life *endpointLifecycleV1, record []byte) ([]byte, error) {
	if channel.beforePublish != nil {
		channel.beforePublish()
	}
	if life == nil || !life.lockV1() {
		clear(record)
		return nil, ErrSecureChannel
	}
	coordinator := life.coordinator
	if !life.validStrictCandidateLockedV1() || coordinator.closed || life.state != auth.StateEstablished {
		coordinator.mu.Unlock()
		clear(record)
		return nil, ErrSecureChannel
	}
	if err := life.profileGenerationValueLockedV1(); err != nil {
		coordinator.closeLockedV1()
		coordinator.mu.Unlock()
		clear(record)
		return nil, ErrProfileRotationRequired
	}
	coordinator.mu.Unlock()
	return record, nil
}

func (channel *strictProtectedChannelV1) ensureEnvelopeForLifeV1(life *endpointLifecycleV1, clientRole bool) (uint64, error) {
	if life == nil || !life.lockV1() {
		return 0, ErrSecureChannel
	}
	defer life.coordinator.mu.Unlock()
	if !life.validStrictCandidateLockedV1() || life.coordinator.closed || life.schedule == nil {
		return 0, ErrSecureChannel
	}
	if clientRole {
		return life.schedule.Epoch, channel.ensureClientEnvelopeV1(*life.schedule)
	}
	return life.schedule.Epoch, channel.ensureRelayEnvelopeV1(*life.schedule)
}

func (channel *strictProtectedChannelV1) ensureClientEnvelopeV1(schedule security.KeySchedule) error {
	if channel.clientEnvelope != nil && channel.clientEpoch == schedule.Epoch {
		return nil
	}
	codec, err := security.NewClientEnvelopeV1(schedule, channel.context)
	if err != nil {
		return err
	}
	channel.clientEnvelope, channel.clientEpoch = codec, schedule.Epoch
	return nil
}

func (channel *strictProtectedChannelV1) ensureRelayEnvelopeV1(schedule security.KeySchedule) error {
	if channel.relayEnvelope != nil && channel.relayEpoch == schedule.Epoch {
		return nil
	}
	codec, err := security.NewRelayEnvelopeV1(schedule, channel.context)
	if err != nil {
		return err
	}
	channel.relayEnvelope, channel.relayEpoch = codec, schedule.Epoch
	return nil
}

func (channel *strictProtectedChannelV1) sealClientApplicationV1(slot uint16, plaintext []byte) ([]byte, [32]byte, error) {
	return channel.sealApplicationV1(true, slot, plaintext, nil)
}

func (channel *strictProtectedChannelV1) sealClientMultiFragmentV1(slot uint16, plaintext []byte, fragmentLengths []uint32) ([][]byte, [32]byte, error) {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	if len(fragmentLengths) < 2 || len(fragmentLengths) > strictFragmentMaxCountV1 || len(plaintext) == 0 || uint64(len(plaintext)) > uint64(channel.reassembly.maxOperation) {
		return nil, [32]byte{}, ErrRecordInvalid
	}
	var total uint64
	for _, length := range fragmentLengths {
		if length == 0 {
			return nil, [32]byte{}, ErrRecordInvalid
		}
		total += uint64(length)
	}
	if total != uint64(len(plaintext)) {
		return nil, [32]byte{}, ErrRecordInvalid
	}
	life := channel.client.state.life
	if err := canReserveFragmentSetV1(life, slot, len(fragmentLengths)); err != nil {
		return nil, [32]byte{}, err
	}
	first, err := life.beginOperationV1(slot)
	if err != nil {
		return nil, [32]byte{}, err
	}
	records := make([][]byte, 0, len(fragmentLengths))
	offset := uint32(0)
	for index, length := range fragmentLengths {
		transmission := first
		if index > 0 {
			transmission, err = channel.reserveAdditionalFragmentV1(life, first.operationID)
			if err != nil {
				for _, record := range records {
					clear(record)
				}
				return nil, first.operationID, err
			}
		}
		fragment := ApplicationFragmentV1{
			OperationID: first.operationID, FragmentIndex: uint16(index), FragmentCount: uint16(len(fragmentLengths)),
			OperationLength: uint32(len(plaintext)), FragmentOffset: offset,
			Fragment: append([]byte(nil), plaintext[offset:offset+length]...),
		}
		record, err := channel.sealPreparedApplicationFragmentLockedV1(true, life, transmission, fragment)
		clear(fragment.Fragment)
		if err != nil {
			for _, sealed := range records {
				clear(sealed)
			}
			return nil, first.operationID, err
		}
		records = append(records, record)
		offset += length
	}
	return records, first.operationID, nil
}

func canReserveFragmentSetV1(life *endpointLifecycleV1, streamSlot uint16, count int) error {
	if life == nil || count < 2 || !life.lockV1() {
		return ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if err := life.readyLockedV1(); err != nil {
		return err
	}
	streamEnded := life.nonceMode == security.NonceModeStreamPartitionedCounterV1 && life.outStreams[streamSlot].ended
	remaining := uint64(0)
	if life.outKeyAttempts >= life.config.MaxKeyLifetimeMessages || life.outSequenceEnd || streamEnded {
		remaining = uint64(life.config.MaxKeyLifetimeMessages)
	} else {
		remaining = uint64(life.config.MaxKeyLifetimeMessages - life.outKeyAttempts)
	}
	if uint64(count) > remaining {
		return ErrRecordInvalid
	}
	return nil
}

func (channel *strictProtectedChannelV1) reserveAdditionalFragmentV1(life *endpointLifecycleV1, operationID [32]byte) (operationTransmissionV1, error) {
	if !life.lockV1() {
		return operationTransmissionV1{}, ErrLifecycle
	}
	defer life.coordinator.mu.Unlock()
	if err := life.readyLockedV1(); err != nil {
		return operationTransmissionV1{}, err
	}
	operation := life.outstanding[operationID]
	if operation == nil || operation.id != operationID || operation.streamSlot == 0 {
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
	epoch, sequence, oldSchedule, err := life.commitOutboundRecordLockedV1(operation.streamSlot, &candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return operationTransmissionV1{}, life.failLockedV1(err)
	}
	transmission := life.operationTransmissionLockedV1(operation, epoch, sequence)
	life.issuedOperations[operationReservationKeyV1(transmission)] = transmission
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return transmission, nil
}

func (channel *strictProtectedChannelV1) sealPreparedApplicationFragmentLockedV1(client bool, life *endpointLifecycleV1, transmission operationTransmissionV1, fragment ApplicationFragmentV1) ([]byte, error) {
	key := channel.clientKey
	if !client {
		key = channel.relayKey
	}
	channel.observeAllocationV1(key, 1, transmission.recordEpoch, transmission.streamSlot, transmission.recordSequence)
	if client {
		if _, err := channel.ensureEnvelopeForLifeV1(life, true); err != nil {
			return nil, err
		}
		record, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(channel.context, transmission.streamSlot, fragment, func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
			envelope, err := channel.clientEnvelope.SealApplicationV1(slot, body)
			envelope, err = channel.rejectAfterSealV1(envelope, err)
			if err == nil && (envelope.Epoch != transmission.recordEpoch || envelope.Sequence != transmission.recordSequence) {
				clear(envelope.Ciphertext)
				return security.EnvelopeRecordV1{}, security.ErrNonceMismatch
			}
			return envelope, err
		})
		if err != nil {
			return nil, err
		}
		return channel.publishRecordV1(life, record)
	}
	if _, err := channel.ensureEnvelopeForLifeV1(life, false); err != nil {
		return nil, err
	}
	record, err := (RelayApplicationCodecV1{}).SealApplicationFragmentV1(channel.context, transmission.streamSlot, fragment, func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
		envelope, err := channel.relayEnvelope.SealApplicationV1(slot, body)
		envelope, err = channel.rejectAfterSealV1(envelope, err)
		if err == nil && (envelope.Epoch != transmission.recordEpoch || envelope.Sequence != transmission.recordSequence) {
			clear(envelope.Ciphertext)
			return security.EnvelopeRecordV1{}, security.ErrNonceMismatch
		}
		return envelope, err
	})
	if err != nil {
		return nil, err
	}
	return channel.publishRecordV1(life, record)
}

func (channel *strictProtectedChannelV1) sealRelayApplicationV1(slot uint16, plaintext []byte) ([]byte, [32]byte, error) {
	return channel.sealApplicationV1(false, slot, plaintext, nil)
}

func (channel *strictProtectedChannelV1) retryClientApplicationV1(operationID [32]byte, plaintext []byte) ([]byte, error) {
	record, _, err := channel.sealApplicationV1(true, 0, plaintext, &operationID)
	return record, err
}

func (channel *strictProtectedChannelV1) sealApplicationV1(client bool, slot uint16, plaintext []byte, retry *[32]byte) ([]byte, [32]byte, error) {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	if len(plaintext) == 0 || uint64(len(plaintext)) > uint64(^uint32(0)) {
		return nil, [32]byte{}, ErrRecordInvalid
	}
	var life *endpointLifecycleV1
	if client {
		life = channel.client.state.life
	} else {
		life = channel.relay.state.life
	}
	var transmission operationTransmissionV1
	var err error
	if retry == nil {
		transmission, err = life.beginOperationV1(slot)
	} else {
		transmission, err = life.retryOperationV1(*retry)
	}
	if err != nil {
		return nil, [32]byte{}, err
	}
	if retry != nil && transmission.streamSlot == 0 {
		return nil, [32]byte{}, ErrRecordInvalid
	}
	var labEnvelope *security.EnvelopeCodecV1
	if channel.labReusedNonce && channel.labSealCount == 1 && channel.labFirstNonce.key == channel.clientKey && client {
		transmission, err = life.labReuseIssuedCoordinatesV1(transmission, channel.labFirstNonce.epoch, channel.labFirstNonce.slot, channel.labFirstNonce.sequence)
		if err != nil {
			return nil, [32]byte{}, err
		}
		labEnvelope, err = security.NewClientEnvelopeV1(*life.schedule, channel.context)
		if err != nil {
			return nil, [32]byte{}, err
		}
	} else if channel.labReusedNonce && channel.labSealCount == 1 && channel.labFirstNonce.key == channel.relayKey && !client {
		transmission, err = life.labReuseIssuedCoordinatesV1(transmission, channel.labFirstNonce.epoch, channel.labFirstNonce.slot, channel.labFirstNonce.sequence)
		if err != nil {
			return nil, [32]byte{}, err
		}
		labEnvelope, err = security.NewRelayEnvelopeV1(*life.schedule, channel.context)
		if err != nil {
			return nil, [32]byte{}, err
		}
	}
	fragment := ApplicationFragmentV1{OperationID: transmission.operationID, FragmentCount: 1, OperationLength: uint32(len(plaintext)), Fragment: append([]byte(nil), plaintext...)}
	defer clear(fragment.Fragment)
	key := channel.clientKey
	if !client {
		key = channel.relayKey
	}
	channel.observeAllocationV1(key, 1, transmission.recordEpoch, transmission.streamSlot, transmission.recordSequence)
	if client {
		if _, err := channel.ensureEnvelopeForLifeV1(life, true); err != nil {
			return nil, [32]byte{}, err
		}
		sealEnvelope := channel.clientEnvelope
		if labEnvelope != nil {
			sealEnvelope = labEnvelope
		}
		record, err := (ClientApplicationCodecV1{}).SealApplicationFragmentV1(channel.context, transmission.streamSlot, fragment, func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
			envelope, err := sealEnvelope.SealApplicationV1(slot, body)
			envelope, err = channel.rejectAfterSealV1(envelope, err)
			if err == nil && (envelope.Epoch != transmission.recordEpoch || envelope.Sequence != transmission.recordSequence) {
				clear(envelope.Ciphertext)
				return security.EnvelopeRecordV1{}, security.ErrNonceMismatch
			}
			return envelope, err
		})
		if err != nil {
			return nil, transmission.operationID, err
		}
		record, err = channel.publishRecordV1(life, record)
		return record, transmission.operationID, err
	}
	if _, err := channel.ensureEnvelopeForLifeV1(life, false); err != nil {
		return nil, [32]byte{}, err
	}
	sealEnvelope := channel.relayEnvelope
	if labEnvelope != nil {
		sealEnvelope = labEnvelope
	}
	record, err := (RelayApplicationCodecV1{}).SealApplicationFragmentV1(channel.context, transmission.streamSlot, fragment, func(slot uint16, body []byte) (security.EnvelopeRecordV1, error) {
		envelope, err := sealEnvelope.SealApplicationV1(slot, body)
		envelope, err = channel.rejectAfterSealV1(envelope, err)
		if err == nil && (envelope.Epoch != transmission.recordEpoch || envelope.Sequence != transmission.recordSequence) {
			clear(envelope.Ciphertext)
			return security.EnvelopeRecordV1{}, security.ErrNonceMismatch
		}
		return envelope, err
	})
	if err != nil {
		return nil, transmission.operationID, err
	}
	record, err = channel.publishRecordV1(life, record)
	return record, transmission.operationID, err
}

func (channel *strictProtectedChannelV1) openClientApplicationV1(record []byte) ([]byte, OperationAckV1, error) {
	return channel.openApplicationV1(true, record)
}

func (channel *strictProtectedChannelV1) openRelayApplicationV1(record []byte) ([]byte, OperationAckV1, error) {
	return channel.openApplicationV1(false, record)
}

func (channel *strictProtectedChannelV1) openApplicationV1(fromClient bool, record []byte) ([]byte, OperationAckV1, error) {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	var sender, receiver *endpointLifecycleV1
	var codec *security.EnvelopeCodecV1
	if fromClient {
		sender, receiver = channel.client.state.life, channel.relay.state.life
	} else {
		sender, receiver = channel.relay.state.life, channel.client.state.life
	}
	if err := channel.guardOpenV1(receiver); err != nil {
		return nil, OperationAckV1{}, err
	}
	expectedDirection := applicationDirectionRelayV1
	if fromClient {
		expectedDirection = applicationDirectionClientV1
	}
	header, _, err := parseApplicationRecordV1(record, expectedDirection, channel.context.MaxEnvelopeBytes)
	if err != nil {
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	if fromClient {
		if _, err := channel.ensureEnvelopeForLifeV1(sender, false); err != nil {
			return nil, OperationAckV1{}, err
		}
		codec = channel.relayEnvelope
	} else {
		if _, err := channel.ensureEnvelopeForLifeV1(sender, true); err != nil {
			return nil, OperationAckV1{}, err
		}
		codec = channel.clientEnvelope
	}
	var capability security.AuthenticatedReplayV1
	var authenticated bool
	var authErr error
	open := func(envelope security.EnvelopeRecordV1) ([]byte, error) {
		body, prepared, err := codec.AuthenticateApplicationV1(envelope)
		if err != nil {
			authErr = err
			return nil, err
		}
		capability, authenticated = prepared, true
		return body, nil
	}
	var fragment ApplicationFragmentV1
	if fromClient {
		fragment, err = (RelayApplicationCodecV1{}).OpenApplicationFragmentV1(channel.context, record, open)
	} else {
		fragment, err = (ClientApplicationCodecV1{}).OpenApplicationFragmentV1(channel.context, record, open)
	}
	if err != nil {
		if authenticated {
			_ = capability.Discard()
		}
		if authErr != nil {
			return nil, OperationAckV1{}, authErr
		}
		return nil, OperationAckV1{}, err
	}
	defer clear(fragment.Fragment)
	transmission, ok := lookupIssuedOperationV1(sender, header.StreamSlot, header.Epoch, header.Sequence)
	if !ok || transmission.operationID != fragment.OperationID {
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	if fragment.FragmentCount != 1 {
		return channel.acceptMultiFragmentV1(receiver, transmission, header, fragment, capability)
	}
	if fragment.FragmentIndex != 0 || fragment.FragmentOffset != 0 || uint32(len(fragment.Fragment)) != fragment.OperationLength {
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	commit := capability.Commit
	if channel.labAcceptsReplay {
		commit = capability.Discard
	}
	ack, err := receiver.commitFirstAuthenticatedOperationV1(transmission, commit)
	if err != nil {
		_ = capability.Discard()
		return nil, OperationAckV1{}, err
	}
	if !receiver.lastCommitDeliver && !channel.labAcceptsReplay {
		return nil, ack, nil
	}
	return append([]byte(nil), fragment.Fragment...), ack, nil
}

func (channel *strictProtectedChannelV1) acceptMultiFragmentV1(receiver *endpointLifecycleV1, transmission operationTransmissionV1, header ApplicationHeaderV1, fragment ApplicationFragmentV1, capability security.AuthenticatedReplayV1) ([]byte, OperationAckV1, error) {
	state := channel.reassembly
	if state == nil {
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	state.mu.Lock()
	state.expireLockedV1()
	if state.destroyed || fragment.FragmentCount < 2 || fragment.FragmentCount > strictFragmentMaxCountV1 ||
		fragment.FragmentIndex >= fragment.FragmentCount || fragment.OperationLength == 0 || fragment.OperationLength > state.maxOperation || len(fragment.Fragment) == 0 {
		state.mu.Unlock()
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	entry := state.entries[fragment.OperationID]
	newEntry := entry == nil
	if newEntry {
		if len(state.entries) >= strictFragmentMaxOperationsV1 || state.pendingBytes+uint64(fragment.OperationLength) > state.maxBytes {
			state.mu.Unlock()
			_ = capability.Discard()
			return nil, OperationAckV1{}, ErrRecordInvalid
		}
		entry = &strictFragmentEntryV1{
			operationID: fragment.OperationID, streamSlot: header.StreamSlot, direction: header.Direction, epoch: header.Epoch,
			count: fragment.FragmentCount, length: fragment.OperationLength, createdTick: state.tick,
			fragments: make(map[uint16]strictStoredFragmentV1, fragment.FragmentCount),
		}
	} else if entry.streamSlot != header.StreamSlot || entry.direction != header.Direction || entry.epoch != header.Epoch ||
		entry.count != fragment.FragmentCount || entry.length != fragment.OperationLength {
		state.mu.Unlock()
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	if entry.finalizing {
		state.mu.Unlock()
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	if _, duplicate := entry.fragments[fragment.FragmentIndex]; duplicate {
		state.mu.Unlock()
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	currentStart := uint64(fragment.FragmentOffset)
	currentEnd := currentStart + uint64(len(fragment.Fragment))
	if currentEnd > uint64(fragment.OperationLength) {
		state.mu.Unlock()
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	for _, stored := range entry.fragments {
		start, end := uint64(stored.offset), uint64(stored.offset)+uint64(len(stored.data))
		if currentStart < end && start < currentEnd {
			state.mu.Unlock()
			_ = capability.Discard()
			return nil, OperationAckV1{}, ErrRecordInvalid
		}
	}
	prepared := strictStoredFragmentV1{offset: fragment.FragmentOffset, data: append([]byte(nil), fragment.Fragment...)}
	complete := len(entry.fragments)+1 == int(entry.count)
	if len(entry.fragments)+1 > int(entry.count) {
		clear(prepared.data)
		state.mu.Unlock()
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	if !complete {
		if channel.beforeFragmentCommit != nil {
			channel.beforeFragmentCommit()
		}
		if err := capability.Commit(); err != nil {
			clear(prepared.data)
			state.mu.Unlock()
			return nil, OperationAckV1{}, err
		}
		if newEntry {
			state.entries[fragment.OperationID] = entry
			state.pendingBytes += uint64(entry.length)
		}
		entry.fragments[fragment.FragmentIndex] = prepared
		state.advanceTickLockedV1()
		state.mu.Unlock()
		return nil, OperationAckV1{}, nil
	}
	assembled, valid := assembleStrictFragmentsV1(entry, fragment.FragmentIndex, prepared)
	if valid {
		entry.finalizing = true
	}
	state.mu.Unlock()
	if !valid {
		clear(prepared.data)
		_ = capability.Discard()
		return nil, OperationAckV1{}, ErrRecordInvalid
	}
	if channel.beforeFragmentCommit != nil {
		channel.beforeFragmentCommit()
	}
	commitFinal := func() error {
		if err := capability.Commit(); err != nil {
			return err
		}
		state.mu.Lock()
		delete(state.entries, fragment.OperationID)
		state.pendingBytes -= uint64(entry.length)
		clearStrictFragmentEntryV1(entry)
		state.advanceTickLockedV1()
		state.mu.Unlock()
		return nil
	}
	ack, err := receiver.commitFirstAuthenticatedOperationV1(transmission, commitFinal)
	if err != nil {
		state.mu.Lock()
		if state.entries[fragment.OperationID] == entry {
			entry.finalizing = false
		}
		state.mu.Unlock()
		clear(prepared.data)
		clear(assembled)
		_ = capability.Discard()
		return nil, OperationAckV1{}, err
	}
	if !receiver.lastCommitDeliver {
		return nil, ack, nil
	}
	clear(prepared.data)
	return assembled, ack, nil
}

func assembleStrictFragmentsV1(entry *strictFragmentEntryV1, finalIndex uint16, final strictStoredFragmentV1) ([]byte, bool) {
	if entry == nil || len(entry.fragments)+1 != int(entry.count) {
		return nil, false
	}
	type interval struct {
		index  uint16
		offset uint32
		data   []byte
	}
	intervals := make([]interval, 0, entry.count)
	for index, fragment := range entry.fragments {
		intervals = append(intervals, interval{index: index, offset: fragment.offset, data: fragment.data})
	}
	intervals = append(intervals, interval{index: finalIndex, offset: final.offset, data: final.data})
	sort.Slice(intervals, func(i, j int) bool { return intervals[i].offset < intervals[j].offset })
	assembled := make([]byte, entry.length)
	var next uint64
	seen := make(map[uint16]struct{}, entry.count)
	for _, part := range intervals {
		if _, exists := seen[part.index]; exists || uint64(part.offset) != next {
			clear(assembled)
			return nil, false
		}
		seen[part.index] = struct{}{}
		end := uint64(part.offset) + uint64(len(part.data))
		if end > uint64(entry.length) {
			clear(assembled)
			return nil, false
		}
		copy(assembled[part.offset:uint32(end)], part.data)
		next = end
	}
	if next != uint64(entry.length) || len(seen) != int(entry.count) {
		clear(assembled)
		return nil, false
	}
	return assembled, true
}

func (state *strictFragmentReassemblyV1) advanceTickLockedV1() {
	step := state.tickStep
	if step == 0 {
		step = 1
	}
	state.tick += step
}

func (state *strictFragmentReassemblyV1) expireLockedV1() {
	for id, entry := range state.entries {
		if !entry.finalizing && state.tick-entry.createdTick >= strictFragmentLifetimeTicksV1 {
			state.pendingBytes -= uint64(entry.length)
			clearStrictFragmentEntryV1(entry)
			delete(state.entries, id)
		}
	}
}

func lookupIssuedOperationV1(sender *endpointLifecycleV1, slot uint16, epoch, sequence uint64) (operationTransmissionV1, bool) {
	if sender == nil || !sender.lockV1() {
		return operationTransmissionV1{}, false
	}
	defer sender.coordinator.mu.Unlock()
	if !sender.validStrictCandidateLockedV1() || sender.coordinator.closed {
		return operationTransmissionV1{}, false
	}
	value, ok := sender.issuedOperations[recordReservationKeyV1{streamSlot: slot, epoch: epoch, sequence: sequence}]
	return value, ok
}

func (channel *strictProtectedChannelV1) sealRelayAckV1(operationID [32]byte, retry bool) ([]byte, error) {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	life := channel.relay.state.life
	var transmission acknowledgementTransmissionV1
	var err error
	if retry {
		transmission, err = life.retryOperationAckV1(operationID)
	} else {
		transmission, err = life.beginOperationAckV1(operationID)
	}
	if err != nil {
		return nil, err
	}
	if _, err := channel.ensureEnvelopeForLifeV1(life, false); err != nil {
		return nil, err
	}
	channel.observeAllocationV1(channel.relayKey, 2, transmission.recordEpoch, 0, transmission.recordSequence)
	record, err := (RelayControlCodecV1{}).SealOperationAckV1(channel.control, transmission.recordEpoch, transmission.recordSequence, transmission.ack, func(epoch, sequence uint64, body, aad []byte) ([]byte, error) {
		envelope, err := channel.relayEnvelope.SealControlV1(RecordTypeOperationAckV1, body, aad)
		envelope, err = channel.rejectAfterSealV1(envelope, err)
		if err != nil {
			return nil, err
		}
		if envelope.Epoch != epoch || envelope.Sequence != sequence || envelope.Direction != controlDirectionRelayV1 {
			clear(envelope.Ciphertext)
			return nil, security.ErrNonceMismatch
		}
		return envelope.Ciphertext, nil
	})
	if err != nil {
		return nil, err
	}
	return channel.publishRecordV1(life, record)
}

func (channel *strictProtectedChannelV1) openRelayAckV1(record []byte) error {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	sender, receiver := channel.relay.state.life, channel.client.state.life
	if err := channel.guardOpenV1(receiver); err != nil {
		return err
	}
	header, _, err := parseControlRecordV1(record, controlDirectionRelayV1, RecordTypeOperationAckV1)
	if err != nil {
		return ErrOperationAckInvalid
	}
	if _, err := channel.ensureEnvelopeForLifeV1(sender, true); err != nil {
		return err
	}
	var capability security.AuthenticatedReplayV1
	var authenticated bool
	var authErr error
	ack, err := (ClientControlCodecV1{}).OpenOperationAckV1(channel.control, record, func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error) {
		envelope := security.EnvelopeRecordV1{RecordType: RecordTypeOperationAckV1, Epoch: epoch, Direction: controlDirectionRelayV1, Sequence: sequence, SealedLength: uint32(len(sealed)), Ciphertext: sealed}
		body, prepared, err := channel.clientEnvelope.AuthenticateControlV1(envelope, aad)
		if err != nil {
			authErr = err
			return nil, err
		}
		capability, authenticated = prepared, true
		return body, nil
	})
	if err != nil {
		if authenticated {
			_ = capability.Discard()
		}
		if authErr != nil {
			return errors.Join(ErrOperationAckInvalid, security.ErrAuthenticationFailed)
		}
		return ErrOperationAckInvalid
	}
	err = receiver.commitStrictAuthenticatedOperationAckV1(sender, header.Direction, header.Epoch, header.Sequence, ack, capability.Commit)
	if err != nil {
		_ = capability.Discard()
		return err
	}
	return nil
}

func (channel *strictProtectedChannelV1) reserveCloseV1(life *endpointLifecycleV1) (uint64, uint64, error) {
	if !life.lockV1() {
		return 0, 0, ErrSecureChannel
	}
	defer life.coordinator.mu.Unlock()
	candidate, err := life.prepareOutboundRecordLockedV1(0)
	if err != nil {
		return 0, 0, err
	}
	profileOwner, err := life.lockProfileCommitGuardLockedV1()
	if err != nil {
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return 0, 0, life.failLockedV1(err)
	}
	epoch, sequence, oldSchedule, err := life.commitOutboundRecordLockedV1(0, &candidate)
	if err != nil {
		unlockProfileCommitGuardV1(profileOwner)
		life.destroyOutboundRecordCandidateLockedV1(&candidate)
		return 0, 0, life.failLockedV1(err)
	}
	unlockProfileCommitGuardV1(profileOwner)
	life.destroyScheduleLockedV1(&oldSchedule)
	return epoch, sequence, nil
}

func (channel *strictProtectedChannelV1) sealClientCloseV1() ([]byte, error) {
	return channel.sealCloseV1(true)
}

func (channel *strictProtectedChannelV1) sealRelayCloseV1() ([]byte, error) {
	return channel.sealCloseV1(false)
}

func (channel *strictProtectedChannelV1) sealCloseV1(client bool) ([]byte, error) {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	var life *endpointLifecycleV1
	var envelope *security.EnvelopeCodecV1
	if client {
		life = channel.client.state.life
	} else {
		life = channel.relay.state.life
	}
	epoch, sequence, err := channel.reserveCloseV1(life)
	if err != nil {
		return nil, err
	}
	key := channel.clientKey
	if !client {
		key = channel.relayKey
	}
	channel.observeAllocationV1(key, 2, epoch, 0, sequence)
	if client {
		_, err = channel.ensureEnvelopeForLifeV1(life, true)
		envelope = channel.clientEnvelope
	} else {
		_, err = channel.ensureEnvelopeForLifeV1(life, false)
		envelope = channel.relayEnvelope
	}
	if err != nil {
		return nil, err
	}
	seal := func(recordType uint16, direction uint16) ControlSealV1 {
		return func(wantEpoch, wantSequence uint64, body, aad []byte) ([]byte, error) {
			sealed, err := envelope.SealControlV1(recordType, body, aad)
			sealed, err = channel.rejectAfterSealV1(sealed, err)
			if err != nil {
				return nil, err
			}
			if sealed.Epoch != wantEpoch || sealed.Sequence != wantSequence || sealed.Direction != direction {
				clear(sealed.Ciphertext)
				return nil, security.ErrNonceMismatch
			}
			return sealed.Ciphertext, nil
		}
	}
	if client {
		record, err := (ClientControlCodecV1{}).SealCloseV1(channel.control, epoch, sequence, CloseV1{Code: CloseCodeTerminalV1}, seal(RecordTypeCloseV1, controlDirectionClientV1))
		if err != nil {
			return nil, err
		}
		return channel.publishRecordV1(life, record)
	}
	record, err := (RelayControlCodecV1{}).SealCloseV1(channel.control, epoch, sequence, CloseV1{Code: CloseCodeTerminalV1}, seal(RecordTypeCloseV1, controlDirectionRelayV1))
	if err != nil {
		return nil, err
	}
	return channel.publishRecordV1(life, record)
}

func (channel *strictProtectedChannelV1) openClientCloseV1(record []byte) error {
	return channel.openCloseV1(true, record)
}

func (channel *strictProtectedChannelV1) openRelayCloseV1(record []byte) error {
	return channel.openCloseV1(false, record)
}

func (channel *strictProtectedChannelV1) openCloseV1(fromClient bool, record []byte) error {
	channel.mu.Lock()
	defer channel.mu.Unlock()
	var sender, receiver *endpointLifecycleV1
	var codec *security.EnvelopeCodecV1
	if fromClient {
		sender, receiver = channel.client.state.life, channel.relay.state.life
	} else {
		sender, receiver = channel.relay.state.life, channel.client.state.life
	}
	terminal := func() error {
		if receiver != nil && receiver.coordinator != nil {
			receiver.coordinator.close()
		}
		return security.ErrAuthenticationFailed
	}
	if err := channel.guardOpenV1(receiver); err != nil {
		return err
	}
	expectedDirection := controlDirectionRelayV1
	if fromClient {
		expectedDirection = controlDirectionClientV1
	}
	header, _, err := parseControlRecordV1(record, expectedDirection, RecordTypeCloseV1)
	if err != nil {
		return terminal()
	}
	senderEpoch, err := channel.ensureEnvelopeForLifeV1(sender, !fromClient)
	if err != nil {
		return terminal()
	}
	if fromClient {
		codec = channel.relayEnvelope
	} else {
		codec = channel.clientEnvelope
	}
	var capability security.AuthenticatedReplayV1
	var authenticated bool
	open := func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error) {
		envelope := security.EnvelopeRecordV1{RecordType: RecordTypeCloseV1, Epoch: epoch, Direction: expectedDirection, Sequence: sequence, SealedLength: uint32(len(sealed)), Ciphertext: sealed}
		body, prepared, err := codec.AuthenticateControlV1(envelope, aad)
		if err != nil {
			return nil, err
		}
		capability, authenticated = prepared, true
		return body, nil
	}
	if fromClient {
		_, err = (RelayControlCodecV1{}).OpenCloseV1(channel.control, record, open)
	} else {
		_, err = (ClientControlCodecV1{}).OpenCloseV1(channel.control, record, open)
	}
	if err != nil {
		if authenticated {
			_ = capability.Discard()
		}
		return terminal()
	}
	if header.Epoch != senderEpoch {
		_ = capability.Discard()
		return terminal()
	}
	if capability.Commit() != nil {
		return terminal()
	}
	receiver.coordinator.close()
	return nil
}
