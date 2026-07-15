// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package security

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"sync"

	"kurdistan/internal/protocol/ir"
)

const (
	RecordClassApplicationV1 uint16 = 1
	RecordClassSyntheticV1   uint16 = 2
)

// EnvelopeContextV1 is the retained, authenticated, non-secret envelope
// authority. Policy and hashes are copied into the codec at construction.
type EnvelopeContextV1 struct {
	EffectivePolicy     ir.EffectiveSecurityPolicy
	MaxEnvelopeBytes    uint32
	EffectivePolicyHash [32]byte
	TranscriptHash      [32]byte
	CapabilityHash      [32]byte
	ProfileHash         [32]byte
	FramingHash         [32]byte
	CarrierContextHash  [32]byte
}

// EnvelopeRecordV1 deliberately contains no nonce. The receiver derives it
// from its retained role-fixed owner and these authenticated clear operands.
type EnvelopeRecordV1 struct {
	RecordType   uint16
	Epoch        uint64
	Direction    uint16
	Slot         uint16
	Sequence     uint64
	SealedLength uint32
	Ciphertext   []byte
}

type envelopeNonceOwnerV1 struct {
	outboundDirection uint16
	inboundDirection  uint16
	allocateControl   func() (NonceAllocationV1, error)
	allocateApp       func(uint16) (NonceAllocationV1, error)
	expectedControl   func(uint64) ([nonceBytesV1]byte, error)
	expectedApp       func(uint16, uint64) ([nonceBytesV1]byte, error)
}

type strictEnvelopeStateV1 struct {
	mu              sync.Mutex
	replay          map[uint16]*ReplayWindowV1
	nonces          envelopeNonceOwnerV1
	replayAuthority *authenticatedReplayAuthorityV1
	sealFail        func() error // package-private deterministic test seam
}

// EnvelopeCodecV1 is an additive strict codec. Copies share allocation and
// replay ownership, preventing rollback through value copying.
type EnvelopeCodecV1 struct {
	context  EnvelopeContextV1
	epoch    uint64
	outbound cipher.AEAD
	inbound  cipher.AEAD
	state    *strictEnvelopeStateV1
}

// AuthenticatedReplayV1 is a one-shot authority to commit the exact replay
// value authenticated by AuthenticateApplicationV1 or AuthenticateControlV1.
// Copies share the same synchronized decision state. Its zero value is invalid.
type AuthenticatedReplayV1 struct {
	state *authenticatedReplayStateV1
}

type authenticatedReplayStateV1 struct {
	mu       sync.Mutex
	self     *authenticatedReplayStateV1
	codec    *EnvelopeCodecV1
	owner    *strictEnvelopeStateV1
	slot     uint16
	sequence uint64
	grant    *authenticatedReplayGrantV1
	decided  bool
}

type authenticatedReplayAuthorityV1 struct{ marker byte }

type authenticatedReplayGrantV1 struct {
	authority *authenticatedReplayAuthorityV1
	state     *authenticatedReplayStateV1
	codec     *EnvelopeCodecV1
	owner     *strictEnvelopeStateV1
	slot      uint16
	sequence  uint64
}

func newAuthenticatedReplayV1(codec *EnvelopeCodecV1, slot uint16, sequence uint64) AuthenticatedReplayV1 {
	state := &authenticatedReplayStateV1{codec: codec, owner: codec.state, slot: slot, sequence: sequence}
	grant := &authenticatedReplayGrantV1{authority: codec.state.replayAuthority, state: state, codec: codec, owner: codec.state, slot: slot, sequence: sequence}
	state.grant = grant
	state.self = state
	return AuthenticatedReplayV1{state: state}
}

// Commit atomically rechecks and commits the authenticated replay value once.
func (capability AuthenticatedReplayV1) Commit() error {
	state := capability.state
	if state == nil {
		return ErrReplayDuplicate
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || state.decided {
		return ErrReplayDuplicate
	}
	state.decided = true
	return state.codec.commitReplayV1(state.slot, state.sequence)
}

// Discard irreversibly invalidates this capability and all of its copies
// without changing replay state.
func (capability AuthenticatedReplayV1) Discard() error {
	state := capability.state
	if state == nil {
		return ErrReplayDuplicate
	}
	state.mu.Lock()
	defer state.mu.Unlock()
	if !state.validLockedV1() || state.decided {
		return ErrReplayDuplicate
	}
	state.decided = true
	return nil
}

func (state *authenticatedReplayStateV1) validLockedV1() bool {
	return state != nil && state.self == state && state.codec != nil && state.owner != nil && state.codec.state == state.owner &&
		state.owner.replayAuthority != nil && state.grant != nil && state.grant.authority == state.owner.replayAuthority && state.grant.state == state &&
		state.grant.codec == state.codec && state.grant.owner == state.owner && state.grant.slot == state.slot && state.grant.sequence == state.sequence
}

func NewClientEnvelopeV1(schedule KeySchedule, context EnvelopeContextV1) (*EnvelopeCodecV1, error) {
	if err := validateEnvelopeContextV1(context); err != nil {
		return nil, err
	}
	owner, err := NewClientNonceOwnerV1(schedule, context.EffectivePolicy.NonceMode)
	if err != nil {
		return nil, err
	}
	return newEnvelopeCodecV1(schedule, context, envelopeNonceOwnerV1{
		outboundDirection: owner.OutboundDirectionV1(), inboundDirection: owner.InboundDirectionV1(),
		allocateControl: owner.AllocateOutboundControlV1, allocateApp: owner.AllocateOutboundApplicationV1,
		expectedControl: owner.ExpectedInboundControlV1, expectedApp: owner.ExpectedInboundApplicationV1,
	}, schedule.ClientWriteKey, schedule.ServerWriteKey)
}

func NewRelayEnvelopeV1(schedule KeySchedule, context EnvelopeContextV1) (*EnvelopeCodecV1, error) {
	if err := validateEnvelopeContextV1(context); err != nil {
		return nil, err
	}
	owner, err := NewRelayNonceOwnerV1(schedule, context.EffectivePolicy.NonceMode)
	if err != nil {
		return nil, err
	}
	return newEnvelopeCodecV1(schedule, context, envelopeNonceOwnerV1{
		outboundDirection: owner.OutboundDirectionV1(), inboundDirection: owner.InboundDirectionV1(),
		allocateControl: owner.AllocateOutboundControlV1, allocateApp: owner.AllocateOutboundApplicationV1,
		expectedControl: owner.ExpectedInboundControlV1, expectedApp: owner.ExpectedInboundApplicationV1,
	}, schedule.ServerWriteKey, schedule.ClientWriteKey)
}

func newEnvelopeCodecV1(schedule KeySchedule, context EnvelopeContextV1, owner envelopeNonceOwnerV1, outboundKey, inboundKey []byte) (*EnvelopeCodecV1, error) {
	if err := validateEnvelopeContextV1(context); err != nil {
		return nil, err
	}
	if schedule.Epoch != schedule.boundEpoch || !schedule.exactV1 {
		return nil, ErrNonceMismatch
	}
	outbound, err := newAEADV1(outboundKey)
	if err != nil {
		return nil, err
	}
	inbound, err := newAEADV1(inboundKey)
	if err != nil {
		return nil, err
	}
	context.EffectivePolicy.ClientMandatoryCapabilities = append([]string(nil), context.EffectivePolicy.ClientMandatoryCapabilities...)
	context.EffectivePolicy.ServerMandatoryCapabilities = append([]string(nil), context.EffectivePolicy.ServerMandatoryCapabilities...)
	context.EffectivePolicy.SelectedCapabilities = append([]string(nil), context.EffectivePolicy.SelectedCapabilities...)
	return &EnvelopeCodecV1{context: context, epoch: schedule.Epoch, outbound: outbound, inbound: inbound,
		state: &strictEnvelopeStateV1{nonces: owner, replay: make(map[uint16]*ReplayWindowV1), replayAuthority: &authenticatedReplayAuthorityV1{marker: 1}}}, nil
}

func newAEADV1(key []byte) (cipher.AEAD, error) {
	if len(key) != 32 {
		return nil, ErrAEADInvalid
	}
	block, err := aes.NewCipher(append([]byte(nil), key...))
	if err != nil {
		return nil, ErrAEADInvalid
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, ErrAEADInvalid
	}
	return aead, nil
}

func validateEnvelopeContextV1(context EnvelopeContextV1) error {
	p := context.EffectivePolicy
	if p.AEADSuite != "aead_aes_256_gcm" || validateNonceModeV1(p.NonceMode) != nil ||
		validateReplayPolicyV1(p.ReplayPolicy, p.ReplayWindowSize) != nil {
		return ErrPolicyInvalid
	}
	switch p.SecureEnvelopeMode {
	case "metadata_authenticated", "synthetic_aead_test":
	case "full_context_bound_envelope":
		if zeroHashV1(context.CapabilityHash) || zeroHashV1(context.ProfileHash) || zeroHashV1(context.FramingHash) || zeroHashV1(context.CarrierContextHash) {
			return ErrEnvelopeContextInvalid
		}
	default:
		return ErrPolicyInvalid
	}
	if context.MaxEnvelopeBytes < 16 || zeroHashV1(context.EffectivePolicyHash) || zeroHashV1(context.TranscriptHash) {
		return ErrEnvelopeContextInvalid
	}
	return nil
}

func zeroHashV1(value [32]byte) bool { return value == [32]byte{} }

func (c *EnvelopeCodecV1) ExpectedClassV1() (uint16, error) {
	if c == nil || c.state == nil {
		return 0, ErrEnvelopeContextInvalid
	}
	switch c.context.EffectivePolicy.SecureEnvelopeMode {
	case "metadata_authenticated", "full_context_bound_envelope":
		return RecordClassApplicationV1, nil
	case "synthetic_aead_test":
		return RecordClassSyntheticV1, nil
	default:
		return 0, ErrPolicyInvalid
	}
}

func (c *EnvelopeCodecV1) SealControlV1(recordType uint16, plaintext, recordAAD []byte) (EnvelopeRecordV1, error) {
	return c.sealV1(nonceControlRecordV1, recordType, 0, plaintext, recordAAD)
}

func (c *EnvelopeCodecV1) SealApplicationV1(slot uint16, plaintext []byte) (EnvelopeRecordV1, error) {
	return c.sealV1(nonceApplicationRecordV1, 1, slot, plaintext, nil)
}

func (c *EnvelopeCodecV1) sealV1(class nonceRecordClassV1, recordType, slot uint16, plaintext, recordAAD []byte) (EnvelopeRecordV1, error) {
	if c == nil || c.state == nil || c.outbound == nil || recordType == 0 {
		return EnvelopeRecordV1{}, ErrNonceMismatch
	}
	if (class == nonceApplicationRecordV1 && recordType != 1) || (class == nonceControlRecordV1 && recordType == 1) {
		return EnvelopeRecordV1{}, ErrNonceMismatch
	}
	if uint64(len(plaintext))+uint64(c.outbound.Overhead()) > uint64(c.context.MaxEnvelopeBytes) {
		return EnvelopeRecordV1{}, ErrAEADInvalid
	}
	var allocation NonceAllocationV1
	var err error
	if class == nonceControlRecordV1 {
		allocation, err = c.state.nonces.allocateControl()
	} else {
		allocation, err = c.state.nonces.allocateApp(slot)
	}
	if err != nil {
		return EnvelopeRecordV1{}, err
	}
	record := EnvelopeRecordV1{RecordType: recordType, Epoch: allocation.Epoch, Direction: allocation.Direction, Slot: allocation.Slot, Sequence: allocation.Sequence, SealedLength: uint32(len(plaintext) + c.outbound.Overhead())}
	// Allocation is already committed. Any error below permanently burns it.
	if c.state.sealFail != nil {
		if err := c.state.sealFail(); err != nil {
			return EnvelopeRecordV1{}, ErrAEADInvalid
		}
	}
	record.Ciphertext = c.outbound.Seal(nil, allocation.Nonce[:], plaintext, c.aadV1(record, recordAAD))
	return record, nil
}

func (c *EnvelopeCodecV1) OpenControlV1(record EnvelopeRecordV1, recordAAD []byte) ([]byte, error) {
	plaintext, capability, err := c.AuthenticateControlV1(record, recordAAD)
	if err != nil {
		return nil, err
	}
	if err := capability.Commit(); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

func (c *EnvelopeCodecV1) OpenApplicationV1(record EnvelopeRecordV1) ([]byte, error) {
	plaintext, capability, err := c.AuthenticateApplicationV1(record)
	if err != nil {
		return nil, err
	}
	if err := capability.Commit(); err != nil {
		clear(plaintext)
		return nil, err
	}
	return plaintext, nil
}

// AuthenticateControlV1 authenticates a strict control record without
// mutating replay state. The caller owns and must clear the returned plaintext,
// then Commit or Discard the capability after validating the authenticated
// control body.
func (c *EnvelopeCodecV1) AuthenticateControlV1(record EnvelopeRecordV1, recordAAD []byte) ([]byte, AuthenticatedReplayV1, error) {
	return c.authenticateV1(nonceControlRecordV1, record, recordAAD)
}

// AuthenticateApplicationV1 authenticates a strict application record without
// mutating replay state. The caller owns and must clear the returned plaintext,
// then Commit or Discard the capability after validating the authenticated
// application body.
func (c *EnvelopeCodecV1) AuthenticateApplicationV1(record EnvelopeRecordV1) ([]byte, AuthenticatedReplayV1, error) {
	return c.authenticateV1(nonceApplicationRecordV1, record, nil)
}

func (c *EnvelopeCodecV1) authenticateV1(class nonceRecordClassV1, record EnvelopeRecordV1, recordAAD []byte) ([]byte, AuthenticatedReplayV1, error) {
	if c == nil || c.state == nil || c.inbound == nil || record.RecordType == 0 ||
		record.Direction != c.state.nonces.inboundDirection || record.Epoch != c.epoch {
		return nil, AuthenticatedReplayV1{}, ErrNonceMismatch
	}
	if (class == nonceApplicationRecordV1 && record.RecordType != 1) || (class == nonceControlRecordV1 && record.RecordType == 1) {
		return nil, AuthenticatedReplayV1{}, ErrNonceMismatch
	}
	if err := validateNonceSlotV1(class, record.Slot); err != nil {
		return nil, AuthenticatedReplayV1{}, err
	}
	if len(record.Ciphertext) < c.inbound.Overhead() || uint64(len(record.Ciphertext)) > uint64(c.context.MaxEnvelopeBytes) || uint64(record.SealedLength) != uint64(len(record.Ciphertext)) {
		return nil, AuthenticatedReplayV1{}, ErrAEADInvalid
	}
	var expected [nonceBytesV1]byte
	var err error
	if class == nonceControlRecordV1 {
		expected, err = c.state.nonces.expectedControl(record.Sequence)
	} else {
		expected, err = c.state.nonces.expectedApp(record.Slot, record.Sequence)
	}
	if err != nil {
		return nil, AuthenticatedReplayV1{}, err
	}
	replay, err := c.replayPrecheckV1(record.Slot)
	if err != nil {
		return nil, AuthenticatedReplayV1{}, err
	}
	if err := replay.Plausible(record.Sequence); err != nil {
		return nil, AuthenticatedReplayV1{}, err
	}
	temporary, err := c.inbound.Open(nil, expected[:], record.Ciphertext, c.aadV1(record, recordAAD))
	if err != nil {
		return nil, AuthenticatedReplayV1{}, ErrAuthenticationFailed
	}
	return temporary, newAuthenticatedReplayV1(c, record.Slot, record.Sequence), nil
}

func (c *EnvelopeCodecV1) replayKeyV1(slot uint16) uint16 {
	key := uint16(0)
	if c.context.EffectivePolicy.NonceMode == NonceModeStreamPartitionedCounterV1 {
		key = slot
	}
	return key
}

func (c *EnvelopeCodecV1) replayPrecheckV1(slot uint16) (*ReplayWindowV1, error) {
	key := c.replayKeyV1(slot)
	c.state.mu.Lock()
	if replay := c.state.replay[key]; replay != nil {
		c.state.mu.Unlock()
		return replay, nil
	}
	c.state.mu.Unlock()
	return NewReplayWindowV1(c.context.EffectivePolicy.ReplayPolicy, c.context.EffectivePolicy.ReplayWindowSize)
}

func (c *EnvelopeCodecV1) commitReplayV1(slot uint16, sequence uint64) error {
	key := c.replayKeyV1(slot)
	c.state.mu.Lock()
	defer c.state.mu.Unlock()
	replay := c.state.replay[key]
	if replay == nil {
		var err error
		replay, err = NewReplayWindowV1(c.context.EffectivePolicy.ReplayPolicy, c.context.EffectivePolicy.ReplayWindowSize)
		if err != nil {
			return err
		}
	}
	if err := replay.CommitAuthenticated(sequence); err != nil {
		return err
	}
	if c.state.replay[key] == nil {
		c.state.replay[key] = replay
	}
	return nil
}

func (c *EnvelopeCodecV1) aadV1(record EnvelopeRecordV1, recordAAD []byte) []byte {
	if record.RecordType == 1 {
		return c.applicationAADV1(record)
	}
	var out bytes.Buffer
	out.WriteString("kurdistan/envelope/v1")
	_ = binary.Write(&out, binary.BigEndian, record.RecordType)
	_ = binary.Write(&out, binary.BigEndian, record.Epoch)
	_ = binary.Write(&out, binary.BigEndian, record.Direction)
	_ = binary.Write(&out, binary.BigEndian, record.Slot)
	_ = binary.Write(&out, binary.BigEndian, record.Sequence)
	class, _ := c.ExpectedClassV1()
	_ = binary.Write(&out, binary.BigEndian, class)
	out.Write(c.context.EffectivePolicyHash[:])
	out.Write(c.context.TranscriptHash[:])
	if c.context.EffectivePolicy.SecureEnvelopeMode == "full_context_bound_envelope" {
		out.Write(c.context.CapabilityHash[:])
		out.Write(c.context.ProfileHash[:])
		out.Write(c.context.FramingHash[:])
		out.Write(c.context.CarrierContextHash[:])
	}
	out.Write(recordAAD)
	return out.Bytes()
}

func (c *EnvelopeCodecV1) applicationAADV1(record EnvelopeRecordV1) []byte {
	capacity := 94
	if c.context.EffectivePolicy.SecureEnvelopeMode == "full_context_bound_envelope" {
		capacity = 222
	}
	out := bytes.NewBuffer(make([]byte, 0, capacity))
	_ = binary.Write(out, binary.BigEndian, uint16(1))
	_ = binary.Write(out, binary.BigEndian, uint16(1))
	out.Write(c.context.EffectivePolicyHash[:])
	out.Write(c.context.TranscriptHash[:])
	class, _ := c.ExpectedClassV1()
	_ = binary.Write(out, binary.BigEndian, class)
	_ = binary.Write(out, binary.BigEndian, record.Epoch)
	_ = binary.Write(out, binary.BigEndian, record.Direction)
	_ = binary.Write(out, binary.BigEndian, record.Slot)
	_ = binary.Write(out, binary.BigEndian, record.Sequence)
	_ = binary.Write(out, binary.BigEndian, record.SealedLength)
	if c.context.EffectivePolicy.SecureEnvelopeMode == "full_context_bound_envelope" {
		out.Write(c.context.CapabilityHash[:])
		out.Write(c.context.ProfileHash[:])
		out.Write(c.context.FramingHash[:])
		out.Write(c.context.CarrierContextHash[:])
	}
	return out.Bytes()
}

type SecureEnvelope struct {
	Sequence        uint64 `json:"sequence"`
	StreamID        uint64 `json:"stream_id"`
	Semantic        string `json:"semantic"`
	CarrierFamily   string `json:"carrier_family"`
	TranscriptHash  string `json:"transcript_hash"`
	CapabilityHash  string `json:"capability_hash"`
	Nonce           []byte `json:"-"`
	Ciphertext      []byte `json:"-"`
	CiphertextBytes int    `json:"ciphertext_bytes"`
	AuthTagBytes    int    `json:"auth_tag_bytes"`
	MetadataClass   string `json:"metadata_class"`
}

type EnvelopeMetadata struct {
	StreamID      uint64
	Semantic      string
	CarrierFamily string
	MetadataClass string
}

type EnvelopeCodec struct {
	ctx    SecurityContext
	aead   cipher.AEAD
	nonces *NonceManager
	replay *ReplayWindow
}

func NewEnvelopeCodec(ctx SecurityContext, keys KeySchedule, direction string) (*EnvelopeCodec, error) {
	if err := ValidateContextIdentity(ctx); err != nil {
		return nil, err
	}
	if !SuiteSupported(keys.Suite) || keys.Suite != ctx.Suite {
		return nil, contextIdentityError(ContextIdentitySuite, "inconsistent")
	}
	var key []byte
	var base []byte
	switch direction {
	case "server":
		key = keys.ServerWriteKey
		base = keys.ServerNonceBase
	case "client":
		key = keys.ClientWriteKey
		base = keys.ClientNonceBase
	default:
		return nil, contextIdentityError(ContextIdentityDirection, "unknown")
	}
	if len(key) != 32 {
		return nil, fmt.Errorf("%w: invalid key length", ErrInvalidConfig)
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &EnvelopeCodec{
		ctx:    ctx,
		aead:   aead,
		nonces: NewNonceManager(direction, base, "directional_counter"),
		replay: NewReplayWindow("windowed_replay", 64),
	}, nil
}

func (c *EnvelopeCodec) Seal(meta EnvelopeMetadata, plaintext []byte) (SecureEnvelope, error) {
	if err := validateIdentityText(ContextIdentitySemantic, meta.Semantic); err != nil {
		return SecureEnvelope{}, err
	}
	if err := validateIdentityText(ContextIdentityCarrier, meta.CarrierFamily); err != nil {
		return SecureEnvelope{}, err
	}
	nonce, seq, err := c.nonces.Next()
	if err != nil {
		return SecureEnvelope{}, err
	}
	env := SecureEnvelope{
		Sequence:       seq,
		StreamID:       meta.StreamID,
		Semantic:       meta.Semantic,
		CarrierFamily:  meta.CarrierFamily,
		TranscriptHash: c.ctx.TranscriptHash,
		CapabilityHash: c.ctx.CapabilityHash,
		Nonce:          nonce,
		MetadataClass:  meta.MetadataClass,
		AuthTagBytes:   c.aead.Overhead(),
	}
	env.Ciphertext = c.aead.Seal(nil, nonce, plaintext, envelopeAAD(env))
	env.CiphertextBytes = len(env.Ciphertext)
	return env, nil
}

func (c *EnvelopeCodec) Open(env SecureEnvelope) ([]byte, error) {
	if err := validateHashIdentity(ContextIdentityTranscriptHash, env.TranscriptHash); err != nil {
		return nil, err
	}
	if err := validateHashIdentity(ContextIdentityCapabilityHash, env.CapabilityHash); err != nil {
		return nil, err
	}
	if err := validateIdentityText(ContextIdentitySemantic, env.Semantic); err != nil {
		return nil, err
	}
	if err := validateIdentityText(ContextIdentityCarrier, env.CarrierFamily); err != nil {
		return nil, err
	}
	if !identityEqual(env.TranscriptHash, c.ctx.TranscriptHash) {
		return nil, ErrTranscriptMismatch
	}
	if !identityEqual(env.CapabilityHash, c.ctx.CapabilityHash) {
		return nil, ErrCapabilityMismatch
	}
	if len(env.Nonce) != c.aead.NonceSize() || len(env.Ciphertext) == 0 {
		return nil, fmt.Errorf("%w: malformed envelope", ErrEnvelopeRejected)
	}
	if err := c.replay.precheck(env.Sequence); err != nil {
		return nil, err
	}
	plaintext, err := c.aead.Open(nil, env.Nonce, env.Ciphertext, envelopeAAD(env))
	if err != nil {
		return nil, err
	}
	if err := c.replay.commit(env.Sequence); err != nil {
		return nil, err
	}
	return plaintext, nil
}

func envelopeAAD(env SecureEnvelope) []byte {
	raw, _ := json.Marshal(struct {
		Sequence       uint64 `json:"sequence"`
		StreamID       uint64 `json:"stream_id"`
		Semantic       string `json:"semantic"`
		CarrierFamily  string `json:"carrier_family"`
		TranscriptHash string `json:"transcript_hash"`
		CapabilityHash string `json:"capability_hash"`
		MetadataClass  string `json:"metadata_class"`
	}{
		Sequence:       env.Sequence,
		StreamID:       env.StreamID,
		Semantic:       env.Semantic,
		CarrierFamily:  env.CarrierFamily,
		TranscriptHash: env.TranscriptHash,
		CapabilityHash: env.CapabilityHash,
		MetadataClass:  env.MetadataClass,
	})
	return raw
}
