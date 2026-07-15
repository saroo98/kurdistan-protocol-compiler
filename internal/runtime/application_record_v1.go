// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"encoding/binary"
	"errors"

	"kurdistan/internal/crypto/security"
)

const (
	ApplicationRecordVersionV1      uint16 = 0x0001
	RecordTypeApplicationFragmentV1 uint16 = 0x0001
	RecordClassApplicationV1        uint16 = 0x0001
	RecordClassSyntheticV1          uint16 = 0x0002
	applicationDirectionClientV1    uint16 = 0x0001
	applicationDirectionRelayV1     uint16 = 0x0002
	applicationHeaderBytesV1               = 28
	applicationMinimalAADBytesV1           = 94
	applicationFullAADBytesV1              = 222
	applicationBodyFixedBytesV1            = 54
	applicationAEADOverheadV1              = 16
	applicationMinimumSealedBytesV1        = applicationBodyFixedBytesV1 + applicationAEADOverheadV1
)

// ApplicationHeaderV1 is the only clear application-record metadata. Operation
// identity and fragment topology remain in the authenticated encrypted body.
type ApplicationHeaderV1 struct {
	Version      uint16
	Type         uint16
	Epoch        uint64
	Direction    uint16
	StreamSlot   uint16
	Sequence     uint64
	SealedLength uint32
}

// ApplicationFragmentV1 is authenticated plaintext. Class is deliberately not
// caller-selectable; role codecs derive it from the retained effective policy.
type ApplicationFragmentV1 struct {
	OperationID     [32]byte
	FragmentIndex   uint16
	FragmentCount   uint16
	OperationLength uint32
	FragmentOffset  uint32
	Fragment        []byte
}

// ApplicationSealV1 owns nonce allocation and exact local AAD construction. It
// returns the strict envelope fields that are serialized into the clear header;
// direction, class, nonce, epoch, sequence, and AAD are not caller operands.
type ApplicationSealV1 func(slot uint16, plaintext []byte) (security.EnvelopeRecordV1, error)

// ApplicationOpenV1 authenticates a strict envelope without committing replay
// or lifecycle state. Later protected-channel composition owns those commits.
// security.EnvelopeCodecV1.OpenApplicationV1 currently commits replay and is
// therefore not a valid direct implementation of this callback.
type ApplicationOpenV1 func(record security.EnvelopeRecordV1) ([]byte, error)

type ClientApplicationCodecV1 struct{}
type RelayApplicationCodecV1 struct{}

func (ClientApplicationCodecV1) SealApplicationFragmentV1(context security.EnvelopeContextV1, slot uint16, fragment ApplicationFragmentV1, seal ApplicationSealV1) ([]byte, error) {
	return sealApplicationFragmentV1(applicationDirectionClientV1, context, slot, fragment, seal)
}

func (ClientApplicationCodecV1) OpenApplicationFragmentV1(context security.EnvelopeContextV1, record []byte, open ApplicationOpenV1) (ApplicationFragmentV1, error) {
	return openApplicationFragmentV1(applicationDirectionRelayV1, context, record, open)
}

func (RelayApplicationCodecV1) SealApplicationFragmentV1(context security.EnvelopeContextV1, slot uint16, fragment ApplicationFragmentV1, seal ApplicationSealV1) ([]byte, error) {
	return sealApplicationFragmentV1(applicationDirectionRelayV1, context, slot, fragment, seal)
}

func (RelayApplicationCodecV1) OpenApplicationFragmentV1(context security.EnvelopeContextV1, record []byte, open ApplicationOpenV1) (ApplicationFragmentV1, error) {
	return openApplicationFragmentV1(applicationDirectionClientV1, context, record, open)
}

func sealApplicationFragmentV1(direction uint16, context security.EnvelopeContextV1, slot uint16, fragment ApplicationFragmentV1, seal ApplicationSealV1) ([]byte, error) {
	expectedClass, err := applicationExpectedClassV1(context)
	if err != nil {
		return nil, err
	}
	if slot == 0 || seal == nil || !validApplicationFragmentV1(fragment) {
		return nil, ErrRecordInvalid
	}
	bodyLength := uint64(applicationBodyFixedBytesV1) + uint64(len(fragment.Fragment))
	sealedLength := bodyLength + applicationAEADOverheadV1
	maxInt := uint64(^uint(0) >> 1)
	if bodyLength > maxInt || sealedLength > uint64(context.MaxEnvelopeBytes) || sealedLength > uint64(^uint32(0)) || uint64(applicationHeaderBytesV1)+sealedLength > maxInt {
		return nil, ErrRecordInvalid
	}
	body := encodeApplicationBodyV1(expectedClass, fragment)
	callbackBody := make([]byte, len(body), int(sealedLength))
	copy(callbackBody, body)
	envelope, err := seal(slot, callbackBody)
	clear(body)
	if err != nil {
		clear(callbackBody)
		clear(envelope.Ciphertext)
		return nil, normalizeApplicationSealErrorV1(err)
	}
	ownedCiphertext := append([]byte(nil), envelope.Ciphertext...)
	clear(callbackBody)
	clear(envelope.Ciphertext)
	envelope.Ciphertext = ownedCiphertext
	if envelope.RecordType != RecordTypeApplicationFragmentV1 || envelope.Direction != direction || envelope.Slot != slot ||
		envelope.SealedLength != uint32(sealedLength) || len(envelope.Ciphertext) != int(envelope.SealedLength) || envelope.SealedLength > context.MaxEnvelopeBytes {
		clear(envelope.Ciphertext)
		return nil, ErrRecordInvalid
	}
	header := ApplicationHeaderV1{
		Version: ApplicationRecordVersionV1, Type: RecordTypeApplicationFragmentV1,
		Epoch: envelope.Epoch, Direction: envelope.Direction, StreamSlot: envelope.Slot,
		Sequence: envelope.Sequence, SealedLength: envelope.SealedLength,
	}
	headerBytes := encodeApplicationHeaderV1(header)
	record := make([]byte, 0, applicationHeaderBytesV1+len(envelope.Ciphertext))
	record = append(record, headerBytes[:]...)
	record = append(record, envelope.Ciphertext...)
	clear(envelope.Ciphertext)
	return record, nil
}

func openApplicationFragmentV1(expectedDirection uint16, context security.EnvelopeContextV1, record []byte, open ApplicationOpenV1) (ApplicationFragmentV1, error) {
	header, sealed, err := parseApplicationRecordV1(record, expectedDirection, context.MaxEnvelopeBytes)
	if err != nil {
		return ApplicationFragmentV1{}, ErrRecordInvalid
	}
	expectedClass, err := applicationExpectedClassV1(context)
	if err != nil {
		return ApplicationFragmentV1{}, err
	}
	if open == nil {
		return ApplicationFragmentV1{}, ErrRecordInvalid
	}
	envelope := security.EnvelopeRecordV1{
		RecordType: header.Type, Epoch: header.Epoch, Direction: header.Direction,
		Slot: header.StreamSlot, Sequence: header.Sequence, SealedLength: header.SealedLength,
		Ciphertext: append([]byte(nil), sealed...),
	}
	body, err := open(envelope)
	defer clear(envelope.Ciphertext)
	if err != nil {
		clear(body)
		return ApplicationFragmentV1{}, normalizeApplicationOpenErrorV1(err)
	}
	defer clear(body)
	if uint64(header.SealedLength) != uint64(len(body))+applicationAEADOverheadV1 {
		return ApplicationFragmentV1{}, ErrRecordInvalid
	}
	fragment, class, err := parseApplicationBodyV1(body)
	if err != nil {
		return ApplicationFragmentV1{}, ErrRecordInvalid
	}
	if class != expectedClass {
		clear(fragment.Fragment)
		return ApplicationFragmentV1{}, security.ErrEnvelopeModeRejected
	}
	return fragment, nil
}

func applicationExpectedClassV1(context security.EnvelopeContextV1) (uint16, error) {
	if context.MaxEnvelopeBytes < applicationMinimumSealedBytesV1 || context.EffectivePolicyHash == [32]byte{} || context.TranscriptHash == [32]byte{} {
		return 0, security.ErrEnvelopeContextInvalid
	}
	switch context.EffectivePolicy.SecureEnvelopeMode {
	case "metadata_authenticated":
		return RecordClassApplicationV1, nil
	case "synthetic_aead_test":
		return RecordClassSyntheticV1, nil
	case "full_context_bound_envelope":
		if context.CapabilityHash == [32]byte{} || context.ProfileHash == [32]byte{} || context.FramingHash == [32]byte{} || context.CarrierContextHash == [32]byte{} {
			return 0, security.ErrEnvelopeContextInvalid
		}
		return RecordClassApplicationV1, nil
	default:
		return 0, security.ErrPolicyInvalid
	}
}

func parseApplicationRecordV1(record []byte, expectedDirection uint16, maxEnvelopeBytes uint32) (ApplicationHeaderV1, []byte, error) {
	if len(record) < applicationHeaderBytesV1 {
		return ApplicationHeaderV1{}, nil, ErrRecordInvalid
	}
	header, err := parseApplicationHeaderV1(record[:applicationHeaderBytesV1])
	if err != nil || header.Version != ApplicationRecordVersionV1 || header.Type != RecordTypeApplicationFragmentV1 ||
		header.Direction != expectedDirection || (header.Direction != applicationDirectionClientV1 && header.Direction != applicationDirectionRelayV1) ||
		header.StreamSlot == 0 || header.SealedLength < applicationMinimumSealedBytesV1 {
		return ApplicationHeaderV1{}, nil, ErrRecordInvalid
	}
	if maxEnvelopeBytes != 0 && header.SealedLength > maxEnvelopeBytes {
		return ApplicationHeaderV1{}, nil, ErrRecordInvalid
	}
	total := uint64(applicationHeaderBytesV1) + uint64(header.SealedLength)
	if total > uint64(^uint(0)>>1) || total != uint64(len(record)) {
		return ApplicationHeaderV1{}, nil, ErrRecordInvalid
	}
	return header, record[applicationHeaderBytesV1:], nil
}

func encodeApplicationHeaderV1(header ApplicationHeaderV1) [applicationHeaderBytesV1]byte {
	var out [applicationHeaderBytesV1]byte
	binary.BigEndian.PutUint16(out[0:2], header.Version)
	binary.BigEndian.PutUint16(out[2:4], header.Type)
	binary.BigEndian.PutUint64(out[4:12], header.Epoch)
	binary.BigEndian.PutUint16(out[12:14], header.Direction)
	binary.BigEndian.PutUint16(out[14:16], header.StreamSlot)
	binary.BigEndian.PutUint64(out[16:24], header.Sequence)
	binary.BigEndian.PutUint32(out[24:28], header.SealedLength)
	return out
}

func parseApplicationHeaderV1(encoded []byte) (ApplicationHeaderV1, error) {
	if len(encoded) != applicationHeaderBytesV1 {
		return ApplicationHeaderV1{}, ErrRecordInvalid
	}
	return ApplicationHeaderV1{
		Version: binary.BigEndian.Uint16(encoded[0:2]), Type: binary.BigEndian.Uint16(encoded[2:4]),
		Epoch: binary.BigEndian.Uint64(encoded[4:12]), Direction: binary.BigEndian.Uint16(encoded[12:14]),
		StreamSlot: binary.BigEndian.Uint16(encoded[14:16]), Sequence: binary.BigEndian.Uint64(encoded[16:24]),
		SealedLength: binary.BigEndian.Uint32(encoded[24:28]),
	}, nil
}

func encodeApplicationBodyV1(class uint16, fragment ApplicationFragmentV1) []byte {
	out := make([]byte, applicationBodyFixedBytesV1+len(fragment.Fragment))
	binary.BigEndian.PutUint16(out[0:2], ApplicationRecordVersionV1)
	binary.BigEndian.PutUint16(out[2:4], RecordTypeApplicationFragmentV1)
	binary.BigEndian.PutUint16(out[4:6], class)
	copy(out[6:38], fragment.OperationID[:])
	binary.BigEndian.PutUint16(out[38:40], fragment.FragmentIndex)
	binary.BigEndian.PutUint16(out[40:42], fragment.FragmentCount)
	binary.BigEndian.PutUint32(out[42:46], fragment.OperationLength)
	binary.BigEndian.PutUint32(out[46:50], fragment.FragmentOffset)
	binary.BigEndian.PutUint32(out[50:54], uint32(len(fragment.Fragment)))
	copy(out[54:], fragment.Fragment)
	return out
}

func parseApplicationBodyV1(encoded []byte) (ApplicationFragmentV1, uint16, error) {
	if len(encoded) < applicationBodyFixedBytesV1 || binary.BigEndian.Uint16(encoded[0:2]) != ApplicationRecordVersionV1 || binary.BigEndian.Uint16(encoded[2:4]) != RecordTypeApplicationFragmentV1 {
		return ApplicationFragmentV1{}, 0, ErrRecordInvalid
	}
	class := binary.BigEndian.Uint16(encoded[4:6])
	var fragment ApplicationFragmentV1
	copy(fragment.OperationID[:], encoded[6:38])
	fragment.FragmentIndex = binary.BigEndian.Uint16(encoded[38:40])
	fragment.FragmentCount = binary.BigEndian.Uint16(encoded[40:42])
	fragment.OperationLength = binary.BigEndian.Uint32(encoded[42:46])
	fragment.FragmentOffset = binary.BigEndian.Uint32(encoded[46:50])
	fragmentLength := binary.BigEndian.Uint32(encoded[50:54])
	if uint64(applicationBodyFixedBytesV1)+uint64(fragmentLength) != uint64(len(encoded)) {
		return ApplicationFragmentV1{}, 0, ErrRecordInvalid
	}
	fragment.Fragment = append([]byte(nil), encoded[applicationBodyFixedBytesV1:]...)
	if uint32(len(fragment.Fragment)) != fragmentLength || !validApplicationFragmentV1(fragment) {
		clear(fragment.Fragment)
		return ApplicationFragmentV1{}, 0, ErrRecordInvalid
	}
	return fragment, class, nil
}

func validApplicationFragmentV1(fragment ApplicationFragmentV1) bool {
	if fragment.OperationID == [32]byte{} || fragment.FragmentCount == 0 || fragment.OperationLength == 0 || len(fragment.Fragment) == 0 ||
		uint64(len(fragment.Fragment)) > uint64(^uint32(0)) || fragment.FragmentIndex >= fragment.FragmentCount {
		return false
	}
	fragmentLength := uint32(len(fragment.Fragment))
	end := uint64(fragment.FragmentOffset) + uint64(fragmentLength)
	if end > uint64(fragment.OperationLength) {
		return false
	}
	if fragment.FragmentCount == 1 && (fragment.FragmentIndex != 0 || fragment.FragmentOffset != 0 || fragmentLength != fragment.OperationLength) {
		return false
	}
	return true
}

func normalizeApplicationSealErrorV1(err error) error {
	for _, admitted := range []error{security.ErrNonceExhausted, security.ErrNonceMismatch, security.ErrAEADInvalid, security.ErrPolicyInvalid, security.ErrEnvelopeContextInvalid} {
		if errors.Is(err, admitted) {
			return admitted
		}
	}
	return security.ErrAEADInvalid
}

func normalizeApplicationOpenErrorV1(err error) error {
	for _, admitted := range []error{security.ErrNonceExhausted, security.ErrNonceMismatch, security.ErrAEADInvalid, security.ErrAuthenticationFailed, security.ErrPolicyInvalid, security.ErrEnvelopeContextInvalid} {
		if errors.Is(err, admitted) {
			return admitted
		}
	}
	return security.ErrAuthenticationFailed
}
