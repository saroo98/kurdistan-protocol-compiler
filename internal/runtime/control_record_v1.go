// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import "encoding/binary"

const (
	ControlRecordVersionV1    uint16 = 0x0001
	RecordTypeOperationAckV1  uint16 = 0x0002
	RecordTypeCloseV1         uint16 = 0x0003
	CloseCodeTerminalV1       uint16 = 0x0001
	controlDirectionClientV1  uint16 = 0x0001
	controlDirectionRelayV1   uint16 = 0x0002
	controlHeaderBytesV1             = 26
	controlAADBytesV1                = 90
	operationAckBodyBytesV1          = 44
	operationAckSealedBytesV1        = 60
	closeBodyBytesV1                 = 6
	closeSealedBytesV1               = 22
)

// ControlHeaderV1 is the fixed clear portion of a protected control record.
// Direction is produced and checked only by the role-specific codecs below.
type ControlHeaderV1 struct {
	Version      uint16
	Type         uint16
	Epoch        uint64
	Direction    uint16
	Sequence     uint64
	SealedLength uint32
}

// ControlContextV1 is local authenticated context. It is never read from the
// wire and is copied by value into the AAD encoder.
type ControlContextV1 struct {
	EffectivePolicyHash [32]byte
	TH4                 [32]byte
}

// OperationAckV1 is the authenticated acknowledgement value. Version and type
// are fixed by the canonical body encoder rather than supplied by a caller.
type OperationAckV1 struct {
	OperationID    [32]byte
	CompletedCount uint64
}

// CloseV1 has one admitted v1 code. Version and type are fixed by the encoder.
type CloseV1 struct {
	Code uint16
}

// ControlSealV1 is a bounded, non-retained sealing primitive. The role-specific
// caller owns its key and nonce allocator. Epoch and sequence let that owner
// verify its allocation without exposing a nonce, slot, or direction operand.
type ControlSealV1 func(epoch, sequence uint64, plaintext, aad []byte) ([]byte, error)

// ControlOpenV1 is a bounded, non-retained authentication primitive. It must
// not commit replay or lifecycle state; those operations belong to later
// protected-channel composition after the returned body is validated.
type ControlOpenV1 func(epoch, sequence uint64, sealed, aad []byte) ([]byte, error)

// ClientControlCodecV1 fixes outbound direction to client-to-relay and inbound
// direction to relay-to-client. It is intentionally stateless.
type ClientControlCodecV1 struct{}

// RelayControlCodecV1 fixes outbound direction to relay-to-client and inbound
// direction to client-to-relay. It is intentionally stateless.
type RelayControlCodecV1 struct{}

func (ClientControlCodecV1) SealOperationAckV1(context ControlContextV1, epoch, sequence uint64, ack OperationAckV1, seal ControlSealV1) ([]byte, error) {
	return sealOperationAckV1(controlDirectionClientV1, context, epoch, sequence, ack, seal)
}

func (ClientControlCodecV1) OpenOperationAckV1(context ControlContextV1, record []byte, open ControlOpenV1) (OperationAckV1, error) {
	return openOperationAckV1(controlDirectionRelayV1, context, record, open)
}

func (ClientControlCodecV1) SealCloseV1(context ControlContextV1, epoch, sequence uint64, close CloseV1, seal ControlSealV1) ([]byte, error) {
	return sealCloseV1(controlDirectionClientV1, context, epoch, sequence, close, seal)
}

func (ClientControlCodecV1) OpenCloseV1(context ControlContextV1, record []byte, open ControlOpenV1) (CloseV1, error) {
	return openCloseV1(controlDirectionRelayV1, context, record, open)
}

func (RelayControlCodecV1) SealOperationAckV1(context ControlContextV1, epoch, sequence uint64, ack OperationAckV1, seal ControlSealV1) ([]byte, error) {
	return sealOperationAckV1(controlDirectionRelayV1, context, epoch, sequence, ack, seal)
}

func (RelayControlCodecV1) OpenOperationAckV1(context ControlContextV1, record []byte, open ControlOpenV1) (OperationAckV1, error) {
	return openOperationAckV1(controlDirectionClientV1, context, record, open)
}

func (RelayControlCodecV1) SealCloseV1(context ControlContextV1, epoch, sequence uint64, close CloseV1, seal ControlSealV1) ([]byte, error) {
	return sealCloseV1(controlDirectionRelayV1, context, epoch, sequence, close, seal)
}

func (RelayControlCodecV1) OpenCloseV1(context ControlContextV1, record []byte, open ControlOpenV1) (CloseV1, error) {
	return openCloseV1(controlDirectionClientV1, context, record, open)
}

func sealOperationAckV1(direction uint16, context ControlContextV1, epoch, sequence uint64, ack OperationAckV1, seal ControlSealV1) ([]byte, error) {
	body, err := encodeOperationAckBodyV1(ack)
	if err != nil {
		return nil, err
	}
	return sealControlRecordV1(context, epoch, direction, sequence, RecordTypeOperationAckV1, operationAckSealedBytesV1, body[:], seal)
}

func openOperationAckV1(direction uint16, context ControlContextV1, record []byte, open ControlOpenV1) (OperationAckV1, error) {
	header, sealed, err := parseControlRecordV1(record, direction, RecordTypeOperationAckV1)
	if err != nil || open == nil {
		return OperationAckV1{}, ErrRecordInvalid
	}
	aad := encodeControlAADV1(header, context)
	body, err := open(
		header.Epoch,
		header.Sequence,
		append([]byte(nil), sealed...),
		append([]byte(nil), aad[:]...),
	)
	if err != nil {
		return OperationAckV1{}, ErrRecordInvalid
	}
	ack, err := parseOperationAckBodyV1(body)
	if err != nil {
		return OperationAckV1{}, ErrOperationAckInvalid
	}
	return ack, nil
}

func sealCloseV1(direction uint16, context ControlContextV1, epoch, sequence uint64, close CloseV1, seal ControlSealV1) ([]byte, error) {
	body, err := encodeCloseBodyV1(close)
	if err != nil {
		return nil, err
	}
	return sealControlRecordV1(context, epoch, direction, sequence, RecordTypeCloseV1, closeSealedBytesV1, body[:], seal)
}

func openCloseV1(direction uint16, context ControlContextV1, record []byte, open ControlOpenV1) (CloseV1, error) {
	header, sealed, err := parseControlRecordV1(record, direction, RecordTypeCloseV1)
	if err != nil || open == nil {
		return CloseV1{}, ErrRecordInvalid
	}
	aad := encodeControlAADV1(header, context)
	body, err := open(
		header.Epoch,
		header.Sequence,
		append([]byte(nil), sealed...),
		append([]byte(nil), aad[:]...),
	)
	if err != nil {
		return CloseV1{}, ErrRecordInvalid
	}
	close, err := parseCloseBodyV1(body)
	if err != nil {
		return CloseV1{}, ErrRecordInvalid
	}
	return close, nil
}

func sealControlRecordV1(context ControlContextV1, epoch uint64, direction uint16, sequence uint64, recordType uint16, sealedLength uint32, body []byte, seal ControlSealV1) ([]byte, error) {
	if seal == nil {
		return nil, ErrRecordInvalid
	}
	header := ControlHeaderV1{
		Version:      ControlRecordVersionV1,
		Type:         recordType,
		Epoch:        epoch,
		Direction:    direction,
		Sequence:     sequence,
		SealedLength: sealedLength,
	}
	headerBytes := encodeControlHeaderV1(header)
	aad := encodeControlAADV1(header, context)
	sealed, err := seal(
		header.Epoch,
		header.Sequence,
		append([]byte(nil), body...),
		append([]byte(nil), aad[:]...),
	)
	if err != nil || len(sealed) != int(sealedLength) {
		return nil, ErrRecordInvalid
	}
	record := make([]byte, 0, controlHeaderBytesV1+len(sealed))
	record = append(record, headerBytes[:]...)
	record = append(record, sealed...)
	return record, nil
}

func parseControlRecordV1(record []byte, expectedDirection, expectedType uint16) (ControlHeaderV1, []byte, error) {
	if len(record) < controlHeaderBytesV1 {
		return ControlHeaderV1{}, nil, ErrRecordInvalid
	}
	header, err := parseControlHeaderV1(record[:controlHeaderBytesV1])
	if err != nil || header.Version != ControlRecordVersionV1 {
		return ControlHeaderV1{}, nil, ErrRecordInvalid
	}
	if header.Type != RecordTypeOperationAckV1 && header.Type != RecordTypeCloseV1 {
		return ControlHeaderV1{}, nil, ErrRecordInvalid
	}
	if header.Type != expectedType || header.Direction != expectedDirection {
		return ControlHeaderV1{}, nil, ErrRecordInvalid
	}
	expectedSealedLength, ok := controlSealedLengthV1(header.Type)
	if !ok || header.SealedLength != expectedSealedLength {
		return ControlHeaderV1{}, nil, ErrRecordInvalid
	}
	total := uint64(controlHeaderBytesV1) + uint64(header.SealedLength)
	maxInt := uint64(^uint(0) >> 1)
	if total > maxInt || total != uint64(len(record)) {
		return ControlHeaderV1{}, nil, ErrRecordInvalid
	}
	return header, record[controlHeaderBytesV1:], nil
}

func controlSealedLengthV1(recordType uint16) (uint32, bool) {
	switch recordType {
	case RecordTypeOperationAckV1:
		return operationAckSealedBytesV1, true
	case RecordTypeCloseV1:
		return closeSealedBytesV1, true
	default:
		return 0, false
	}
}

func encodeControlHeaderV1(header ControlHeaderV1) [controlHeaderBytesV1]byte {
	var out [controlHeaderBytesV1]byte
	binary.BigEndian.PutUint16(out[0:2], header.Version)
	binary.BigEndian.PutUint16(out[2:4], header.Type)
	binary.BigEndian.PutUint64(out[4:12], header.Epoch)
	binary.BigEndian.PutUint16(out[12:14], header.Direction)
	binary.BigEndian.PutUint64(out[14:22], header.Sequence)
	binary.BigEndian.PutUint32(out[22:26], header.SealedLength)
	return out
}

func parseControlHeaderV1(encoded []byte) (ControlHeaderV1, error) {
	if len(encoded) != controlHeaderBytesV1 {
		return ControlHeaderV1{}, ErrRecordInvalid
	}
	return ControlHeaderV1{
		Version:      binary.BigEndian.Uint16(encoded[0:2]),
		Type:         binary.BigEndian.Uint16(encoded[2:4]),
		Epoch:        binary.BigEndian.Uint64(encoded[4:12]),
		Direction:    binary.BigEndian.Uint16(encoded[12:14]),
		Sequence:     binary.BigEndian.Uint64(encoded[14:22]),
		SealedLength: binary.BigEndian.Uint32(encoded[22:26]),
	}, nil
}

func encodeControlAADV1(header ControlHeaderV1, context ControlContextV1) [controlAADBytesV1]byte {
	var out [controlAADBytesV1]byte
	binary.BigEndian.PutUint16(out[0:2], header.Version)
	binary.BigEndian.PutUint16(out[2:4], header.Type)
	copy(out[4:36], context.EffectivePolicyHash[:])
	copy(out[36:68], context.TH4[:])
	binary.BigEndian.PutUint64(out[68:76], header.Epoch)
	binary.BigEndian.PutUint16(out[76:78], header.Direction)
	binary.BigEndian.PutUint64(out[78:86], header.Sequence)
	binary.BigEndian.PutUint32(out[86:90], header.SealedLength)
	return out
}

func encodeOperationAckBodyV1(ack OperationAckV1) ([operationAckBodyBytesV1]byte, error) {
	if !validOperationAckV1(ack) {
		return [operationAckBodyBytesV1]byte{}, ErrOperationAckInvalid
	}
	var out [operationAckBodyBytesV1]byte
	binary.BigEndian.PutUint16(out[0:2], ControlRecordVersionV1)
	binary.BigEndian.PutUint16(out[2:4], RecordTypeOperationAckV1)
	copy(out[4:36], ack.OperationID[:])
	binary.BigEndian.PutUint64(out[36:44], ack.CompletedCount)
	return out, nil
}

func parseOperationAckBodyV1(encoded []byte) (OperationAckV1, error) {
	if len(encoded) != operationAckBodyBytesV1 ||
		binary.BigEndian.Uint16(encoded[0:2]) != ControlRecordVersionV1 ||
		binary.BigEndian.Uint16(encoded[2:4]) != RecordTypeOperationAckV1 {
		return OperationAckV1{}, ErrOperationAckInvalid
	}
	var ack OperationAckV1
	copy(ack.OperationID[:], encoded[4:36])
	ack.CompletedCount = binary.BigEndian.Uint64(encoded[36:44])
	if !validOperationAckV1(ack) {
		return OperationAckV1{}, ErrOperationAckInvalid
	}
	return ack, nil
}

func validOperationAckV1(ack OperationAckV1) bool {
	return ack.OperationID != [32]byte{} && ack.CompletedCount != 0
}

func encodeCloseBodyV1(close CloseV1) ([closeBodyBytesV1]byte, error) {
	if close.Code != CloseCodeTerminalV1 {
		return [closeBodyBytesV1]byte{}, ErrRecordInvalid
	}
	var out [closeBodyBytesV1]byte
	binary.BigEndian.PutUint16(out[0:2], ControlRecordVersionV1)
	binary.BigEndian.PutUint16(out[2:4], RecordTypeCloseV1)
	binary.BigEndian.PutUint16(out[4:6], close.Code)
	return out, nil
}

func parseCloseBodyV1(encoded []byte) (CloseV1, error) {
	if len(encoded) != closeBodyBytesV1 ||
		binary.BigEndian.Uint16(encoded[0:2]) != ControlRecordVersionV1 ||
		binary.BigEndian.Uint16(encoded[2:4]) != RecordTypeCloseV1 ||
		binary.BigEndian.Uint16(encoded[4:6]) != CloseCodeTerminalV1 {
		return CloseV1{}, ErrRecordInvalid
	}
	return CloseV1{Code: CloseCodeTerminalV1}, nil
}
