// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"errors"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/product/profile"
)

const activationWireVersion = uint64(1)

type ActivationEnvironment interface {
	NewActivationSession(VerifyPreview) (*profile.ActivationSession, error)
}

type activationRecordWire struct {
	Version uint64                   `cbor:"1,keyasint"`
	Record  profile.ActivationRecord `cbor:"2,keyasint"`
}

type activationHandle struct {
	session *profile.ActivationSession
}

func (state *activationHandle) Destroy() {
	if state == nil {
		return
	}
	state.session.Destroy()
	state.session = nil
}

type ActivationNext struct {
	Sequence uint64
	Kind     profile.ActivationCommandKind
	Payload  []byte
}

const ActivationCommandComplete profile.ActivationCommandKind = "complete"

// OpenActivation consumes a verified-preview handle and creates the strictly
// ordered Phase 8 activation session selected by the installed trust
// environment. Release builds intentionally provide no environment.
func OpenActivation(registry *HandleRegistry, verified Handle, environment ActivationEnvironment) (Handle, ErrorCode) {
	if registry == nil || environment == nil {
		return 0, CodeTrustUnavailable
	}
	value, code := registry.Get(verified, HandleVerifyPreview)
	if code != CodeOK {
		return 0, code
	}
	preview, ok := value.(*VerifyPreview)
	if !ok || preview == nil {
		return 0, CodeInternalFailure
	}
	session, err := environment.NewActivationSession(*preview)
	if err != nil || session == nil {
		return 0, CodeVerificationRejected
	}
	return registry.Open(HandleActivation, &activationHandle{session: session})
}

func ActivationNextCommand(registry *HandleRegistry, handle Handle) (ActivationNext, ErrorCode) {
	value, code := registry.Get(handle, HandleActivation)
	if code != CodeOK {
		return ActivationNext{}, code
	}
	state, ok := value.(*activationHandle)
	if !ok || state.session == nil {
		return ActivationNext{}, CodeInternalFailure
	}
	command, ok := state.session.Next()
	if !ok {
		record, err := state.session.Result()
		if err != nil {
			return ActivationNext{}, activationErrorCode(err)
		}
		encoded, err := EncodeActivationRecord(record)
		if err != nil {
			return ActivationNext{}, CodeInternalFailure
		}
		return ActivationNext{Kind: ActivationCommandComplete, Payload: encoded}, CodeOK
	}
	next := ActivationNext{Sequence: command.Sequence, Kind: command.Kind}
	if command.Kind == profile.ActivationCommandStageCandidate {
		encoded, err := EncodeActivationRecord(command.Record)
		if err != nil {
			return ActivationNext{}, CodeInternalFailure
		}
		next.Payload = encoded
	}
	return next, CodeOK
}

// SubmitActivationCommand accepts only the categorical storage outcome and the
// bounded opaque record bytes required by snapshot/reopen commands.
func SubmitActivationCommand(
	registry *HandleRegistry,
	handle Handle,
	sequence uint64,
	kind profile.ActivationCommandKind,
	storageOK bool,
	active, lastKnownGood, reopened []byte,
) ErrorCode {
	value, code := registry.Get(handle, HandleActivation)
	if code != CodeOK {
		return code
	}
	state, ok := value.(*activationHandle)
	if !ok || state.session == nil {
		return CodeInternalFailure
	}
	result := profile.ActivationCommandResult{}
	if !storageOK {
		result.Err = errors.New("androidbridge: categorical storage failure")
	} else {
		var err error
		switch kind {
		case profile.ActivationCommandSnapshot:
			if len(active) != 0 {
				result.Active, err = DecodeActivationRecord(active)
			}
			if err == nil && len(lastKnownGood) != 0 {
				result.LastKnownGood, err = DecodeActivationRecord(lastKnownGood)
			}
		case profile.ActivationCommandReopenCandidate:
			if len(reopened) == 0 {
				err = errors.New("androidbridge: missing reopened record")
			} else {
				result.Record, err = DecodeActivationRecord(reopened)
			}
		default:
			if len(active) != 0 || len(lastKnownGood) != 0 || len(reopened) != 0 {
				err = errors.New("androidbridge: unexpected command payload")
			}
		}
		if err != nil {
			return CodeInvalidArgument
		}
	}
	command := profile.ActivationCommand{Sequence: sequence, Kind: kind}
	if err := state.session.Submit(command, result); err != nil {
		return CodePolicyRejected
	}
	return CodeOK
}

func ActivationResult(registry *HandleRegistry, handle Handle) ([]byte, ErrorCode) {
	value, code := registry.Get(handle, HandleActivation)
	if code != CodeOK {
		return nil, code
	}
	state, ok := value.(*activationHandle)
	if !ok || state.session == nil {
		return nil, CodeInternalFailure
	}
	record, err := state.session.Result()
	if err != nil {
		return nil, activationErrorCode(err)
	}
	encoded, err := EncodeActivationRecord(record)
	if err != nil {
		return nil, CodeInternalFailure
	}
	return encoded, CodeOK
}

func EncodeActivationRecord(record profile.ActivationRecord) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	encoded, err := mode.Marshal(activationRecordWire{Version: activationWireVersion, Record: record})
	if err != nil || len(encoded) == 0 || len(encoded) > MaxBridgeResultBytes {
		return nil, errors.New("androidbridge: activation record exceeds boundary")
	}
	return encoded, nil
}

func DecodeActivationRecord(encoded []byte) (profile.ActivationRecord, error) {
	if len(encoded) == 0 || len(encoded) > MaxBridgeResultBytes {
		return profile.ActivationRecord{}, errors.New("androidbridge: invalid activation record")
	}
	options := cbor.DecOptions{
		DupMapKey:         cbor.DupMapKeyEnforcedAPF,
		IndefLength:       cbor.IndefLengthForbidden,
		MaxNestedLevels:   16,
		MaxArrayElements:  2048,
		MaxMapPairs:       128,
		ExtraReturnErrors: cbor.ExtraDecErrorUnknownField,
	}
	mode, err := options.DecMode()
	if err != nil {
		return profile.ActivationRecord{}, err
	}
	var wire activationRecordWire
	if err := mode.Unmarshal(encoded, &wire); err != nil || wire.Version != activationWireVersion {
		return profile.ActivationRecord{}, errors.New("androidbridge: invalid activation record")
	}
	canonical, err := EncodeActivationRecord(wire.Record)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return profile.ActivationRecord{}, errors.New("androidbridge: non-canonical activation record")
	}
	return wire.Record, nil
}

func activationErrorCode(err error) ErrorCode {
	var activation *profile.ActivationError
	if !errors.As(err, &activation) {
		return CodeInternalFailure
	}
	switch activation.Code {
	case profile.ActivationInvalidArtifact, profile.ActivationTrustRejected:
		return CodeVerificationRejected
	case profile.ActivationPolicyRejected:
		return CodePolicyRejected
	case profile.ActivationStorageFailure:
		return CodeStorageFailure
	case profile.ActivationRecoveryFailure:
		return CodeRecoveryRequired
	case profile.ActivationQuarantineFailure:
		return CodeQuarantined
	default:
		return CodeInternalFailure
	}
}
