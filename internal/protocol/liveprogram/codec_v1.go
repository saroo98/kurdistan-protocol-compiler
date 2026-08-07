// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package liveprogram

import (
	"bytes"
	"fmt"

	"github.com/fxamacker/cbor/v2"
)

const programFieldCount = 11

func EncodeV1(program ProgramV1) ([]byte, error) {
	if err := ValidateV1(program); err != nil {
		return nil, err
	}
	encoded, err := marshal(programMap(program))
	if err != nil {
		return nil, fail(ErrorNonCanonical)
	}
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return nil, fail(ErrorSize)
	}
	return encoded, nil
}

func DecodeV1(encoded []byte) (ProgramV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxEncodedBytes {
		return ProgramV1{}, fail(ErrorSize)
	}
	if err := validateCore(encoded); err != nil {
		return ProgramV1{}, fail(ErrorNonCanonical)
	}
	fields, err := rawMap(encoded, programFieldCount)
	if err != nil {
		return ProgramV1{}, err
	}
	var program ProgramV1
	if err := decode(fields[1], &program.Schema); err != nil || program.Schema != SchemaV1 {
		return ProgramV1{}, fail(ErrorSchema)
	}
	if err := fixedBytes(fields[2], program.ProgramID[:]); err != nil {
		return ProgramV1{}, fail(ErrorSchema)
	}
	if err := decode(fields[3], &program.SourceSchemaVersion); err != nil {
		return ProgramV1{}, fail(ErrorSchema)
	}
	if err := fixedBytes(fields[4], program.SourceGenerationHash[:]); err != nil {
		return ProgramV1{}, fail(ErrorSchema)
	}
	if program.Messages, err = decodeMessages(fields[5]); err != nil {
		return ProgramV1{}, err
	}
	if program.Frame, err = decodeFrame(fields[6]); err != nil {
		return ProgramV1{}, err
	}
	if program.Scheduler, err = decodeScheduler(fields[7]); err != nil {
		return ProgramV1{}, err
	}
	if program.Stream, err = decodeStream(fields[8]); err != nil {
		return ProgramV1{}, err
	}
	if program.Padding, err = decodePadding(fields[9]); err != nil {
		return ProgramV1{}, err
	}
	if program.Security, err = decodeSecurity(fields[10]); err != nil {
		return ProgramV1{}, err
	}
	if program.Limits, err = decodeLimits(fields[11]); err != nil {
		return ProgramV1{}, err
	}
	if err := ValidateV1(program); err != nil {
		return ProgramV1{}, err
	}
	reencoded, err := EncodeV1(program)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return ProgramV1{}, fail(ErrorNonCanonical)
	}
	return program.Clone(), nil
}

func programMap(p ProgramV1) map[uint64]any {
	return map[uint64]any{
		1: p.Schema, 2: p.ProgramID[:], 3: p.SourceSchemaVersion, 4: p.SourceGenerationHash[:],
		5: messageMaps(p.Messages), 6: frameMap(p.Frame), 7: schedulerMap(p.Scheduler), 8: streamMap(p.Stream),
		9: paddingMap(p.Padding), 10: securityMap(p.Security), 11: limitsMap(p.Limits),
	}
}

func messageMaps(values []MessageV1) []any {
	out := make([]any, len(values))
	for i, value := range values {
		out[i] = map[uint64]any{1: value.Semantic, 2: value.WireSymbol, 3: value.Direction, 4: value.MinPayloadBytes, 5: value.MaxPayloadBytes}
	}
	return out
}

func frameMap(value FrameV1) map[uint64]any {
	return map[uint64]any{1: value.LengthMode, 2: value.TypeMode, 3: append([]string(nil), value.HeaderOrder...), 4: value.FragmentationMode, 5: value.ChecksumMode, 6: value.PaddingPlacement,
		7: map[uint64]any{1: append([]byte(nil), value.Compiled.DataTypeTag...), 2: append([]byte(nil), value.Compiled.PaddingTypeTag...), 3: value.Compiled.ProfileXORStreamMask, 4: value.Compiled.TableStreamMask, 5: value.Compiled.CRC32PrefixState}}
}

func schedulerMap(value SchedulerV1) map[uint64]any {
	return map[uint64]any{1: value.Mode, 2: value.MaxBatchBytes, 3: value.FlushIntervalMs, 4: value.MaxInFlightFrames, 5: value.PriorityMode}
}

func streamMap(value StreamV1) map[uint64]any {
	return map[uint64]any{1: value.IDEncodingMode, 2: value.MaxConcurrentStreams}
}

func paddingMap(value PaddingV1) map[uint64]any {
	return map[uint64]any{1: value.Mode, 2: value.MinPaddingBytes, 3: value.MaxPaddingBytes, 4: value.Probability}
}

func securityMap(value SecurityV1) map[uint64]any {
	return map[uint64]any{1: value.CompilerSecurityVersion, 2: value.MinimumRuntimeVersion, 3: securityPolicyMap(value.Policy),
		4: append([]string(nil), value.ClientMandatoryCapabilities...), 5: append([]string(nil), value.RelayMandatoryCapabilities...), 6: append([]string(nil), value.SelectedCapabilities...)}
}

func securityPolicyMap(value SecurityPolicyV1) map[uint64]any {
	return map[uint64]any{1: value.SecurityVersion, 2: value.TranscriptMode, 3: value.KDFSuite, 4: value.AEADSuite, 5: value.MACSuite, 6: value.NonceMode, 7: value.ReplayPolicy, 8: value.ReplayWindowSize,
		9: value.DowngradePolicy, 10: value.CapabilityNegotiationPolicy, 11: value.ProfileCompatibilityPolicy, 12: value.KeyRotationPolicy, 13: value.ConfigValidationPolicy, 14: value.SecureEnvelopeMode,
		15: value.MaxSessionMessages, 16: value.MaxKeyLifetimeMessages}
}

func limitsMap(value LimitsV1) map[uint64]any {
	return map[uint64]any{1: value.MaxFrameBytes, 2: value.MaxPayloadBytes, 3: value.MaxSessionMillis, 4: value.MaxSessionMessages, 5: value.MaxKeyLifetimeMessages}
}

func decodeMessages(raw []byte) ([]MessageV1, error) {
	var values []cbor.RawMessage
	if err := decode(raw, &values); err != nil || len(values) != 2 {
		return nil, fail(ErrorSchema)
	}
	out := make([]MessageV1, len(values))
	for i, item := range values {
		fields, err := rawMap(item, 5)
		if err != nil || decode(fields[1], &out[i].Semantic) != nil || decode(fields[2], &out[i].WireSymbol) != nil || decode(fields[3], &out[i].Direction) != nil || decode(fields[4], &out[i].MinPayloadBytes) != nil || decode(fields[5], &out[i].MaxPayloadBytes) != nil {
			return nil, fail(ErrorSchema)
		}
	}
	return out, nil
}

func decodeFrame(raw []byte) (FrameV1, error) {
	fields, err := rawMap(raw, 7)
	if err != nil {
		return FrameV1{}, err
	}
	var out FrameV1
	if decode(fields[1], &out.LengthMode) != nil || decode(fields[2], &out.TypeMode) != nil || decode(fields[3], &out.HeaderOrder) != nil || decode(fields[4], &out.FragmentationMode) != nil || decode(fields[5], &out.ChecksumMode) != nil || decode(fields[6], &out.PaddingPlacement) != nil {
		return FrameV1{}, fail(ErrorSchema)
	}
	compiled, err := rawMap(fields[7], 5)
	if err != nil || decode(compiled[1], &out.Compiled.DataTypeTag) != nil || decode(compiled[2], &out.Compiled.PaddingTypeTag) != nil || decode(compiled[3], &out.Compiled.ProfileXORStreamMask) != nil || decode(compiled[4], &out.Compiled.TableStreamMask) != nil || decode(compiled[5], &out.Compiled.CRC32PrefixState) != nil {
		return FrameV1{}, fail(ErrorSchema)
	}
	return out, nil
}

func decodeScheduler(raw []byte) (SchedulerV1, error) {
	fields, err := rawMap(raw, 5)
	if err != nil {
		return SchedulerV1{}, err
	}
	var out SchedulerV1
	if decode(fields[1], &out.Mode) != nil || decode(fields[2], &out.MaxBatchBytes) != nil || decode(fields[3], &out.FlushIntervalMs) != nil || decode(fields[4], &out.MaxInFlightFrames) != nil || decode(fields[5], &out.PriorityMode) != nil {
		return SchedulerV1{}, fail(ErrorSchema)
	}
	return out, nil
}

func decodeStream(raw []byte) (StreamV1, error) {
	fields, err := rawMap(raw, 2)
	if err != nil {
		return StreamV1{}, err
	}
	var out StreamV1
	if decode(fields[1], &out.IDEncodingMode) != nil || decode(fields[2], &out.MaxConcurrentStreams) != nil {
		return StreamV1{}, fail(ErrorSchema)
	}
	return out, nil
}

func decodePadding(raw []byte) (PaddingV1, error) {
	fields, err := rawMap(raw, 4)
	if err != nil {
		return PaddingV1{}, err
	}
	var out PaddingV1
	if decode(fields[1], &out.Mode) != nil || decode(fields[2], &out.MinPaddingBytes) != nil || decode(fields[3], &out.MaxPaddingBytes) != nil || decode(fields[4], &out.Probability) != nil {
		return PaddingV1{}, fail(ErrorSchema)
	}
	return out, nil
}

func decodeSecurity(raw []byte) (SecurityV1, error) {
	fields, err := rawMap(raw, 6)
	if err != nil {
		return SecurityV1{}, err
	}
	var out SecurityV1
	if decode(fields[1], &out.CompilerSecurityVersion) != nil || decode(fields[2], &out.MinimumRuntimeVersion) != nil || decode(fields[4], &out.ClientMandatoryCapabilities) != nil || decode(fields[5], &out.RelayMandatoryCapabilities) != nil || decode(fields[6], &out.SelectedCapabilities) != nil {
		return SecurityV1{}, fail(ErrorSchema)
	}
	policy, err := rawMap(fields[3], 16)
	if err != nil {
		return SecurityV1{}, err
	}
	values := []any{&out.Policy.SecurityVersion, &out.Policy.TranscriptMode, &out.Policy.KDFSuite, &out.Policy.AEADSuite, &out.Policy.MACSuite, &out.Policy.NonceMode, &out.Policy.ReplayPolicy, &out.Policy.ReplayWindowSize,
		&out.Policy.DowngradePolicy, &out.Policy.CapabilityNegotiationPolicy, &out.Policy.ProfileCompatibilityPolicy, &out.Policy.KeyRotationPolicy, &out.Policy.ConfigValidationPolicy, &out.Policy.SecureEnvelopeMode, &out.Policy.MaxSessionMessages, &out.Policy.MaxKeyLifetimeMessages}
	for index, destination := range values {
		if decode(policy[uint64(index+1)], destination) != nil {
			return SecurityV1{}, fail(ErrorSchema)
		}
	}
	return out, nil
}

func decodeLimits(raw []byte) (LimitsV1, error) {
	fields, err := rawMap(raw, 5)
	if err != nil {
		return LimitsV1{}, err
	}
	var out LimitsV1
	if decode(fields[1], &out.MaxFrameBytes) != nil || decode(fields[2], &out.MaxPayloadBytes) != nil || decode(fields[3], &out.MaxSessionMillis) != nil || decode(fields[4], &out.MaxSessionMessages) != nil || decode(fields[5], &out.MaxKeyLifetimeMessages) != nil {
		return LimitsV1{}, fail(ErrorSchema)
	}
	return out, nil
}

func marshal(value any) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

func decode(raw []byte, value any) error {
	mode, err := strictMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(raw, value)
}

func rawMap(raw []byte, count int) (map[uint64]cbor.RawMessage, error) {
	var fields map[uint64]cbor.RawMessage
	if decode(raw, &fields) != nil || len(fields) != count {
		return nil, fail(ErrorSchema)
	}
	for label := uint64(1); label <= uint64(count); label++ {
		if _, ok := fields[label]; !ok {
			return nil, fail(ErrorSchema)
		}
	}
	return fields, nil
}

func fixedBytes(raw []byte, destination []byte) error {
	var value []byte
	if decode(raw, &value) != nil || len(value) != len(destination) {
		return fmt.Errorf("fixed bytes")
	}
	copy(destination, value)
	return nil
}

func validateCore(encoded []byte) error {
	mode, err := strictMode()
	if err != nil {
		return err
	}
	var value any
	if err := mode.Unmarshal(encoded, &value); err != nil {
		return err
	}
	canonical, err := marshal(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return fmt.Errorf("noncanonical")
	}
	return nil
}

func strictMode() (cbor.DecMode, error) {
	return cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxNestedLevels: 32, MaxArrayElements: 64, MaxMapPairs: 32,
		IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, IntDec: cbor.IntDecConvertNone, UTF8: cbor.UTF8RejectInvalid, BignumTag: cbor.BignumTagForbidden}.DecMode()
}
