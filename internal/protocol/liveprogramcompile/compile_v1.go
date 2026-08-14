// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package liveprogramcompile is the owner-side conversion boundary from the
// model/compiler IR to the product-safe runtime program.  Release consumers
// decode liveprogram directly and never import this package.
package liveprogramcompile

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"hash/crc32"
	"reflect"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
)

type InputV1 struct {
	Profile                 *ir.Profile
	ClientMandatoryFeatures []string
	RelayMandatoryFeatures  []string
	SelectedFeatures        []string
}

// ErrProjectionCollisionV1 marks a source-dependent projection collision that
// an owner-side compiler may safely retry with a fresh source candidate.
var ErrProjectionCollisionV1 = errors.New("live program projection collision")

func CompileV1(input InputV1) (liveprogram.ProgramV1, error) {
	if input.Profile == nil {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	if err := ir.Validate(input.Profile); err != nil || input.Profile.GenerationHash == "" {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	canonicalHash, err := ir.CanonicalHash(input.Profile)
	if err != nil || canonicalHash != input.Profile.GenerationHash {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	var sourceHash [32]byte
	rawHash, err := hex.DecodeString(canonicalHash)
	if err != nil || len(rawHash) != len(sourceHash) {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	copy(sourceHash[:], rawHash)
	effective, err := ir.BuildEffectiveSecurityPolicy(input.Profile, input.ClientMandatoryFeatures, input.RelayMandatoryFeatures, input.SelectedFeatures)
	if err != nil || ir.ValidateEffectiveSecurityPolicy(effective) != nil {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	data, dataOK := ir.MessageBySemantic(input.Profile, ir.SemanticData)
	padding, paddingOK := ir.MessageBySemantic(input.Profile, ir.SemanticPadding)
	if !dataOK || !paddingOK || countSemantic(input.Profile.Messages, ir.SemanticData) != 1 || countSemantic(input.Profile.Messages, ir.SemanticPadding) != 1 {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	if !liveprogram.IsSafeWireSymbolV1(data.WireSymbol) || !liveprogram.IsSafeWireSymbolV1(padding.WireSymbol) {
		return liveprogram.ProgramV1{}, ErrProjectionCollisionV1
	}
	program := liveprogram.ProgramV1{
		Schema:               liveprogram.SchemaV1,
		ProgramID:            liveprogram.DeriveProgramIDV1(sourceHash),
		SourceSchemaVersion:  input.Profile.Version,
		SourceGenerationHash: sourceHash,
		Messages: []liveprogram.MessageV1{
			{Semantic: data.Semantic, WireSymbol: data.WireSymbol, Direction: data.Direction, MinPayloadBytes: data.MinPayloadSize, MaxPayloadBytes: data.MaxPayloadSize},
			{Semantic: padding.Semantic, WireSymbol: padding.WireSymbol, Direction: padding.Direction, MinPayloadBytes: padding.MinPayloadSize, MaxPayloadBytes: padding.MaxPayloadSize},
		},
		Frame: liveprogram.FrameV1{
			LengthMode: input.Profile.FrameGrammar.LengthMode, TypeMode: input.Profile.FrameGrammar.TypeMode, HeaderOrder: append([]string(nil), input.Profile.FrameGrammar.HeaderOrder...),
			FragmentationMode: input.Profile.FrameGrammar.FragmentationMode, ChecksumMode: input.Profile.FrameGrammar.ChecksumMode, PaddingPlacement: input.Profile.FrameGrammar.PaddingPlacement,
			Compiled: liveprogram.CompiledFramingV1{DataTypeTag: legacyTypeTag(input.Profile, data), PaddingTypeTag: legacyTypeTag(input.Profile, padding), ProfileXORStreamMask: legacyStreamMask(input.Profile, "profile"), TableStreamMask: legacyStreamMask(input.Profile, "table"), CRC32PrefixState: crc32.Update(0, crc32.IEEETable, []byte(input.Profile.ID))},
		},
		Scheduler: liveprogram.SchedulerV1{Mode: input.Profile.Scheduler.Mode, MaxBatchBytes: input.Profile.Scheduler.MaxBatchBytes, FlushIntervalMs: input.Profile.Scheduler.FlushIntervalMs, MaxInFlightFrames: input.Profile.Scheduler.MaxInFlightFrames, PriorityMode: input.Profile.Scheduler.PriorityMode},
		Stream:    liveprogram.StreamV1{IDEncodingMode: input.Profile.Stream.IDEncodingMode, MaxConcurrentStreams: input.Profile.Stream.MaxConcurrentStreams},
		Padding:   liveprogram.PaddingV1{Mode: input.Profile.Padding.Mode, MinPaddingBytes: input.Profile.Padding.MinPaddingBytes, MaxPaddingBytes: input.Profile.Padding.MaxPaddingBytes, Probability: input.Profile.Padding.Probability},
		Security:  projectSecurity(input.Profile, effective),
		Limits:    liveprogram.LimitsV1{MaxFrameBytes: input.Profile.Limits.MaxFrameBytes, MaxPayloadBytes: input.Profile.Limits.MaxPayloadBytes, MaxSessionMillis: input.Profile.Limits.MaxSessionMillis, MaxSessionMessages: input.Profile.Security.MaxSessionMessages, MaxKeyLifetimeMessages: input.Profile.Security.MaxKeyLifetimeMessages},
	}
	if bytes.Equal(program.Frame.Compiled.DataTypeTag, program.Frame.Compiled.PaddingTypeTag) {
		return liveprogram.ProgramV1{}, ErrProjectionCollisionV1
	}
	if err := liveprogram.ValidateV1(program); err != nil {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	encoded, err := liveprogram.EncodeV1(program)
	if err != nil {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	decoded, err := liveprogram.DecodeV1(encoded)
	if err != nil || !reflect.DeepEqual(program, decoded) {
		return liveprogram.ProgramV1{}, errors.New("live program compilation rejected")
	}
	if bytes.Contains(encoded, []byte(input.Profile.ID)) {
		return liveprogram.ProgramV1{}, ErrProjectionCollisionV1
	}
	return decoded.Clone(), nil
}

func projectSecurity(profile *ir.Profile, effective ir.EffectiveSecurityPolicy) liveprogram.SecurityV1 {
	return liveprogram.SecurityV1{CompilerSecurityVersion: profile.Compatibility.CompilerSecurityVersion, MinimumRuntimeVersion: profile.Compatibility.MinimumRuntimeVersion,
		Policy:                      liveprogram.SecurityPolicyV1{SecurityVersion: effective.SecurityVersion, TranscriptMode: effective.TranscriptMode, KDFSuite: effective.KDFSuite, AEADSuite: effective.AEADSuite, MACSuite: effective.MACSuite, NonceMode: effective.NonceMode, ReplayPolicy: effective.ReplayPolicy, ReplayWindowSize: effective.ReplayWindowSize, DowngradePolicy: effective.DowngradePolicy, CapabilityNegotiationPolicy: effective.CapabilityNegotiationPolicy, ProfileCompatibilityPolicy: effective.ProfileCompatibilityPolicy, KeyRotationPolicy: effective.KeyRotationPolicy, ConfigValidationPolicy: effective.ConfigValidationPolicy, SecureEnvelopeMode: effective.SecureEnvelopeMode, MaxSessionMessages: effective.MaxSessionMessages, MaxKeyLifetimeMessages: effective.MaxKeyLifetimeMessages},
		ClientMandatoryCapabilities: append([]string(nil), effective.ClientMandatoryCapabilities...), RelayMandatoryCapabilities: append([]string(nil), effective.ServerMandatoryCapabilities...), SelectedCapabilities: append([]string(nil), effective.SelectedCapabilities...)}
}

func countSemantic(messages []ir.MessageSymbol, semantic string) int {
	count := 0
	for _, message := range messages {
		if message.Semantic == semantic {
			count++
		}
	}
	return count
}

func legacyTypeTag(profile *ir.Profile, message ir.MessageSymbol) []byte {
	switch profile.FrameGrammar.TypeMode {
	case "table_indexed_symbol":
		for index, candidate := range profile.Messages {
			if candidate.WireSymbol == message.WireSymbol {
				return []byte{byte(index), byte(crc32.ChecksumIEEE([]byte(profile.ID+":"+message.WireSymbol)) & 0xff)}
			}
		}
	case "derived_from_state":
		sum := crc32.ChecksumIEEE([]byte(profile.ID + ":state:" + message.WireSymbol))
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], sum)
		return out[:]
	case "derived_from_header_order":
		sum := crc32.ChecksumIEEE([]byte(fmt.Sprint(profile.FrameGrammar.HeaderOrder) + ":" + message.WireSymbol))
		var out [4]byte
		binary.BigEndian.PutUint32(out[:], sum)
		return out[:]
	}
	return []byte(message.WireSymbol)
}

func legacyStreamMask(profile *ir.Profile, salt string) uint32 {
	return crc32.ChecksumIEEE([]byte(profile.ID + ":" + salt + ":" + fmt.Sprint(profile.FrameGrammar.HeaderOrder)))
}
