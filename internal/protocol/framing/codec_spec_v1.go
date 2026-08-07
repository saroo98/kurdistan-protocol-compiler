// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package framing

import (
	"encoding/binary"
	"fmt"
	"hash/crc32"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
)

// codecSpec is immutable protocol-shaping state.  Both legacy profiles and
// decoded live programs project into this structure; live programs never
// reconstruct an IR profile or retain its identifier.
type codecSpec struct {
	messages                 []codecMessage
	lengthMode, checksumMode string
	headerOrder              []string
	fragmentationMode        string
	paddingPlacement         string
	padding                  ir.PaddingPolicy
	maxFrameBytes            int
	maxPayloadBytes          int
	maxBatchBytes            int
	streamEncodingMode       string
	profileXORStreamMask     uint32
	tableStreamMask          uint32
	crc32PrefixState         uint32
}

type codecMessage struct {
	semantic, wireSymbol string
	typeTag              []byte
}

func codecSpecFromProfile(profile *ir.Profile) (codecSpec, error) {
	if err := ir.Validate(profile); err != nil {
		return codecSpec{}, err
	}
	spec := codecSpec{lengthMode: profile.FrameGrammar.LengthMode, checksumMode: profile.FrameGrammar.ChecksumMode, headerOrder: append([]string(nil), profile.FrameGrammar.HeaderOrder...), fragmentationMode: profile.FrameGrammar.FragmentationMode, paddingPlacement: profile.FrameGrammar.PaddingPlacement,
		padding: profile.Padding, maxFrameBytes: profile.Limits.MaxFrameBytes, maxPayloadBytes: profile.Limits.MaxPayloadBytes, maxBatchBytes: profile.Scheduler.MaxBatchBytes, streamEncodingMode: profile.Stream.IDEncodingMode,
		profileXORStreamMask: legacyStreamMaskFromProfile(profile, "profile"), tableStreamMask: legacyStreamMaskFromProfile(profile, "table"), crc32PrefixState: crc32.Update(0, crc32.IEEETable, []byte(profile.ID))}
	spec.messages = make([]codecMessage, len(profile.Messages))
	for index, message := range profile.Messages {
		spec.messages[index] = codecMessage{semantic: message.Semantic, wireSymbol: message.WireSymbol, typeTag: legacyTypeTagFromProfile(profile, message)}
	}
	return spec, nil
}

func codecSpecFromLiveProgram(program liveprogram.ProgramV1) (codecSpec, error) {
	if err := liveprogram.ValidateV1(program); err != nil {
		return codecSpec{}, fmt.Errorf("live program framing rejected")
	}
	spec := codecSpec{lengthMode: program.Frame.LengthMode, checksumMode: program.Frame.ChecksumMode, headerOrder: append([]string(nil), program.Frame.HeaderOrder...), fragmentationMode: program.Frame.FragmentationMode, paddingPlacement: program.Frame.PaddingPlacement,
		padding:       ir.PaddingPolicy{Mode: program.Padding.Mode, MinPaddingBytes: program.Padding.MinPaddingBytes, MaxPaddingBytes: program.Padding.MaxPaddingBytes, Probability: program.Padding.Probability},
		maxFrameBytes: program.Limits.MaxFrameBytes, maxPayloadBytes: program.Limits.MaxPayloadBytes, maxBatchBytes: program.Scheduler.MaxBatchBytes, streamEncodingMode: program.Stream.IDEncodingMode,
		profileXORStreamMask: program.Frame.Compiled.ProfileXORStreamMask, tableStreamMask: program.Frame.Compiled.TableStreamMask, crc32PrefixState: program.Frame.Compiled.CRC32PrefixState}
	spec.messages = []codecMessage{
		{semantic: program.Messages[0].Semantic, wireSymbol: program.Messages[0].WireSymbol, typeTag: append([]byte(nil), program.Frame.Compiled.DataTypeTag...)},
		{semantic: program.Messages[1].Semantic, wireSymbol: program.Messages[1].WireSymbol, typeTag: append([]byte(nil), program.Frame.Compiled.PaddingTypeTag...)},
	}
	return spec, nil
}

func legacyTypeTagFromProfile(profile *ir.Profile, message ir.MessageSymbol) []byte {
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
	default:
		return []byte(message.WireSymbol)
	}
	return nil
}

func legacyStreamMaskFromProfile(profile *ir.Profile, salt string) uint32 {
	return crc32.ChecksumIEEE([]byte(profile.ID + ":" + salt + ":" + fmt.Sprint(profile.FrameGrammar.HeaderOrder)))
}

func (spec codecSpec) messageBySemantic(semantic string) (codecMessage, bool) {
	for _, message := range spec.messages {
		if message.semantic == semantic {
			return message, true
		}
	}
	return codecMessage{}, false
}

func (spec codecSpec) messageByTag(tag []byte) (codecMessage, bool) {
	for _, message := range spec.messages {
		if string(message.typeTag) == string(tag) {
			return message, true
		}
	}
	return codecMessage{}, false
}
