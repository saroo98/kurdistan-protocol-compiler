// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package liveprogram

import (
	"bytes"
	"crypto/sha256"
	"math"
	"testing"
)

func TestProgramV1RoundTripIsCanonicalAndCloneIsDefensive(t *testing.T) {
	program := fixtureProgramV1()
	encoded, err := EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeV1(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeV1(decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encoded, reencoded) {
		t.Fatal("canonical program round trip changed bytes")
	}
	clone := decoded.Clone()
	clone.Messages[0].WireSymbol = "mutated"
	clone.Security.ClientMandatoryCapabilities[0] = "mutated"
	if decoded.Messages[0].WireSymbol == clone.Messages[0].WireSymbol || decoded.Security.ClientMandatoryCapabilities[0] == clone.Security.ClientMandatoryCapabilities[0] {
		t.Fatal("program clone aliases caller-visible state")
	}
}

func TestProgramV1RejectsUnsafeShapeAndMalleableCBOR(t *testing.T) {
	valid := fixtureProgramV1()
	for name, mutate := range map[string]func(*ProgramV1){
		"extra semantic": func(p *ProgramV1) {
			p.Messages = append(p.Messages, MessageV1{Semantic: "open_stream", WireSymbol: "open", Direction: "bidirectional", MinPayloadBytes: 0, MaxPayloadBytes: 1024})
		},
		"duplicate wire symbol":          func(p *ProgramV1) { p.Messages[1].WireSymbol = p.Messages[0].WireSymbol },
		"invalid scheduler bound":        func(p *ProgramV1) { p.Scheduler.MaxBatchBytes = 0 },
		"invalid stream bound":           func(p *ProgramV1) { p.Stream.MaxConcurrentStreams = 65 },
		"invalid padding bound":          func(p *ProgramV1) { p.Padding.Probability = 2 },
		"non-finite padding probability": func(p *ProgramV1) { p.Padding.Probability = math.NaN() },
		"missing compiled data type tag": func(p *ProgramV1) { p.Frame.Compiled.DataTypeTag = nil },
		"equal compiled type tags":       func(p *ProgramV1) { p.Frame.Compiled.DataTypeTag = bytes.Clone(p.Frame.Compiled.PaddingTypeTag) },
	} {
		t.Run(name, func(t *testing.T) {
			candidate := valid.Clone()
			mutate(&candidate)
			if err := ValidateV1(candidate); err == nil {
				t.Fatal("unsafe program accepted")
			}
		})
	}
	for name, encoded := range map[string][]byte{
		"duplicate key":     {0xa2, 0x01, 0x01, 0x01, 0x01},
		"indefinite map":    {0xbf, 0x01, 0x01, 0xff},
		"tag":               {0xc0, 0xa0},
		"nonminimal number": {0xa1, 0x18, 0x01, 0x01},
		"unknown label":     {0xa1, 0x18, 0x1a, 0x01},
		"oversized":         make([]byte, MaxEncodedBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeV1(encoded); err == nil {
				t.Fatal("malleable or oversized program was accepted")
			}
		})
	}
}

func TestProgramV1DecodeRejectsNonFinitePaddingProbability(t *testing.T) {
	for name, probability := range map[string]float64{"nan": math.NaN(), "positive infinity": math.Inf(1), "negative infinity": math.Inf(-1)} {
		t.Run(name, func(t *testing.T) {
			candidate := fixtureProgramV1()
			candidate.Padding.Probability = probability
			encoded, err := marshal(programMap(candidate))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeV1(encoded); err == nil {
				t.Fatal("non-finite padding probability decoded")
			}
		})
	}
}

func TestProgramV1RejectsPaddingWiderThanFrame(t *testing.T) {
	program := fixtureProgramV1()
	program.Padding.MaxPaddingBytes = program.Limits.MaxFrameBytes + 1
	if err := ValidateV1(program); err == nil {
		t.Fatal("padding wider than the maximum frame was accepted")
	}
}

func fixtureProgramV1() ProgramV1 {
	var source [32]byte
	for i := range source {
		source[i] = byte(i + 1)
	}
	digest := sha256.Sum256(append([]byte("kurd-live-program-v1\x00"), source[:]...))
	var id [16]byte
	copy(id[:], digest[:16])
	return ProgramV1{
		Schema:               SchemaV1,
		ProgramID:            id,
		SourceSchemaVersion:  "0.2.0-lab",
		SourceGenerationHash: source,
		Messages: []MessageV1{
			{Semantic: "data", WireSymbol: "data", Direction: "bidirectional", MinPayloadBytes: 0, MaxPayloadBytes: 4096},
			{Semantic: "padding", WireSymbol: "padding", Direction: "bidirectional", MinPayloadBytes: 0, MaxPayloadBytes: 4096},
		},
		Frame:     FrameV1{LengthMode: "varint_prefix", TypeMode: "explicit_generated_tag", HeaderOrder: []string{"length", "type", "stream", "flags"}, FragmentationMode: "bounded_variable_chunks", ChecksumMode: "crc32", PaddingPlacement: "suffix", Compiled: CompiledFramingV1{DataTypeTag: []byte("data"), PaddingTypeTag: []byte("padding"), ProfileXORStreamMask: 1, TableStreamMask: 2, CRC32PrefixState: 3}},
		Scheduler: SchedulerV1{Mode: "balanced", MaxBatchBytes: 4096, FlushIntervalMs: 10, MaxInFlightFrames: 4, PriorityMode: "fifo"},
		Stream:    StreamV1{IDEncodingMode: "fixed32_be", MaxConcurrentStreams: 16},
		Padding:   PaddingV1{Mode: "bounded", MinPaddingBytes: 1, MaxPaddingBytes: 8, Probability: 1},
		Security: SecurityV1{
			CompilerSecurityVersion: "0.13.0-lab", MinimumRuntimeVersion: "0.13.0-lab",
			Policy:                      SecurityPolicyV1{SecurityVersion: "0.13.0-lab", TranscriptMode: "canonical_v1", KDFSuite: "kdf_hkdf_sha256", AEADSuite: "aead_aes_256_gcm", MACSuite: "mac_hmac_sha256", NonceMode: "counter_xor_base", ReplayPolicy: "ordered_only", ReplayWindowSize: 64, DowngradePolicy: "strict_capabilities", CapabilityNegotiationPolicy: "strict_required", ProfileCompatibilityPolicy: "strict_schema", KeyRotationPolicy: "session_only", ConfigValidationPolicy: "strict_required", SecureEnvelopeMode: "metadata_authenticated", MaxSessionMessages: 1024, MaxKeyLifetimeMessages: 512},
			ClientMandatoryCapabilities: []string{"multi_stream"}, RelayMandatoryCapabilities: []string{"multi_stream"}, SelectedCapabilities: []string{"multi_stream"},
		},
		Limits: LimitsV1{MaxFrameBytes: 8192, MaxPayloadBytes: 4096, MaxSessionMillis: 30000, MaxSessionMessages: 1024, MaxKeyLifetimeMessages: 512},
	}
}
