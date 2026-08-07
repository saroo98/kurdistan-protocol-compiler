package framing

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func TestEncodeDecodeRoundTrip(t *testing.T) {
	p, _ := compiler.Generate(10)
	op := Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}
	frames, err := EncodeOperation(p, op, 1)
	if err != nil {
		t.Fatal(err)
	}
	got, _, err := DecodeFrames(p, frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, op.Payload) || got.Semantic != op.Semantic {
		t.Fatal("round trip mismatch")
	}
}

func TestProfileAEncodingDiffersFromProfileB(t *testing.T) {
	a, _ := compiler.Generate(10)
	b, _ := compiler.Generate(11)
	op := Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}
	framesA, _ := EncodeOperation(a, op, 1)
	framesB, _ := EncodeOperation(b, op, 1)
	if bytes.Equal(framesA[0], framesB[0]) {
		t.Fatal("different profiles produced same frame")
	}
}

func TestProfileABytesFailUnderProfileB(t *testing.T) {
	a, _ := compiler.Generate(10)
	b, _ := compiler.Generate(11)
	op := Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: []byte("hello")}
	framesA, _ := EncodeOperation(a, op, 1)
	if _, err := DecodeFrame(b, framesA[0]); err == nil {
		t.Fatal("profile A frame decoded under profile B")
	}
}

func TestLiveProgramFramingPreservesLegacyBytesAcrossCompiledModes(t *testing.T) {
	capabilities := ir.SecurityCapabilities()
	seen := map[string]bool{}
	for seed := int64(1); seed <= 96; seed++ {
		profile, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: profile, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities})
		if err != nil {
			t.Fatal(err)
		}
		for _, operation := range []Operation{{Semantic: ir.SemanticData, StreamID: 7, Sequence: 9, Payload: []byte("live-frame")}, {Semantic: ir.SemanticPadding, StreamID: 7, Sequence: 10, Payload: []byte("padding")}} {
			legacy, err := EncodeOperation(profile, operation, 99)
			if err != nil {
				t.Fatal(err)
			}
			live, err := EncodeLiveOperation(program, operation, 99)
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(live, legacy) {
				t.Fatalf("live framing bytes differ for type=%s stream=%s checksum=%s", profile.FrameGrammar.TypeMode, profile.Stream.IDEncodingMode, profile.FrameGrammar.ChecksumMode)
			}
		}
		seen[profile.FrameGrammar.TypeMode+"/"+profile.Stream.IDEncodingMode+"/"+profile.FrameGrammar.ChecksumMode] = true
	}
	if len(seen) < 12 {
		t.Fatalf("compiled corpus did not cover enough applicable framing modes: %d", len(seen))
	}
}

func TestCompiledFramingConstantsInfluenceLiveFrames(t *testing.T) {
	capabilities := ir.SecurityCapabilities()
	covered := map[string]bool{}
	for seed := int64(1); seed <= 256; seed++ {
		profile, err := compiler.Generate(seed)
		if err != nil {
			t.Fatal(err)
		}
		program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: profile, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities})
		if err != nil {
			t.Fatal(err)
		}
		operation := Operation{Semantic: ir.SemanticData, StreamID: 7, Sequence: 9, Payload: []byte("compiled-constant")}
		mutations := []struct {
			name  string
			apply func(*liveprogram.ProgramV1)
		}{
			{"data_type_tag", func(p *liveprogram.ProgramV1) { p.Frame.Compiled.DataTypeTag[0] ^= 0xff }},
			{"padding_type_tag", func(p *liveprogram.ProgramV1) { p.Frame.Compiled.PaddingTypeTag[0] ^= 0xff }},
			{"equal_type_tags", func(p *liveprogram.ProgramV1) {
				p.Frame.Compiled.DataTypeTag = append([]byte(nil), p.Frame.Compiled.PaddingTypeTag...)
			}},
		}
		if program.Stream.IDEncodingMode == "profile_xor32" {
			mutations = append(mutations, struct {
				name  string
				apply func(*liveprogram.ProgramV1)
			}{"profile_xor_mask", func(p *liveprogram.ProgramV1) { p.Frame.Compiled.ProfileXORStreamMask ^= 1 }})
		}
		if program.Stream.IDEncodingMode == "table_mapped32_le" {
			mutations = append(mutations, struct {
				name  string
				apply func(*liveprogram.ProgramV1)
			}{"table_mask", func(p *liveprogram.ProgramV1) { p.Frame.Compiled.TableStreamMask ^= 1 }})
		}
		if program.Frame.ChecksumMode == "crc32" {
			mutations = append(mutations, struct {
				name  string
				apply func(*liveprogram.ProgramV1)
			}{"crc_prefix", func(p *liveprogram.ProgramV1) { p.Frame.Compiled.CRC32PrefixState ^= 1 }})
		}
		for _, mutation := range mutations {
			candidate := program.Clone()
			mutation.apply(&candidate)
			operationForMutation := operation
			if mutation.name == "padding_type_tag" {
				operationForMutation.Semantic, operationForMutation.Payload = ir.SemanticPadding, []byte("padding")
			}
			baseline, err := EncodeLiveOperation(program, operationForMutation, 9)
			if err != nil {
				t.Fatal(err)
			}
			changed, err := EncodeLiveOperation(candidate, operationForMutation, 9)
			if err == nil && reflect.DeepEqual(baseline, changed) {
				t.Fatalf("compiled %s did not affect live framing", mutation.name)
			}
			covered[mutation.name] = true
		}
	}
	for _, name := range []string{"data_type_tag", "padding_type_tag", "profile_xor_mask", "table_mask", "crc_prefix"} {
		if !covered[name] {
			t.Fatalf("corpus did not cover compiled %s", name)
		}
	}
}

func TestEncodeLiveOperationRejectsEqualCompiledTypeTags(t *testing.T) {
	profile, err := compiler.Generate(47)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: profile, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities})
	if err != nil {
		t.Fatal(err)
	}
	program.Frame.Compiled.DataTypeTag = append([]byte(nil), program.Frame.Compiled.PaddingTypeTag...)
	if _, err := EncodeLiveOperation(program, Operation{Semantic: ir.SemanticData, StreamID: 7, Payload: []byte("ambiguous")}, 1); err == nil {
		t.Fatal("live framing accepted equal compiled data and padding type tags")
	}
}

func TestMalformedInputDoesNotPanic(t *testing.T) {
	p, _ := compiler.Generate(10)
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("decode panicked: %v", r)
		}
	}()
	if _, err := DecodeFrame(p, []byte{1, 2, 3}); err == nil {
		t.Fatal("expected malformed input error")
	}
}

func TestOversizedFrameRejected(t *testing.T) {
	p, _ := compiler.Generate(10)
	tooBig := bytes.Repeat([]byte{1}, p.Limits.MaxFrameBytes+100)
	if _, err := DecodeFrame(p, tooBig); err == nil {
		t.Fatal("expected oversized frame to fail")
	}
}

func TestFragmentedDataReconstructs(t *testing.T) {
	p, _ := compiler.Generate(12)
	p.FrameGrammar.FragmentationMode = "fixed_size_chunks"
	p.GenerationHash = ""
	payload := bytes.Repeat([]byte("a"), 20*1024)
	frames, err := EncodeOperation(p, Operation{Semantic: ir.SemanticData, StreamID: 1, Payload: payload}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatal("expected fragmentation")
	}
	got, _, err := DecodeFrames(p, frames)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.Payload, payload) {
		t.Fatal("fragmented payload mismatch")
	}
}

func TestFragmentCoverageRejectsMalformedSets(t *testing.T) {
	p, frames, payload := fragmentedFixture(t, 1, 11, bytes.Repeat([]byte("a"), 20*1024))
	parts := decodeFixtureParts(t, p, frames)

	tests := []struct {
		name   string
		kind   FragmentErrorKind
		mutate func(t *testing.T, frames [][]byte) [][]byte
	}{
		{
			name: "duplicate",
			kind: FragmentErrorDuplicate,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				frames[1] = append([]byte(nil), frames[0]...)
				return frames
			},
		},
		{
			name: "missing",
			kind: FragmentErrorMissing,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				return frames[:len(frames)-1]
			},
		},
		{
			name: "out_of_range",
			kind: FragmentErrorOutOfRange,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				frames[len(frames)-1] = encodeFixtureFrame(t, p, parts[len(parts)-1].Operation, len(parts), len(parts))
				return frames
			},
		},
		{
			name: "reordered",
			kind: FragmentErrorReordered,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				frames[0], frames[1] = frames[1], frames[0]
				return frames
			},
		},
		{
			name: "mixed_semantic",
			kind: FragmentErrorSemantic,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				op := parts[1].Operation
				op.Semantic = ir.SemanticOpenStream
				frames[1] = encodeFixtureFrame(t, p, op, 1, len(parts))
				return frames
			},
		},
		{
			name: "mixed_stream",
			kind: FragmentErrorStream,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				op := parts[1].Operation
				op.StreamID++
				frames[1] = encodeFixtureFrame(t, p, op, 1, len(parts))
				return frames
			},
		},
		{
			name: "mixed_operation",
			kind: FragmentErrorOperation,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				op := parts[1].Operation
				op.Sequence++
				frames[1] = encodeFixtureFrame(t, p, op, 1, len(parts))
				return frames
			},
		},
		{
			name: "conflicting_count",
			kind: FragmentErrorConflictingCount,
			mutate: func(t *testing.T, frames [][]byte) [][]byte {
				frames[1] = encodeFixtureFrame(t, p, parts[1].Operation, 1, len(parts)+1)
				return frames
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			malformed := tt.mutate(t, cloneFrames(frames))
			got, _, err := DecodeFrames(p, malformed)
			if err == nil {
				t.Fatal("expected fragment coverage rejection")
			}
			if !errors.Is(err, ErrFragmentCoverage) {
				t.Fatalf("error %v does not match ErrFragmentCoverage", err)
			}
			var fragmentErr *FragmentError
			if !errors.As(err, &fragmentErr) {
				t.Fatalf("error %T is not a *FragmentError", err)
			}
			if fragmentErr.Kind != tt.kind {
				t.Fatalf("fragment error kind = %q, want %q", fragmentErr.Kind, tt.kind)
			}
			if !reflect.DeepEqual(got, Operation{}) || len(got.Payload) != 0 {
				t.Fatalf("rejected fragments emitted an operation: %#v", got)
			}

			unrelatedPayload := append([]byte("unrelated:"), payload...)
			_, unrelatedFrames, _ := fragmentedFixture(t, 99, 777, unrelatedPayload)
			unrelated, _, err := DecodeFrames(p, unrelatedFrames)
			if err != nil {
				t.Fatalf("unrelated operation failed after rejection: %v", err)
			}
			if unrelated.StreamID != 99 || unrelated.Sequence != 777 || !bytes.Equal(unrelated.Payload, unrelatedPayload) {
				t.Fatal("unrelated operation did not reassemble byte-for-byte")
			}
		})
	}
}

func TestFragmentCoveragePreservesValidBindings(t *testing.T) {
	p, frames, payload := fragmentedFixture(t, 17, 23, bytes.Repeat([]byte("valid"), 5*1024))
	got, parts, err := DecodeFrames(p, frames)
	if err != nil {
		t.Fatal(err)
	}
	if got.Semantic != ir.SemanticData || got.StreamID != 17 || got.Sequence != 23 || !bytes.Equal(got.Payload, payload) {
		t.Fatal("valid fragmented operation bindings changed")
	}
	for i, part := range parts {
		if part.Operation.Semantic != got.Semantic || part.Operation.StreamID != got.StreamID || part.Operation.Sequence != got.Sequence {
			t.Fatalf("fragment %d operation binding changed", i)
		}
		if part.FragIndex != i || part.FragCount != len(parts) {
			t.Fatalf("fragment %d coverage binding = (%d, %d), want (%d, %d)", i, part.FragIndex, part.FragCount, i, len(parts))
		}
	}
}

func fragmentedFixture(t *testing.T, streamID uint32, sequence uint64, payload []byte) (*ir.Profile, [][]byte, []byte) {
	t.Helper()
	p, err := compiler.Generate(12)
	if err != nil {
		t.Fatal(err)
	}
	p.FrameGrammar.FragmentationMode = "fixed_size_chunks"
	p.GenerationHash = ""
	frames, err := EncodeOperation(p, Operation{
		Semantic: ir.SemanticData,
		StreamID: streamID,
		Sequence: sequence,
		Payload:  payload,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(frames) < 2 {
		t.Fatal("expected fragmented fixture")
	}
	return p, frames, append([]byte(nil), payload...)
}

func decodeFixtureParts(t *testing.T, p *ir.Profile, frames [][]byte) []DecodedFrame {
	t.Helper()
	parts := make([]DecodedFrame, len(frames))
	for i, frame := range frames {
		part, err := DecodeFrame(p, frame)
		if err != nil {
			t.Fatal(err)
		}
		parts[i] = part
	}
	return parts
}

func encodeFixtureFrame(t *testing.T, p *ir.Profile, op Operation, fragIndex, fragCount int) []byte {
	t.Helper()
	frame, err := encodeFrame(p, op, nil, fragIndex, fragCount)
	if err != nil {
		t.Fatal(err)
	}
	return frame
}

func cloneFrames(frames [][]byte) [][]byte {
	clone := make([][]byte, len(frames))
	for i, frame := range frames {
		clone[i] = append([]byte(nil), frame...)
	}
	return clone
}
