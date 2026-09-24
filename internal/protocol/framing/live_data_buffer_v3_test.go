// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package framing

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"math"
	"math/rand"
	"reflect"
	"testing"
	"unsafe"

	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func bufferProgramV3(t testing.TB) liveprogram.ProgramV1 {
	t.Helper()
	profile, err := compiler.Generate(10)
	if err != nil {
		t.Fatal(err)
	}
	caps := ir.SecurityCapabilities()
	p, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: profile, ClientMandatoryFeatures: caps[:2], RelayMandatoryFeatures: caps[:2], SelectedFeatures: caps})
	if err != nil {
		t.Fatal(err)
	}
	p.Frame.LengthMode = "fixed_4_prefix"
	p.Frame.ChecksumMode = "none"
	p.Frame.HeaderOrder = []string{"length", "type", "stream", "flags"}
	p.Frame.PaddingPlacement = "suffix"
	p.Frame.FragmentationMode = "scheduler_controlled_chunks"
	p.Frame.Compiled.DataTypeTag = []byte{1}
	p.Frame.Compiled.PaddingTypeTag = []byte{2}
	p.Stream.IDEncodingMode = "fixed32_be"
	p.Padding = liveprogram.PaddingV1{Mode: "none"}
	p.Scheduler.MaxBatchBytes = 32768
	p.Limits.MaxFrameBytes = 131072
	p.Limits.MaxPayloadBytes = 65535
	p.Messages[0].MinPayloadBytes = 8
	p.Messages[0].MaxPayloadBytes = 65535
	p.Messages[1].MaxPayloadBytes = 65535
	if err := liveprogram.ValidateV1(p); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestEncodePacketV2IndependentLegacyBytes(t *testing.T) {
	// Replacing the fixed legacy Sequence with zero must break this comparison.
	for _, fragment := range []string{"fixed_size_chunks", "bounded_variable_chunks", "scheduler_controlled_chunks"} {
		for _, pad := range []string{"none", "fixed", "bounded", "probabilistic"} {
			p := bufferProgramV3(t)
			p.Frame.FragmentationMode = fragment
			p.Frame.ChecksumMode = "crc32"
			p.Scheduler.MaxBatchBytes = 512
			if pad != "none" {
				p.Padding = liveprogram.PaddingV1{Mode: pad, MinPaddingBytes: 3, MaxPaddingBytes: 31, Probability: .5}
			}
			c, err := NewLiveDataCodecV3(p)
			if err != nil {
				t.Fatal(err)
			}
			encoder, ok := any(c).(interface {
				EncodePacketV2Into([]byte, []byte, []byte, uint32, int64, *[256]FrameSpanV3) (int, int, error)
			})
			if !ok {
				t.Fatal("bounded legacy packet encoder is absent")
			}
			payload := bytes.Repeat([]byte{7}, 1537)
			bounds, err := c.Bounds(len(payload))
			if err != nil {
				t.Fatal(err)
			}
			for _, stream := range []uint32{2, 3, 65534, 2} {
				for _, seed := range []int64{int64(stream), -1, 99} {
					want, err := EncodeLiveOperation(p, Operation{Semantic: "data", StreamID: stream, Sequence: uint64(stream), Payload: payload}, seed)
					if err != nil {
						t.Fatal(err)
					}
					dst, scratch := make([]byte, bounds.FrameBytes), make([]byte, bounds.PaddingBytes)
					var spans [256]FrameSpanV3
					n, count, err := encoder.EncodePacketV2Into(dst, scratch, payload, stream, seed, &spans)
					if err != nil || count != len(want) {
						t.Fatal("legacy count", err)
					}
					flat, _ := flattenV3(want)
					if !bytes.Equal(flat, dst[:n]) {
						t.Fatalf("legacy bytes %s/%s stream%d seed%d", fragment, pad, stream, seed)
					}
					out := make([]byte, len(payload))
					if _, err := c.DecodeInto(out, dst[:n], spans[:count]); err != nil || !bytes.Equal(out, payload) {
						t.Fatal("nonzero sequence RX", err)
					}
					before := append([]byte(nil), dst...)
					if _, _, err := encoder.EncodePacketV2Into(dst[:len(dst)-1], scratch, payload, stream, seed, &spans); err == nil || !bytes.Equal(dst, before) {
						t.Fatal("short packet encode wrote")
					}
				}
			}
		}
	}
}

func TestLegacyDuplicateHeaderFieldsPreserveBytes(t *testing.T) {
	// These literal headers independently specify stream7, fragment0 of1,
	// no padding and a one-byte explicit data tag. Duplicate length placeholders
	// emit no bytes; every type/stream/flags occurrence does emit bytes.
	cases := []struct {
		name   string
		order  []string
		header []byte
	}{
		{"type", []string{"length", "type", "type", "stream", "flags"}, []byte{1, 'd', 1, 'd', 4, 0, 0, 0, 7, 0, 0, 0, 0, 1, 0, 0}},
		{"stream", []string{"length", "type", "stream", "stream", "flags"}, []byte{1, 'd', 4, 0, 0, 0, 7, 4, 0, 0, 0, 7, 0, 0, 0, 0, 1, 0, 0}},
		{"flags", []string{"length", "type", "stream", "flags", "flags"}, []byte{1, 'd', 4, 0, 0, 0, 7, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0}},
		{"length", []string{"length", "type", "length", "stream", "flags", "length"}, []byte{1, 'd', 4, 0, 0, 0, 7, 0, 0, 0, 0, 1, 0, 0}},
	}
	for _, tc := range cases {
		for _, checksum := range []string{"none", "crc32"} {
			t.Run(tc.name+"/"+checksum, func(t *testing.T) {
				defer func() {
					if recovered := recover(); recovered != nil {
						t.Fatalf("previously admitted duplicate header panicked: %v", recovered)
					}
				}()
				profile, err := compiler.Generate(10)
				if err != nil {
					t.Fatal(err)
				}
				profile.GenerationHash = ""
				profile.FrameGrammar.HeaderOrder = tc.order
				profile.FrameGrammar.TypeMode = "explicit_generated_tag"
				profile.FrameGrammar.LengthMode = "fixed_4_prefix"
				profile.FrameGrammar.ChecksumMode = checksum
				profile.FrameGrammar.PaddingPlacement = "none"
				profile.Stream.IDEncodingMode = "fixed32_be"
				profile.Padding = ir.PaddingPolicy{Mode: "none"}
				for i := range profile.Messages {
					if profile.Messages[i].Semantic == "data" {
						profile.Messages[i].WireSymbol = "d"
					}
				}
				if err := ir.Validate(profile); err != nil {
					t.Fatalf("historically accepted profile rejected: %v", err)
				}
				payload := []byte("abcdefghij")
				body := append(append([]byte(nil), tc.header...), make([]byte, 51)...)
				body = append(body, payload...)
				if checksum == "crc32" {
					// The historical checksum covers profile ID followed by the body.
					crc := crc32.ChecksumIEEE(append([]byte(profile.ID), body...))
					var encodedCRC [4]byte
					binary.BigEndian.PutUint32(encodedCRC[:], crc)
					body = append(body, encodedCRC[:]...)
				}
				want := make([]byte, 4+len(body))
				binary.BigEndian.PutUint32(want[:4], uint32(len(body)))
				copy(want[4:], body)
				// Decode the independent expected bytes before testing the encoder.
				decoded, _, err := DecodeFrames(profile, [][]byte{want})
				if err != nil || decoded.StreamID != 7 || !bytes.Equal(decoded.Payload, payload) {
					t.Fatalf("independent legacy vector rejected: %v", err)
				}
				frames, err := EncodeOperation(profile, Operation{Semantic: "data", StreamID: 7, Payload: payload}, 0)
				if err != nil {
					t.Fatal(err)
				}
				if len(frames) != 1 || !bytes.Equal(frames[0], want) {
					t.Fatal("legacy duplicate header encoding differs from independent expected bytes")
				}
				decoded, _, err = DecodeFrames(profile, frames)
				if err != nil || !bytes.Equal(decoded.Payload, payload) {
					t.Fatalf("legacy duplicate header payload did not round trip: %v", err)
				}
			})
		}
		t.Run(tc.name+"/header-helper", func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("duplicate header helper panicked: %v", recovered)
				}
			}()
			spec := codecSpec{headerOrder: tc.order, streamEncodingMode: "fixed32_be", maxFrameBytes: 128}
			got, err := encodeHeaderFieldsWithSpec(spec, codecMessage{typeTag: []byte{'d'}}, 7, 0, 1, 0)
			if err != nil || !bytes.Equal(got, tc.header) {
				t.Fatalf("header helper did not preserve every emitted occurrence: %v", err)
			}
		})
	}
}

func TestLegacyDuplicateHeaderSizingLimits(t *testing.T) {
	msg := codecMessage{typeTag: []byte{'d'}}
	// Duplicate flags yield a 21-byte header, plus 61 bytes of metadata/payload.
	for _, tc := range []struct {
		name                     string
		checksum                 string
		limit, content, wantBody int
		ok                       bool
	}{
		{"exact-none", "none", 82, 61, 82, true},
		{"short-none", "none", 81, 61, 0, false},
		{"exact-crc", "crc32", 86, 61, 86, true},
		{"short-crc", "crc32", 85, 61, 0, false},
		{"negative-content", "none", 128, -1, 0, false},
		{"content-overflow", "none", 128, math.MaxInt, 0, false},
		{"header-exceeds-limit", "none", 20, 0, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := codecSpec{headerOrder: []string{"length", "type", "stream", "flags", "flags"}, streamEncodingMode: "fixed32_be", lengthMode: "fixed_4_prefix", checksumMode: tc.checksum, maxFrameBytes: tc.limit}
			body, wrapper, err := frameSizeWithSpec(spec, msg, 7, tc.content)
			if (err == nil) != tc.ok || tc.ok && (body != tc.wantBody || wrapper != 4) {
				t.Fatalf("size=(%d,%d), err=%v; want body=%d accepted=%v", body, wrapper, err, tc.wantBody, tc.ok)
			}
		})
	}
}

func flattenV3(frames [][]byte) ([]byte, []FrameSpanV3) {
	var slab []byte
	spans := make([]FrameSpanV3, len(frames))
	for i, f := range frames {
		spans[i] = FrameSpanV3{uint32(len(slab)), uint32(len(f))}
		slab = append(slab, f...)
	}
	return slab, spans
}

func TestLiveDataBufferV3Parity(t *testing.T) {
	base := bufferProgramV3(t)
	payload := bytes.Repeat([]byte{0x37}, 17001)
	for fi, frag := range []string{"fixed_size_chunks", "bounded_variable_chunks", "scheduler_controlled_chunks", "no_fragmentation_for_small_payloads"} {
		for li, length := range []string{"varint_prefix", "fixed_2_prefix", "fixed_4_prefix", "length_suffix_lab"} {
			for si, stream := range []string{"fixed32_be", "profile_xor32", "table_mapped32_le", "varint"} {
				for ci, crc := range []string{"none", "crc32"} {
					for pi, pad := range []string{"none", "fixed", "bounded", "probabilistic", "inter_frame"} {
						p := base.Clone()
						p.Frame.FragmentationMode = frag
						p.Frame.LengthMode = length
						p.Stream.IDEncodingMode = stream
						p.Frame.ChecksumMode = crc
						if (fi+li+si+ci+pi)%2 == 1 {
							p.Frame.HeaderOrder = []string{"flags", "stream", "length", "type"}
							p.Frame.PaddingPlacement = "prefix"
						}
						if pad != "none" {
							p.Padding = liveprogram.PaddingV1{Mode: pad, MinPaddingBytes: 2, MaxPaddingBytes: 17, Probability: .5}
						}
						c, err := NewLiveDataCodecV3(p)
						if err != nil {
							t.Fatal(err)
						}
						bound, err := c.Bounds(len(payload))
						if err != nil {
							t.Fatal(err)
						}
						dst := make([]byte, bound.FrameBytes)
						scratch := make([]byte, bound.PaddingBytes)
						out := make([]byte, len(payload))
						var spans [256]FrameSpanV3
						for _, id := range []uint32{2, 127, 128, 16383, 16384, 65534} {
							seed := int64(id)
							want, err := EncodeLiveOperation(p, Operation{Semantic: "data", StreamID: id, Payload: payload}, seed)
							if err != nil {
								t.Fatal(err)
							}
							n, count, err := c.EncodeInto(dst, scratch, payload, id, seed, &spans)
							if err != nil {
								t.Fatal(err)
							}
							if count != len(want) || count != int(bound.FrameCount) || n > len(dst) {
								t.Fatal("bound/count parity")
							}
							for i, f := range want {
								s := spans[i]
								if !bytes.Equal(f, dst[s.Offset:s.Offset+s.Length]) || s.Length > bound.LargestFrameBytes {
									t.Fatalf("raw parity %s/%s/%s/%s/%s id%d frame%d", frag, length, stream, crc, pad, id, i)
								}
							}
							info, err := c.DecodeInto(out, dst[:n], spans[:count])
							if err != nil || info != (LiveDataInfoV3{id, uint32(len(payload))}) || !bytes.Equal(out, payload) {
								t.Fatal("decode parity", err)
							}
						}
					}
				}
			}
		}
	}
}

func TestLiveDataBufferV3Bounds(t *testing.T) {
	for _, tc := range []struct {
		name   string
		size   int
		mutate func(*liveprogram.ProgramV1)
		ok     bool
		count  uint16
	}{
		{"negative", -1, nil, false, 0}, {"zero", 0, nil, false, 0}, {"min-minus-one", 7, nil, false, 0}, {"min", 8, nil, true, 1}, {"max", 65535, nil, true, 2}, {"max-plus-one", 65536, nil, false, 0}, {"overflow", math.MaxInt, nil, false, 0},
		{"256", 256, func(p *liveprogram.ProgramV1) { p.Scheduler.MaxBatchBytes = 1 }, true, 256},
		{"257", 257, func(p *liveprogram.ProgramV1) { p.Scheduler.MaxBatchBytes = 1 }, false, 0},
		{"small-frame", 256, func(p *liveprogram.ProgramV1) { p.Limits.MaxFrameBytes = 512 }, true, 256},
		{"padding65535", 8, func(p *liveprogram.ProgramV1) {
			p.Padding = liveprogram.PaddingV1{Mode: "fixed", MaxPaddingBytes: 65535}
		}, true, 1},
		{"padding65536", 8, func(p *liveprogram.ProgramV1) {
			p.Padding = liveprogram.PaddingV1{Mode: "fixed", MaxPaddingBytes: 65536}
		}, false, 0},
		{"body65535", 8, func(p *liveprogram.ProgramV1) {
			p.Frame.LengthMode = "fixed_2_prefix"
			p.Padding = liveprogram.PaddingV1{Mode: "fixed", MaxPaddingBytes: 65462}
		}, true, 1},
		{"body65536", 8, func(p *liveprogram.ProgramV1) {
			p.Frame.LengthMode = "fixed_2_prefix"
			p.Padding = liveprogram.PaddingV1{Mode: "fixed", MaxPaddingBytes: 65463}
		}, false, 0},
		{"signed-max", 273, func(p *liveprogram.ProgramV1) { p.Messages[0].MaxPayloadBytes = 272 }, false, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := bufferProgramV3(t)
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			c, err := NewLiveDataCodecV3(p)
			if err != nil {
				t.Fatal(err)
			}
			b, err := c.Bounds(tc.size)
			if (err == nil) != tc.ok {
				t.Fatalf("bounds %+v err %v", b, err)
			}
			if tc.ok && b.FrameCount != tc.count {
				t.Fatal("count", b)
			}
		})
	}
	c, err := NewLiveDataCodecV3(bufferProgramV3(t))
	if err != nil {
		t.Fatal(err)
	}
	b, err := c.Bounds(8)
	if err != nil || b != (LiveDataBoundsV3{FrameBytes: 77, LargestFrameBytes: 77, FrameCount: 1}) {
		t.Fatal("51-byte metadata accounting", b, err)
	}
	for _, mutate := range []func(*liveprogram.ProgramV1){func(p *liveprogram.ProgramV1) { p.Messages[0].MinPayloadBytes = 9 }, func(p *liveprogram.ProgramV1) { p.Messages[0].MaxPayloadBytes = 271 }, func(p *liveprogram.ProgramV1) { p.Frame.Compiled.DataTypeTag = nil }} {
		p := bufferProgramV3(t)
		mutate(&p)
		if _, err := NewLiveDataCodecV3(p); err == nil {
			t.Fatal("invalid V3 program accepted")
		}
	}
}

func TestLiveDataBufferV3PreflightAndOwnership(t *testing.T) {
	p := bufferProgramV3(t)
	p.Padding = liveprogram.PaddingV1{Mode: "probabilistic", MinPaddingBytes: 1, MaxPaddingBytes: 16, Probability: .5}
	c, err := NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte{3}, 272)
	b, err := c.Bounds(len(payload))
	if err != nil {
		t.Fatal(err)
	}
	dst := bytes.Repeat([]byte{0xaa}, int(b.FrameBytes))
	scratch := bytes.Repeat([]byte{0xbb}, int(b.PaddingBytes))
	var spans [256]FrameSpanV3
	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"short-frame", func() error { _, _, e := c.EncodeInto(dst[:len(dst)-1], scratch, payload, 2, 99, &spans); return e }},
		{"short-pad", func() error { _, _, e := c.EncodeInto(dst, scratch[:len(scratch)-1], payload, 2, 99, &spans); return e }},
		{"nil-spans", func() error { _, _, e := c.EncodeInto(dst, scratch, payload, 2, 99, nil); return e }},
		{"slot0", func() error { _, _, e := c.EncodeInto(dst, scratch, payload, 0, 99, &spans); return e }},
		{"slot1", func() error { _, _, e := c.EncodeInto(dst, scratch, payload, 1, 99, &spans); return e }},
		{"slot65535", func() error { _, _, e := c.EncodeInto(dst, scratch, payload, 65535, 99, &spans); return e }},
		{"dst-payload", func() error { _, _, e := c.EncodeInto(dst, scratch, dst[:272], 2, 99, &spans); return e }},
		{"dst-pad", func() error { _, _, e := c.EncodeInto(dst, dst[:16], payload, 2, 99, &spans); return e }},
		{"pad-payload", func() error { _, _, e := c.EncodeInto(dst, payload[:16], payload, 2, 99, &spans); return e }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.run(); err == nil {
				t.Fatal("invalid preflight accepted")
			}
			if !bytes.Equal(dst, bytes.Repeat([]byte{0xaa}, len(dst))) || !bytes.Equal(scratch, bytes.Repeat([]byte{0xbb}, len(scratch))) || spans != ([256]FrameSpanV3{}) {
				t.Fatal("rejection wrote output")
			}
		})
	}
	// Mutating the source program after preparation must not change retained authority.
	p.Frame.HeaderOrder[0] = "flags"
	p.Frame.Compiled.DataTypeTag[0] = 88
	p.Messages[0].MaxPayloadBytes = 9
	n, count, err := c.EncodeInto(dst, scratch, payload, 2, 99, &spans)
	if err != nil {
		t.Fatal(err)
	}
	clean := bufferProgramV3(t)
	clean.Padding = liveprogram.PaddingV1{Mode: "probabilistic", MinPaddingBytes: 1, MaxPaddingBytes: 16, Probability: .5}
	want, err := EncodeLiveOperation(clean, Operation{Semantic: "data", StreamID: 2, Payload: payload}, 99)
	if err != nil {
		t.Fatal(err)
	}
	flat, _ := flattenV3(want)
	if !bytes.Equal(dst[:n], flat) {
		t.Fatal("source alias or rejected preflight RNG drift")
	}
	out := bytes.Repeat([]byte{0xcc}, len(payload))
	if _, err := c.DecodeInto(out[:len(out)-1], dst[:n], spans[:count]); err == nil || !bytes.Equal(out, bytes.Repeat([]byte{0xcc}, len(out))) {
		t.Fatal("short decode wrote")
	}
	before := append([]byte(nil), dst...)
	if _, err := c.DecodeInto(dst, dst[:n], spans[:count]); err == nil || !bytes.Equal(before, dst) {
		t.Fatal("decode overlap")
	}
}

func TestLiveDataBufferV3MalformedAndMetadata(t *testing.T) {
	p := bufferProgramV3(t)
	p.Scheduler.MaxBatchBytes = 8
	c, err := NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	op := Operation{Semantic: "data", StreamID: 2, Sequence: 9, Offset: 13, CreditBytes: 4, EndStream: true, Reason: "x", Priority: "interactive", TargetClass: "echo", TargetVariant: "small", RequestClass: "a", ResponseMode: "b", TargetErrorCode: "c", TargetCloseReason: "d", TargetResetReason: "e", MetadataClass: "f", RelayIntentID: 99, PayloadByteCount: 9, ResponseByteCount: 12, ResponseChunkIndex: 2, Payload: bytes.Repeat([]byte{7}, 16)}
	frames, err := EncodeLiveOperation(p, op, 1)
	if err != nil {
		t.Fatal(err)
	}
	// fixed4 prefix + 14 header + bool offset20. Nonzero EndStream bytes normalize equally.
	frames[1][4+14+20] = 0xfe
	slab, spans := flattenV3(frames)
	out := make([]byte, 16)
	if _, _, err := DecodeLiveFrames(p, frames); err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecodeInto(out, slab, spans); err != nil || !bytes.Equal(out, op.Payload) {
		t.Fatal("received ancillary metadata/boolean rejected", err)
	}
	if allocations := testing.AllocsPerRun(100, func() {
		if _, err := c.DecodeInto(out, slab, spans); err != nil {
			panic(err)
		}
	}); allocations != 0 {
		t.Fatalf("received ancillary metadata allocated strings: %v", allocations)
	}
	spec, err := codecSpecFromLiveProgram(p)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		kind   FragmentErrorKind
		mutate func([][]byte) [][]byte
	}{
		{"empty", FragmentErrorEmpty, func(f [][]byte) [][]byte { return nil }},
		{"missing", FragmentErrorMissing, func(f [][]byte) [][]byte { return f[:1] }},
		{"duplicate", FragmentErrorDuplicate, func(f [][]byte) [][]byte { f[1] = f[0]; return f }},
		{"reorder", FragmentErrorReordered, func(f [][]byte) [][]byte { f[0], f[1] = f[1], f[0]; return f }},
		{"range", FragmentErrorOutOfRange, func(f [][]byte) [][]byte { binary.BigEndian.PutUint16(f[1][12:14], 2); return f }},
		{"count", FragmentErrorConflictingCount, func(f [][]byte) [][]byte { binary.BigEndian.PutUint16(f[1][14:16], 3); return f }},
		{"semantic", FragmentErrorSemantic, func(f [][]byte) [][]byte {
			o := op
			o.Semantic = "padding"
			f[1], _ = encodeFrameWithSpec(spec, o, nil, 1, 2)
			return f
		}},
		{"stream", FragmentErrorStream, func(f [][]byte) [][]byte { f[1][10] = 3; return f }},
		{"metadata", FragmentErrorOperation, func(f [][]byte) [][]byte { f[1][4+14] ^= 1; return f }},
		{"unknown-tag", "", func(f [][]byte) [][]byte { f[0][5] = 99; return f }},
		{"padding", "", func(f [][]byte) [][]byte { binary.BigEndian.PutUint16(f[1][16:18], 65535); return f }},
		{"truncated", "", func(f [][]byte) [][]byte { f[1] = f[1][:len(f[1])-1]; return f }},
		{"nondata", "", func(f [][]byte) [][]byte {
			for i := range f {
				f[i][5] = 2
			}
			return f
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			bad := tc.mutate(cloneFrames(frames))
			slab, spans := flattenV3(bad)
			dst := bytes.Repeat([]byte{0xaa}, 1024)
			info, err := c.DecodeInto(dst, slab, spans)
			if err == nil || info != (LiveDataInfoV3{}) || !bytes.Equal(dst, bytes.Repeat([]byte{0xaa}, 1024)) {
				t.Fatal("malformed emitted output", err)
			}
			if tc.kind != "" {
				var fe *FragmentError
				if !errors.As(err, &fe) || fe.Kind != tc.kind {
					t.Fatalf("kind got %v want %s", err, tc.kind)
				}
			}
		})
	}
	for _, sp := range [][]FrameSpanV3{nil, {{1, uint32(len(slab) - 1)}}, {{0, 0}}, {{0, math.MaxUint32}}, {{0, uint32(len(slab) - 1)}}, {{0, uint32(len(slab))}, {0, 1}}, make([]FrameSpanV3, 257)} {
		if _, err := c.DecodeInto(out, slab, sp); err == nil {
			t.Fatal("invalid spans accepted")
		}
	}
}

func TestLiveDataBufferV3Allocations(t *testing.T) {
	p := bufferProgramV3(t)
	p.Frame.FragmentationMode = "fixed_size_chunks"
	p.Padding = liveprogram.PaddingV1{Mode: "bounded", MinPaddingBytes: 1, MaxPaddingBytes: 16, Probability: 1}
	c, err := NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 8193)
	b, err := c.Bounds(len(payload))
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, b.FrameBytes)
	pad := make([]byte, b.PaddingBytes)
	out := make([]byte, len(payload))
	var spans [256]FrameSpanV3
	n, count, err := c.EncodeInto(dst, pad, payload, 2, 99, &spans)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.DecodeInto(out, dst[:n], spans[:count]); err != nil {
		t.Fatal(err)
	}
	for name, run := range map[string]func(){"Bounds": func() {
		_, err := c.Bounds(len(payload))
		if err != nil {
			panic(err)
		}
	}, "EncodeInto": func() {
		_, _, err := c.EncodeInto(dst, pad, payload, 2, 99, &spans)
		if err != nil {
			panic(err)
		}
	}, "DecodeInto": func() {
		_, err := c.DecodeInto(out, dst[:n], spans[:count])
		if err != nil {
			panic(err)
		}
	}} {
		if a := testing.AllocsPerRun(100, run); a != 0 {
			t.Errorf("%s allocations %v", name, a)
		}
	}
	t.Logf("constructor allocations %.0f", testing.AllocsPerRun(20, func() {
		if _, err := NewLiveDataCodecV3(p); err != nil {
			panic(err)
		}
	}))
	stringBytes := len(c.spec.lengthMode) + len(c.spec.checksumMode) + len(c.spec.fragmentationMode) + len(c.spec.paddingPlacement) + len(c.spec.streamEncodingMode) + len(c.spec.padding.Mode)
	for _, s := range c.spec.headerOrder {
		stringBytes += len(s)
	}
	for _, m := range c.spec.messages {
		stringBytes += len(m.semantic) + len(m.wireSymbol)
	}
	t.Logf("retained sizes: codec=%d engine=%d rand=%d source=%d messages=%d*%d header=%d*%d tags=%d+%d strings=%d", unsafe.Sizeof(*c), unsafe.Sizeof(*c.engine), unsafe.Sizeof(rand.Rand{}), reflect.TypeOf(rand.NewSource(0)).Elem().Size(), cap(c.spec.messages), unsafe.Sizeof(codecMessage{}), cap(c.spec.headerOrder), unsafe.Sizeof(""), cap(c.spec.messages[0].typeTag), cap(c.spec.messages[1].typeTag), stringBytes)
}

func TestLiveDataBufferV3GoldenAndHeaderOrders(t *testing.T) {
	p := bufferProgramV3(t)
	payload := []byte("12345678")
	c, err := NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	// Independently specified fixed4 record: 73-byte body, tag1, stream2,
	// fragment0 of1, no pad, 51 zero metadata bytes, then the eight payload bytes.
	want := append([]byte{0, 0, 0, 73, 1, 1, 4, 0, 0, 0, 2, 0, 0, 0, 0, 1, 0, 0}, make([]byte, 51)...)
	want = append(want, payload...)
	dst := make([]byte, len(want))
	var spans [256]FrameSpanV3
	if n, _, err := c.EncodeInto(dst, nil, payload, 2, 0, &spans); err != nil || n != len(want) || !bytes.Equal(dst, want) {
		t.Fatal("independent golden mismatch", err)
	}
	// All 24 header orders and all admitted padding-placement modes.
	fields := []string{"length", "type", "stream", "flags"}
	for a := range fields {
		for b := range fields {
			for d := range fields {
				for e := range fields {
					if a == b || a == d || a == e || b == d || b == e || d == e {
						continue
					}
					for _, placement := range []string{"none", "prefix", "suffix", "inter_frame", "probabilistic"} {
						p.Frame.HeaderOrder = []string{fields[a], fields[b], fields[d], fields[e]}
						p.Frame.PaddingPlacement = placement
						p.Padding = liveprogram.PaddingV1{Mode: "fixed", MinPaddingBytes: 7, MaxPaddingBytes: 7}
						c, err := NewLiveDataCodecV3(p)
						if err != nil {
							t.Fatal(err)
						}
						bounds, err := c.Bounds(8)
						if err != nil {
							t.Fatal(err)
						}
						frames, err := EncodeLiveOperation(p, Operation{Semantic: "data", StreamID: 2, Payload: payload}, 77)
						if err != nil {
							t.Fatal(err)
						}
						dst := make([]byte, bounds.FrameBytes)
						pad := make([]byte, bounds.PaddingBytes)
						n, count, err := c.EncodeInto(dst, pad, payload, 2, 77, &spans)
						if err != nil || count != 1 || !bytes.Equal(dst[:n], frames[0]) {
							t.Fatal("header/placement parity", err)
						}
						out := make([]byte, 8)
						if _, err := c.DecodeInto(out, dst[:n], spans[:count]); err != nil || !bytes.Equal(out, payload) {
							t.Fatal("header/placement decode", err)
						}
					}
				}
			}
		}
	}
}

func TestLiveDataBufferV3DecodeBoundaries(t *testing.T) {
	p := bufferProgramV3(t)
	for _, tc := range []struct {
		name   string
		mutate func(*liveprogram.ProgramV1)
		size   int
		id     uint32
		ok     bool
	}{
		{"empty", nil, 0, 2, false}, {"below-min", nil, 7, 2, false}, {"min", nil, 8, 2, true},
		{"aggregate-selected-max", func(p *liveprogram.ProgramV1) { p.Scheduler.MaxBatchBytes = 128; p.Messages[0].MaxPayloadBytes = 272 }, 273, 2, false},
		{"aggregate-selected-equal", func(p *liveprogram.ProgramV1) { p.Scheduler.MaxBatchBytes = 128; p.Messages[0].MaxPayloadBytes = 272 }, 272, 2, true},
		{"invalid-slot1", nil, 8, 1, false}, {"invalid-slot65535", nil, 8, 65535, false},
		{"256-fragments", func(p *liveprogram.ProgramV1) { p.Scheduler.MaxBatchBytes = 1 }, 256, 2, true},
		{"257-fragments", func(p *liveprogram.ProgramV1) { p.Scheduler.MaxBatchBytes = 1 }, 257, 2, false},
		{"tag255", func(p *liveprogram.ProgramV1) { p.Frame.Compiled.DataTypeTag = bytes.Repeat([]byte{3}, 255) }, 8, 2, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := p.Clone()
			if tc.mutate != nil {
				tc.mutate(&p)
			}
			c, err := NewLiveDataCodecV3(p)
			if err != nil {
				t.Fatal(err)
			}
			payload := bytes.Repeat([]byte{3}, tc.size)
			frames, err := EncodeLiveOperation(p, Operation{Semantic: "data", StreamID: tc.id, Payload: payload}, 0)
			if err != nil {
				t.Fatal(err)
			}
			slab, spans := flattenV3(frames)
			out := bytes.Repeat([]byte{0xaa}, tc.size+1)
			info, err := c.DecodeInto(out, slab, spans)
			if (err == nil) != tc.ok {
				t.Fatalf("decode %+v %v", info, err)
			}
			if tc.ok {
				if !bytes.Equal(out[:tc.size], payload) || out[tc.size] != 0xaa {
					t.Fatal("copy length")
				}
			} else if info != (LiveDataInfoV3{}) || !bytes.Equal(out, bytes.Repeat([]byte{0xaa}, len(out))) {
				t.Fatal("rejection mutated output")
			}
		})
	}
	// Every truncated header/metadata/payload/checksum is rejected before copying.
	for _, checksum := range []string{"none", "crc32"} {
		p.Frame.ChecksumMode = checksum
		c, err := NewLiveDataCodecV3(p)
		if err != nil {
			t.Fatal(err)
		}
		frames, err := EncodeLiveOperation(p, Operation{Semantic: "data", StreamID: 2, Payload: []byte("12345678")}, 0)
		if err != nil {
			t.Fatal(err)
		}
		f := frames[0]
		for n := 4; n < len(f); n++ {
			bad := append([]byte(nil), f[:n]...)
			binary.BigEndian.PutUint32(bad, uint32(n-4))
			out := bytes.Repeat([]byte{0xaa}, 8)
			if _, err := c.DecodeInto(out, bad, []FrameSpanV3{{0, uint32(n)}}); err == nil || !bytes.Equal(out, bytes.Repeat([]byte{0xaa}, 8)) {
				t.Fatalf("truncated %s at%d", checksum, n)
			}
		}
		if checksum == "crc32" {
			f[len(f)-1] ^= 1
			out := bytes.Repeat([]byte{0xaa}, 8)
			if _, err := c.DecodeInto(out, f, []FrameSpanV3{{0, uint32(len(f))}}); err == nil || !bytes.Equal(out, bytes.Repeat([]byte{0xaa}, 8)) {
				t.Fatal("CRC corruption accepted")
			}
		}
	}
}

func TestLiveDataBufferV3SpanOverlapAndRNGPreflight(t *testing.T) {
	p := bufferProgramV3(t)
	p.Padding = liveprogram.PaddingV1{Mode: "bounded", MinPaddingBytes: 16, MaxPaddingBytes: 16}
	c, err := NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 272)
	bounds, err := c.Bounds(272)
	if err != nil {
		t.Fatal(err)
	}
	dst := make([]byte, bounds.FrameBytes)
	pad := make([]byte, 16)
	var spans [256]FrameSpanV3
	c.engine.ResetSeed(88)
	_, _ = c.engine.Generate()
	comparison := rand.New(rand.NewSource(88))
	for i := 0; i < 16; i++ {
		comparison.Intn(256)
	}
	// A rejected seed99 call must not even reset the engine's current seed88 state.
	if _, _, err := c.EncodeInto(dst[:len(dst)-1], pad, payload, 2, 99, &spans); err == nil {
		t.Fatal("short accepted")
	}
	if _, err := c.engine.GenerateInto(pad); err != nil {
		t.Fatal(err)
	}
	for _, v := range pad {
		if v != byte(comparison.Intn(256)) {
			t.Fatal("preflight consumed/reset RNG")
		}
	}
	raw := unsafe.Slice((*byte)(unsafe.Pointer(&spans)), int(unsafe.Sizeof(spans)))
	before := spans
	for _, run := range []func() error{
		func() error { _, _, err := c.EncodeInto(raw, pad, payload, 2, 1, &spans); return err },
		func() error { _, _, err := c.EncodeInto(dst, raw[:16], payload, 2, 1, &spans); return err },
		func() error { _, _, err := c.EncodeInto(dst, pad, raw[:272], 2, 1, &spans); return err },
	} {
		if err := run(); err == nil || spans != before {
			t.Fatal("span overlap accepted or modified")
		}
	}
	n, count, err := c.EncodeInto(dst, pad, payload, 2, 1, &spans)
	if err != nil {
		t.Fatal(err)
	}
	before = spans
	if _, err := c.DecodeInto(raw, dst[:n], spans[:count]); err == nil || spans != before {
		t.Fatal("decode span overlap")
	}
	p.Scheduler.MaxBatchBytes = 1
	c, err = NewLiveDataCodecV3(p)
	if err != nil {
		t.Fatal(err)
	}
	if n := testing.AllocsPerRun(100, func() {
		if _, err := c.Bounds(257); err == nil {
			panic("257 accepted")
		}
	}); n != 0 {
		t.Fatal("257 rejection allocated", n)
	}
}

func BenchmarkLiveDataBufferV3(b *testing.B) {
	for _, size := range []int{272, 16392} {
		b.Run(fmt.Sprint(size), func(b *testing.B) {
			p := bufferProgramV3(b)
			c, err := NewLiveDataCodecV3(p)
			if err != nil {
				b.Fatal(err)
			}
			payload := make([]byte, size)
			bounds, err := c.Bounds(size)
			if err != nil {
				b.Fatal(err)
			}
			dst := make([]byte, bounds.FrameBytes)
			pad := make([]byte, bounds.PaddingBytes)
			out := make([]byte, size)
			var spans [256]FrameSpanV3
			b.ReportAllocs()
			b.SetBytes(int64(size))
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				n, count, err := c.EncodeInto(dst, pad, payload, 2, int64(i), &spans)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := c.DecodeInto(out, dst[:n], spans[:count]); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
