// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro
package framing

import (
	"errors"
	"strings"
	"unsafe"

	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/padding"
)

// FrameSpanV3 describes one consecutive encoded frame in the caller's slab.
type FrameSpanV3 struct{ Offset, Length uint32 }
type LiveDataInfoV3 struct {
	StreamID     uint32
	PayloadBytes uint32
}

// LiveDataBoundsV3 reserves complete length-wrapped frames and one reusable
// per-fragment padding scratch. It does not account for crypto/session memory.
type LiveDataBoundsV3 struct {
	FrameBytes, LargestFrameBytes uint32
	FrameCount                    uint16
	PaddingBytes                  uint32
}

// LiveDataCodecV3 retains only an immutable validated projection, selected data
// bounds and a reusable RNG. EncodeInto is single-owner. Separate codecs may be
// used for TX and RX; no operation retains any caller byte buffer or span table.
// This pure codec neither authenticates V3 authority nor admits a native session.
type LiveDataCodecV3 struct {
	spec                          codecSpec
	minPayload, maxPayload, chunk int
	engine                        *padding.Engine
}

var errLiveDataBufferV3 = errors.New("framing: invalid V3 data buffer or bounds")

// NewLiveDataCodecV3 validates/projects once and requires the selected data
// bounds to permit eight bytes and a maximum of at least 272 bytes. Retained
// backing capacities are exactly two codecMessage records, four header string
// descriptors, each compiled tag's length, fourteen cloned string lengths,
// and one codec/Engine/Rand/source object each. No payload/frame buffer is owned.
func NewLiveDataCodecV3(program liveprogram.ProgramV1) (*LiveDataCodecV3, error) {
	spec, err := codecSpecFromLiveProgram(program)
	if err != nil {
		return nil, err
	}
	message := program.Messages[0]
	if message.MinPayloadBytes > 8 || message.MaxPayloadBytes < 272 {
		return nil, errLiveDataBufferV3
	}
	// Clone strings as well as the projection's byte/slice arrays: retain neither
	// mutable source arrays nor oversized source-string backing storage.
	spec.lengthMode = strings.Clone(spec.lengthMode)
	spec.checksumMode = strings.Clone(spec.checksumMode)
	spec.fragmentationMode = strings.Clone(spec.fragmentationMode)
	spec.paddingPlacement = strings.Clone(spec.paddingPlacement)
	spec.streamEncodingMode = strings.Clone(spec.streamEncodingMode)
	spec.padding.Mode = strings.Clone(spec.padding.Mode)
	for i := range spec.headerOrder {
		spec.headerOrder[i] = strings.Clone(spec.headerOrder[i])
	}
	for i := range spec.messages {
		spec.messages[i].semantic = strings.Clone(spec.messages[i].semantic)
		spec.messages[i].wireSymbol = strings.Clone(spec.messages[i].wireSymbol)
	}
	chunk := int64(spec.maxBatchBytes)
	frameChunk := int64(spec.maxFrameBytes) - 512
	if chunk <= 0 || chunk > frameChunk {
		chunk = frameChunk
	}
	switch spec.fragmentationMode {
	case "fixed_size_chunks":
		chunk = min(chunk, 4096)
	case "bounded_variable_chunks":
		chunk = min(chunk, 6144)
	case "scheduler_controlled_chunks":
		chunk = min(chunk, int64(spec.maxBatchBytes))
	default:
		chunk = min(chunk, 16384)
	}
	chunk = max(chunk, 1)
	return &LiveDataCodecV3{spec: spec, minPayload: message.MinPayloadBytes, maxPayload: min(message.MaxPayloadBytes, spec.maxPayloadBytes), chunk: int(chunk), engine: padding.New(spec.padding, 0)}, nil
}

// Bounds performs no allocation, random draw or payload read. Stream overhead
// is conservatively four bytes across all admitted outer application slots.
func (c *LiveDataCodecV3) Bounds(payloadBytes int) (LiveDataBoundsV3, error) {
	if c == nil || c.engine == nil || payloadBytes <= 0 || payloadBytes < c.minPayload || payloadBytes > c.maxPayload {
		return LiveDataBoundsV3{}, errLiveDataBufferV3
	}
	count := 1 + (payloadBytes-1)/c.chunk
	if count > 256 {
		return LiveDataBoundsV3{}, errLiveDataBufferV3
	}
	q := 0
	if c.spec.padding.Mode != "none" {
		q = c.spec.padding.MaxPaddingBytes
	}
	if q > 65535 {
		return LiveDataBoundsV3{}, errLiveDataBufferV3
	}
	last := payloadBytes - (count-1)*c.chunk
	frameSize := func(n int) (uint64, error) {
		// Validated program limits bound each term to <= 8 MiB; widening first
		// avoids native-int overflow. No fragment-size slice is ever constructed.
		body := uint64(len(c.spec.messages[0].typeTag)) + 4 + 9 + 51 + uint64(n) + uint64(q)
		if c.spec.checksumMode == "crc32" {
			body += 4
		}
		if body > uint64(c.spec.maxFrameBytes) || body > uint64(^uint32(0)) {
			return 0, errLiveDataBufferV3
		}
		wrapper, err := lengthWrapperSize(c.spec, int(body))
		if err != nil {
			return 0, err
		}
		return body + uint64(wrapper), nil
	}
	tail, err := frameSize(last)
	if err != nil {
		return LiveDataBoundsV3{}, err
	}
	largest, total := tail, tail
	if count > 1 {
		full, err := frameSize(c.chunk)
		if err != nil {
			return LiveDataBoundsV3{}, err
		}
		largest = max(full, tail)
		total += uint64(count-1) * full
	}
	// At most 256 terms, each <= 1 MiB + 4. uint64 additions/multiplication
	// cannot overflow under the constructor's validated program ceilings.
	if total > uint64(^uint32(0)) || largest > uint64(^uint32(0)) {
		return LiveDataBoundsV3{}, errLiveDataBufferV3
	}
	return LiveDataBoundsV3{uint32(total), uint32(largest), uint16(count), uint32(q)}, nil
}

// EncodeInto exclusively borrows all supplied slices and spans until return.
// Their lengths (not only capacities) must cover Bounds, and none may overlap.
// Every rejectable input is checked before RNG reset/draw or any output write.
// On success only the returned frame prefix and first frameCount spans are valid.
func (c *LiveDataCodecV3) EncodeInto(framesDst, paddingScratch, payload []byte, streamID uint32, seed int64, spans *[256]FrameSpanV3) (int, int, error) {
	return c.encodeDataInto(framesDst, paddingScratch, payload, streamID, seed, spans, 0)
}

// EncodePacketV2Into preserves PacketPumpV1's fixed sequence metadata. It has
// the same bounds, exclusive borrowing and nonwriting failure contract as V3.
func (c *LiveDataCodecV3) EncodePacketV2Into(framesDst, paddingScratch, payload []byte, streamID uint32, seed int64, spans *[256]FrameSpanV3) (int, int, error) {
	return c.encodeDataInto(framesDst, paddingScratch, payload, streamID, seed, spans, uint64(streamID))
}

func (c *LiveDataCodecV3) encodeDataInto(framesDst, paddingScratch, payload []byte, streamID uint32, seed int64, spans *[256]FrameSpanV3, sequence uint64) (int, int, error) {
	b, err := c.Bounds(len(payload))
	if err != nil {
		return 0, 0, err
	}
	if streamID < 2 || streamID > 65534 || spans == nil || uint64(len(framesDst)) < uint64(b.FrameBytes) || uint64(len(paddingScratch)) < uint64(b.PaddingBytes) {
		return 0, 0, errLiveDataBufferV3
	}
	spanBytes := unsafe.Slice((*byte)(unsafe.Pointer(spans)), int(unsafe.Sizeof(*spans)))
	if byteSlicesOverlap(framesDst, paddingScratch) || byteSlicesOverlap(framesDst, payload) || byteSlicesOverlap(paddingScratch, payload) || byteSlicesOverlap(spanBytes, framesDst) || byteSlicesOverlap(spanBytes, paddingScratch) || byteSlicesOverlap(spanBytes, payload) {
		return 0, 0, errLiveDataBufferV3
	}
	c.engine.ResetSeed(seed)
	var metadata [51]byte
	writeOperationMetadata(metadata[:], Operation{Sequence: sequence})
	pos, offset := 0, 0
	for i := 0; i < int(b.FrameCount); i++ {
		size := min(c.chunk, len(payload)-offset)
		padLen, _ := c.engine.GenerateInto(paddingScratch[:int(b.PaddingBytes)])
		// Bounds already proved all possible padding/stream sizes representable.
		body, wrapper, _ := frameSizeWithSpec(c.spec, c.spec.messages[0], streamID, len(metadata)+size+padLen)
		n := body + wrapper
		writeFrameWithSpec(c.spec, framesDst[pos:pos+n], c.spec.messages[0], streamID, metadata[:], payload[offset:offset+size], paddingScratch[:padLen], i, int(b.FrameCount), body, wrapper)
		spans[i] = FrameSpanV3{uint32(pos), uint32(n)}
		pos += n
		offset += size
	}
	return pos, int(b.FrameCount), nil
}

// DecodeInto borrows immutable input and spans, and exclusively borrows output.
// Ordered spans must cover frameBytes exactly. No input/output overlap is
// supported. All fragments and the aggregate are validated before copying.
// Ancillary metadata is compared using decoded semantics, then discarded.
func (c *LiveDataCodecV3) DecodeInto(payloadDst, frameBytes []byte, spans []FrameSpanV3) (LiveDataInfoV3, error) {
	if c == nil || c.engine == nil {
		return LiveDataInfoV3{}, errLiveDataBufferV3
	}
	if len(spans) == 0 {
		return LiveDataInfoV3{}, fragmentError(FragmentErrorEmpty)
	}
	if len(spans) > 256 || byteSlicesOverlap(payloadDst, frameBytes) {
		return LiveDataInfoV3{}, errLiveDataBufferV3
	}
	spanBytes := unsafe.Slice((*byte)(unsafe.Pointer(unsafe.SliceData(spans))), len(spans)*int(unsafe.Sizeof(FrameSpanV3{})))
	if byteSlicesOverlap(payloadDst, spanBytes) {
		return LiveDataInfoV3{}, errLiveDataBufferV3
	}
	end := uint64(0)
	for _, span := range spans {
		if span.Length == 0 || uint64(span.Offset) != end {
			return LiveDataInfoV3{}, errLiveDataBufferV3
		}
		end += uint64(span.Length)
		if end > uint64(len(frameBytes)) {
			return LiveDataInfoV3{}, errLiveDataBufferV3
		}
	}
	if end != uint64(len(frameBytes)) {
		return LiveDataInfoV3{}, errLiveDataBufferV3
	}
	var expected frameView
	total := 0
	for i, span := range spans {
		part, err := parseFrameView(c.spec, frameBytes[int(span.Offset):int(uint64(span.Offset)+uint64(span.Length))])
		if err != nil {
			return LiveDataInfoV3{}, err
		}
		if i == 0 {
			expected = part
			if part.fragCount != len(spans) {
				return LiveDataInfoV3{}, fragmentError(FragmentErrorMissing)
			}
		}
		if part.fragCount != expected.fragCount {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorConflictingCount)
		}
		if part.fragIndex >= len(spans) {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorOutOfRange)
		}
		if part.fragIndex < i {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorDuplicate)
		}
		if part.fragIndex != i {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorReordered)
		}
		if part.msg.semantic != expected.msg.semantic {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorSemantic)
		}
		if part.streamID != expected.streamID {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorStream)
		}
		if part.msg.wireSymbol != expected.msg.wireSymbol {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorMessage)
		}
		if !part.metadata.validOperation() || !part.metadata.equal(expected.metadata) {
			return LiveDataInfoV3{}, fragmentError(FragmentErrorOperation)
		}
		if part.msg.semantic != "data" || part.streamID < 2 || part.streamID > 65534 || part.bodyBytes > c.spec.maxFrameBytes || len(part.payload) > c.maxPayload-total {
			return LiveDataInfoV3{}, errLiveDataBufferV3
		}
		total += len(part.payload)
	}
	if total <= 0 || total < c.minPayload || total > len(payloadDst) {
		return LiveDataInfoV3{}, errLiveDataBufferV3
	}
	pos := 0
	for _, span := range spans {
		// The immutable input was completely validated above. Reparse borrowed
		// views rather than allocating fragment descriptors/reassembly buffers.
		part, _ := parseFrameView(c.spec, frameBytes[int(span.Offset):int(uint64(span.Offset)+uint64(span.Length))])
		pos += copy(payloadDst[pos:total], part.payload)
	}
	return LiveDataInfoV3{expected.streamID, uint32(total)}, nil
}

func byteSlicesOverlap(a, b []byte) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	ap, bp := uintptr(unsafe.Pointer(unsafe.SliceData(a))), uintptr(unsafe.Pointer(unsafe.SliceData(b)))
	if ap <= bp {
		return bp-ap < uintptr(len(a))
	}
	return ap-bp < uintptr(len(b))
}
