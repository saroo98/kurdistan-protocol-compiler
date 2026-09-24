// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package framing

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
)

// These primitives are shared by the allocating legacy codec and the prepared
// caller-buffer codec. Callers validate capacity before invoking any writer.
func writeStreamID(spec codecSpec, dst []byte, streamID uint32) (int, error) {
	switch spec.streamEncodingMode {
	case "fixed32_be", "":
		binary.BigEndian.PutUint32(dst, streamID)
	case "profile_xor32":
		binary.BigEndian.PutUint32(dst, streamID^spec.profileXORStreamMask)
	case "table_mapped32_le":
		binary.LittleEndian.PutUint32(dst, streamID^spec.tableStreamMask)
	case "varint":
		return binary.PutUvarint(dst, uint64(streamID)), nil
	default:
		return 0, fmt.Errorf("unsupported stream id encoding")
	}
	return 4, nil
}

func writeHeaderFields(spec codecSpec, dst []byte, msg codecMessage, streamID uint32, fragIndex, fragCount, padLen int) (int, error) {
	var stream [binary.MaxVarintLen32]byte
	streamLen, err := writeStreamID(spec, stream[:], streamID)
	if err != nil {
		return 0, err
	}
	if len(msg.typeTag) > 255 {
		return 0, fmt.Errorf("type tag too long")
	}
	pos := 0
	for _, field := range spec.headerOrder {
		switch field {
		case "type":
			dst[pos] = byte(len(msg.typeTag))
			pos++
			pos += copy(dst[pos:], msg.typeTag)
		case "stream":
			dst[pos] = byte(streamLen)
			pos++
			pos += copy(dst[pos:], stream[:streamLen])
		case "flags":
			dst[pos] = 0
			if fragCount > 1 {
				dst[pos] |= 1
			}
			if padLen > 0 {
				dst[pos] |= 2
			}
			binary.BigEndian.PutUint16(dst[pos+1:pos+3], uint16(fragIndex))
			binary.BigEndian.PutUint16(dst[pos+3:pos+5], uint16(fragCount))
			binary.BigEndian.PutUint16(dst[pos+5:pos+7], uint16(padLen))
			pos += 7
		}
	}
	return pos, nil
}

func uvarintSize(value uint64) int {
	n := 1
	for value >= 128 {
		n++
		value >>= 7
	}
	return n
}

func lengthWrapperSize(spec codecSpec, bodyBytes int) (int, error) {
	switch spec.lengthMode {
	case "varint_prefix":
		return uvarintSize(uint64(bodyBytes)), nil
	case "fixed_2_prefix":
		if bodyBytes > 65535 {
			return 0, fmt.Errorf("frame too large for fixed 2-byte length")
		}
		return 2, nil
	case "fixed_4_prefix", "length_suffix_lab":
		return 4, nil
	default:
		return 0, fmt.Errorf("unsupported length mode")
	}
}

// headerFieldsSize counts every emitted occurrence. Legacy IR validation permits
// repeated known fields, whereas live programs require an exact header set.
// Length placeholders, including duplicates, emit no bytes in the body.
func headerFieldsSize(spec codecSpec, msg codecMessage, streamID uint32, limit int) (int, error) {
	var stream [binary.MaxVarintLen32]byte
	n, err := writeStreamID(spec, stream[:], streamID)
	if err != nil {
		return 0, err
	}
	if len(msg.typeTag) > 255 {
		return 0, fmt.Errorf("type tag too long")
	}
	if limit < 0 {
		return 0, fmt.Errorf("frame exceeds profile limit")
	}
	size := 0
	for _, field := range spec.headerOrder {
		fieldBytes := 0
		switch field {
		case "type":
			fieldBytes = 1 + len(msg.typeTag)
		case "stream":
			fieldBytes = 1 + n
		case "flags":
			fieldBytes = 7
		}
		if fieldBytes > limit-size {
			return 0, fmt.Errorf("frame exceeds profile limit")
		}
		size += fieldBytes
	}
	return size, nil
}

func frameSizeWithSpec(spec codecSpec, msg codecMessage, streamID uint32, contentBytes int) (bodyBytes, wrapperBytes int, err error) {
	if contentBytes < 0 || contentBytes > spec.maxFrameBytes {
		return 0, 0, fmt.Errorf("frame exceeds profile limit")
	}
	checksumBytes := 0
	if spec.checksumMode == "crc32" {
		checksumBytes = 4
	}
	if checksumBytes > spec.maxFrameBytes-contentBytes {
		return 0, 0, fmt.Errorf("frame exceeds profile limit")
	}
	headerBytes, err := headerFieldsSize(spec, msg, streamID, spec.maxFrameBytes-contentBytes-checksumBytes)
	if err != nil {
		return 0, 0, err
	}
	// The subtraction-before-add checks above prove the complete sum fits the
	// admitted body limit and native int before any destination allocation.
	bodyBytes = headerBytes + contentBytes + checksumBytes
	wrapperBytes, err = lengthWrapperSize(spec, bodyBytes)
	if err == nil && wrapperBytes > int(^uint(0)>>1)-bodyBytes {
		return 0, 0, fmt.Errorf("frame length overflow")
	}
	return
}

func writeFrameWithSpec(spec codecSpec, dst []byte, msg codecMessage, streamID uint32, meta, payload, pad []byte, fragIndex, fragCount, bodyBytes, wrapperBytes int) {
	start := wrapperBytes
	if spec.lengthMode == "length_suffix_lab" {
		start = 0
	}
	body := dst[start : start+bodyBytes]
	pos, _ := writeHeaderFields(spec, body, msg, streamID, fragIndex, fragCount, len(pad))
	if spec.paddingPlacement == "prefix" {
		pos += copy(body[pos:], pad)
	}
	pos += copy(body[pos:], meta)
	pos += copy(body[pos:], payload)
	if spec.paddingPlacement != "prefix" {
		pos += copy(body[pos:], pad)
	}
	if spec.checksumMode == "crc32" {
		binary.BigEndian.PutUint32(body[pos:pos+4], crcForSpec(spec, body[:pos]))
	}
	switch spec.lengthMode {
	case "varint_prefix":
		binary.PutUvarint(dst, uint64(bodyBytes))
	case "fixed_2_prefix":
		binary.BigEndian.PutUint16(dst, uint16(bodyBytes))
	case "fixed_4_prefix":
		binary.BigEndian.PutUint32(dst, uint32(bodyBytes))
	case "length_suffix_lab":
		binary.BigEndian.PutUint32(dst[bodyBytes:], uint32(bodyBytes))
	}
}

// metadataView borrows validated encoded metadata; only materialize creates strings.
type metadataView struct {
	fixed  []byte
	values [10][]byte
}

func operationMetadataStrings(op Operation) [10]string {
	return [10]string{op.Reason, op.Priority, op.TargetClass, op.TargetVariant, op.RequestClass, op.ResponseMode, op.TargetErrorCode, op.TargetCloseReason, op.TargetResetReason, op.MetadataClass}
}

func writeOperationMetadata(dst []byte, op Operation) {
	binary.BigEndian.PutUint64(dst[0:8], op.Sequence)
	binary.BigEndian.PutUint64(dst[8:16], op.Offset)
	binary.BigEndian.PutUint32(dst[16:20], uint32(op.CreditBytes))
	dst[20] = 0
	if op.EndStream {
		dst[20] = 1
	}
	binary.BigEndian.PutUint64(dst[21:29], op.RelayIntentID)
	binary.BigEndian.PutUint32(dst[29:33], uint32(op.PayloadByteCount))
	binary.BigEndian.PutUint32(dst[33:37], uint32(op.ResponseByteCount))
	binary.BigEndian.PutUint32(dst[37:41], uint32(op.ResponseChunkIndex))
	pos := 41
	for _, value := range operationMetadataStrings(op) {
		dst[pos] = byte(len(value))
		pos++
		pos += copy(dst[pos:], value)
	}
}

func parseMetadataView(in []byte) (metadataView, []byte, error) {
	var view metadataView
	if len(in) < 51 {
		return view, nil, io.ErrUnexpectedEOF
	}
	view.fixed = in[:41:41]
	rest := in[41:]
	for i := range view.values {
		if len(rest) < 1 {
			return metadataView{}, nil, io.ErrUnexpectedEOF
		}
		n := int(rest[0])
		rest = rest[1:]
		if len(rest) < n {
			return metadataView{}, nil, io.ErrUnexpectedEOF
		}
		view.values[i] = rest[:n:n]
		rest = rest[n:]
	}
	return view, rest, nil
}

func (v metadataView) equal(other metadataView) bool {
	if !bytes.Equal(v.fixed[:20], other.fixed[:20]) || (v.fixed[20] != 0) != (other.fixed[20] != 0) || !bytes.Equal(v.fixed[21:], other.fixed[21:]) {
		return false
	}
	for i := range v.values {
		if !bytes.Equal(v.values[i], other.values[i]) {
			return false
		}
	}
	return true
}

// Re-encoding an Operation rejects negative int fields on a 32-bit target.
// Keep that legacy comparison rule without constructing an Operation or strings.
func (v metadataView) validOperation() bool {
	for _, offset := range [...]int{16, 29, 33, 37} {
		if int(binary.BigEndian.Uint32(v.fixed[offset:offset+4])) < 0 {
			return false
		}
	}
	return true
}

func (v metadataView) materialize() Operation {
	in := v.fixed
	return Operation{
		Sequence: binary.BigEndian.Uint64(in[:8]), Offset: binary.BigEndian.Uint64(in[8:16]),
		CreditBytes: int(binary.BigEndian.Uint32(in[16:20])), EndStream: in[20] != 0,
		RelayIntentID:      binary.BigEndian.Uint64(in[21:29]),
		PayloadByteCount:   int(binary.BigEndian.Uint32(in[29:33])),
		ResponseByteCount:  int(binary.BigEndian.Uint32(in[33:37])),
		ResponseChunkIndex: int(binary.BigEndian.Uint32(in[37:41])),
		Reason:             string(v.values[0]), Priority: string(v.values[1]),
		TargetClass: string(v.values[2]), TargetVariant: string(v.values[3]),
		RequestClass: string(v.values[4]), ResponseMode: string(v.values[5]),
		TargetErrorCode: string(v.values[6]), TargetCloseReason: string(v.values[7]),
		TargetResetReason: string(v.values[8]), MetadataClass: string(v.values[9]),
	}
}

type frameView struct {
	msg                                     codecMessage
	streamID                                uint32
	fragIndex, fragCount, padLen, bodyBytes int
	metadata                                metadataView
	payload                                 []byte
}

func parseFrameView(spec codecSpec, frame []byte) (frameView, error) {
	if len(frame) == 0 || len(frame) > spec.maxFrameBytes+binary.MaxVarintLen64 {
		return frameView{}, fmt.Errorf("invalid frame size")
	}
	body, err := unwrapLengthWithSpec(spec, frame)
	if err != nil {
		return frameView{}, err
	}
	bodyBytes := len(body)
	if spec.checksumMode == "crc32" {
		if len(body) < 4 {
			return frameView{}, fmt.Errorf("missing checksum")
		}
		want := binary.BigEndian.Uint32(body[len(body)-4:])
		body = body[:len(body)-4]
		if crcForSpec(spec, body) != want {
			return frameView{}, fmt.Errorf("checksum mismatch")
		}
	}
	msg, stream, index, count, padLen, section, err := decodeHeaderAndPayloadWithSpec(spec, body)
	if err != nil {
		return frameView{}, err
	}
	if padLen > len(section) {
		return frameView{}, fmt.Errorf("padding length exceeds payload section")
	}
	if padLen > 0 {
		if spec.paddingPlacement == "prefix" {
			section = section[padLen:]
		} else {
			section = section[:len(section)-padLen]
		}
	}
	meta, payload, err := parseMetadataView(section)
	if err != nil {
		return frameView{}, err
	}
	if len(payload) > spec.maxPayloadBytes {
		return frameView{}, fmt.Errorf("payload exceeds profile limit")
	}
	return frameView{msg: msg, streamID: stream, fragIndex: index, fragCount: count, padLen: padLen, bodyBytes: bodyBytes, metadata: meta, payload: payload}, nil
}
