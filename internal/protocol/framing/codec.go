// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package framing

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/crc32"
	"io"

	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/padding"
	"kurdistan/internal/protocol/proxysem"
	"kurdistan/internal/protocol/scheduler"
)

type Operation struct {
	Semantic    string
	StreamID    uint32
	Sequence    uint64
	Offset      uint64
	CreditBytes int
	Reason      string
	Priority    string
	EndStream   bool
	Payload     []byte

	RelayIntentID      uint64
	TargetClass        string
	TargetVariant      string
	RequestClass       string
	ResponseMode       string
	TargetErrorCode    string
	TargetCloseReason  string
	TargetResetReason  string
	MetadataClass      string
	ResponseChunkIndex int
	PayloadByteCount   int
	ResponseByteCount  int
}

type DecodedFrame struct {
	Operation    Operation
	WireSymbol   string
	FrameBytes   int
	PayloadBytes int
	PaddingBytes int
	FragIndex    int
	FragCount    int
}

var ErrFragmentCoverage = errors.New("fragment coverage")

type FragmentErrorKind string

const (
	FragmentErrorEmpty            FragmentErrorKind = "empty"
	FragmentErrorMissing          FragmentErrorKind = "missing"
	FragmentErrorConflictingCount FragmentErrorKind = "conflicting_count"
	FragmentErrorSemantic         FragmentErrorKind = "semantic"
	FragmentErrorStream           FragmentErrorKind = "stream"
	FragmentErrorMessage          FragmentErrorKind = "message"
	FragmentErrorOperation        FragmentErrorKind = "operation"
	FragmentErrorOutOfRange       FragmentErrorKind = "out_of_range"
	FragmentErrorDuplicate        FragmentErrorKind = "duplicate"
	FragmentErrorReordered        FragmentErrorKind = "reordered"
)

type FragmentError struct {
	Kind FragmentErrorKind
}

func (e *FragmentError) Error() string {
	return fmt.Sprintf("fragment coverage: %s", e.Kind)
}

func (e *FragmentError) Unwrap() error {
	return ErrFragmentCoverage
}

func fragmentError(kind FragmentErrorKind) error {
	return &FragmentError{Kind: kind}
}

func EncodeOperation(p *ir.Profile, op Operation, seed int64) ([][]byte, error) {
	if err := ir.Validate(p); err != nil {
		return nil, err
	}
	if err := validateProxyOperation(p, op); err != nil {
		return nil, err
	}
	spec, err := codecSpecFromProfile(p)
	if err != nil {
		return nil, err
	}
	return encodeOperationWithSpec(spec, op, seed)
}

// EncodeLiveOperation encodes product-safe data or padding without accepting
// an IR profile or any model authentication material.
func EncodeLiveOperation(program liveprogram.ProgramV1, op Operation, seed int64) ([][]byte, error) {
	spec, err := codecSpecFromLiveProgram(program)
	if err != nil {
		return nil, err
	}
	return encodeOperationWithSpec(spec, op, seed)
}

func encodeOperationWithSpec(spec codecSpec, op Operation, seed int64) ([][]byte, error) {
	if len(op.Payload) > spec.maxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds program limit")
	}
	if _, ok := spec.messageBySemantic(op.Semantic); !ok {
		return nil, fmt.Errorf("unknown semantic")
	}
	sizes := scheduler.FragmentSizesFor(spec.fragmentationMode, spec.maxBatchBytes, spec.maxFrameBytes, len(op.Payload))
	engine := padding.New(spec.padding, seed)
	frames := make([][]byte, 0, len(sizes))
	offset := 0
	for idx, size := range sizes {
		chunk := op.Payload[offset : offset+size]
		offset += size
		pad, err := engine.Generate()
		if err != nil {
			return nil, err
		}
		partOp := op
		partOp.Payload = chunk
		frame, err := encodeFrameWithSpec(spec, partOp, pad, idx, len(sizes))
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func DecodeFrames(p *ir.Profile, frames [][]byte) (Operation, []DecodedFrame, error) {
	spec, err := codecSpecFromProfile(p)
	if err != nil {
		return Operation{}, nil, err
	}
	return decodeFramesWithSpec(spec, frames)
}

// DecodeLiveFrames decodes a product-safe live program with the same immutable
// codec spec used by the legacy adapter.
func DecodeLiveFrames(program liveprogram.ProgramV1, frames [][]byte) (Operation, []DecodedFrame, error) {
	spec, err := codecSpecFromLiveProgram(program)
	if err != nil {
		return Operation{}, nil, err
	}
	return decodeFramesWithSpec(spec, frames)
}

func decodeFramesWithSpec(spec codecSpec, frames [][]byte) (Operation, []DecodedFrame, error) {
	decoded := make([]DecodedFrame, 0, len(frames))
	for _, frame := range frames {
		part, err := decodeFrameWithSpec(spec, frame)
		if err != nil {
			return Operation{}, nil, err
		}
		decoded = append(decoded, part)
	}
	if len(decoded) == 0 {
		return Operation{}, nil, fragmentError(FragmentErrorEmpty)
	}
	expected := decoded[0]
	if expected.FragCount != len(decoded) {
		return Operation{}, decoded, fragmentError(FragmentErrorMissing)
	}
	expectedMetadata, err := encodeOperationMetadata(expected.Operation)
	if err != nil {
		return Operation{}, decoded, fragmentError(FragmentErrorOperation)
	}
	payloads := make([][]byte, len(decoded))
	seen := make([]bool, len(decoded))
	total := 0
	for position, part := range decoded {
		if part.FragCount != expected.FragCount {
			return Operation{}, decoded, fragmentError(FragmentErrorConflictingCount)
		}
		if part.FragIndex < 0 || part.FragIndex >= len(decoded) {
			return Operation{}, decoded, fragmentError(FragmentErrorOutOfRange)
		}
		if seen[part.FragIndex] {
			return Operation{}, decoded, fragmentError(FragmentErrorDuplicate)
		}
		seen[part.FragIndex] = true
		if part.FragIndex != position {
			return Operation{}, decoded, fragmentError(FragmentErrorReordered)
		}
		if part.Operation.Semantic != expected.Operation.Semantic {
			return Operation{}, decoded, fragmentError(FragmentErrorSemantic)
		}
		if part.Operation.StreamID != expected.Operation.StreamID {
			return Operation{}, decoded, fragmentError(FragmentErrorStream)
		}
		if part.WireSymbol != expected.WireSymbol {
			return Operation{}, decoded, fragmentError(FragmentErrorMessage)
		}
		metadata, err := encodeOperationMetadata(part.Operation)
		if err != nil || !bytes.Equal(metadata, expectedMetadata) {
			return Operation{}, decoded, fragmentError(FragmentErrorOperation)
		}
		payloads[part.FragIndex] = part.Operation.Payload
		total += len(part.Operation.Payload)
	}
	for _, present := range seen {
		if !present {
			return Operation{}, decoded, fragmentError(FragmentErrorMissing)
		}
	}
	payload := make([]byte, 0, total)
	for _, part := range payloads {
		payload = append(payload, part...)
	}
	result := expected.Operation
	result.Payload = payload
	return result, decoded, nil
}

func WriteOperation(w io.Writer, p *ir.Profile, op Operation, seed int64) ([]DecodedFrame, error) {
	frames, err := EncodeOperation(p, op, seed)
	if err != nil {
		return nil, err
	}
	decoded := make([]DecodedFrame, 0, len(frames))
	for _, frame := range frames {
		if _, err := w.Write(frame); err != nil {
			return nil, err
		}
		part, err := DecodeFrame(p, frame)
		if err != nil {
			return nil, err
		}
		decoded = append(decoded, part)
	}
	return decoded, nil
}

func ReadOperation(r *bufio.Reader, p *ir.Profile) (Operation, []DecodedFrame, error) {
	first, err := ReadFrame(r, p)
	if err != nil {
		return Operation{}, nil, err
	}
	part, err := DecodeFrame(p, first)
	if err != nil {
		return Operation{}, nil, err
	}
	frames := [][]byte{first}
	for len(frames) < part.FragCount {
		next, err := ReadFrame(r, p)
		if err != nil {
			return Operation{}, nil, err
		}
		frames = append(frames, next)
	}
	return DecodeFrames(p, frames)
}

func ReadFrame(r *bufio.Reader, p *ir.Profile) ([]byte, error) {
	spec, err := codecSpecFromProfile(p)
	if err != nil {
		return nil, err
	}
	return readFrameWithSpec(r, spec)
}

func readFrameWithSpec(r *bufio.Reader, spec codecSpec) ([]byte, error) {
	switch spec.lengthMode {
	case "varint_prefix":
		prefix := []byte{}
		for {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			prefix = append(prefix, b)
			length, n := binary.Uvarint(prefix)
			if n > 0 {
				return readPrefixBodyWithSpec(r, spec, prefix, int(length))
			}
			if len(prefix) > binary.MaxVarintLen64 {
				return nil, fmt.Errorf("invalid varint length")
			}
		}
	case "fixed_2_prefix":
		prefix := make([]byte, 2)
		if _, err := io.ReadFull(r, prefix); err != nil {
			return nil, err
		}
		return readPrefixBodyWithSpec(r, spec, prefix, int(binary.BigEndian.Uint16(prefix)))
	case "fixed_4_prefix":
		prefix := make([]byte, 4)
		if _, err := io.ReadFull(r, prefix); err != nil {
			return nil, err
		}
		return readPrefixBodyWithSpec(r, spec, prefix, int(binary.BigEndian.Uint32(prefix)))
	case "length_suffix_lab":
		buf := []byte{}
		for len(buf) < spec.maxFrameBytes {
			b, err := r.ReadByte()
			if err != nil {
				return nil, err
			}
			buf = append(buf, b)
			if len(buf) < 4 {
				continue
			}
			length := int(binary.BigEndian.Uint32(buf[len(buf)-4:]))
			if length == len(buf)-4 {
				candidate := append([]byte(nil), buf...)
				if _, err := decodeFrameWithSpec(spec, candidate); err == nil {
					return candidate, nil
				}
			}
		}
		return nil, fmt.Errorf("suffix frame exceeds limit")
	default:
		return nil, fmt.Errorf("unsupported length mode")
	}
}

func readPrefixBodyWithSpec(r io.Reader, spec codecSpec, prefix []byte, length int) ([]byte, error) {
	if length <= 0 || length > spec.maxFrameBytes {
		return nil, fmt.Errorf("invalid frame length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(append([]byte(nil), prefix...), body...), nil
}

func encodeFrame(p *ir.Profile, op Operation, pad []byte, fragIndex, fragCount int) ([]byte, error) {
	spec, err := codecSpecFromProfile(p)
	if err != nil {
		return nil, err
	}
	return encodeFrameWithSpec(spec, op, pad, fragIndex, fragCount)
}

func encodeFrameWithSpec(spec codecSpec, op Operation, pad []byte, fragIndex, fragCount int) ([]byte, error) {
	msg, ok := spec.messageBySemantic(op.Semantic)
	if !ok {
		return nil, fmt.Errorf("unknown semantic")
	}
	if len(pad) > 0 && (len(pad) < spec.padding.MinPaddingBytes || len(pad) > spec.padding.MaxPaddingBytes) {
		return nil, fmt.Errorf("padding outside bounds")
	}
	meta, err := encodeOperationMetadata(op)
	if err != nil {
		return nil, err
	}
	contentBytes := 0
	for _, size := range [...]int{len(meta), len(op.Payload), len(pad)} {
		if size > spec.maxFrameBytes-contentBytes {
			return nil, fmt.Errorf("frame exceeds profile limit")
		}
		contentBytes += size
	}
	body, wrapper, err := frameSizeWithSpec(spec, msg, op.StreamID, contentBytes)
	if err != nil {
		return nil, err
	}
	out := make([]byte, body+wrapper)
	writeFrameWithSpec(spec, out, msg, op.StreamID, meta, op.Payload, pad, fragIndex, fragCount, body, wrapper)
	return out, nil
}

func DecodeFrame(p *ir.Profile, frame []byte) (DecodedFrame, error) {
	spec, err := codecSpecFromProfile(p)
	if err != nil {
		return DecodedFrame{}, err
	}
	return decodeFrameWithSpec(spec, frame)
}

func decodeFrameWithSpec(spec codecSpec, frame []byte) (DecodedFrame, error) {
	view, err := parseFrameView(spec, frame)
	if err != nil {
		return DecodedFrame{}, err
	}
	op := view.metadata.materialize()
	op.Semantic = view.msg.semantic
	op.StreamID = view.streamID
	op.Payload = view.payload
	return DecodedFrame{Operation: op, WireSymbol: view.msg.wireSymbol, FrameBytes: len(frame), PayloadBytes: len(view.payload), PaddingBytes: view.padLen, FragIndex: view.fragIndex, FragCount: view.fragCount}, nil
}

func encodeHeaderFieldsWithSpec(spec codecSpec, msg codecMessage, streamID uint32, fragIndex, fragCount, padLen int) ([]byte, error) {
	size, err := headerFieldsSize(spec, msg, streamID, spec.maxFrameBytes)
	if err != nil {
		return nil, err
	}
	out := make([]byte, size)
	_, err = writeHeaderFields(spec, out, msg, streamID, fragIndex, fragCount, padLen)
	if err != nil {
		return nil, err
	}
	return out, nil
}

func decodeHeaderAndPayloadWithSpec(spec codecSpec, body []byte) (codecMessage, uint32, int, int, int, []byte, error) {
	rest := body
	var msg codecMessage
	var hasType bool
	var streamID uint32
	fragIndex, fragCount, padLen := 0, 1, 0
	for _, field := range spec.headerOrder {
		switch field {
		case "length":
			continue
		case "type":
			if len(rest) < 1 {
				return msg, 0, 0, 0, 0, nil, io.ErrUnexpectedEOF
			}
			n := int(rest[0])
			rest = rest[1:]
			if len(rest) < n {
				return msg, 0, 0, 0, 0, nil, io.ErrUnexpectedEOF
			}
			tag := rest[:n]
			rest = rest[n:]
			found, ok := spec.messageByTag(tag)
			if !ok {
				return msg, 0, 0, 0, 0, nil, fmt.Errorf("unknown type tag")
			}
			msg = found
			hasType = true
		case "stream":
			if len(rest) < 1 {
				return msg, 0, 0, 0, 0, nil, io.ErrUnexpectedEOF
			}
			n := int(rest[0])
			rest = rest[1:]
			if n <= 0 || len(rest) < n {
				return msg, 0, 0, 0, 0, nil, io.ErrUnexpectedEOF
			}
			id, err := decodeStreamIDWithSpec(spec, rest[:n])
			if err != nil {
				return msg, 0, 0, 0, 0, nil, err
			}
			streamID = id
			rest = rest[n:]
		case "flags":
			if len(rest) < 7 {
				return msg, 0, 0, 0, 0, nil, io.ErrUnexpectedEOF
			}
			fragIndex = int(binary.BigEndian.Uint16(rest[1:3]))
			fragCount = int(binary.BigEndian.Uint16(rest[3:5]))
			padLen = int(binary.BigEndian.Uint16(rest[5:7]))
			rest = rest[7:]
		}
	}
	if !hasType {
		return msg, 0, 0, 0, 0, nil, fmt.Errorf("missing type tag")
	}
	if fragCount <= 0 {
		return msg, 0, 0, 0, 0, nil, fmt.Errorf("invalid fragment count")
	}
	return msg, streamID, fragIndex, fragCount, padLen, rest, nil
}

func wrapLengthWithSpec(spec codecSpec, body []byte) ([]byte, error) {
	switch spec.lengthMode {
	case "varint_prefix":
		prefix := make([]byte, binary.MaxVarintLen64)
		n := binary.PutUvarint(prefix, uint64(len(body)))
		return append(prefix[:n], body...), nil
	case "fixed_2_prefix":
		if len(body) > 0xffff {
			return nil, fmt.Errorf("frame too large for fixed 2-byte length")
		}
		var prefix [2]byte
		binary.BigEndian.PutUint16(prefix[:], uint16(len(body)))
		return append(prefix[:], body...), nil
	case "fixed_4_prefix":
		var prefix [4]byte
		binary.BigEndian.PutUint32(prefix[:], uint32(len(body)))
		return append(prefix[:], body...), nil
	case "length_suffix_lab":
		var suffix [4]byte
		binary.BigEndian.PutUint32(suffix[:], uint32(len(body)))
		return append(append([]byte(nil), body...), suffix[:]...), nil
	default:
		return nil, fmt.Errorf("unsupported length mode")
	}
}

func unwrapLengthWithSpec(spec codecSpec, frame []byte) ([]byte, error) {
	switch spec.lengthMode {
	case "varint_prefix":
		length, n := binary.Uvarint(frame)
		if n <= 0 {
			return nil, fmt.Errorf("invalid varint length")
		}
		if int(length) != len(frame)-n {
			return nil, fmt.Errorf("frame length mismatch")
		}
		return frame[n:], nil
	case "fixed_2_prefix":
		if len(frame) < 2 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(binary.BigEndian.Uint16(frame[:2]))
		if length != len(frame)-2 {
			return nil, fmt.Errorf("frame length mismatch")
		}
		return frame[2:], nil
	case "fixed_4_prefix":
		if len(frame) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(binary.BigEndian.Uint32(frame[:4]))
		if length != len(frame)-4 {
			return nil, fmt.Errorf("frame length mismatch")
		}
		return frame[4:], nil
	case "length_suffix_lab":
		if len(frame) < 4 {
			return nil, io.ErrUnexpectedEOF
		}
		length := int(binary.BigEndian.Uint32(frame[len(frame)-4:]))
		if length != len(frame)-4 {
			return nil, fmt.Errorf("frame length mismatch")
		}
		return frame[:len(frame)-4], nil
	default:
		return nil, fmt.Errorf("unsupported length mode")
	}
}

func encodeOperationMetadata(op Operation) ([]byte, error) {
	if len(op.Reason) > 255 {
		return nil, fmt.Errorf("reason too long")
	}
	if len(op.Priority) > 255 {
		return nil, fmt.Errorf("priority too long")
	}
	if op.CreditBytes < 0 {
		return nil, fmt.Errorf("credit bytes cannot be negative")
	}
	if op.PayloadByteCount < 0 || op.ResponseByteCount < 0 || op.ResponseChunkIndex < 0 {
		return nil, fmt.Errorf("proxy byte counts and chunk indexes cannot be negative")
	}
	size := 51
	for _, value := range operationMetadataStrings(op) {
		if len(value) > 255 {
			return nil, fmt.Errorf("proxy metadata value too long")
		}
		size += len(value)
	}
	out := make([]byte, size)
	writeOperationMetadata(out, op)
	return out, nil
}

func decodeOperationMetadata(in []byte) (Operation, []byte, error) {
	view, payload, err := parseMetadataView(in)
	if err != nil {
		return Operation{}, nil, err
	}
	return view.materialize(), payload, nil
}

func validateProxyOperation(p *ir.Profile, op Operation) error {
	switch op.Semantic {
	case ir.SemanticOpenRelay, ir.SemanticTargetDescriptor:
		if op.TargetClass == "" {
			return fmt.Errorf("target class is required for %s", op.Semantic)
		}
		if err := proxysem.DefaultRegistry().Validate(proxysem.TargetDescriptor{Class: op.TargetClass, Variant: op.TargetVariant}); err != nil {
			return err
		}
	case ir.SemanticTargetData:
		if op.PayloadByteCount > p.ProxySemantics.MaxRequestBytes || len(op.Payload) > p.ProxySemantics.MaxRequestBytes {
			return fmt.Errorf("proxy request exceeds profile limit")
		}
	case ir.SemanticTargetResponse:
		if op.ResponseByteCount > p.ProxySemantics.MaxResponseBytes || len(op.Payload) > p.ProxySemantics.MaxResponseBytes {
			return fmt.Errorf("proxy response exceeds profile limit")
		}
	case ir.SemanticTargetError:
		if op.TargetErrorCode == "" {
			return fmt.Errorf("target error code is required")
		}
	case ir.SemanticTargetClose:
		if op.TargetCloseReason == "" && op.Reason == "" {
			return fmt.Errorf("target close reason is required")
		}
	case ir.SemanticTargetReset:
		if op.TargetResetReason == "" && op.Reason == "" {
			return fmt.Errorf("target reset reason is required")
		}
	}
	return nil
}

func encodeStreamIDWithSpec(spec codecSpec, streamID uint32) ([]byte, error) {
	var buf [binary.MaxVarintLen32]byte
	n, err := writeStreamID(spec, buf[:], streamID)
	if err != nil {
		return nil, err
	}
	return buf[:n], nil
}

func decodeStreamIDWithSpec(spec codecSpec, encoded []byte) (uint32, error) {
	switch spec.streamEncodingMode {
	case "fixed32_be", "":
		if len(encoded) != 4 {
			return 0, fmt.Errorf("invalid fixed stream id length")
		}
		return binary.BigEndian.Uint32(encoded), nil
	case "profile_xor32":
		if len(encoded) != 4 {
			return 0, fmt.Errorf("invalid xor stream id length")
		}
		return binary.BigEndian.Uint32(encoded) ^ spec.profileXORStreamMask, nil
	case "table_mapped32_le":
		if len(encoded) != 4 {
			return 0, fmt.Errorf("invalid table stream id length")
		}
		return binary.LittleEndian.Uint32(encoded) ^ spec.tableStreamMask, nil
	case "varint":
		value, n := binary.Uvarint(encoded)
		if n <= 0 || value > 1<<32-1 {
			return 0, fmt.Errorf("invalid varint stream id")
		}
		return uint32(value), nil
	default:
		return 0, fmt.Errorf("unsupported stream id encoding")
	}
}

func appendCRCWithSpec(spec codecSpec, body []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], crcForSpec(spec, body))
	return append(body, b[:]...)
}

func crcForSpec(spec codecSpec, body []byte) uint32 {
	return crc32.Update(spec.crc32PrefixState, crc32.IEEETable, body)
}

func IsMalformed(err error) bool {
	return err != nil && !errors.Is(err, io.EOF)
}
