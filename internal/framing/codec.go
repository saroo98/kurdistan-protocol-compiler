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

	"kurdistan/internal/ir"
	"kurdistan/internal/padding"
	"kurdistan/internal/scheduler"
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

func EncodeOperation(p *ir.Profile, op Operation, seed int64) ([][]byte, error) {
	if err := ir.Validate(p); err != nil {
		return nil, err
	}
	if len(op.Payload) > p.Limits.MaxPayloadBytes {
		return nil, fmt.Errorf("payload exceeds profile limit")
	}
	if _, ok := ir.MessageBySemantic(p, op.Semantic); !ok {
		return nil, fmt.Errorf("unknown semantic %q", op.Semantic)
	}
	sizes := scheduler.FragmentSizes(p, len(op.Payload))
	engine := padding.New(p.Padding, seed)
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
		frame, err := encodeFrame(p, partOp, pad, idx, len(sizes))
		if err != nil {
			return nil, err
		}
		frames = append(frames, frame)
	}
	return frames, nil
}

func DecodeFrames(p *ir.Profile, frames [][]byte) (Operation, []DecodedFrame, error) {
	decoded := make([]DecodedFrame, 0, len(frames))
	for _, frame := range frames {
		part, err := DecodeFrame(p, frame)
		if err != nil {
			return Operation{}, nil, err
		}
		decoded = append(decoded, part)
	}
	if len(decoded) == 0 {
		return Operation{}, nil, fmt.Errorf("no frames")
	}
	if decoded[0].FragCount != len(decoded) {
		return Operation{}, decoded, fmt.Errorf("missing fragments")
	}
	payloads := make([][]byte, len(decoded))
	total := 0
	for _, part := range decoded {
		if part.Operation.Semantic != decoded[0].Operation.Semantic || part.Operation.StreamID != decoded[0].Operation.StreamID {
			return Operation{}, decoded, fmt.Errorf("fragment semantic mismatch")
		}
		if part.FragIndex < 0 || part.FragIndex >= len(decoded) {
			return Operation{}, decoded, fmt.Errorf("fragment index out of range")
		}
		payloads[part.FragIndex] = part.Operation.Payload
		total += len(part.Operation.Payload)
	}
	payload := make([]byte, 0, total)
	for _, part := range payloads {
		payload = append(payload, part...)
	}
	result := decoded[0].Operation
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
	switch p.FrameGrammar.LengthMode {
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
				return readPrefixBody(r, p, prefix, int(length))
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
		return readPrefixBody(r, p, prefix, int(binary.BigEndian.Uint16(prefix)))
	case "fixed_4_prefix":
		prefix := make([]byte, 4)
		if _, err := io.ReadFull(r, prefix); err != nil {
			return nil, err
		}
		return readPrefixBody(r, p, prefix, int(binary.BigEndian.Uint32(prefix)))
	case "length_suffix_lab":
		buf := []byte{}
		for len(buf) < p.Limits.MaxFrameBytes {
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
				if _, err := DecodeFrame(p, candidate); err == nil {
					return candidate, nil
				}
			}
		}
		return nil, fmt.Errorf("suffix frame exceeds limit")
	default:
		return nil, fmt.Errorf("unsupported length mode")
	}
}

func readPrefixBody(r io.Reader, p *ir.Profile, prefix []byte, length int) ([]byte, error) {
	if length <= 0 || length > p.Limits.MaxFrameBytes {
		return nil, fmt.Errorf("invalid frame length %d", length)
	}
	body := make([]byte, length)
	if _, err := io.ReadFull(r, body); err != nil {
		return nil, err
	}
	return append(append([]byte(nil), prefix...), body...), nil
}

func encodeFrame(p *ir.Profile, op Operation, pad []byte, fragIndex, fragCount int) ([]byte, error) {
	msg, ok := ir.MessageBySemantic(p, op.Semantic)
	if !ok {
		return nil, fmt.Errorf("unknown semantic %q", op.Semantic)
	}
	if len(pad) > 0 && (len(pad) < p.Padding.MinPaddingBytes || len(pad) > p.Padding.MaxPaddingBytes) {
		return nil, fmt.Errorf("padding outside bounds")
	}
	meta, err := encodeOperationMetadata(op)
	if err != nil {
		return nil, err
	}
	payloadSection := append(meta, op.Payload...)
	if len(pad) > 0 {
		switch p.FrameGrammar.PaddingPlacement {
		case "prefix":
			payloadSection = append(append([]byte(nil), pad...), payloadSection...)
		default:
			payloadSection = append(append([]byte(nil), payloadSection...), pad...)
		}
	}
	fields, err := encodeHeaderFields(p, msg, op.StreamID, fragIndex, fragCount, len(pad))
	if err != nil {
		return nil, err
	}
	body := append(fields, payloadSection...)
	if p.FrameGrammar.ChecksumMode == "crc32" {
		body = appendCRC(p, body)
	}
	if len(body) > p.Limits.MaxFrameBytes {
		return nil, fmt.Errorf("frame exceeds profile limit")
	}
	return wrapLength(p, body)
}

func DecodeFrame(p *ir.Profile, frame []byte) (DecodedFrame, error) {
	if len(frame) == 0 || len(frame) > p.Limits.MaxFrameBytes+binary.MaxVarintLen64 {
		return DecodedFrame{}, fmt.Errorf("invalid frame size")
	}
	body, err := unwrapLength(p, frame)
	if err != nil {
		return DecodedFrame{}, err
	}
	if p.FrameGrammar.ChecksumMode == "crc32" {
		if len(body) < 4 {
			return DecodedFrame{}, fmt.Errorf("missing checksum")
		}
		want := binary.BigEndian.Uint32(body[len(body)-4:])
		body = body[:len(body)-4]
		if crcFor(p, body) != want {
			return DecodedFrame{}, fmt.Errorf("checksum mismatch")
		}
	}
	msg, streamID, fragIndex, fragCount, padLen, payloadSection, err := decodeHeaderAndPayload(p, body)
	if err != nil {
		return DecodedFrame{}, err
	}
	if padLen > len(payloadSection) {
		return DecodedFrame{}, fmt.Errorf("padding length exceeds payload section")
	}
	payloadWithMeta := payloadSection
	if padLen > 0 {
		switch p.FrameGrammar.PaddingPlacement {
		case "prefix":
			payloadWithMeta = payloadSection[padLen:]
		default:
			payloadWithMeta = payloadSection[:len(payloadSection)-padLen]
		}
	}
	meta, payload, err := decodeOperationMetadata(payloadWithMeta)
	if err != nil {
		return DecodedFrame{}, err
	}
	if len(payload) > p.Limits.MaxPayloadBytes {
		return DecodedFrame{}, fmt.Errorf("payload exceeds profile limit")
	}
	meta.Semantic = msg.Semantic
	meta.StreamID = streamID
	meta.Payload = payload
	return DecodedFrame{
		Operation:    meta,
		WireSymbol:   msg.WireSymbol,
		FrameBytes:   len(frame),
		PayloadBytes: len(payload),
		PaddingBytes: padLen,
		FragIndex:    fragIndex,
		FragCount:    fragCount,
	}, nil
}

func encodeHeaderFields(p *ir.Profile, msg ir.MessageSymbol, streamID uint32, fragIndex, fragCount, padLen int) ([]byte, error) {
	var out []byte
	for _, field := range p.FrameGrammar.HeaderOrder {
		switch field {
		case "length":
			continue
		case "type":
			tag := typeTag(p, msg)
			if len(tag) > 255 {
				return nil, fmt.Errorf("type tag too long")
			}
			out = append(out, byte(len(tag)))
			out = append(out, tag...)
		case "stream":
			encoded, err := encodeStreamID(p, streamID)
			if err != nil {
				return nil, err
			}
			if len(encoded) > 255 {
				return nil, fmt.Errorf("stream id encoding too long")
			}
			out = append(out, byte(len(encoded)))
			out = append(out, encoded...)
		case "flags":
			var b [7]byte
			if fragCount > 1 {
				b[0] |= 1
			}
			if padLen > 0 {
				b[0] |= 2
			}
			binary.BigEndian.PutUint16(b[1:3], uint16(fragIndex))
			binary.BigEndian.PutUint16(b[3:5], uint16(fragCount))
			binary.BigEndian.PutUint16(b[5:7], uint16(padLen))
			out = append(out, b[:]...)
		}
	}
	return out, nil
}

func decodeHeaderAndPayload(p *ir.Profile, body []byte) (ir.MessageSymbol, uint32, int, int, int, []byte, error) {
	rest := body
	var msg ir.MessageSymbol
	var hasType bool
	var streamID uint32
	fragIndex, fragCount, padLen := 0, 1, 0
	for _, field := range p.FrameGrammar.HeaderOrder {
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
			found, ok := messageByTag(p, tag)
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
			id, err := decodeStreamID(p, rest[:n])
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

func wrapLength(p *ir.Profile, body []byte) ([]byte, error) {
	switch p.FrameGrammar.LengthMode {
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

func unwrapLength(p *ir.Profile, frame []byte) ([]byte, error) {
	switch p.FrameGrammar.LengthMode {
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

func typeTag(p *ir.Profile, msg ir.MessageSymbol) []byte {
	switch p.FrameGrammar.TypeMode {
	case "table_indexed_symbol":
		for i, candidate := range p.Messages {
			if candidate.WireSymbol == msg.WireSymbol {
				return []byte{byte(i), byte(crc32.ChecksumIEEE([]byte(p.ID+":"+msg.WireSymbol)) & 0xff)}
			}
		}
	case "derived_from_state":
		sum := crc32.ChecksumIEEE([]byte(p.ID + ":state:" + msg.WireSymbol))
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], sum)
		return b[:]
	case "derived_from_header_order":
		sum := crc32.ChecksumIEEE([]byte(fmt.Sprint(p.FrameGrammar.HeaderOrder) + ":" + msg.WireSymbol))
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], sum)
		return b[:]
	}
	return []byte(msg.WireSymbol)
}

func messageByTag(p *ir.Profile, tag []byte) (ir.MessageSymbol, bool) {
	for _, msg := range p.Messages {
		if bytes.Equal(typeTag(p, msg), tag) {
			return msg, true
		}
	}
	return ir.MessageSymbol{}, false
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
	var out []byte
	var fixed [21]byte
	binary.BigEndian.PutUint64(fixed[0:8], op.Sequence)
	binary.BigEndian.PutUint64(fixed[8:16], op.Offset)
	binary.BigEndian.PutUint32(fixed[16:20], uint32(op.CreditBytes))
	if op.EndStream {
		fixed[20] = 1
	}
	out = append(out, fixed[:]...)
	out = append(out, byte(len(op.Reason)))
	out = append(out, []byte(op.Reason)...)
	out = append(out, byte(len(op.Priority)))
	out = append(out, []byte(op.Priority)...)
	return out, nil
}

func decodeOperationMetadata(in []byte) (Operation, []byte, error) {
	if len(in) < 23 {
		return Operation{}, nil, io.ErrUnexpectedEOF
	}
	op := Operation{
		Sequence:    binary.BigEndian.Uint64(in[0:8]),
		Offset:      binary.BigEndian.Uint64(in[8:16]),
		CreditBytes: int(binary.BigEndian.Uint32(in[16:20])),
		EndStream:   in[20] != 0,
	}
	rest := in[21:]
	reasonLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < reasonLen+1 {
		return Operation{}, nil, io.ErrUnexpectedEOF
	}
	op.Reason = string(rest[:reasonLen])
	rest = rest[reasonLen:]
	priorityLen := int(rest[0])
	rest = rest[1:]
	if len(rest) < priorityLen {
		return Operation{}, nil, io.ErrUnexpectedEOF
	}
	op.Priority = string(rest[:priorityLen])
	rest = rest[priorityLen:]
	return op, rest, nil
}

func encodeStreamID(p *ir.Profile, streamID uint32) ([]byte, error) {
	switch p.Stream.IDEncodingMode {
	case "fixed32_be", "":
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], streamID)
		return b[:], nil
	case "profile_xor32":
		var b [4]byte
		binary.BigEndian.PutUint32(b[:], streamID^streamMask(p, "profile"))
		return b[:], nil
	case "table_mapped32_le":
		var b [4]byte
		binary.LittleEndian.PutUint32(b[:], streamID^streamMask(p, "table"))
		return b[:], nil
	case "varint":
		buf := make([]byte, binary.MaxVarintLen32)
		n := binary.PutUvarint(buf, uint64(streamID))
		return buf[:n], nil
	default:
		return nil, fmt.Errorf("unsupported stream id encoding %q", p.Stream.IDEncodingMode)
	}
}

func decodeStreamID(p *ir.Profile, encoded []byte) (uint32, error) {
	switch p.Stream.IDEncodingMode {
	case "fixed32_be", "":
		if len(encoded) != 4 {
			return 0, fmt.Errorf("invalid fixed stream id length")
		}
		return binary.BigEndian.Uint32(encoded), nil
	case "profile_xor32":
		if len(encoded) != 4 {
			return 0, fmt.Errorf("invalid xor stream id length")
		}
		return binary.BigEndian.Uint32(encoded) ^ streamMask(p, "profile"), nil
	case "table_mapped32_le":
		if len(encoded) != 4 {
			return 0, fmt.Errorf("invalid table stream id length")
		}
		return binary.LittleEndian.Uint32(encoded) ^ streamMask(p, "table"), nil
	case "varint":
		value, n := binary.Uvarint(encoded)
		if n <= 0 || value > 1<<32-1 {
			return 0, fmt.Errorf("invalid varint stream id")
		}
		return uint32(value), nil
	default:
		return 0, fmt.Errorf("unsupported stream id encoding %q", p.Stream.IDEncodingMode)
	}
}

func streamMask(p *ir.Profile, salt string) uint32 {
	return crc32.ChecksumIEEE([]byte(p.ID + ":" + salt + ":" + fmt.Sprint(p.FrameGrammar.HeaderOrder)))
}

func appendCRC(p *ir.Profile, body []byte) []byte {
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], crcFor(p, body))
	return append(body, b[:]...)
}

func crcFor(p *ir.Profile, body []byte) uint32 {
	h := crc32.NewIEEE()
	_, _ = h.Write([]byte(p.ID))
	_, _ = h.Write(body)
	return h.Sum32()
}

func IsMalformed(err error) bool {
	return err != nil && !errors.Is(err, io.EOF)
}
