// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"encoding/json"
	"errors"
	"strings"

	"kurdistan/internal/observe/bytetransport"
)

type MalformedByteCase struct {
	Name           string `json:"name"`
	InputClass     string `json:"input_class"`
	ExpectedReject bool   `json:"expected_reject"`
	RejectBucket   string `json:"reject_bucket"`
	PanicAllowed   bool   `json:"panic_allowed"`
}

type MalformedCaseResult struct {
	Name         string `json:"name"`
	Rejected     bool   `json:"rejected"`
	RejectBucket string `json:"reject_bucket"`
	SafeError    bool   `json:"safe_error"`
}

func DefaultMalformedCorpus() []MalformedByteCase {
	names := []struct {
		name   string
		class  string
		bucket string
	}{
		{"empty_input", "empty", "truncated"},
		{"truncated_header", "truncated_header", "truncated"},
		{"unknown_frame_kind", "unknown_kind", "unknown_kind"},
		{"oversized_frame", "oversized_frame", "oversized"},
		{"oversized_payload", "oversized_payload", "payload_length"},
		{"invalid_length_field", "invalid_length", "payload_length"},
		{"trailing_invalid_bytes", "trailing_invalid", "payload_bounds"},
		{"negative_or_invalid_fragment_index", "invalid_fragment", "validate"},
		{"fragment_count_mismatch", "fragment_mismatch", "fragment_count_mismatch"},
		{"duplicate_fragment", "duplicate_fragment", "duplicate_fragment"},
		{"missing_fragment", "missing_fragment", "incomplete_reassembly"},
		{"oversized_reassembly", "oversized_reassembly", "oversized_reassembly"},
		{"sequence_replay", "sequence_replay", "sequence_replay"},
		{"old_sequence", "old_sequence", "sequence_replay"},
		{"future_sequence_jump", "future_sequence", "sequence_future"},
		{"post_close_data", "post_close_data", "terminal"},
		{"post_reset_data", "post_reset_data", "terminal"},
		{"corrupted_checksum", "corrupted_checksum", "checksum"},
		{"invalid_metadata_class", "invalid_metadata", "metadata"},
		{"oversized_metadata", "oversized_metadata", "metadata"},
		{"random_bounded_noise", "random_noise", "truncated"},
	}
	out := make([]MalformedByteCase, 0, len(names))
	for _, item := range names {
		out = append(out, MalformedByteCase{
			Name:           item.name,
			InputClass:     item.class,
			ExpectedReject: true,
			RejectBucket:   item.bucket,
			PanicAllowed:   false,
		})
	}
	return out
}

func RunMalformedCase(tc MalformedByteCase) MalformedCaseResult {
	cfg := bytetransport.DefaultConfig("malformed-corpus")
	cfg.MaxPayloadBytes = 128
	cfg.MaxFrameBytes = 256
	cfg.MaxReassemblyBytes = 512
	cfg.MaxFragments = 4
	reject := func(bucket string) MalformedCaseResult {
		return MalformedCaseResult{Name: tc.Name, Rejected: true, RejectBucket: bucket, SafeError: true}
	}
	// Stateful / multi-frame malformations (fragment reassembly, sequence
	// tracking, terminal-stream, and metadata bounds) cannot be expressed as a
	// single-frame byte decode. They are driven through the real reassembler,
	// sequence validator, and frame validator instead, so the result reflects
	// actual decoder behaviour rather than a hardcoded verdict.
	if res, ok := runStatefulMalformedCase(tc, cfg); ok {
		return res
	}
	frame := bytetransport.ByteFrame{
		SessionID:     cfg.RuntimeID,
		StreamID:      1,
		Sequence:      1,
		Kind:          bytetransport.FrameData,
		FragmentCount: 1,
		ByteCount:     8,
		MetadataClass: "malformed",
	}
	encoded, err := bytetransport.EncodeFrame(cfg, frame)
	if err != nil {
		return reject("encode")
	}
	raw := append([]byte(nil), encoded.Bytes...)
	switch tc.InputClass {
	case "empty":
		raw = nil
	case "truncated_header":
		raw = raw[:4]
	case "unknown_kind":
		raw[1] = 250
		rewriteChecksum(raw)
	case "oversized_frame":
		raw = append(raw, make([]byte, cfg.MaxFrameBytes+1)...)
	case "oversized_payload":
		raw = mutatePayloadLength(raw, uint32(cfg.MaxPayloadBytes+1))
	case "invalid_length":
		raw = mutatePayloadLength(raw, 1)
	case "trailing_invalid":
		raw = append(raw[:len(raw)-4], []byte{9, 9, 9, 9, 9}...)
		rewriteChecksum(raw)
	case "invalid_fragment":
		raw = mutateU16(raw, 3, 5)
		rewriteChecksum(raw)
	case "corrupted_checksum":
		raw[len(raw)-1] ^= 0xff
	case "random_noise":
		raw = []byte{17, 23, 42, 99, 5, 8}
	}
	result, err := bytetransport.DecodeFrameBytes(cfg, raw)
	if err != nil {
		return MalformedCaseResult{Name: tc.Name, Rejected: true, RejectBucket: normalizeRejectBucket(result.RejectReason), SafeError: safeRejectError(err)}
	}
	if result.Rejected {
		return MalformedCaseResult{Name: tc.Name, Rejected: true, RejectBucket: normalizeRejectBucket(result.RejectReason), SafeError: true}
	}
	return MalformedCaseResult{Name: tc.Name, Rejected: false, RejectBucket: "accepted", SafeError: true}
}

// runStatefulMalformedCase drives the multi-frame / stateful malformation
// classes through the real bytetransport reassembler, sequence validator, and
// frame validator. It returns (result, true) for the classes it handles; the
// Rejected flag is true only when the real component actually rejects, so the
// corpus assertion depends on decoder behaviour, not a literal.
func runStatefulMalformedCase(tc MalformedByteCase, cfg bytetransport.ByteTransportConfig) (MalformedCaseResult, bool) {
	base := bytetransport.ByteFrame{
		SessionID:     cfg.RuntimeID,
		StreamID:      1,
		Sequence:      1,
		Kind:          bytetransport.FrameData,
		FragmentIndex: 0,
		FragmentCount: 1,
		ByteCount:     8,
		MetadataClass: "malformed",
	}
	result := func(bucket string, rejected, safe bool) (MalformedCaseResult, bool) {
		if !rejected {
			return MalformedCaseResult{Name: tc.Name, Rejected: false, RejectBucket: "accepted", SafeError: safe}, true
		}
		return MalformedCaseResult{Name: tc.Name, Rejected: true, RejectBucket: bucket, SafeError: safe}, true
	}
	switch tc.InputClass {
	case "fragment_mismatch":
		f := base
		f.FragmentCount = cfg.MaxFragments + 1
		rej, safe := reassemblerRejects(cfg, []bytetransport.ByteFrame{f})
		return result("fragment_count_mismatch", rej, safe)
	case "duplicate_fragment":
		f := base
		f.FragmentCount = 3
		rej, safe := reassemblerRejects(cfg, []bytetransport.ByteFrame{f, f})
		return result("duplicate_fragment", rej, safe)
	case "missing_fragment":
		f0, f1 := base, base
		f0.FragmentCount, f1.FragmentCount = 3, 3
		f0.FragmentIndex, f1.FragmentIndex = 0, 1
		rej, safe := reassemblerRejects(cfg, []bytetransport.ByteFrame{f0, f1})
		return result("incomplete_reassembly", rej, safe)
	case "oversized_reassembly":
		f0, f1, f2 := base, base, base
		for _, f := range []*bytetransport.ByteFrame{&f0, &f1, &f2} {
			f.FragmentCount = 4
			f.ByteCount = 200
		}
		f0.FragmentIndex, f1.FragmentIndex, f2.FragmentIndex = 0, 1, 2
		rej, safe := reassemblerRejects(cfg, []bytetransport.ByteFrame{f0, f1, f2})
		return result("oversized_reassembly", rej, safe)
	case "sequence_replay":
		a := base
		a.Sequence = 5
		rej, safe := sequenceRejects(0, []bytetransport.ByteFrame{a, a})
		return result("sequence_replay", rej, safe)
	case "old_sequence":
		a, b := base, base
		a.Sequence, b.Sequence = 5, 3
		rej, safe := sequenceRejects(0, []bytetransport.ByteFrame{a, b})
		return result("sequence_replay", rej, safe)
	case "future_sequence":
		a, b := base, base
		a.Sequence, b.Sequence = 5, 105
		rej, safe := sequenceRejects(8, []bytetransport.ByteFrame{a, b})
		return result("sequence_future", rej, safe)
	case "post_close_data":
		c, d := base, base
		c.Kind, c.Sequence = bytetransport.FrameClose, 1
		d.Kind, d.Sequence = bytetransport.FrameData, 2
		rej, safe := sequenceRejects(0, []bytetransport.ByteFrame{c, d})
		return result("terminal", rej, safe)
	case "post_reset_data":
		c, d := base, base
		c.Kind, c.Reset, c.Sequence = bytetransport.FrameReset, true, 1
		d.Kind, d.Sequence = bytetransport.FrameData, 2
		rej, safe := sequenceRejects(0, []bytetransport.ByteFrame{c, d})
		return result("terminal", rej, safe)
	case "invalid_metadata":
		f := base
		f.MetadataClass = strings.Repeat("x", 200)
		err := bytetransport.ValidateFrame(cfg, f)
		return result("metadata", err != nil, safeRejectError(err))
	case "oversized_metadata":
		f := base
		f.MetadataClass = strings.Repeat("x", 500)
		err := bytetransport.ValidateFrame(cfg, f)
		return result("metadata", err != nil, safeRejectError(err))
	default:
		return MalformedCaseResult{}, false
	}
}

// reassemblerRejects feeds frames to a real Reassembler and reports whether the
// reassembly was rejected (an Add error or a rejected result) or never completed
// (incomplete reassembly withholds the payload, which is also a safe rejection).
func reassemblerRejects(cfg bytetransport.ByteTransportConfig, frames []bytetransport.ByteFrame) (bool, bool) {
	r, err := bytetransport.NewReassembler(cfg)
	if err != nil {
		return true, safeRejectError(err)
	}
	var last bytetransport.DecodeResult
	for _, f := range frames {
		res, aerr := r.Add(f)
		if aerr != nil {
			return true, safeRejectError(aerr)
		}
		if res.Rejected {
			return true, true
		}
		last = res
	}
	return !last.Complete, true
}

// sequenceRejects feeds frames to a real SequenceValidator and reports whether
// any frame was rejected.
func sequenceRejects(maxAhead uint64, frames []bytetransport.ByteFrame) (bool, bool) {
	v := bytetransport.NewSequenceValidator(maxAhead)
	for _, f := range frames {
		if err := v.Accept(f); err != nil {
			return true, safeRejectError(err)
		}
	}
	return false, true
}

func ValidateMalformedCorpus(cases []MalformedByteCase) error {
	if len(cases) == 0 {
		return ErrFixtureInvalid
	}
	seen := map[string]bool{}
	for _, tc := range cases {
		if tc.Name == "" || tc.InputClass == "" || tc.RejectBucket == "" || tc.PanicAllowed {
			return ErrFixtureInvalid
		}
		if seen[tc.Name] {
			return ErrFixtureInvalid
		}
		seen[tc.Name] = true
		result := RunMalformedCase(tc)
		if tc.ExpectedReject && !result.Rejected {
			return ErrFixtureInvalid
		}
		if tc.ExpectedReject && result.RejectBucket != tc.RejectBucket {
			return ErrFixtureInvalid
		}
	}
	return nil
}

func MarshalMalformedCorpus(cases []MalformedByteCase) ([]byte, error) {
	raw, err := json.MarshalIndent(struct {
		Version string              `json:"version"`
		Cases   []MalformedByteCase `json:"cases"`
	}{Version: SchemaVersion, Cases: cases}, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(raw, '\n'), nil
}

func safeRejectError(err error) bool {
	if err == nil {
		return true
	}
	return !errors.Is(err, bytetransport.ErrInvalidConfig)
}

func normalizeRejectBucket(bucket string) string {
	switch bucket {
	case "encoded size":
		return "oversized"
	case "payload length":
		return "payload_length"
	case "trailing or truncated payload":
		return "payload_bounds"
	case "unknown kind":
		return "unknown_kind"
	case "":
		return "rejected"
	default:
		return bucket
	}
}

func mutateU16(raw []byte, offset int, value uint16) []byte {
	if len(raw) > offset+1 {
		raw[offset] = byte(value >> 8)
		raw[offset+1] = byte(value)
	}
	return raw
}

func mutatePayloadLength(raw []byte, value uint32) []byte {
	if len(raw) < 8 {
		return raw
	}
	offset := len(raw) - 4 - 8 - 4
	if offset < 0 || offset+4 > len(raw) {
		return raw
	}
	raw[offset] = byte(value >> 24)
	raw[offset+1] = byte(value >> 16)
	raw[offset+2] = byte(value >> 8)
	raw[offset+3] = byte(value)
	rewriteChecksum(raw)
	return raw
}

func rewriteChecksum(raw []byte) {
	if len(raw) < 4 {
		return
	}
	sum := fnv32a(raw[:len(raw)-4])
	raw[len(raw)-4] = byte(sum >> 24)
	raw[len(raw)-3] = byte(sum >> 16)
	raw[len(raw)-2] = byte(sum >> 8)
	raw[len(raw)-1] = byte(sum)
}

func fnv32a(raw []byte) uint32 {
	var h uint32 = 2166136261
	for _, b := range raw {
		h ^= uint32(b)
		h *= 16777619
	}
	return h
}
