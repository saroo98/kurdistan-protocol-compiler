// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package liveprogram defines the product-safe subset of a generated protocol
// profile.  It intentionally has no dependency on IR, compiler, testkit, or
// lab packages so it can be decoded by release runtime code.
package liveprogram

import (
	"crypto/sha256"
	"errors"
	"sort"
	"strings"
)

const (
	SchemaV1        = "kurd-live-program-v1"
	MaxEncodedBytes = 48 << 10
)

type ErrorCategory string

const (
	ErrorInvalid      ErrorCategory = "invalid"
	ErrorSize         ErrorCategory = "size"
	ErrorSchema       ErrorCategory = "schema"
	ErrorNonCanonical ErrorCategory = "non-canonical"
	ErrorUnsupported  ErrorCategory = "unsupported"
)

type Error struct{ Category ErrorCategory }

func (e *Error) Error() string { return "live program: " + string(e.Category) }

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}

func fail(category ErrorCategory) error { return &Error{Category: category} }

type ProgramV1 struct {
	Schema               string
	ProgramID            [16]byte
	SourceSchemaVersion  string
	SourceGenerationHash [32]byte
	Messages             []MessageV1
	Frame                FrameV1
	Scheduler            SchedulerV1
	Stream               StreamV1
	Padding              PaddingV1
	Security             SecurityV1
	Limits               LimitsV1
}

type MessageV1 struct {
	Semantic, WireSymbol, Direction  string
	MinPayloadBytes, MaxPayloadBytes int
}

type FrameV1 struct {
	LengthMode, TypeMode string
	HeaderOrder          []string
	FragmentationMode    string
	ChecksumMode         string
	PaddingPlacement     string
	Compiled             CompiledFramingV1
}

// CompiledFramingV1 contains only the precomputed outputs which legacy
// framing derives from a profile identifier.  The identifier itself is never
// retained or reconstructed on the release path.
type CompiledFramingV1 struct {
	DataTypeTag, PaddingTypeTag []byte
	ProfileXORStreamMask        uint32
	TableStreamMask             uint32
	CRC32PrefixState            uint32
}

type SchedulerV1 struct {
	Mode, PriorityMode             string
	MaxBatchBytes, FlushIntervalMs int
	MaxInFlightFrames              int
}

type StreamV1 struct {
	IDEncodingMode       string
	MaxConcurrentStreams int
}

type PaddingV1 struct {
	Mode                             string
	MinPaddingBytes, MaxPaddingBytes int
	Probability                      float64
}

type SecurityV1 struct {
	CompilerSecurityVersion, MinimumRuntimeVersion                                string
	Policy                                                                        SecurityPolicyV1
	ClientMandatoryCapabilities, RelayMandatoryCapabilities, SelectedCapabilities []string
}

type SecurityPolicyV1 struct {
	SecurityVersion, TranscriptMode, KDFSuite, AEADSuite, MACSuite, NonceMode, ReplayPolicy string
	ReplayWindowSize                                                                        int
	DowngradePolicy, CapabilityNegotiationPolicy, ProfileCompatibilityPolicy                string
	KeyRotationPolicy, ConfigValidationPolicy, SecureEnvelopeMode                           string
	MaxSessionMessages, MaxKeyLifetimeMessages                                              int
}

type LimitsV1 struct {
	MaxFrameBytes, MaxPayloadBytes, MaxSessionMillis int
	MaxSessionMessages, MaxKeyLifetimeMessages       int
}

// DeriveProgramIDV1 is stable across owner-side compilation and release-side
// decoding.  It exposes no source profile identifier or compiler seed.
func DeriveProgramIDV1(source [32]byte) [16]byte {
	digest := sha256.Sum256(append([]byte(SchemaV1+"\x00"), source[:]...))
	var id [16]byte
	copy(id[:], digest[:16])
	return id
}

func (p ProgramV1) Clone() ProgramV1 {
	p.Messages = append([]MessageV1(nil), p.Messages...)
	p.Frame.HeaderOrder = append([]string(nil), p.Frame.HeaderOrder...)
	p.Frame.Compiled.DataTypeTag = append([]byte(nil), p.Frame.Compiled.DataTypeTag...)
	p.Frame.Compiled.PaddingTypeTag = append([]byte(nil), p.Frame.Compiled.PaddingTypeTag...)
	p.Security.ClientMandatoryCapabilities = append([]string(nil), p.Security.ClientMandatoryCapabilities...)
	p.Security.RelayMandatoryCapabilities = append([]string(nil), p.Security.RelayMandatoryCapabilities...)
	p.Security.SelectedCapabilities = append([]string(nil), p.Security.SelectedCapabilities...)
	return p
}

func ValidateV1(p ProgramV1) error {
	if p.Schema != SchemaV1 || p.ProgramID != DeriveProgramIDV1(p.SourceGenerationHash) || p.SourceSchemaVersion == "" || allZero(p.SourceGenerationHash[:]) {
		return fail(ErrorInvalid)
	}
	if len(p.Messages) != 2 || p.Messages[0].Semantic != "data" || p.Messages[1].Semantic != "padding" {
		return fail(ErrorSchema)
	}
	seenWire := make(map[string]struct{}, len(p.Messages))
	for _, message := range p.Messages {
		if !safeToken(message.WireSymbol) || message.Direction != "bidirectional" || message.MinPayloadBytes < 0 || message.MaxPayloadBytes < message.MinPayloadBytes || message.MaxPayloadBytes > p.Limits.MaxPayloadBytes {
			return fail(ErrorInvalid)
		}
		if _, exists := seenWire[message.WireSymbol]; exists {
			return fail(ErrorSchema)
		}
		seenWire[message.WireSymbol] = struct{}{}
	}
	if !oneOf(p.Frame.LengthMode, "varint_prefix", "fixed_2_prefix", "fixed_4_prefix", "length_suffix_lab") ||
		!oneOf(p.Frame.TypeMode, "explicit_generated_tag", "derived_from_state", "derived_from_header_order", "table_indexed_symbol") ||
		!oneOf(p.Frame.FragmentationMode, "no_fragmentation_for_small_payloads", "fixed_size_chunks", "bounded_variable_chunks", "scheduler_controlled_chunks") ||
		!oneOf(p.Frame.ChecksumMode, "none", "crc32") || !oneOf(p.Frame.PaddingPlacement, "none", "prefix", "suffix", "inter_frame", "probabilistic") ||
		!exactSet(p.Frame.HeaderOrder, []string{"length", "type", "stream", "flags"}) {
		return fail(ErrorInvalid)
	}
	if len(p.Frame.Compiled.DataTypeTag) == 0 || len(p.Frame.Compiled.DataTypeTag) > 255 || len(p.Frame.Compiled.PaddingTypeTag) == 0 || len(p.Frame.Compiled.PaddingTypeTag) > 255 {
		return fail(ErrorInvalid)
	}
	if !oneOf(p.Scheduler.Mode, "max_speed", "balanced", "interactive_first", "bulk_first") || p.Scheduler.MaxBatchBytes < 1 || p.Scheduler.MaxBatchBytes > 32<<10 ||
		p.Scheduler.FlushIntervalMs < 0 || p.Scheduler.FlushIntervalMs > 1000 || !oneOfInt(p.Scheduler.MaxInFlightFrames, 4, 8, 16, 32) || p.Scheduler.PriorityMode == "" {
		return fail(ErrorInvalid)
	}
	if !oneOf(p.Stream.IDEncodingMode, "fixed32_be", "profile_xor32", "table_mapped32_le", "varint") || !oneOfInt(p.Stream.MaxConcurrentStreams, 2, 4, 8, 16) {
		return fail(ErrorInvalid)
	}
	if !oneOf(p.Padding.Mode, "none", "bounded", "probabilistic", "fixed", "inter_frame") || p.Padding.MinPaddingBytes < 0 || p.Padding.MaxPaddingBytes < p.Padding.MinPaddingBytes || p.Padding.Probability < 0 || p.Padding.Probability > 1 ||
		(p.Padding.Mode == "none" && (p.Padding.MinPaddingBytes != 0 || p.Padding.MaxPaddingBytes != 0 || p.Padding.Probability != 0)) {
		return fail(ErrorInvalid)
	}
	if err := validateSecurity(p.Security); err != nil {
		return err
	}
	if p.Limits.MaxFrameBytes < 1 || p.Limits.MaxFrameBytes > 1<<20 || p.Limits.MaxPayloadBytes < 1 || p.Limits.MaxPayloadBytes > 8<<20 ||
		p.Limits.MaxSessionMillis < 1 || p.Limits.MaxSessionMessages < 1 || p.Limits.MaxKeyLifetimeMessages < 1 || p.Limits.MaxKeyLifetimeMessages > p.Limits.MaxSessionMessages ||
		p.Limits.MaxSessionMessages != p.Security.Policy.MaxSessionMessages || p.Limits.MaxKeyLifetimeMessages != p.Security.Policy.MaxKeyLifetimeMessages {
		return fail(ErrorInvalid)
	}
	return nil
}

func validateSecurity(value SecurityV1) error {
	p := value.Policy
	if value.CompilerSecurityVersion == "" || value.MinimumRuntimeVersion == "" || p.SecurityVersion == "" ||
		!oneOf(p.TranscriptMode, "canonical_v1", "canonical_with_capabilities_v1", "canonical_with_carrier_binding_v1", "canonical_full_binding_v1") ||
		p.KDFSuite != "kdf_hkdf_sha256" || p.AEADSuite != "aead_aes_256_gcm" || p.MACSuite != "mac_hmac_sha256" ||
		!oneOf(p.NonceMode, "counter_xor_base", "counter_append_base", "directional_counter", "stream_partitioned_counter") ||
		!oneOf(p.ReplayPolicy, "ordered_only", "bounded_reorder", "windowed_replay") || p.ReplayWindowSize <= 1 || p.ReplayWindowSize > 4096 ||
		!oneOf(p.DowngradePolicy, "strict_suite_and_capabilities", "strict_capabilities", "suite_bound_transcript") ||
		!oneOf(p.CapabilityNegotiationPolicy, "strict_required", "intersection_with_required", "profile_declared_required") ||
		!oneOf(p.ProfileCompatibilityPolicy, "strict_schema", "schema_and_feature", "full_policy_binding") ||
		!oneOf(p.KeyRotationPolicy, "session_only", "message_lifetime_bound", "profile_lifetime_bound") ||
		!oneOf(p.ConfigValidationPolicy, "strict_required", "strict_with_redaction", "strict_profile_bound") ||
		!oneOf(p.SecureEnvelopeMode, "metadata_authenticated", "synthetic_aead_test", "full_context_bound_envelope") ||
		p.MaxSessionMessages < 1 || p.MaxSessionMessages > 1<<24 || p.MaxKeyLifetimeMessages < 1 || p.MaxKeyLifetimeMessages > p.MaxSessionMessages {
		return fail(ErrorInvalid)
	}
	for _, capabilities := range [][]string{value.ClientMandatoryCapabilities, value.RelayMandatoryCapabilities, value.SelectedCapabilities} {
		if !canonicalCapabilities(capabilities) {
			return fail(ErrorInvalid)
		}
	}
	selected := map[string]struct{}{}
	for _, capability := range value.SelectedCapabilities {
		selected[capability] = struct{}{}
	}
	for _, floor := range [][]string{value.ClientMandatoryCapabilities, value.RelayMandatoryCapabilities} {
		for _, capability := range floor {
			if _, ok := selected[capability]; !ok {
				return fail(ErrorInvalid)
			}
		}
	}
	return nil
}

func canonicalCapabilities(values []string) bool {
	if len(values) == 0 || len(values) > 32 {
		return false
	}
	for i, value := range values {
		if !knownCapability(value) || (i > 0 && values[i-1] >= value) {
			return false
		}
	}
	return true
}

func knownCapability(value string) bool {
	return oneOf(value, "multi_stream", "proxy_semantics", "carrier_abstraction", "adapter_interface", "carrier_loss_recovery", "carrier_backpressure", "generated_backend", "transcript_binding", "replay_window", "nonce_schedule")
}

func exactSet(values, expected []string) bool {
	if len(values) != len(expected) {
		return false
	}
	got := append([]string(nil), values...)
	want := append([]string(nil), expected...)
	sort.Strings(got)
	sort.Strings(want)
	for i := range got {
		if got[i] != want[i] {
			return false
		}
	}
	return true
}

func safeToken(value string) bool {
	if value == "" || len(value) > 96 {
		return false
	}
	lower := strings.ToLower(value)
	for _, forbidden := range []string{"test", "lab", "key", "seed", "path", "endpoint", "secret", "auth"} {
		if strings.Contains(lower, forbidden) {
			return false
		}
	}
	for _, r := range value {
		if r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			continue
		}
		return false
	}
	return true
}

func oneOf(value string, values ...string) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func oneOfInt(value int, values ...int) bool {
	for _, candidate := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func allZero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
