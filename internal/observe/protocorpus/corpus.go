// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

type FieldDescriptor struct {
	Kind           FieldKind       `json:"kind"`
	Visibility     VisibilityClass `json:"visibility"`
	SizeBucket     string          `json:"size_bucket"`
	PositionBucket string          `json:"position_bucket"`
	Required       bool            `json:"required"`
	Repeats        bool            `json:"repeats"`
	SafeValueClass string          `json:"safe_value_class"`
}

type PhaseDescriptor struct {
	Phase              ProtocolPhase     `json:"phase"`
	MessageCountBucket string            `json:"message_count_bucket"`
	DirectionPattern   string            `json:"direction_pattern"`
	RoundTripBucket    string            `json:"round_trip_bucket"`
	Fields             []FieldDescriptor `json:"fields"`
}

type ProtocolShapeEntry struct {
	Name               string            `json:"name"`
	Family             ProtocolFamily    `json:"family"`
	Phases             []PhaseDescriptor `json:"phases"`
	FirstFlightBucket  string            `json:"first_flight_bucket"`
	FirstNPacketBucket string            `json:"first_n_packet_bucket"`
	FrameSizeBuckets   []string          `json:"frame_size_buckets"`
	FragmentRhythm     string            `json:"fragment_rhythm"`
	ControlRichness    string            `json:"control_richness"`
	MetadataExposure   string            `json:"metadata_exposure"`
	Notes              []string          `json:"notes"`
}

func DefaultCorpus() CorpusManifest {
	entries := []ProtocolShapeEntry{
		entry("structured_tls_like_family", FamilyStructuredEncrypted, "mixed_visible_encrypted", []ProtocolPhase{PhaseGreeting, PhaseHandshake, PhaseData, PhaseClose}, "1rtt", "clear-leading-fields"),
		entry("ssh_like_greeting_family", FamilyGreetingBased, "cleartext_header_encrypted_payload", []ProtocolPhase{PhaseGreeting, PhaseHandshake, PhaseData, PhaseClose}, "1_5rtt", "line-greeting-then-binary"),
		entry("noise_like_minimal_handshake_family", FamilyMinimalHandshake, "encrypted_header_encrypted_payload", []ProtocolPhase{PhaseHandshake, PhaseData, PhaseClose}, "1rtt", "minimal-static-fields"),
		entry("fully_encrypted_randomized_family", FamilyFullyEncrypted, "none_visible", []ProtocolPhase{PhaseHandshake, PhaseData, PhaseReset, PhaseClose}, "unknown", "opaque-variable-records"),
		entry("length_prefixed_secure_channel_family", FamilyLengthPrefixed, "minimal_visible", []ProtocolPhase{PhaseHandshake, PhaseControl, PhaseData, PhaseClose}, "1rtt", "length-prefix-visible"),
		entry("message_oriented_secure_channel_family", FamilyMessageOriented, "minimal_visible", []ProtocolPhase{PhaseHandshake, PhaseControl, PhaseData, PhaseReset, PhaseClose}, "1rtt", "message-boundary-visible"),
		entry("control_rich_secure_channel_family", FamilyControlRich, "mixed_visible_encrypted", []ProtocolPhase{PhaseHandshake, PhaseControl, PhaseData, PhaseControl, PhaseClose}, "2rtt", "control-heavy"),
		entry("multi_round_handshake_family", FamilyMultiRoundHandshake, "mixed_visible_encrypted", []ProtocolPhase{PhaseGreeting, PhaseHandshake, PhaseHandshake, PhaseControl, PhaseData, PhaseClose}, "multi_rtt", "multi-round"),
		entry("minimal_roundtrip_handshake_family", FamilyMinimalHandshake, "encrypted_header_encrypted_payload", []ProtocolPhase{PhaseHandshake, PhaseData, PhaseClose}, "0rtt", "early-data-like"),
		entry("certificate_like_handshake_family", FamilyStructuredEncrypted, "mixed_visible_encrypted", []ProtocolPhase{PhaseGreeting, PhaseHandshake, PhaseHandshake, PhaseData, PhaseClose}, "2rtt", "certificate-shaped-abstract"),
		entry("reserved_field_handshake_family", FamilyStructuredEncrypted, "minimal_visible", []ProtocolPhase{PhaseHandshake, PhaseControl, PhaseData, PhaseClose}, "1rtt", "reserved-field-abstract"),
		entry("padding_rich_data_family", FamilyStreamOriented, "encrypted_header_encrypted_payload", []ProtocolPhase{PhaseHandshake, PhaseData, PhaseData, PhaseClose}, "1rtt", "padding-rich"),
	}
	manifest := NewManifest("abstract-protocol-feature-corpus", entries)
	manifest.Normalize()
	return manifest
}

func entry(name string, family ProtocolFamily, exposure string, phases []ProtocolPhase, rtt string, layout string) ProtocolShapeEntry {
	out := ProtocolShapeEntry{
		Name:               name,
		Family:             family,
		FirstFlightBucket:  "size_129_512",
		FirstNPacketBucket: "firstn_mixed_small",
		FrameSizeBuckets:   []string{"size_33_64", "size_65_128", "size_129_512"},
		FragmentRhythm:     "profile_bucket_fragment",
		ControlRichness:    "moderate",
		MetadataExposure:   exposure,
		Notes:              []string{"abstract feature shape for comparative corpus checks", "not a protocol implementation"},
	}
	if len(phases) <= 3 {
		out.FirstFlightBucket = "size_33_64"
		out.FirstNPacketBucket = "firstn_compact"
	}
	if family == FamilyFullyEncrypted {
		out.FrameSizeBuckets = []string{"size_65_128", "size_129_512", "size_513_1500"}
		out.FragmentRhythm = "randomized_bucket_fragment"
		out.ControlRichness = "low"
	}
	if family == FamilyControlRich {
		out.ControlRichness = "high"
		out.FrameSizeBuckets = []string{"size_17_32", "size_33_64", "size_65_128", "size_129_512"}
	}
	for i, phase := range phases {
		out.Phases = append(out.Phases, phaseDescriptor(phase, i, rtt, layout, exposure))
	}
	return out
}

func phaseDescriptor(phase ProtocolPhase, index int, rtt, layout, exposure string) PhaseDescriptor {
	messageBucket := "count_1"
	if index%2 == 1 {
		messageBucket = "count_2_3"
	}
	direction := "client_first"
	if index > 0 {
		direction = "alternating"
	}
	fields := []FieldDescriptor{
		field(FieldType, VisibilityCleartext, "size_1_3", "leading", true, false, layout),
		field(FieldLength, VisibilityCleartext, "size_1_3", "leading", true, false, "bucketed-length"),
	}
	switch phase {
	case PhaseGreeting:
		fields = append(fields, field(FieldVersion, VisibilityCleartext, "size_4_8", "middle", false, false, "abstract-version"))
	case PhaseHandshake:
		fields = append(fields,
			field(FieldNonceLike, VisibilityDerived, "size_17_32", "middle", false, false, "nonce-class"),
			field(FieldKeyLike, VisibilityDerived, "size_33_64", "middle", false, false, "key-material-class"),
		)
		if exposure == "mixed_visible_encrypted" {
			fields = append(fields, field(FieldCertificateLike, VisibilityDerived, "size_129_512", "middle", false, false, "certificate-like-class"))
		}
	case PhaseControl:
		fields = append(fields, field(FieldReserved, VisibilityCleartext, "size_1_3", "middle", false, true, "reserved-class"))
	case PhaseData:
		fields = append(fields, field(FieldPayload, VisibilityEncrypted, "size_129_512", "trailing", true, true, "opaque-data-class"))
	case PhaseClose:
		fields = append(fields, field(FieldAuthTagLike, VisibilityDerived, "size_9_16", "trailing", false, false, "auth-tag-class"))
	case PhaseReset:
		fields = append(fields, field(FieldPadding, VisibilityEncrypted, "size_17_32", "trailing", false, true, "reset-padding-class"))
	}
	return PhaseDescriptor{
		Phase:              phase,
		MessageCountBucket: messageBucket,
		DirectionPattern:   direction,
		RoundTripBucket:    rtt,
		Fields:             fields,
	}
}

func field(kind FieldKind, visibility VisibilityClass, size, position string, required, repeats bool, valueClass string) FieldDescriptor {
	return FieldDescriptor{Kind: kind, Visibility: visibility, SizeBucket: size, PositionBucket: position, Required: required, Repeats: repeats, SafeValueClass: valueClass}
}
