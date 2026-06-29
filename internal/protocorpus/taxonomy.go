// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

type CorpusVersion string

const (
	CorpusSchemaVersion  CorpusVersion = "protocorpus-v1"
	FeatureSchemaVersion string        = "wirefeatures-v1"
)

type ProtocolFamily string

const (
	FamilyStructuredEncrypted ProtocolFamily = "structured_encrypted"
	FamilyFullyEncrypted      ProtocolFamily = "fully_encrypted"
	FamilyGreetingBased       ProtocolFamily = "greeting_based"
	FamilyLengthPrefixed      ProtocolFamily = "length_prefixed"
	FamilyMessageOriented     ProtocolFamily = "message_oriented"
	FamilyStreamOriented      ProtocolFamily = "stream_oriented"
	FamilyControlRich         ProtocolFamily = "control_rich"
	FamilyMinimalHandshake    ProtocolFamily = "minimal_handshake"
	FamilyMultiRoundHandshake ProtocolFamily = "multi_round_handshake"
)

type ProtocolPhase string

const (
	PhaseGreeting  ProtocolPhase = "greeting"
	PhaseHandshake ProtocolPhase = "handshake"
	PhaseControl   ProtocolPhase = "control"
	PhaseData      ProtocolPhase = "data"
	PhaseClose     ProtocolPhase = "close"
	PhaseReset     ProtocolPhase = "reset"
)

type FieldKind string

const (
	FieldType             FieldKind = "type"
	FieldLength           FieldKind = "length"
	FieldVersion          FieldKind = "version"
	FieldNonceLike        FieldKind = "nonce_like"
	FieldKeyLike          FieldKind = "key_like"
	FieldCertificateLike  FieldKind = "certificate_like"
	FieldReserved         FieldKind = "reserved"
	FieldPaddingLength    FieldKind = "padding_length"
	FieldPadding          FieldKind = "padding"
	FieldPayload          FieldKind = "payload"
	FieldAuthTagLike      FieldKind = "auth_tag_like"
	FieldUnknownEncrypted FieldKind = "unknown_encrypted"
)

type VisibilityClass string

const (
	VisibilityCleartext VisibilityClass = "cleartext"
	VisibilityEncrypted VisibilityClass = "encrypted"
	VisibilityDerived   VisibilityClass = "derived"
	VisibilityAbsent    VisibilityClass = "absent"
)

var sizeBuckets = []string{
	"size_0",
	"size_1_3",
	"size_4_8",
	"size_9_16",
	"size_17_32",
	"size_33_64",
	"size_65_128",
	"size_129_512",
	"size_513_1500",
	"size_1501_4096",
	"size_4097_plus",
}

var roundTripBuckets = []string{"0rtt", "1rtt", "1_5rtt", "2rtt", "multi_rtt", "unknown"}

var directionPatterns = []string{
	"client_first",
	"server_first",
	"alternating",
	"client_burst",
	"server_burst",
	"bidirectional_interleaved",
	"unknown",
}

var metadataExposureBuckets = []string{
	"none_visible",
	"minimal_visible",
	"mixed_visible_encrypted",
	"cleartext_header_encrypted_payload",
	"encrypted_header_encrypted_payload",
	"unknown",
}

func SupportedFamilies() []ProtocolFamily {
	return []ProtocolFamily{
		FamilyStructuredEncrypted,
		FamilyFullyEncrypted,
		FamilyGreetingBased,
		FamilyLengthPrefixed,
		FamilyMessageOriented,
		FamilyStreamOriented,
		FamilyControlRich,
		FamilyMinimalHandshake,
		FamilyMultiRoundHandshake,
	}
}

func SupportedPhases() []ProtocolPhase {
	return []ProtocolPhase{PhaseGreeting, PhaseHandshake, PhaseControl, PhaseData, PhaseClose, PhaseReset}
}

func SupportedFieldKinds() []FieldKind {
	return []FieldKind{
		FieldType,
		FieldLength,
		FieldVersion,
		FieldNonceLike,
		FieldKeyLike,
		FieldCertificateLike,
		FieldReserved,
		FieldPaddingLength,
		FieldPadding,
		FieldPayload,
		FieldAuthTagLike,
		FieldUnknownEncrypted,
	}
}

func SupportedVisibilityClasses() []VisibilityClass {
	return []VisibilityClass{VisibilityCleartext, VisibilityEncrypted, VisibilityDerived, VisibilityAbsent}
}

func SupportedSizeBuckets() []string {
	return append([]string(nil), sizeBuckets...)
}

func SupportedRoundTripBuckets() []string {
	return append([]string(nil), roundTripBuckets...)
}

func SupportedDirectionPatterns() []string {
	return append([]string(nil), directionPatterns...)
}

func SupportedMetadataExposureBuckets() []string {
	return append([]string(nil), metadataExposureBuckets...)
}
