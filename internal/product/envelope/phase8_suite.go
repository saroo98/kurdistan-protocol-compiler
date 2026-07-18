// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	"github.com/fxamacker/cbor/v2"
)

// SuiteID is an authenticated profile-artifact cryptographic suite identifier.
// Suite identifiers are never negotiated and unsupported identifiers fail closed.
type SuiteID uint16

const (
	// SuiteClassicalV1 is the only enabled Phase 8 suite.
	SuiteClassicalV1 SuiteID = 0x0001
	// SuiteReservedPQV1 and SuiteReservedHybridV1 reserve registry positions only.
	// They are deliberately unsupported because the available HPKE compositions
	// are draft-only on the pinned toolchain.
	SuiteReservedPQV1     SuiteID = 0x0101
	SuiteReservedHybridV1 SuiteID = 0x0102

	COSESign1Tag        uint64 = 18
	COSEAlgorithmES256  int64  = -7
	COSEHeaderAlgorithm int64  = 1
	COSEHeaderCritical  int64  = 2
	COSEHeaderContent   int64  = 3
	COSEHeaderKeyID     int64  = 4

	// Private-use labels are below -65536 in the IANA COSE Header Parameters
	// registry. Both are critical in every v1 signed object.
	COSEHeaderProfileFormatVersion int64 = -65537
	COSEHeaderProfileSuiteID       int64 = -65538
	COSEHeaderArtifactMetadata     int64 = -65539

	ProfileFormatVersion uint64 = 1
	SealFormatVersion    uint64 = 1

	HPKEModeBase      uint8  = 0x00
	HPKEKEMP256SHA256 uint16 = 0x0010
	HPKEKDFSHA256     uint16 = 0x0001
	HPKEAEADAES256GCM uint16 = 0x0002

	ES256RawSignatureSize = 64
	HPKEP256EncSize       = 65
	HPKEAEADTagSize       = 16

	MinKeyIDBytes = 8
	MaxKeyIDBytes = 64

	// Phase 8 uses a fresh HPKE encapsulation for every sealed artifact and
	// permits exactly one Seal/Open operation per context. This is stricter than
	// RFC 9180's sequence space and avoids depending on the pinned Go package's
	// lack of an explicit uint64 overflow error.
	MaxHPKEMessagesPerContext = 1

	MaxSignedObjectBytes     = 1 << 20
	MaxPayloadBytes          = MaxSignedObjectBytes - 4096
	MaxSignedProtectedBytes  = 4096
	MaxArtifactMetadataBytes = 512
	MaxCiphertextBytes       = MaxSignedObjectBytes + HPKEAEADTagSize
	MaxCBORNestedLevels      = 16
	MaxCBORArrayElements     = 2048
	MaxCBORMapPairs          = 128
	MaxOuterProtectedBytes   = 4096
	// MaxSealedFrameBytes is one byte below the simultaneous maxima of all
	// three frame components. The post-marshal check therefore has an
	// independently executable one-over boundary while normal frames retain
	// more than four KiB of framing headroom.
	MaxSealedFrameBytes      = MaxOuterProtectedBytes + HPKEP256EncSize + MaxCiphertextBytes + 10
	MaxTotalInputBytes       = MaxSealedFrameBytes
	SignedPayloadContentType = "application/vnd.kurdistan.profile+cbor"
	SignedObjectContentType  = "application/vnd.kurdistan.profile+cose"
	SealedObjectContentType  = "application/vnd.kurdistan.profile-sealed+cbor"
)

var (
	ErrUnsupportedSuite     = errors.New("envelope: unsupported profile cryptographic suite")
	ErrHPKEContextExhausted = errors.New("envelope: HPKE context exhausted")
	ErrArtifactSizeLimit    = errors.New("envelope: artifact size limit exceeded")
	ErrMetadataMismatch     = errors.New("envelope: issuer-signed and outer artifact metadata differ")

	signatureExternalAAD = []byte("kurdistan-vpn/profile-signature/external-aad/v1")
	hpkeInfoDomain       = []byte("kurdistan-vpn/profile-seal/hpke-info/v1")
	hpkeAADDomain        = []byte("kurdistan-vpn/profile-seal/hpke-aad/v1")
)

// Suite describes the mandatory, non-negotiable v1 construction.
type Suite struct {
	ID                 SuiteID
	SignatureAlgorithm int64
	HPKEMode           uint8
	HPKEKEM            uint16
	HPKEKDF            uint16
	HPKEAEAD           uint16
}

// MandatoryV1Suite returns a value copy of the only enabled Phase 8 suite.
func MandatoryV1Suite() Suite {
	return Suite{
		ID:                 SuiteClassicalV1,
		SignatureAlgorithm: COSEAlgorithmES256,
		HPKEMode:           HPKEModeBase,
		HPKEKEM:            HPKEKEMP256SHA256,
		HPKEKDF:            HPKEKDFSHA256,
		HPKEAEAD:           HPKEAEADAES256GCM,
	}
}

// ValidateSuiteID rejects reserved, unknown, and downgrade suite identifiers.
func ValidateSuiteID(id SuiteID) error {
	if id != SuiteClassicalV1 {
		return fmt.Errorf("%w: 0x%04x", ErrUnsupportedSuite, uint16(id))
	}
	return nil
}

// SignatureExternalAAD returns a copy of the exact non-empty COSE external AAD.
func SignatureExternalAAD() []byte {
	return append([]byte(nil), signatureExternalAAD...)
}

// BuildArtifactMetadata builds the one canonical metadata value that is bound
// by both the issuer signature and recipient seal. Issuer binding does not
// grant Provider or Registrar authority; those policy roles remain separate.
func BuildArtifactMetadata(metadata ArtifactMetadata) ([]byte, error) {
	if err := ValidateArtifactMetadata(metadata); err != nil {
		return nil, err
	}
	return marshalDeterministicBounded(map[uint64]any{
		1: string(metadata.Class),
		2: metadata.AudienceClass,
		3: []byte(metadata.RecipientHint),
		4: metadata.RecipientEpoch,
	}, MaxArtifactMetadataBytes, "artifact metadata")
}

// BuildSignedProtectedHeaders builds the exact RFC 9052 protected-header map.
// The result is the bstr content used by both COSE_Sign1 and Sig_structure.
func BuildSignedProtectedHeaders(keyID []byte, metadata ArtifactMetadata) ([]byte, error) {
	if len(keyID) < MinKeyIDBytes || len(keyID) > MaxKeyIDBytes {
		return nil, fmt.Errorf("envelope: key ID length must be %d..%d bytes", MinKeyIDBytes, MaxKeyIDBytes)
	}
	metadataBytes, err := BuildArtifactMetadata(metadata)
	if err != nil {
		return nil, err
	}
	headers := map[int64]any{
		COSEHeaderAlgorithm:            COSEAlgorithmES256,
		COSEHeaderCritical:             []int64{COSEHeaderProfileFormatVersion, COSEHeaderProfileSuiteID, COSEHeaderArtifactMetadata},
		COSEHeaderContent:              SignedPayloadContentType,
		COSEHeaderKeyID:                append([]byte(nil), keyID...),
		COSEHeaderProfileFormatVersion: ProfileFormatVersion,
		COSEHeaderProfileSuiteID:       uint64(SuiteClassicalV1),
		COSEHeaderArtifactMetadata:     metadataBytes,
	}
	return marshalDeterministicBounded(headers, MaxSignedProtectedBytes, "signed protected headers")
}

// BuildCOSESigStructure builds the exact bytes signed for tagged COSE_Sign1:
// ["Signature1", body_protected, external_aad, payload].
func BuildCOSESigStructure(protected, payload []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("envelope: signed protected headers are required")
	}
	if len(protected) > MaxSignedProtectedBytes {
		return nil, fmt.Errorf("%w: signed protected headers", ErrArtifactSizeLimit)
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, errors.New("envelope: signed payload size is outside the admitted range")
	}
	return marshalDeterministic([]any{
		"Signature1",
		append([]byte(nil), protected...),
		SignatureExternalAAD(),
		append([]byte(nil), payload...),
	})
}

// BuildTaggedCOSESign1 builds the exact tagged COSE_Sign1 object. The
// unprotected header map is always empty; dispatch and suite fields are
// therefore authenticated or absent.
func BuildTaggedCOSESign1(protected, payload, signature []byte) ([]byte, error) {
	if len(protected) == 0 {
		return nil, errors.New("envelope: signed protected headers are required")
	}
	if len(protected) > MaxSignedProtectedBytes {
		return nil, fmt.Errorf("%w: signed protected headers", ErrArtifactSizeLimit)
	}
	if len(payload) == 0 || len(payload) > MaxPayloadBytes {
		return nil, errors.New("envelope: signed payload size is outside the admitted range")
	}
	if _, _, err := DecodeRawES256Signature(signature); err != nil {
		return nil, err
	}
	return marshalDeterministicBounded(cbor.Tag{Number: COSESign1Tag, Content: []any{
		append([]byte(nil), protected...),
		map[int64]any{},
		append([]byte(nil), payload...),
		append([]byte(nil), signature...),
	}}, MaxSignedObjectBytes, "signed object")
}

// BuildSealProtected builds the exact deterministic, authenticated outer
// dispatch map. It contains no enc or ciphertext bytes, so HPKE info and AAD
// can be derived without a circular definition.
func BuildSealProtected(metadata ArtifactMetadata) ([]byte, error) {
	if err := ValidateArtifactMetadata(metadata); err != nil {
		return nil, err
	}
	if metadata.Class == ArtifactSignedPublic {
		return nil, errors.New("envelope: signed-public artifacts are not recipient sealed")
	}
	metadataBytes, err := BuildArtifactMetadata(metadata)
	if err != nil {
		return nil, err
	}
	protected := map[uint64]any{
		1: SealFormatVersion,
		2: uint64(SuiteClassicalV1),
		3: SignedObjectContentType,
		4: metadataBytes,
	}
	return marshalDeterministicBounded(protected, MaxOuterProtectedBytes, "outer protected metadata")
}

// BuildHPKEInfo binds context setup to the exact outer protected bytes.
func BuildHPKEInfo(outerProtected []byte) ([]byte, error) {
	return buildDomainSeparated(hpkeInfoDomain, outerProtected)
}

// BuildHPKEAAD binds the sole AEAD operation to the exact outer protected bytes.
func BuildHPKEAAD(outerProtected []byte) ([]byte, error) {
	return buildDomainSeparated(hpkeAADDomain, outerProtected)
}

// BuildSealedFrame builds [outer_protected, enc, ciphertext]. The plaintext is
// the complete tagged COSE_Sign1 bytes and is supplied only to HPKE, never to
// this outer framing function.
func BuildSealedFrame(outerProtected, enc, ciphertext []byte) ([]byte, error) {
	if len(outerProtected) == 0 || len(outerProtected) > MaxOuterProtectedBytes {
		return nil, errors.New("envelope: outer protected bytes are outside the admitted range")
	}
	if len(enc) != HPKEP256EncSize {
		return nil, fmt.Errorf("envelope: HPKE encapsulation must be %d bytes", HPKEP256EncSize)
	}
	if len(ciphertext) <= HPKEAEADTagSize || len(ciphertext) > MaxCiphertextBytes {
		return nil, errors.New("envelope: HPKE ciphertext size is outside the admitted range")
	}
	return marshalDeterministicBounded([]any{
		append([]byte(nil), outerProtected...),
		append([]byte(nil), enc...),
		append([]byte(nil), ciphertext...),
	}, MaxSealedFrameBytes, "sealed frame")
}

// ValidateOpenedArtifactMetadataBinding compares the issuer-signed canonical
// metadata in an opened tagged COSE_Sign1 object with the metadata protected by
// HPKE. Callers must verify the issuer signature over the exact signed object;
// this equality check must also succeed before metadata can reach policy or
// state. A matching issuer signature does not grant Provider or Registrar
// authority, which remains a later verification-lifecycle decision.
func ValidateOpenedArtifactMetadataBinding(openedSignedObject, outerProtected []byte) error {
	parsed, err := ParseSignedProfileOpaque(openedSignedObject)
	if err != nil {
		return errors.New("envelope: opened object is not a valid tagged COSE_Sign1")
	}
	signedMetadata, err := signedMetadataBytes(parsed.Protected)
	if err != nil {
		return err
	}
	outerMetadata, err := outerMetadataBytes(outerProtected)
	if err != nil {
		return err
	}
	if !bytes.Equal(signedMetadata, outerMetadata) {
		return ErrMetadataMismatch
	}
	decodedOuterMetadata, err := decodeArtifactMetadata(outerMetadata)
	if err != nil {
		return err
	}
	if decodedOuterMetadata.Class == ArtifactSignedPublic {
		return errors.New("envelope: signed-public metadata is invalid in a sealed outer object")
	}
	return nil
}

// ValidateCoreDeterministicCBOR applies the generic v1 wire floor before any
// schema or authority interpretation. Schema-specific code must still enforce
// exact labels, types, array arity, and the location of the sole allowed tag.
func ValidateCoreDeterministicCBOR(data []byte) error {
	if len(data) == 0 || len(data) > MaxTotalInputBytes {
		return errors.New("envelope: CBOR artifact size is outside the admitted range")
	}
	options := cbor.DecOptions{
		DupMapKey:            cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:      MaxCBORNestedLevels,
		MaxArrayElements:     MaxCBORArrayElements,
		MaxMapPairs:          MaxCBORMapPairs,
		IndefLength:          cbor.IndefLengthForbidden,
		TagsMd:               cbor.TagsAllowed,
		IntDec:               cbor.IntDecConvertNone,
		UTF8:                 cbor.UTF8RejectInvalid,
		BignumTag:            cbor.BignumTagForbidden,
		UnrecognizedTagToAny: cbor.UnrecognizedTagNumAndContentToAny,
	}
	mode, err := options.DecMode()
	if err != nil {
		return fmt.Errorf("envelope: strict CBOR mode: %w", err)
	}
	var decoded any
	if err := mode.Unmarshal(data, &decoded); err != nil {
		return fmt.Errorf("envelope: strict CBOR: %w", err)
	}
	if err := validateCBORValue(decoded); err != nil {
		return err
	}
	reencoded, err := marshalDeterministic(decoded)
	if err != nil {
		return err
	}
	if !bytes.Equal(data, reencoded) {
		return errors.New("envelope: CBOR input is not core deterministic")
	}
	return nil
}

// EncodeRawES256Signature converts ECDSA (R,S) to RFC 9053's fixed-width
// 32-byte R || 32-byte S form and normalizes S to the lower half-order.
func EncodeRawES256Signature(r, s *big.Int) ([]byte, error) {
	n := p256Order()
	if r == nil || s == nil || r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 {
		return nil, errors.New("envelope: ES256 signature scalar is outside the valid range")
	}
	lowS := new(big.Int).Set(s)
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if lowS.Cmp(halfOrder) > 0 {
		lowS.Sub(n, lowS)
	}
	out := make([]byte, ES256RawSignatureSize)
	r.FillBytes(out[:32])
	lowS.FillBytes(out[32:])
	return out, nil
}

// DecodeRawES256Signature validates and decodes RFC 9053's fixed-width form.
// High-S signatures are rejected to remove the otherwise valid malleable form.
func DecodeRawES256Signature(signature []byte) (*big.Int, *big.Int, error) {
	if len(signature) != ES256RawSignatureSize {
		return nil, nil, fmt.Errorf("envelope: ES256 signature must be %d raw bytes", ES256RawSignatureSize)
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	n := p256Order()
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(n), 1)
	if r.Sign() <= 0 || s.Sign() <= 0 || r.Cmp(n) >= 0 || s.Cmp(n) >= 0 || s.Cmp(halfOrder) > 0 {
		return nil, nil, errors.New("envelope: ES256 signature is invalid or non-canonical")
	}
	return r, s, nil
}

// HPKEContextBudget enforces the v1 one-artifact-per-encapsulation rule.
type HPKEContextBudget struct {
	remaining uint8
}

// NewHPKEContextBudget returns a fresh one-operation budget.
func NewHPKEContextBudget() *HPKEContextBudget {
	return &HPKEContextBudget{remaining: MaxHPKEMessagesPerContext}
}

// Consume authorizes one Seal/Open operation and then fails closed forever.
func (b *HPKEContextBudget) Consume() error {
	if b == nil || b.remaining == 0 {
		return ErrHPKEContextExhausted
	}
	b.remaining--
	return nil
}

func marshalDeterministic(v any) ([]byte, error) {
	options := cbor.CoreDetEncOptions()
	mode, err := options.EncMode()
	if err != nil {
		return nil, fmt.Errorf("envelope: deterministic CBOR mode: %w", err)
	}
	encoded, err := mode.Marshal(v)
	if err != nil {
		return nil, fmt.Errorf("envelope: deterministic CBOR: %w", err)
	}
	return encoded, nil
}

func marshalDeterministicBounded(v any, maximum int, label string) ([]byte, error) {
	encoded, err := marshalDeterministic(v)
	if err != nil {
		return nil, err
	}
	if err := validateInputSize(label, len(encoded), maximum); err != nil {
		return nil, err
	}
	return encoded, nil
}

func validateInputSize(label string, size, maximum int) error {
	if size <= 0 || size > maximum {
		return fmt.Errorf("%w: %s is %d bytes, maximum %d", ErrArtifactSizeLimit, label, size, maximum)
	}
	return nil
}

func strictCBORDecMode() (cbor.DecMode, error) {
	return cbor.DecOptions{
		DupMapKey:            cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:      MaxCBORNestedLevels,
		MaxArrayElements:     MaxCBORArrayElements,
		MaxMapPairs:          MaxCBORMapPairs,
		IndefLength:          cbor.IndefLengthForbidden,
		TagsMd:               cbor.TagsAllowed,
		IntDec:               cbor.IntDecConvertNone,
		UTF8:                 cbor.UTF8RejectInvalid,
		BignumTag:            cbor.BignumTagForbidden,
		UnrecognizedTagToAny: cbor.UnrecognizedTagNumAndContentToAny,
	}.DecMode()
}

func unmarshalStrict(data []byte, destination any) error {
	mode, err := strictCBORDecMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(data, destination)
}

func signedMetadataBytes(protected []byte) ([]byte, error) {
	if err := validateInputSize("signed protected headers", len(protected), MaxSignedProtectedBytes); err != nil {
		return nil, err
	}
	if err := ValidateCoreDeterministicCBOR(protected); err != nil {
		return nil, err
	}
	var headers map[int64]cbor.RawMessage
	if err := unmarshalStrict(protected, &headers); err != nil || len(headers) != 7 {
		return nil, errors.New("envelope: signed protected header schema is invalid")
	}
	var algorithm int64
	var critical []int64
	var contentType string
	var keyID []byte
	var formatVersion, suiteID uint64
	var metadata []byte
	if err := unmarshalStrict(headers[COSEHeaderAlgorithm], &algorithm); err != nil || algorithm != COSEAlgorithmES256 {
		return nil, errors.New("envelope: signed algorithm is invalid")
	}
	if err := unmarshalStrict(headers[COSEHeaderCritical], &critical); err != nil || len(critical) != 3 || critical[0] != COSEHeaderProfileFormatVersion || critical[1] != COSEHeaderProfileSuiteID || critical[2] != COSEHeaderArtifactMetadata {
		return nil, errors.New("envelope: signed critical headers are invalid")
	}
	if err := unmarshalStrict(headers[COSEHeaderContent], &contentType); err != nil || contentType != SignedPayloadContentType {
		return nil, errors.New("envelope: signed content type is invalid")
	}
	if err := unmarshalStrict(headers[COSEHeaderKeyID], &keyID); err != nil || len(keyID) < MinKeyIDBytes || len(keyID) > MaxKeyIDBytes {
		return nil, errors.New("envelope: signed key ID is invalid")
	}
	if err := unmarshalStrict(headers[COSEHeaderProfileFormatVersion], &formatVersion); err != nil || formatVersion != ProfileFormatVersion {
		return nil, errors.New("envelope: signed profile format is invalid")
	}
	if err := unmarshalStrict(headers[COSEHeaderProfileSuiteID], &suiteID); err != nil || suiteID != uint64(SuiteClassicalV1) {
		return nil, errors.New("envelope: signed suite is invalid")
	}
	if err := unmarshalStrict(headers[COSEHeaderArtifactMetadata], &metadata); err != nil || len(metadata) == 0 || len(metadata) > MaxArtifactMetadataBytes {
		return nil, errors.New("envelope: signed artifact metadata is invalid")
	}
	if _, err := decodeArtifactMetadataSchema(metadata); err != nil {
		return nil, errors.New("envelope: signed artifact metadata is invalid")
	}
	canonical, err := marshalDeterministicBounded(map[int64]any{
		COSEHeaderAlgorithm:            algorithm,
		COSEHeaderCritical:             critical,
		COSEHeaderContent:              contentType,
		COSEHeaderKeyID:                keyID,
		COSEHeaderProfileFormatVersion: formatVersion,
		COSEHeaderProfileSuiteID:       suiteID,
		COSEHeaderArtifactMetadata:     metadata,
	}, MaxSignedProtectedBytes, "signed protected headers")
	if err != nil || !bytes.Equal(protected, canonical) {
		return nil, errors.New("envelope: signed protected headers must use exact direct schema types")
	}
	return metadata, nil
}

func outerMetadataBytes(protected []byte) ([]byte, error) {
	if err := validateInputSize("outer protected metadata", len(protected), MaxOuterProtectedBytes); err != nil {
		return nil, err
	}
	if err := ValidateCoreDeterministicCBOR(protected); err != nil {
		return nil, err
	}
	var headers map[uint64]cbor.RawMessage
	if err := unmarshalStrict(protected, &headers); err != nil || len(headers) != 4 {
		return nil, errors.New("envelope: outer protected schema is invalid")
	}
	var formatVersion, suiteID uint64
	var contentType string
	var metadata []byte
	if err := unmarshalStrict(headers[1], &formatVersion); err != nil || formatVersion != SealFormatVersion {
		return nil, errors.New("envelope: outer seal format is invalid")
	}
	if err := unmarshalStrict(headers[2], &suiteID); err != nil || suiteID != uint64(SuiteClassicalV1) {
		return nil, errors.New("envelope: outer suite is invalid")
	}
	if err := unmarshalStrict(headers[3], &contentType); err != nil || contentType != SignedObjectContentType {
		return nil, errors.New("envelope: outer content type is invalid")
	}
	if err := unmarshalStrict(headers[4], &metadata); err != nil || len(metadata) == 0 || len(metadata) > MaxArtifactMetadataBytes {
		return nil, errors.New("envelope: outer artifact metadata is invalid")
	}
	if _, err := decodeArtifactMetadataSchema(metadata); err != nil {
		return nil, errors.New("envelope: outer artifact metadata is invalid")
	}
	canonical, err := marshalDeterministicBounded(map[uint64]any{
		1: formatVersion,
		2: suiteID,
		3: contentType,
		4: metadata,
	}, MaxOuterProtectedBytes, "outer protected metadata")
	if err != nil || !bytes.Equal(protected, canonical) {
		return nil, errors.New("envelope: outer protected metadata must use exact direct schema types")
	}
	return metadata, nil
}

func decodeArtifactMetadata(encoded []byte) (ArtifactMetadata, error) {
	metadata, err := decodeArtifactMetadataSchema(encoded)
	if err != nil {
		return ArtifactMetadata{}, err
	}
	if err := ValidateArtifactMetadata(metadata); err != nil {
		return ArtifactMetadata{}, err
	}
	return metadata, nil
}

func decodeArtifactMetadataSchema(encoded []byte) (ArtifactMetadata, error) {
	if err := validateInputSize("artifact metadata", len(encoded), MaxArtifactMetadataBytes); err != nil {
		return ArtifactMetadata{}, err
	}
	if err := ValidateCoreDeterministicCBOR(encoded); err != nil {
		return ArtifactMetadata{}, err
	}
	var fields map[uint64]cbor.RawMessage
	if err := unmarshalStrict(encoded, &fields); err != nil || len(fields) != 4 {
		return ArtifactMetadata{}, errors.New("envelope: artifact metadata schema is invalid")
	}
	var class, audience string
	var hint []byte
	var epoch uint64
	if err := unmarshalStrict(fields[1], &class); err != nil {
		return ArtifactMetadata{}, errors.New("envelope: artifact class is invalid")
	}
	if err := unmarshalStrict(fields[2], &audience); err != nil {
		return ArtifactMetadata{}, errors.New("envelope: artifact audience is invalid")
	}
	if err := unmarshalStrict(fields[3], &hint); err != nil {
		return ArtifactMetadata{}, errors.New("envelope: artifact recipient hint is invalid")
	}
	if err := unmarshalStrict(fields[4], &epoch); err != nil {
		return ArtifactMetadata{}, errors.New("envelope: artifact recipient epoch is invalid")
	}
	metadata := ArtifactMetadata{Class: ArtifactClass(class), AudienceClass: audience, RecipientHint: string(hint), RecipientEpoch: epoch}
	canonical, err := marshalDeterministicBounded(map[uint64]any{
		1: class,
		2: audience,
		3: hint,
		4: epoch,
	}, MaxArtifactMetadataBytes, "artifact metadata")
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ArtifactMetadata{}, errors.New("envelope: artifact metadata must use exact direct schema types")
	}
	return metadata, nil
}

func buildDomainSeparated(domain, outerProtected []byte) ([]byte, error) {
	if len(domain) == 0 || len(domain) > 0xffff {
		return nil, errors.New("envelope: invalid domain label")
	}
	if len(outerProtected) == 0 || len(outerProtected) > MaxOuterProtectedBytes {
		return nil, errors.New("envelope: outer protected bytes are outside the admitted range")
	}
	out := make([]byte, 0, 2+len(domain)+4+len(outerProtected))
	var length [4]byte
	binary.BigEndian.PutUint16(length[:2], uint16(len(domain)))
	out = append(out, length[:2]...)
	out = append(out, domain...)
	binary.BigEndian.PutUint32(length[:], uint32(len(outerProtected)))
	out = append(out, length[:]...)
	out = append(out, outerProtected...)
	return out, nil
}

func p256Order() *big.Int {
	// Order of the NIST P-256 base point from FIPS 186-5 / SEC 2.
	n, ok := new(big.Int).SetString("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
	if !ok {
		panic("envelope: invalid embedded P-256 order")
	}
	return n
}

func validateCBORValue(value any) error {
	switch value := value.(type) {
	case nil, bool, string, []byte, uint64, int64:
		return nil
	case []any:
		for _, item := range value {
			if err := validateCBORValue(item); err != nil {
				return err
			}
		}
		return nil
	case map[any]any:
		for key, item := range value {
			if err := validateCBORValue(key); err != nil {
				return err
			}
			if err := validateCBORValue(item); err != nil {
				return err
			}
		}
		return nil
	case cbor.Tag:
		if value.Number != COSESign1Tag {
			return fmt.Errorf("envelope: CBOR tag %d is not admitted", value.Number)
		}
		return validateCBORValue(value.Content)
	case float32, float64, big.Int, *big.Int, cbor.SimpleValue:
		return errors.New("envelope: floating point, bignum, and non-schema simple values are not admitted")
	default:
		return fmt.Errorf("envelope: CBOR value type %T is not admitted", value)
	}
}
