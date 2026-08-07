// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package enrollment owns the public, possession-bound device enrollment
// request and the private key bundle returned only to the generating device.
package enrollment

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"time"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/product/envelope"
)

const (
	RequestVersionV1           uint64 = 1
	ClientAuthAlgorithmEd25519 int64  = -8
	MaxRequestBytes                   = 512
	MaxPrivateBundleBytes             = 128
	MaxValiditySeconds         int64  = 24 * 60 * 60
	keyMaterialBytes                  = 32
)

const (
	requestSignatureDomain = "kurdistan-vpn/enrollment/request-signature/v1\x00"
	requestIDDomain        = "kurdistan-vpn/enrollment/request-id/v1\x00"
)

type ErrorCategory string

const (
	ErrorInvalidValue     ErrorCategory = "invalid-value"
	ErrorSizeLimit        ErrorCategory = "size-limit"
	ErrorNonCanonical     ErrorCategory = "non-canonical"
	ErrorSchema           ErrorCategory = "schema"
	ErrorUnsupportedSuite ErrorCategory = "unsupported-suite"
	ErrorKeyID            ErrorCategory = "key-id"
	ErrorSignature        ErrorCategory = "signature"
	ErrorNotYetValid      ErrorCategory = "not-yet-valid"
	ErrorExpired          ErrorCategory = "expired"
)

func (category ErrorCategory) String() string { return string(category) }

type Error struct{ Category ErrorCategory }

func (e *Error) Error() string { return "enrollment request: " + e.Category.String() }

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}

func fail(category ErrorCategory) error { return &Error{Category: category} }

type PrivateBundleV1 struct {
	RecipientPrivate []byte
	ClientAuthSeed   []byte
}

type PublicRequestV1 struct {
	RequestID, RecipientKeyID, ClientAuthKeyID string
	CreatedAt, ExpiresAt                       int64
	RecipientPublic, ClientAuthPublic, Nonce   []byte
	Signature                                  []byte
}

func Generate(now time.Time, validity time.Duration, random io.Reader) (PublicRequestV1, PrivateBundleV1, error) {
	if random == nil || validity <= 0 || validity%time.Second != 0 || validity > 24*time.Hour {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	created := now.Unix()
	seconds := int64(validity / time.Second)
	if created <= 0 || created > math.MaxInt64-seconds {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}

	ikm := make([]byte, keyMaterialBytes)
	defer clear(ikm)
	if _, err := io.ReadFull(random, ikm); err != nil || zero(ikm) {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	recipientKey, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair(ikm)
	if err != nil {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	recipientPrivate, err := recipientKey.Bytes()
	if err != nil {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	defer clear(recipientPrivate)
	if len(recipientPrivate) != keyMaterialBytes || zero(recipientPrivate) {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	recipientPublic := recipientKey.PublicKey().Bytes()
	if !validRecipientPublic(recipientPublic) {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}

	seed := make([]byte, ed25519.SeedSize)
	defer clear(seed)
	if _, err := io.ReadFull(random, seed); err != nil || zero(seed) {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	clientPrivate := ed25519.NewKeyFromSeed(seed)
	defer clear(clientPrivate)
	clientPublic := bytes.Clone(clientPrivate.Public().(ed25519.PublicKey))
	if !validClientPublic(clientPublic) {
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}

	nonce := make([]byte, keyMaterialBytes)
	if _, err := io.ReadFull(random, nonce); err != nil || zero(nonce) {
		clear(nonce)
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	request := PublicRequestV1{
		CreatedAt: created, ExpiresAt: created + seconds,
		RecipientPublic: bytes.Clone(recipientPublic), ClientAuthPublic: clientPublic, Nonce: nonce,
	}
	request.RecipientKeyID = recipientKeyID(request.RecipientPublic)
	request.ClientAuthKeyID = clientAuthKeyID(request.ClientAuthPublic)
	request.RequestID, err = deriveRequestID(request)
	if err != nil {
		clear(request.Nonce)
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	unsigned, err := encodeUnsignedRequest(request)
	if err != nil {
		clear(request.Nonce)
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	message := make([]byte, 0, len(requestSignatureDomain)+len(unsigned))
	message = append(message, requestSignatureDomain...)
	message = append(message, unsigned...)
	request.Signature = bytes.Clone(ed25519.Sign(clientPrivate, message))
	bundle := PrivateBundleV1{RecipientPrivate: bytes.Clone(recipientPrivate), ClientAuthSeed: bytes.Clone(seed)}
	if err := validateRequest(request, nil); err != nil || validatePrivateBundle(bundle) != nil {
		clear(bundle.RecipientPrivate)
		clear(bundle.ClientAuthSeed)
		return PublicRequestV1{}, PrivateBundleV1{}, fail(ErrorInvalidValue)
	}
	resultRequest := cloneRequest(request)
	resultBundle := cloneBundle(bundle)
	clear(bundle.RecipientPrivate)
	clear(bundle.ClientAuthSeed)
	return resultRequest, resultBundle, nil
}

func EncodeRequestV1(request PublicRequestV1) ([]byte, error) {
	if err := validateRequest(request, nil); err != nil {
		return nil, err
	}
	encoded, err := marshal(requestMap(request, true))
	if err != nil {
		return nil, fail(ErrorNonCanonical)
	}
	if len(encoded) == 0 || len(encoded) > MaxRequestBytes {
		return nil, fail(ErrorSizeLimit)
	}
	return encoded, nil
}

func DecodeAndVerifyRequestV1(encoded []byte, now time.Time) (PublicRequestV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxRequestBytes {
		return PublicRequestV1{}, fail(ErrorSizeLimit)
	}
	if err := validateCore(encoded); err != nil {
		return PublicRequestV1{}, fail(ErrorNonCanonical)
	}
	fields, err := rawMap(encoded, 15)
	if err != nil {
		return PublicRequestV1{}, err
	}
	var version, suite, kem, kdf, aead uint64
	var algorithm int64
	if decode(fields[1], &version) != nil || decode(fields[5], &suite) != nil || decode(fields[6], &kem) != nil || decode(fields[7], &kdf) != nil || decode(fields[8], &aead) != nil || decode(fields[9], &algorithm) != nil {
		return PublicRequestV1{}, fail(ErrorSchema)
	}
	if version != RequestVersionV1 {
		return PublicRequestV1{}, fail(ErrorSchema)
	}
	if suite != uint64(envelope.SuiteClassicalV1) || kem != uint64(envelope.HPKEKEMP256SHA256) || kdf != uint64(envelope.HPKEKDFSHA256) || aead != uint64(envelope.HPKEAEADAES256GCM) || algorithm != ClientAuthAlgorithmEd25519 {
		return PublicRequestV1{}, fail(ErrorUnsupportedSuite)
	}
	var request PublicRequestV1
	values := map[uint64]any{
		2: &request.RequestID, 3: &request.CreatedAt, 4: &request.ExpiresAt,
		10: &request.RecipientPublic, 11: &request.RecipientKeyID, 12: &request.ClientAuthPublic,
		13: &request.ClientAuthKeyID, 14: &request.Nonce, 15: &request.Signature,
	}
	for label, destination := range values {
		if decode(fields[label], destination) != nil {
			return PublicRequestV1{}, fail(ErrorSchema)
		}
	}
	current := now.Unix()
	if err := validateRequest(request, &current); err != nil {
		return PublicRequestV1{}, err
	}
	reencoded, err := EncodeRequestV1(request)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		return PublicRequestV1{}, fail(ErrorNonCanonical)
	}
	return cloneRequest(request), nil
}

func EncodePrivateBundleV1(bundle PrivateBundleV1) ([]byte, error) {
	if err := validatePrivateBundle(bundle); err != nil {
		return nil, err
	}
	recipientPrivate := bytes.Clone(bundle.RecipientPrivate)
	clientAuthSeed := bytes.Clone(bundle.ClientAuthSeed)
	defer clear(recipientPrivate)
	defer clear(clientAuthSeed)
	encoded, err := marshal(map[uint64]any{1: RequestVersionV1, 2: recipientPrivate, 3: clientAuthSeed})
	if err != nil {
		return nil, fail(ErrorNonCanonical)
	}
	if len(encoded) == 0 || len(encoded) > MaxPrivateBundleBytes {
		return nil, fail(ErrorSizeLimit)
	}
	return encoded, nil
}

func DecodePrivateBundleV1(encoded []byte) (PrivateBundleV1, error) {
	if len(encoded) == 0 || len(encoded) > MaxPrivateBundleBytes {
		return PrivateBundleV1{}, fail(ErrorSizeLimit)
	}
	if err := validateCore(encoded); err != nil {
		return PrivateBundleV1{}, fail(ErrorNonCanonical)
	}
	fields, err := rawMap(encoded, 3)
	if err != nil {
		return PrivateBundleV1{}, err
	}
	var version uint64
	var bundle PrivateBundleV1
	defer func() {
		clear(bundle.RecipientPrivate)
		clear(bundle.ClientAuthSeed)
	}()
	if decode(fields[1], &version) != nil || version != RequestVersionV1 || decode(fields[2], &bundle.RecipientPrivate) != nil || decode(fields[3], &bundle.ClientAuthSeed) != nil {
		return PrivateBundleV1{}, fail(ErrorSchema)
	}
	if err := validatePrivateBundle(bundle); err != nil {
		return PrivateBundleV1{}, err
	}
	reencoded, err := EncodePrivateBundleV1(bundle)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		clear(reencoded)
		return PrivateBundleV1{}, fail(ErrorNonCanonical)
	}
	result := cloneBundle(bundle)
	clear(reencoded)
	return result, nil
}

func validateRequest(request PublicRequestV1, current *int64) error {
	if request.CreatedAt <= 0 || request.ExpiresAt <= request.CreatedAt || request.ExpiresAt-request.CreatedAt > MaxValiditySeconds || !validRecipientPublic(request.RecipientPublic) || !validClientPublic(request.ClientAuthPublic) || len(request.Nonce) != keyMaterialBytes || zero(request.Nonce) || len(request.Signature) != ed25519.SignatureSize {
		return fail(ErrorInvalidValue)
	}
	expectedRequestID, err := deriveRequestID(request)
	if err != nil || request.RecipientKeyID != recipientKeyID(request.RecipientPublic) || request.ClientAuthKeyID != clientAuthKeyID(request.ClientAuthPublic) || request.RequestID != expectedRequestID {
		return fail(ErrorKeyID)
	}
	unsigned, err := encodeUnsignedRequest(request)
	if err != nil {
		return fail(ErrorNonCanonical)
	}
	message := make([]byte, 0, len(requestSignatureDomain)+len(unsigned))
	message = append(message, requestSignatureDomain...)
	message = append(message, unsigned...)
	if !ed25519.Verify(ed25519.PublicKey(request.ClientAuthPublic), message, request.Signature) {
		return fail(ErrorSignature)
	}
	if current != nil {
		if *current < request.CreatedAt {
			return fail(ErrorNotYetValid)
		}
		if *current >= request.ExpiresAt {
			return fail(ErrorExpired)
		}
	}
	return nil
}

func validatePrivateBundle(bundle PrivateBundleV1) error {
	if len(bundle.RecipientPrivate) != keyMaterialBytes || zero(bundle.RecipientPrivate) || len(bundle.ClientAuthSeed) != ed25519.SeedSize || zero(bundle.ClientAuthSeed) {
		return fail(ErrorInvalidValue)
	}
	temporary := bytes.Clone(bundle.RecipientPrivate)
	key, err := hpke.DHKEM(ecdh.P256()).NewPrivateKey(temporary)
	clear(temporary)
	if err != nil {
		return fail(ErrorInvalidValue)
	}
	canonical, err := key.Bytes()
	if err != nil {
		return fail(ErrorInvalidValue)
	}
	defer clear(canonical)
	if !bytes.Equal(bundle.RecipientPrivate, canonical) {
		return fail(ErrorInvalidValue)
	}
	return nil
}

func validRecipientPublic(encoded []byte) bool {
	if len(encoded) != envelope.HPKEP256EncSize || encoded[0] != 4 || zero(encoded) {
		return false
	}
	key, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(encoded)
	return err == nil && bytes.Equal(encoded, key.Bytes())
}

func validClientPublic(encoded []byte) bool {
	return len(encoded) == ed25519.PublicKeySize && !zero(encoded)
}

func recipientKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return "recipient." + hex.EncodeToString(digest[:8])
}

func clientAuthKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

func deriveRequestID(request PublicRequestV1) (string, error) {
	identity, err := marshal(requestIdentityMap(request))
	if err != nil {
		return "", err
	}
	hash := sha256.New()
	_, _ = hash.Write([]byte(requestIDDomain))
	_, _ = hash.Write(identity)
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func requestIdentityMap(request PublicRequestV1) map[uint64]any {
	return map[uint64]any{
		1: RequestVersionV1, 3: request.CreatedAt, 4: request.ExpiresAt,
		5: uint64(envelope.SuiteClassicalV1), 6: uint64(envelope.HPKEKEMP256SHA256), 7: uint64(envelope.HPKEKDFSHA256), 8: uint64(envelope.HPKEAEADAES256GCM), 9: ClientAuthAlgorithmEd25519,
		10: bytes.Clone(request.RecipientPublic), 11: request.RecipientKeyID, 12: bytes.Clone(request.ClientAuthPublic), 13: request.ClientAuthKeyID, 14: bytes.Clone(request.Nonce),
	}
}

func encodeUnsignedRequest(request PublicRequestV1) ([]byte, error) {
	return marshal(requestMap(request, false))
}

func requestMap(request PublicRequestV1, includeSignature bool) map[uint64]any {
	values := map[uint64]any{
		1: RequestVersionV1, 2: request.RequestID, 3: request.CreatedAt, 4: request.ExpiresAt,
		5: uint64(envelope.SuiteClassicalV1), 6: uint64(envelope.HPKEKEMP256SHA256), 7: uint64(envelope.HPKEKDFSHA256), 8: uint64(envelope.HPKEAEADAES256GCM), 9: ClientAuthAlgorithmEd25519,
		10: bytes.Clone(request.RecipientPublic), 11: request.RecipientKeyID, 12: bytes.Clone(request.ClientAuthPublic), 13: request.ClientAuthKeyID, 14: bytes.Clone(request.Nonce),
	}
	if includeSignature {
		values[15] = bytes.Clone(request.Signature)
	}
	return values
}

func cloneRequest(request PublicRequestV1) PublicRequestV1 {
	request.RecipientPublic = bytes.Clone(request.RecipientPublic)
	request.ClientAuthPublic = bytes.Clone(request.ClientAuthPublic)
	request.Nonce = bytes.Clone(request.Nonce)
	request.Signature = bytes.Clone(request.Signature)
	return request
}

func cloneBundle(bundle PrivateBundleV1) PrivateBundleV1 {
	bundle.RecipientPrivate = bytes.Clone(bundle.RecipientPrivate)
	bundle.ClientAuthSeed = bytes.Clone(bundle.ClientAuthSeed)
	return bundle
}

func rawMap(raw []byte, count int) (map[uint64]cbor.RawMessage, error) {
	var fields map[uint64]cbor.RawMessage
	if decode(raw, &fields) != nil || len(fields) != count {
		return nil, fail(ErrorSchema)
	}
	for label := uint64(1); label <= uint64(count); label++ {
		if _, ok := fields[label]; !ok {
			return nil, fail(ErrorSchema)
		}
	}
	return fields, nil
}

func marshal(value any) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(value)
}

func decode(raw []byte, destination any) error {
	mode, err := strictMode()
	if err != nil {
		return err
	}
	return mode.Unmarshal(raw, destination)
}

func validateCore(encoded []byte) error {
	mode, err := strictMode()
	if err != nil {
		return err
	}
	var value any
	if err := mode.Unmarshal(encoded, &value); err != nil {
		return err
	}
	canonical, err := marshal(value)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return errors.New("noncanonical")
	}
	return nil
}

func strictMode() (cbor.DecMode, error) {
	return cbor.DecOptions{
		DupMapKey:        cbor.DupMapKeyEnforcedAPF,
		MaxNestedLevels:  16,
		MaxArrayElements: 16,
		MaxMapPairs:      16,
		IndefLength:      cbor.IndefLengthForbidden,
		TagsMd:           cbor.TagsForbidden,
		IntDec:           cbor.IntDecConvertNone,
		UTF8:             cbor.UTF8RejectInvalid,
		BignumTag:        cbor.BignumTagForbidden,
	}.DecMode()
}

func zero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}
