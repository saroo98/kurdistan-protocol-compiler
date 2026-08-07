// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package profilehpke adapts the mandatory Phase 8 HPKE suite to the offline
// product profile interfaces. Each call creates exactly one HPKE context and
// performs exactly one Seal or Open operation.
package profilehpke

import (
	"bytes"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"sync"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

type ErrorCategory string

const (
	ErrorInvalidBinding ErrorCategory = "invalid-binding"
	ErrorInvalidKey     ErrorCategory = "invalid-key"
	ErrorInvalidInput   ErrorCategory = "invalid-input"
	ErrorClosed         ErrorCategory = "closed"
	ErrorSealFailed     ErrorCategory = "seal-failed"
	ErrorOpenFailed     ErrorCategory = "open-failed"
)

func (category ErrorCategory) String() string { return string(category) }

type Error struct{ Category ErrorCategory }

func (e *Error) Error() string { return "profile hpke: " + e.Category.String() }

func IsCategory(err error, category ErrorCategory) bool {
	var target *Error
	return errors.As(err, &target) && target.Category == category
}

func fail(category ErrorCategory) error { return &Error{Category: category} }

type Sealer struct {
	expected        profile.RecipientBinding
	recipientPublic []byte
}

func NewSealer(expected profile.RecipientBinding, recipientPublic []byte) (*Sealer, error) {
	validated, err := validateBinding(expected)
	if err != nil {
		return nil, err
	}
	canonical, err := canonicalPublicKey(recipientPublic)
	if err != nil {
		return nil, err
	}
	if validated.KeyID != recipientKeyID(canonical) {
		return nil, fail(ErrorInvalidBinding)
	}
	return &Sealer{expected: validated, recipientPublic: canonical}, nil
}

func (s *Sealer) SealOffline(actual profile.RecipientBinding, outerProtected, plaintext []byte) (encapsulation, ciphertext []byte, err error) {
	if s == nil || actual != s.expected {
		return nil, nil, fail(ErrorInvalidBinding)
	}
	if len(plaintext) == 0 || len(plaintext) > envelope.MaxSignedObjectBytes {
		return nil, nil, fail(ErrorInvalidInput)
	}
	info, err := envelope.BuildHPKEInfo(outerProtected)
	if err != nil {
		return nil, nil, fail(ErrorInvalidInput)
	}
	aad, err := envelope.BuildHPKEAAD(outerProtected)
	if err != nil {
		return nil, nil, fail(ErrorInvalidInput)
	}
	public, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(s.recipientPublic)
	if err != nil {
		return nil, nil, fail(ErrorInvalidKey)
	}
	encapsulation, sender, err := hpke.NewSender(public, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, nil, fail(ErrorSealFailed)
	}
	ciphertext, err = sender.Seal(aad, plaintext)
	if err != nil || len(encapsulation) != envelope.HPKEP256EncSize || len(ciphertext) <= envelope.HPKEAEADTagSize || len(ciphertext) > envelope.MaxCiphertextBytes {
		return nil, nil, fail(ErrorSealFailed)
	}
	return bytes.Clone(encapsulation), bytes.Clone(ciphertext), nil
}

type Opener struct {
	mu               sync.Mutex
	expected         profile.RecipientBinding
	recipientPrivate []byte
	closed           bool
}

func NewOpener(expected profile.RecipientBinding, recipientPrivate []byte) (*Opener, error) {
	validated, err := validateBinding(expected)
	if err != nil {
		return nil, err
	}
	canonical, public, err := canonicalPrivateKey(recipientPrivate)
	if err != nil {
		return nil, err
	}
	if validated.KeyID != recipientKeyID(public) {
		clear(canonical)
		return nil, fail(ErrorInvalidBinding)
	}
	return &Opener{expected: validated, recipientPrivate: canonical}, nil
}

func (o *Opener) OpenOffline(actual profile.RecipientBinding, outerProtected, encapsulation, ciphertext []byte) ([]byte, error) {
	if o == nil {
		return nil, fail(ErrorClosed)
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, fail(ErrorClosed)
	}
	if actual != o.expected {
		return nil, fail(ErrorInvalidBinding)
	}
	if len(encapsulation) != envelope.HPKEP256EncSize || len(ciphertext) <= envelope.HPKEAEADTagSize || len(ciphertext) > envelope.MaxCiphertextBytes {
		return nil, fail(ErrorInvalidInput)
	}
	info, err := envelope.BuildHPKEInfo(outerProtected)
	if err != nil {
		return nil, fail(ErrorInvalidInput)
	}
	aad, err := envelope.BuildHPKEAAD(outerProtected)
	if err != nil {
		return nil, fail(ErrorInvalidInput)
	}
	temporary := bytes.Clone(o.recipientPrivate)
	private, err := hpke.DHKEM(ecdh.P256()).NewPrivateKey(temporary)
	clear(temporary)
	if err != nil {
		return nil, fail(ErrorInvalidKey)
	}
	recipient, err := hpke.NewRecipient(encapsulation, private, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, fail(ErrorOpenFailed)
	}
	plaintext, err := recipient.Open(aad, ciphertext)
	if err != nil || len(plaintext) == 0 || len(plaintext) > envelope.MaxSignedObjectBytes {
		if plaintext != nil {
			clear(plaintext)
		}
		return nil, fail(ErrorOpenFailed)
	}
	return plaintext, nil
}

func (o *Opener) Close() {
	if o == nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	clear(o.recipientPrivate)
	o.closed = true
}

func validateBinding(binding profile.RecipientBinding) (profile.RecipientBinding, error) {
	resolved, err := profile.ResolveRecipientBinding([]profile.RecipientBinding{binding}, binding.Class, binding.Hint)
	if err != nil || resolved != binding {
		return profile.RecipientBinding{}, fail(ErrorInvalidBinding)
	}
	return resolved, nil
}

func canonicalPublicKey(encoded []byte) ([]byte, error) {
	if len(encoded) != envelope.HPKEP256EncSize || encoded[0] != 4 || zero(encoded) {
		return nil, fail(ErrorInvalidKey)
	}
	input := bytes.Clone(encoded)
	key, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(input)
	if err != nil {
		return nil, fail(ErrorInvalidKey)
	}
	canonical := key.Bytes()
	if !bytes.Equal(input, canonical) {
		return nil, fail(ErrorInvalidKey)
	}
	return bytes.Clone(canonical), nil
}

func canonicalPrivateKey(encoded []byte) ([]byte, []byte, error) {
	if len(encoded) != 32 || zero(encoded) {
		return nil, nil, fail(ErrorInvalidKey)
	}
	input := bytes.Clone(encoded)
	key, err := hpke.DHKEM(ecdh.P256()).NewPrivateKey(input)
	clear(input)
	if err != nil {
		return nil, nil, fail(ErrorInvalidKey)
	}
	canonical, err := key.Bytes()
	if err != nil {
		return nil, nil, fail(ErrorInvalidKey)
	}
	defer clear(canonical)
	if !bytes.Equal(encoded, canonical) {
		return nil, nil, fail(ErrorInvalidKey)
	}
	return bytes.Clone(canonical), bytes.Clone(key.PublicKey().Bytes()), nil
}

func recipientKeyID(public []byte) string {
	digest := sha256.Sum256(public)
	return "recipient." + hex.EncodeToString(digest[:8])
}

func zero(value []byte) bool {
	var combined byte
	for _, item := range value {
		combined |= item
	}
	return combined == 0
}

var _ profile.OfflineRecipientSealer = (*Sealer)(nil)
var _ profile.OfflineRecipientOpener = (*Opener)(nil)
