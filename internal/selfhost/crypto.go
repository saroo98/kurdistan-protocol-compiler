// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"unicode/utf8"

	"golang.org/x/crypto/argon2"

	"kurdistan/internal/product/profile"
)

const (
	recoveryMemoryKiB   uint32 = 64 * 1024
	recoveryIterations  uint32 = 3
	recoveryParallelism uint8  = 1
)

type p256Signer struct {
	keyID string
	key   *ecdsa.PrivateKey
}

func (signer p256Signer) Sign(reference profile.KeyReference, message []byte) ([]byte, error) {
	if signer.key == nil || reference.KeyID != signer.keyID || len(message) == 0 {
		return nil, ErrInvalidInput
	}
	digest := sha256.Sum256(message)
	r, s, err := ecdsa.Sign(rand.Reader, signer.key, digest[:])
	if err != nil {
		return nil, err
	}
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(halfOrder) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return raw, nil
}

type p256Verifier struct {
	keys map[string]*ecdsa.PublicKey
}

func (verifier p256Verifier) Verify(reference profile.KeyReference, message, signature []byte) error {
	key := verifier.keys[reference.KeyID]
	if key == nil || len(message) == 0 || len(signature) != 64 {
		return ErrInvalidInput
	}
	r := new(big.Int).SetBytes(signature[:32])
	s := new(big.Int).SetBytes(signature[32:])
	halfOrder := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if r.Sign() <= 0 || s.Sign() <= 0 || s.Cmp(halfOrder) > 0 {
		return ErrInvalidInput
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(key, digest[:], r, s) {
		return ErrInvalidInput
	}
	return nil
}

func newP256Key(label string) (*ecdsa.PrivateKey, string, []byte, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, "", nil, err
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return nil, "", nil, err
	}
	return key, keyID(label, publicDER), publicDER, nil
}

func parseP256Public(encoded []byte) (*ecdsa.PublicKey, error) {
	value, err := x509.ParsePKIXPublicKey(encoded)
	if err != nil {
		return nil, ErrInvalidInput
	}
	key, ok := value.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, ErrInvalidInput
	}
	return key, nil
}

func parseP256Private(encoded []byte) (*ecdsa.PrivateKey, error) {
	key, err := x509.ParseECPrivateKey(encoded)
	if err != nil || key.Curve != elliptic.P256() {
		return nil, ErrRecoveryRejected
	}
	return key, nil
}

func keyID(label string, public []byte) string {
	digest := sha256.Sum256(public)
	return label + "." + hex.EncodeToString(digest[:8])
}

func fingerprint(public []byte) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:])
}

func randomBytes(size int) ([]byte, error) {
	value := make([]byte, size)
	if _, err := rand.Read(value); err != nil {
		return nil, err
	}
	return value, nil
}

func randomID(prefix string) (string, error) {
	raw, err := randomBytes(16)
	if err != nil {
		return "", err
	}
	return prefix + "." + hex.EncodeToString(raw), nil
}

func sealWithKey(key, plaintext, aad []byte) (sealedSecret, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return sealedSecret{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return sealedSecret{}, err
	}
	nonce, err := randomBytes(aead.NonceSize())
	if err != nil {
		return sealedSecret{}, err
	}
	return sealedSecret{Version: 1, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plaintext, aad)}, nil
}

func openWithKey(key []byte, sealed sealedSecret, aad []byte) ([]byte, error) {
	if sealed.Version != 1 {
		return nil, ErrStateCorrupt
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, ErrStateCorrupt
	}
	aead, err := cipher.NewGCM(block)
	if err != nil || len(sealed.Nonce) != aead.NonceSize() || len(sealed.Ciphertext) <= aead.Overhead() {
		return nil, ErrStateCorrupt
	}
	opened, err := aead.Open(nil, sealed.Nonce, sealed.Ciphertext, aad)
	if err != nil {
		return nil, ErrStateCorrupt
	}
	return opened, nil
}

func validPassphrase(passphrase []byte) bool {
	return utf8.Valid(passphrase) && utf8.RuneCount(passphrase) >= 12 && len(passphrase) <= 1024
}

func sealRecovery(payload recoveryPayload, passphrase []byte) ([]byte, error) {
	if !validPassphrase(passphrase) {
		return nil, ErrInvalidInput
	}
	plain, err := encodeCanonical(payload)
	if err != nil {
		return nil, err
	}
	salt, err := randomBytes(16)
	if err != nil {
		return nil, err
	}
	nonce, err := randomBytes(12)
	if err != nil {
		return nil, err
	}
	key := argon2.IDKey(passphrase, salt, recoveryIterations, recoveryMemoryKiB, recoveryParallelism, 32)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	header := recoveryAAD(salt, nonce)
	envelope := recoveryEnvelope{
		Schema: recoverySchema, KDFMemoryKiB: recoveryMemoryKiB,
		KDFIterations: recoveryIterations, KDFParallelism: recoveryParallelism,
		Salt: salt, Nonce: nonce, Ciphertext: aead.Seal(nil, nonce, plain, header),
	}
	return encodeCanonical(envelope)
}

func openRecovery(encoded, passphrase []byte) (recoveryPayload, error) {
	if !validPassphrase(passphrase) {
		return recoveryPayload{}, ErrRecoveryRejected
	}
	var envelope recoveryEnvelope
	if decodeCanonical(encoded, &envelope, maxStateBytes) != nil || envelope.Schema != recoverySchema ||
		envelope.KDFMemoryKiB != recoveryMemoryKiB || envelope.KDFIterations != recoveryIterations ||
		envelope.KDFParallelism != recoveryParallelism || len(envelope.Salt) != 16 || len(envelope.Nonce) != 12 {
		return recoveryPayload{}, ErrRecoveryRejected
	}
	key := argon2.IDKey(passphrase, envelope.Salt, envelope.KDFIterations, envelope.KDFMemoryKiB, envelope.KDFParallelism, 32)
	defer zero(key)
	block, err := aes.NewCipher(key)
	if err != nil {
		return recoveryPayload{}, ErrRecoveryRejected
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return recoveryPayload{}, ErrRecoveryRejected
	}
	plain, err := aead.Open(nil, envelope.Nonce, envelope.Ciphertext, recoveryAAD(envelope.Salt, envelope.Nonce))
	if err != nil {
		return recoveryPayload{}, ErrRecoveryRejected
	}
	var payload recoveryPayload
	if decodeCanonical(plain, &payload, maxStateBytes) != nil || payload.Schema != recoverySchema || payload.CreatedAt <= 0 {
		return recoveryPayload{}, ErrRecoveryRejected
	}
	return payload, nil
}

func recoveryAAD(salt, nonce []byte) []byte {
	return []byte(fmt.Sprintf("%s|argon2id|%d|%d|%d|%x|%x", recoverySchema, recoveryMemoryKiB, recoveryIterations, recoveryParallelism, salt, nonce))
}

func stateMAC(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte(stateSchema))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}

func verifyStateMAC(key, payload, observed []byte) bool {
	expected := stateMAC(key, payload)
	return len(observed) == len(expected) && subtle.ConstantTimeCompare(observed, expected) == 1
}

func newRelayKey() (ed25519.PrivateKey, string, []byte, error) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, "", nil, err
	}
	return private, keyID("relay", public), append([]byte(nil), public...), nil
}

func zero(value []byte) {
	for index := range value {
		value[index] = 0
	}
}

func requireDistinctKeys(rootID, issuerID, relayID string) error {
	if rootID == "" || issuerID == "" || relayID == "" || rootID == issuerID || rootID == relayID || issuerID == relayID {
		return errors.New("selfhost: key identity collision")
	}
	return nil
}
