// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package phase8issuance contains deterministic test-only cryptographic
// providers. Production commands and product packages must never import it.
package phase8issuance

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hkdf"
	"crypto/hmac"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math/big"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

var testOnlySeed = []byte("WO-806 deterministic TEST ONLY standard cryptography seed")

type Issuer struct {
	key        *ecdsa.PrivateKey
	operations int
}
type IndependentVerifier struct {
	key        *ecdsa.PublicKey
	operations int
}
type RecipientSealer struct {
	key                  hpke.PublicKey
	operations, bindings int
}
type IndependentRecipientOpener struct {
	key                  hpke.PrivateKey
	operations, bindings int
}
type Resolver struct {
	binding profile.RecipientBinding
	wrong   bool
}

func NewIssuer() *Issuer { key := deriveECDSAKey(); return &Issuer{key: key} }
func NewIndependentVerifier() *IndependentVerifier {
	key := deriveECDSAKey()
	public := key.PublicKey
	return &IndependentVerifier{key: &public}
}
func NewRecipientSealer() *RecipientSealer {
	key := deriveHPKEKey()
	return &RecipientSealer{key: key.PublicKey()}
}
func NewIndependentRecipientOpener() *IndependentRecipientOpener {
	return &IndependentRecipientOpener{key: deriveHPKEKey()}
}
func NewResolver(class envelope.ArtifactClass) *Resolver {
	spec := ValidSpec(class)
	var binding profile.RecipientBinding
	if spec.Recipient != nil {
		binding = *spec.Recipient
	}
	return &Resolver{binding: binding}
}
func (p *Issuer) Operations() int                             { return p.operations }
func (p *IndependentVerifier) Operations() int                { return p.operations }
func (p *RecipientSealer) Phase8BindingsUsed() int            { return p.bindings }
func (p *IndependentRecipientOpener) Phase8BindingsUsed() int { return p.bindings }
func (r *Resolver) UseWrongRecipient(v bool)                  { r.wrong = v }

func (p *Issuer) Sign(key profile.KeyReference, message []byte) ([]byte, error) {
	p.operations++
	digest := sha256.Sum256(message)
	r, s := signRFC6979(p.key, digest[:])
	half := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Cmp(half) > 0 {
		s.Sub(elliptic.P256().Params().N, s)
	}
	raw := make([]byte, 64)
	r.FillBytes(raw[:32])
	s.FillBytes(raw[32:])
	return raw, nil
}
func (p *IndependentVerifier) Verify(_ profile.KeyReference, message, signature []byte) error {
	p.operations++
	if len(signature) != 64 {
		return errors.New("test verifier: signature length")
	}
	r, s := new(big.Int).SetBytes(signature[:32]), new(big.Int).SetBytes(signature[32:])
	half := new(big.Int).Rsh(new(big.Int).Set(elliptic.P256().Params().N), 1)
	if s.Sign() <= 0 || s.Cmp(half) > 0 {
		return errors.New("test verifier: non-low-S")
	}
	digest := sha256.Sum256(message)
	if !ecdsa.Verify(p.key, digest[:], r, s) {
		return errors.New("test verifier: signature")
	}
	return nil
}

func (p *RecipientSealer) SealOffline(binding profile.RecipientBinding, outer, plaintext []byte) ([]byte, []byte, error) {
	p.operations++
	info, err := envelope.BuildHPKEInfo(outer)
	if err != nil {
		return nil, nil, err
	}
	aad, err := envelope.BuildHPKEAAD(outer)
	if err != nil {
		return nil, nil, err
	}
	p.bindings++
	return deterministicHPKESeal(p.key.Bytes(), info, append(aad, []byte(binding.Hint)...), plaintext, outer)
}
func (p *IndependentRecipientOpener) OpenOffline(binding profile.RecipientBinding, outer, enc, ciphertext []byte) ([]byte, error) {
	p.operations++
	info, err := envelope.BuildHPKEInfo(outer)
	if err != nil {
		return nil, err
	}
	aad, err := envelope.BuildHPKEAAD(outer)
	if err != nil {
		return nil, err
	}
	p.bindings++
	recipient, err := hpke.NewRecipient(enc, p.key, hpke.HKDFSHA256(), hpke.AES256GCM(), info)
	if err != nil {
		return nil, err
	}
	return recipient.Open(append(aad, []byte(binding.Hint)...), ciphertext)
}
func (r *Resolver) ResolveRecipient(class envelope.ArtifactClass, hint string) (profile.RecipientBinding, error) {
	if r.wrong {
		return profile.RecipientBinding{}, errors.New("test resolver: wrong recipient")
	}
	if r.binding.Class != class || r.binding.Hint != hint {
		return profile.RecipientBinding{}, errors.New("test resolver: not found")
	}
	return r.binding, nil
}

func signRFC6979(key *ecdsa.PrivateKey, digest []byte) (*big.Int, *big.Int) {
	n := key.Params().N
	x := key.D.FillBytes(make([]byte, 32))
	h := new(big.Int).SetBytes(digest)
	h.Mod(h, n)
	h1 := h.FillBytes(make([]byte, 32))
	v := make([]byte, 32)
	for i := range v {
		v[i] = 1
	}
	k := make([]byte, 32)
	k = hmacSHA256(k, v, []byte{0}, x, h1)
	v = hmacSHA256(k, v)
	k = hmacSHA256(k, v, []byte{1}, x, h1)
	v = hmacSHA256(k, v)
	for {
		v = hmacSHA256(k, v)
		nonce := new(big.Int).SetBytes(v)
		if nonce.Sign() > 0 && nonce.Cmp(n) < 0 {
			x1, _ := key.Curve.ScalarBaseMult(nonce.Bytes())
			r := new(big.Int).Mod(x1, n)
			if r.Sign() != 0 {
				s := new(big.Int).Mul(r, key.D)
				s.Add(s, h)
				s.Mul(s, new(big.Int).ModInverse(nonce, n))
				s.Mod(s, n)
				if s.Sign() != 0 {
					return r, s
				}
			}
		}
		k = hmacSHA256(k, v, []byte{0})
		v = hmacSHA256(k, v)
	}
}

func hmacSHA256(key []byte, chunks ...[]byte) []byte {
	mac := hmac.New(sha256.New, key)
	for _, chunk := range chunks {
		_, _ = mac.Write(chunk)
	}
	return mac.Sum(nil)
}

func deterministicHPKESeal(recipientPublic, info, aad, plaintext, context []byte) ([]byte, []byte, error) {
	curve := ecdh.P256()
	pkR, err := curve.NewPublicKey(recipientPublic)
	if err != nil {
		return nil, nil, err
	}
	n := elliptic.P256().Params().N
	d := new(big.Int).SetBytes(hash(testOnlySeed, "hpke-ephemeral:"+hex.EncodeToString(context)))
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	skE, err := curve.NewPrivateKey(d.FillBytes(make([]byte, 32)))
	if err != nil {
		return nil, nil, err
	}
	enc := skE.PublicKey().Bytes()
	dh, err := skE.ECDH(pkR)
	if err != nil {
		return nil, nil, err
	}
	kemSuite := append([]byte("KEM"), uint16Bytes(0x0010)...)
	eaePRK := labeledExtract(kemSuite, nil, "eae_prk", dh)
	sharedSecret, err := labeledExpand(kemSuite, eaePRK, "shared_secret", append(append([]byte{}, enc...), recipientPublic...), 32)
	if err != nil {
		return nil, nil, err
	}
	suite := append([]byte("HPKE"), uint16Bytes(0x0010)...)
	suite = append(suite, uint16Bytes(0x0001)...)
	suite = append(suite, uint16Bytes(0x0002)...)
	pskIDHash := labeledExtract(suite, nil, "psk_id_hash", nil)
	infoHash := labeledExtract(suite, nil, "info_hash", info)
	ksContext := append([]byte{0}, pskIDHash...)
	ksContext = append(ksContext, infoHash...)
	secret := labeledExtract(suite, sharedSecret, "secret", nil)
	key, err := labeledExpand(suite, secret, "key", ksContext, 32)
	if err != nil {
		return nil, nil, err
	}
	nonce, err := labeledExpand(suite, secret, "base_nonce", ksContext, 12)
	if err != nil {
		return nil, nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, nil, err
	}
	return enc, aead.Seal(nil, nonce, plaintext, aad), nil
}

func labeledExtract(suite, salt []byte, label string, ikm []byte) []byte {
	labeledIKM := append([]byte("HPKE-v1"), suite...)
	labeledIKM = append(labeledIKM, label...)
	labeledIKM = append(labeledIKM, ikm...)
	out, err := hkdf.Extract(sha256.New, labeledIKM, salt)
	if err != nil {
		panic(err)
	}
	return out
}

func labeledExpand(suite, prk []byte, label string, info []byte, length uint16) ([]byte, error) {
	labeledInfo := append(uint16Bytes(length), []byte("HPKE-v1")...)
	labeledInfo = append(labeledInfo, suite...)
	labeledInfo = append(labeledInfo, label...)
	labeledInfo = append(labeledInfo, info...)
	return hkdf.Expand(sha256.New, prk, string(labeledInfo), int(length))
}

func uint16Bytes(value uint16) []byte {
	var raw [2]byte
	binary.BigEndian.PutUint16(raw[:], value)
	return raw[:]
}
func deriveECDSAKey() *ecdsa.PrivateKey {
	d := new(big.Int).SetBytes(hash(testOnlySeed, "ecdsa"))
	n := elliptic.P256().Params().N
	d.Mod(d, new(big.Int).Sub(n, big.NewInt(1)))
	d.Add(d, big.NewInt(1))
	x, y := elliptic.P256().ScalarBaseMult(d.Bytes())
	return &ecdsa.PrivateKey{PublicKey: ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, D: d}
}
func deriveHPKEKey() hpke.PrivateKey {
	key, err := hpke.DHKEM(ecdh.P256()).DeriveKeyPair(hash(testOnlySeed, "hpke"))
	if err != nil {
		panic(err)
	}
	return key
}
func hash(seed []byte, label string) []byte {
	sum := sha256.Sum256(append(append([]byte{}, seed...), []byte(label)...))
	return sum[:]
}

func ValidSpec(class envelope.ArtifactClass) profile.OfflineIssuanceSpec {
	audience := envelope.AudiencePublic
	var recipient *profile.RecipientBinding
	if class != envelope.ArtifactSignedPublic {
		switch class {
		case envelope.ArtifactProviderGroup:
			audience = envelope.AudienceProvisionedGroup
		case envelope.ArtifactDeviceRecipient:
			audience = envelope.AudienceProvisionedDevice
		case envelope.ArtifactEncryptedBackup:
			audience = envelope.AudienceProvisionedBackupKey
		}
		binding := profile.RecipientBinding{Class: class, ProviderID: "provider.0001", LineageID: "lineage.0001", ProfileNamespace: "profiles.", Hint: "recipient-hint-0001", KeyID: "recipient-key-0001", Epoch: 2}
		recipient = &binding
	}
	return profile.OfflineIssuanceSpec{Profile: envelope.CanonicalProfileV1{ContentID: "content.0001", ProfileID: "profiles.one", LineageID: "lineage.0001", ProviderID: "provider.0001", ContractVersion: "product-profile-admission-v1", RevocationScope: "revocation.0001", SnapshotMode: "full-snapshot", UpdateKind: "initial", Generation: 7, RequiredSafetyFloor: 2, ValidFrom: 100, ValidUntil: 1000, RootEpoch: 3, RevocationEpoch: 4, RelayIDs: []string{"relay.0001"}, StrategyIDs: []string{"strategy.0001"}, Policy: []byte{0xa1, 0x01, 0x01}}, Class: class, Audience: audience, Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer, IssuerScope: profile.AuthorityScope{ProviderID: "provider.0001", LineageID: "lineage.0001", ProfileNamespace: "profiles."}, IssuerKey: profile.KeyReference{KeyID: "issuer-key-0001", SuiteID: uint16(envelope.SuiteClassicalV1)}, Recipient: recipient, MinimumGeneration: 7, Now: 500}
}
