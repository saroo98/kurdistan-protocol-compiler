// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	tlsMaximumLifetime = 90 * 24 * time.Hour
	tlsProfileMargin   = 24 * time.Hour
)

type openedTLSSeed struct{ seed []byte }

func (opened *openedTLSSeed) Bytes() []byte {
	if opened == nil {
		return nil
	}
	return append([]byte(nil), opened.seed...)
}

func (opened *openedTLSSeed) Close() {
	if opened == nil {
		return
	}
	zero(opened.seed)
	opened.seed = nil
}

func newTLSIdentity(master []byte, deploymentID, san string, epoch uint64, now time.Time) (tlsIdentityV1, error) {
	return newTLSIdentityWithRandom(master, deploymentID, san, epoch, now, rand.Reader)
}

func newTLSIdentityWithRandom(master []byte, deploymentID, san string, epoch uint64, now time.Time, random io.Reader) (tlsIdentityV1, error) {
	canonicalSAN, ip, err := canonicalTLSName(san)
	if err != nil || len(master) != 32 || !validID(deploymentID) || epoch == 0 || now.IsZero() || random == nil {
		return tlsIdentityV1{}, ErrInvalidInput
	}
	seed := make([]byte, ed25519.SeedSize)
	if _, err := io.ReadFull(random, seed); err != nil {
		zero(seed)
		return tlsIdentityV1{}, err
	}
	defer zero(seed)
	private := ed25519.NewKeyFromSeed(seed)
	public := private.Public().(ed25519.PublicKey)
	serial := make([]byte, 16)
	if _, err := io.ReadFull(random, serial); err != nil {
		zero(private)
		return tlsIdentityV1{}, err
	}
	serial[0] &= 0x7f
	if bytes.Equal(serial, make([]byte, len(serial))) {
		serial[len(serial)-1] = 1
	}
	serialNumber := new(big.Int).SetBytes(serial)
	serial = append([]byte(nil), serialNumber.Bytes()...)
	notBefore := now.UTC().Add(-5 * time.Minute).Truncate(time.Second)
	notAfter := notBefore.Add(tlsMaximumLifetime)
	template := &x509.Certificate{
		SerialNumber:          serialNumber,
		Subject:               pkix.Name{},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	if ip.IsValid() {
		template.IPAddresses = []net.IP{append([]byte(nil), ip.AsSlice()...)}
	} else {
		template.DNSNames = []string{canonicalSAN}
	}
	der, err := x509.CreateCertificate(random, template, template, public, private)
	zero(private)
	if err != nil {
		return tlsIdentityV1{}, err
	}
	digest := sha256.Sum256(der)
	identity := tlsIdentityV1{
		Epoch: epoch, KeyID: keyID("tls", public), Serial: append([]byte(nil), serial...),
		NotBefore: notBefore.Unix(), NotAfter: notAfter.Unix(), SAN: canonicalSAN,
		LeafDER: append([]byte(nil), der...), LeafDigest: append([]byte(nil), digest[:]...),
	}
	aad, err := tlsSeedAAD(deploymentID, identity)
	if err != nil {
		return tlsIdentityV1{}, err
	}
	identity.SealedSeed, err = sealWithKey(master, seed, aad)
	if err != nil {
		return tlsIdentityV1{}, err
	}
	if err := validateTLSIdentity(master, deploymentID, identity, nil); err != nil {
		return tlsIdentityV1{}, err
	}
	return identity, nil
}

func validateTLSIdentity(master []byte, deploymentID string, identity tlsIdentityV1, relayPublic []byte) error {
	if identity.Epoch == 0 || !validID(identity.KeyID) || len(identity.Serial) == 0 || len(identity.Serial) > 20 || identity.Serial[0]&0x80 != 0 ||
		identity.NotBefore <= 0 || identity.NotAfter <= identity.NotBefore || time.Duration(identity.NotAfter-identity.NotBefore)*time.Second > tlsMaximumLifetime ||
		len(identity.LeafDER) == 0 || len(identity.LeafDigest) != sha256.Size || len(master) != 32 {
		return ErrStateCorrupt
	}
	canonicalSAN, ip, err := canonicalTLSName(identity.SAN)
	if err != nil || canonicalSAN != identity.SAN {
		return ErrStateCorrupt
	}
	digest := sha256.Sum256(identity.LeafDER)
	if !bytes.Equal(digest[:], identity.LeafDigest) {
		return ErrStateCorrupt
	}
	certificate, err := x509.ParseCertificate(identity.LeafDER)
	if err != nil || certificate.PublicKeyAlgorithm != x509.Ed25519 || certificate.SignatureAlgorithm != x509.PureEd25519 ||
		certificate.SerialNumber.Sign() <= 0 || !bytes.Equal(certificate.SerialNumber.Bytes(), identity.Serial) ||
		certificate.NotBefore.Unix() != identity.NotBefore || certificate.NotAfter.Unix() != identity.NotAfter ||
		certificate.KeyUsage != x509.KeyUsageDigitalSignature || !certificate.BasicConstraintsValid || certificate.IsCA ||
		len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth || len(certificate.UnhandledCriticalExtensions) != 0 {
		return ErrStateCorrupt
	}
	if ip.IsValid() {
		if len(certificate.IPAddresses) != 1 || len(certificate.DNSNames) != 0 || !certificate.IPAddresses[0].Equal(net.IP(ip.AsSlice())) {
			return ErrStateCorrupt
		}
	} else if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != canonicalSAN || len(certificate.IPAddresses) != 0 {
		return ErrStateCorrupt
	}
	if certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) != nil || certificate.VerifyHostname(canonicalSAN) != nil {
		return ErrStateCorrupt
	}
	public, ok := certificate.PublicKey.(ed25519.PublicKey)
	if !ok || identity.KeyID != keyID("tls", public) || bytes.Equal(public, relayPublic) {
		return ErrStateCorrupt
	}
	aad, err := tlsSeedAAD(deploymentID, identity)
	if err != nil {
		return ErrStateCorrupt
	}
	seed, err := openWithKey(master, identity.SealedSeed, aad)
	if err != nil || len(seed) != ed25519.SeedSize {
		zero(seed)
		return ErrStateCorrupt
	}
	defer zero(seed)
	derived := ed25519.NewKeyFromSeed(seed)
	defer zero(derived)
	if !bytes.Equal(derived.Public().(ed25519.PublicKey), public) {
		return ErrStateCorrupt
	}
	return nil
}

func openTLSSeed(master []byte, deploymentID string, identity tlsIdentityV1) (*openedTLSSeed, error) {
	aad, err := tlsSeedAAD(deploymentID, identity)
	if err != nil {
		return nil, err
	}
	seed, err := openWithKey(master, identity.SealedSeed, aad)
	if err != nil || len(seed) != ed25519.SeedSize {
		zero(seed)
		return nil, ErrStateCorrupt
	}
	return &openedTLSSeed{seed: seed}, nil
}

func validateTLSReady(identity tlsIdentityV1, now time.Time) error {
	unix := now.UTC().Unix()
	if now.IsZero() || unix < identity.NotBefore || unix >= identity.NotAfter {
		return ErrTLSUnavailable
	}
	return nil
}

func validateProfileTLSLifetime(identity tlsIdentityV1, validFrom, validUntil int64) error {
	if validFrom < identity.NotBefore || validUntil <= validFrom || validUntil > identity.NotAfter-int64(tlsProfileMargin/time.Second) {
		return ErrTLSUnavailable
	}
	return nil
}

func tlsSeedAAD(deploymentID string, identity tlsIdentityV1) ([]byte, error) {
	value, err := encodeCanonical(map[uint64]any{
		1: deploymentID, 2: identity.Epoch, 3: append([]byte(nil), identity.Serial...), 4: append([]byte(nil), identity.LeafDigest...),
	})
	if err != nil {
		return nil, err
	}
	return append([]byte("kurd-selfhost/tls-seed/v1\x00"), value...), nil
}

func canonicalTLSName(value string) (string, netip.Addr, error) {
	if value == "" || value != strings.TrimSpace(value) || strings.Contains(value, "*") {
		return "", netip.Addr{}, ErrInvalidInput
	}
	if address, err := netip.ParseAddr(value); err == nil {
		if address.Is4In6() {
			return "", netip.Addr{}, ErrInvalidInput
		}
		return address.String(), address, nil
	}
	lower := strings.ToLower(value)
	if lower != value || !validDNSName(lower) {
		return "", netip.Addr{}, ErrInvalidInput
	}
	return lower, netip.Addr{}, nil
}

func validDNSName(value string) bool {
	if value == "" || len(value) > 253 || strings.Contains(value, "*") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character == '-' || character >= 'a' && character <= 'z' || character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func tlsIdentityDigest(identity tlsIdentityV1) string {
	return hex.EncodeToString(identity.LeafDigest)
}
