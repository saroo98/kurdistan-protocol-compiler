// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimepolicy

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func TestPolicyV2RoundTripAndDefensiveClone(t *testing.T) {
	policy := fixturePolicyV2(t)
	encoded, err := EncodeV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := DecodeV2(encoded)
	if err != nil {
		t.Fatal(err)
	}
	reencoded, err := EncodeV2(decoded)
	if err != nil || !bytes.Equal(encoded, reencoded) {
		t.Fatalf("policy round trip changed bytes: err=%v", err)
	}
	clone := decoded.Clone()
	clone.LiveProgram[0] ^= 1
	clone.Endpoints[0].Address[0] ^= 1
	clone.DNSServers[0][0] ^= 1
	if bytes.Equal(clone.LiveProgram, decoded.LiveProgram) || bytes.Equal(clone.Endpoints[0].Address, decoded.Endpoints[0].Address) || bytes.Equal(clone.DNSServers[0], decoded.DNSServers[0]) {
		t.Fatal("policy clone aliases mutable data")
	}
	profile := envelope.CanonicalProfileV1{Policy: bytes.Clone(encoded)}
	if err := decoded.ValidateAgainstEnvelope(profile); err != nil {
		t.Fatal(err)
	}
	profile.Policy[0] ^= 1
	if err := decoded.ValidateAgainstEnvelope(profile); err == nil {
		t.Fatal("mismatched outer policy accepted")
	}
}

func TestPolicyV2RejectsCanonicalAndCrossBindingViolations(t *testing.T) {
	policy := fixturePolicyV2(t)
	encoded, err := EncodeV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string][]byte{
		"duplicate key":     {0xa2, 0x01, 0x02, 0x01, 0x02},
		"indefinite map":    {0xbf, 0x01, 0x02, 0xff},
		"nonminimal number": {0xa1, 0x18, 0x01, 0x02},
		"tag":               {0xc1, 0xa0},
		"trailing bytes":    append(bytes.Clone(encoded), 0),
	} {
		if _, err := DecodeV2(encoded); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}

	mutations := map[string]func(*PolicyV2){
		"live program digest": func(p *PolicyV2) { p.LiveProgramSHA256[0] ^= 1 },
		"client key id":       func(p *PolicyV2) { p.ClientAuthKeyID = "00000000000000000000000000000000" },
		"leaf digest":         func(p *PolicyV2) { p.TLSLeafSHA256[0] ^= 1 },
		"endpoint family":     func(p *PolicyV2) { p.Endpoints[0].Family = 6 },
		"dns server":          func(p *PolicyV2) { p.DNSServers = [][]byte{{1, 1, 1, 1}} },
		"route":               func(p *PolicyV2) { p.Routes[0].PrefixLen = 1 },
		"mtu":                 func(p *PolicyV2) { p.MTU = 1400 },
		"fallback index":      func(p *PolicyV2) { p.Fallback.EndpointIndexes = []uint8{2} },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			changed := policy.Clone()
			mutate(&changed)
			if _, err := EncodeV2(changed); err == nil {
				t.Fatal("cross-bound field mutation accepted")
			}
		})
	}
}

func TestPolicyV2AdmissionDigestBindsEveryAdmissionField(t *testing.T) {
	policy := fixturePolicyV2(t)
	changes := []func(*PolicyV2){
		func(p *PolicyV2) { p.Endpoints[0].Port++ },
		func(p *PolicyV2) { p.ClientAuthPublic[0] ^= 1 },
		func(p *PolicyV2) { p.TLSLeafDER[0] ^= 1 },
		func(p *PolicyV2) { p.LiveProgram[0] ^= 1 },
		func(p *PolicyV2) { p.Routes[0].PrefixLen = 1 },
		func(p *PolicyV2) { p.DNSIPv4[0] ^= 1 },
		func(p *PolicyV2) { p.MTU = 1400 },
		func(p *PolicyV2) { p.Limits.MaxPackets++ },
		func(p *PolicyV2) { p.Fallback.TotalAttempts++ },
	}
	for i, mutate := range changes {
		changed := policy.Clone()
		mutate(&changed)
		digest, err := RelayAdmissionDigestV2(changed)
		if err == nil && digest == policy.RelayAdmissionDigest {
			t.Fatalf("mutation %d did not alter or invalidate admission digest: %v", i, err)
		}
	}
}

func fixturePolicyV2(t testing.TB) PolicyV2 {
	t.Helper()
	legacy, err := compiler.Generate(71)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{Profile: legacy, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities})
	if err != nil {
		t.Fatal(err)
	}
	programBytes, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	_, clientPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, relayPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic := clientPrivate.Public().(ed25519.PublicKey)
	relayPublic := relayPrivate.Public().(ed25519.PublicKey)
	leaf := fixtureLeafDER(t, "relay.example")
	policy := PolicyV2{
		SchemaVersion: 2, WireProtocol: "kurd-wire-v1", CarrierFamily: "tls13-tcp", LiveProgram: programBytes, LiveProgramSHA256: sha256.Sum256(programBytes),
		ClientAuthKeyID: keyID(clientPublic), RelayAuthKeyID: "relay-auth-v1", TLSServerName: "relay.example", TLSLeafDER: leaf, TLSLeafSHA256: sha256.Sum256(leaf),
		Endpoints:  []EndpointV2{{Priority: 0, Address: []byte{198, 51, 100, 10}, Family: 4, Port: 443}},
		ClientIPv4: []byte{10, 77, 0, 2}, DNSIPv4: []byte{10, 77, 0, 1}, Routes: []PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DNSServers: [][]byte{{10, 77, 0, 1}}, MTU: 1280,
		AllowedIPModes: []IPModeV2{IPModeIPv4Only}, AllowedProtocols: []PayloadProtocolV2{PayloadProtocolTCP, PayloadProtocolUDP},
		Limits:   LimitsV2{MaxPackets: 1_000, MaxQueuedPackets: 100, MaxFrames: 1_000, MaxMessages: 1_000, MaxIdleSeconds: 30, MaxReconnectAttempts: 3},
		Fallback: FallbackV2{EndpointIndexes: []uint8{0}, TotalAttempts: 3, AttemptTimeoutSeconds: 5, MaxBackoffSeconds: 10},
	}
	copy(policy.ClientAuthPublic[:], clientPublic)
	copy(policy.RelayAuthPublic[:], relayPublic)
	digest, err := RelayAdmissionDigestV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	policy.RelayAdmissionDigest = digest
	return policy
}

func keyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

func fixtureLeafDER(t testing.TB, serverName string) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true, IsCA: true}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
