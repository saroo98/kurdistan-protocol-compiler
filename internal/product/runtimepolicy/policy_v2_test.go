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

func TestPolicyV2ValidationUsesExplicitTrustedTime(t *testing.T) {
	policy := fixturePolicyV2(t)
	leaf, err := x509.ParseCertificate(policy.TLSLeafDER)
	if err != nil {
		t.Fatal(err)
	}
	trustedTime := leaf.NotBefore.Add(time.Minute)
	encoded, err := EncodeV2At(policy, trustedTime)
	if err != nil {
		t.Fatalf("EncodeV2At trusted time: %v", err)
	}
	decoded, err := DecodeV2At(encoded, trustedTime)
	if err != nil {
		t.Fatalf("DecodeV2At trusted time: %v", err)
	}
	if err := decoded.ValidateAgainstEnvelopeAt(envelope.CanonicalProfileV1{Policy: bytes.Clone(encoded)}, trustedTime); err != nil {
		t.Fatalf("ValidateAgainstEnvelopeAt trusted time: %v", err)
	}
	if _, err := DecodeV2At(encoded, leaf.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("expired TLS leaf accepted at caller-controlled time")
	}
	if _, err := EncodeV2At(policy, time.Time{}); err == nil {
		t.Fatal("zero trusted time accepted")
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
		"relay key id":        func(p *PolicyV2) { p.RelayAuthKeyID = "relay-auth-v1" },
		"zero client key": func(p *PolicyV2) {
			p.ClientAuthPublic = [32]byte{}
			p.ClientAuthKeyID = keyID(p.ClientAuthPublic[:])
		},
		"zero relay key": func(p *PolicyV2) {
			p.RelayAuthPublic = [32]byte{}
			p.RelayAuthKeyID = relayKeyID(p.RelayAuthPublic)
		},
		"leaf digest":     func(p *PolicyV2) { p.TLSLeafSHA256[0] ^= 1 },
		"endpoint family": func(p *PolicyV2) { p.Endpoints[0].Family = 6 },
		"dns server":      func(p *PolicyV2) { p.DNSServers = [][]byte{{1, 1, 1, 1}} },
		"route":           func(p *PolicyV2) { p.Routes[0].PrefixLen = 1 },
		"mtu":             func(p *PolicyV2) { p.MTU = 1400 },
		"fallback index":  func(p *PolicyV2) { p.Fallback.EndpointIndexes = []uint8{2} },
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

func TestPolicyV2RejectsUnauthorizedAddressFamilyMaterial(t *testing.T) {
	dualStack := func(p *PolicyV2) {
		p.ClientIPv6 = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}
		p.DNSIPv6 = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
		p.Routes = append(p.Routes, PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
		p.DNSServers = append(p.DNSServers, bytes.Clone(p.DNSIPv6))
	}
	for name, mutate := range map[string]func(*PolicyV2){
		"dual-addresses-with-ipv4-only-mode": func(p *PolicyV2) { dualStack(p) },
		"ipv4-material-with-ipv6-only-mode": func(p *PolicyV2) {
			dualStack(p)
			p.AllowedIPModes = []IPModeV2{IPModeIPv6Only}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixturePolicyV2(t)
			mutate(&candidate)
			if err := validateModesAndProtocols(candidate.AllowedIPModes, candidate.AllowedProtocols, candidate.ClientIPv4, candidate.ClientIPv6); err == nil {
				t.Fatal("unauthorized address family material accepted")
			}
		})
	}
}

func TestPolicyV2RejectsDuplicateEndpointTarget(t *testing.T) {
	policy := fixturePolicyV2(t)
	duplicate := policy.Endpoints[0]
	duplicate.Priority++
	duplicate.Address = bytes.Clone(duplicate.Address)
	policy.Endpoints = append(policy.Endpoints, duplicate)
	if err := validatePolicy(policy, false); err == nil {
		t.Fatal("duplicate endpoint target with a different priority was accepted")
	}
}

func TestPolicyV2RejectsZeroAuthenticationKeys(t *testing.T) {
	for name, mutate := range map[string]func(*PolicyV2){
		"client": func(p *PolicyV2) {
			p.ClientAuthPublic = [32]byte{}
			p.ClientAuthKeyID = keyID(p.ClientAuthPublic[:])
		},
		"relay": func(p *PolicyV2) {
			p.RelayAuthPublic = [32]byte{}
			p.RelayAuthKeyID = relayKeyID(p.RelayAuthPublic)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixturePolicyV2(t)
			mutate(&candidate)
			if err := validatePolicy(candidate, false); err == nil {
				t.Fatal("zero authentication key accepted")
			}
		})
	}
}

func TestPolicyV2AcceptsPhase16RelayIdentityV1(t *testing.T) {
	public := [32]byte{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31}
	const phase16RelayID = "relay.630dcd2966c43366"
	if !relayKeyIDMatches(phase16RelayID, public) {
		t.Fatal("Phase16 relay identity vector rejected")
	}
	if relayKeyIDMatches("relay.630dcd2966c43367", public) {
		t.Fatal("mismatched relay identity accepted")
	}
}

func TestPolicyV2TLSRequiresExactSAN(t *testing.T) {
	wildcard := fixtureLeafDERWithDNSNames(t, "relay.example", []string{"*.example"})
	if err := validateTLS("relay.example", wildcard, sha256.Sum256(wildcard)); err == nil {
		t.Fatal("wildcard-only TLS SAN accepted")
	}
	exact := fixtureLeafDERWithDNSNames(t, "relay.example", []string{"relay.example"})
	if err := validateTLS("relay.example", exact, sha256.Sum256(exact)); err != nil {
		t.Fatalf("exact TLS SAN rejected: %v", err)
	}
}

func TestPolicyV2TLSAcceptsNonCASelfSignedLeafAndRejectsForgery(t *testing.T) {
	nonCA := fixtureLeafDERWithOptions(t, "relay.example", []string{"relay.example"}, false)
	if err := validateTLS("relay.example", nonCA, sha256.Sum256(nonCA)); err != nil {
		t.Fatalf("non-CA self-signed TLS leaf rejected: %v", err)
	}
	forged := bytes.Clone(nonCA)
	forged[len(forged)-1] ^= 1
	if err := validateTLS("relay.example", forged, sha256.Sum256(forged)); err == nil {
		t.Fatal("forged TLS leaf accepted")
	}
	anyUsage := fixtureLeafDERWithUsage(t, "relay.example", []string{"relay.example"}, []x509.ExtKeyUsage{x509.ExtKeyUsageAny})
	if err := validateTLS("relay.example", anyUsage, sha256.Sum256(anyUsage)); err == nil {
		t.Fatal("TLS leaf with only ExtKeyUsageAny accepted")
	}
}

func TestPolicyV2RejectsIPv4MappedIPv6AddressMaterial(t *testing.T) {
	mapped := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 198, 51, 100, 10}
	if validAddress(mapped, 6) {
		t.Fatal("IPv4-mapped IPv6 accepted as a valid IPv6 address")
	}
	for name, mutate := range map[string]func(*PolicyV2){
		"endpoint": func(p *PolicyV2) {
			p.Endpoints = append(p.Endpoints, EndpointV2{Priority: 1, Address: bytes.Clone(mapped), Family: 6, Port: 443})
		},
		"client": func(p *PolicyV2) {
			p.ClientIPv6, p.DNSIPv6 = bytes.Clone(mapped), []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
			p.Routes = append(p.Routes, PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
			p.DNSServers = append(p.DNSServers, bytes.Clone(p.DNSIPv6))
		},
		"dns": func(p *PolicyV2) {
			p.ClientIPv6, p.DNSIPv6 = []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2}, bytes.Clone(mapped)
			p.Routes = append(p.Routes, PrefixV2{Address: make([]byte, 16), PrefixLen: 0})
			p.DNSServers = append(p.DNSServers, bytes.Clone(p.DNSIPv6))
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidate := fixturePolicyV2(t)
			mutate(&candidate)
			if err := validateAddresses(candidate); err == nil {
				t.Fatal("IPv4-mapped IPv6 policy material accepted")
			}
		})
	}
}

func TestPolicyV2LimitsAndFallbackHonorLiveDataPlaneCeilings(t *testing.T) {
	policy := fixturePolicyV2(t)
	program, err := liveprogram.DecodeV1(policy.LiveProgram)
	if err != nil {
		t.Fatal(err)
	}
	for name, test := range map[string]struct {
		mutate    func(*LimitsV2)
		wantError bool
	}{
		"queued-packets-boundary":       {func(l *LimitsV2) { l.MaxQueuedPackets = 256 }, false},
		"queued-packets-one-over":       {func(l *LimitsV2) { l.MaxQueuedPackets = 257 }, true},
		"reconnect-boundary":            {func(l *LimitsV2) { l.MaxReconnectAttempts = 5 }, false},
		"reconnect-one-over":            {func(l *LimitsV2) { l.MaxReconnectAttempts = 6 }, true},
		"frames-wider-than-messages":    {func(l *LimitsV2) { l.MaxMessages = 999 }, true},
		"packets-wider-than-frames":     {func(l *LimitsV2) { l.MaxPackets = 1_001 }, true},
		"queued-packets-wider-than-max": {func(l *LimitsV2) { l.MaxPackets = 255; l.MaxQueuedPackets = 256 }, true},
	} {
		t.Run(name, func(t *testing.T) {
			limits := policy.Limits
			test.mutate(&limits)
			got := validateLimits(limits, program)
			if (got != nil) != test.wantError {
				t.Fatalf("validateLimits error=%v wantError=%t", got, test.wantError)
			}
		})
	}
	for name, mutate := range map[string]func(*FallbackV2){
		"backoff-boundary":     func(f *FallbackV2) { f.MaxBackoffSeconds = 30 },
		"backoff-one-over":     func(f *FallbackV2) { f.MaxBackoffSeconds = 31 },
		"attempts-cross-field": func(f *FallbackV2) { f.TotalAttempts = policy.Limits.MaxReconnectAttempts + 1 },
		"attempts-at-limit":    func(f *FallbackV2) { f.TotalAttempts = policy.Limits.MaxReconnectAttempts },
	} {
		t.Run(name, func(t *testing.T) {
			fallback := policy.Fallback
			mutate(&fallback)
			got := validateFallback(fallback, len(policy.Endpoints), policy.Limits.MaxReconnectAttempts)
			wantError := name == "backoff-one-over" || name == "attempts-cross-field"
			if (got != nil) != wantError {
				t.Fatalf("validateFallback error=%v wantError=%t", got, wantError)
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
		ClientAuthKeyID: keyID(clientPublic), RelayAuthKeyID: relayKeyID([32]byte(relayPublic)), TLSServerName: "relay.example", TLSLeafDER: leaf, TLSLeafSHA256: sha256.Sum256(leaf),
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

func relayKeyID(public [32]byte) string {
	digest := sha256.Sum256(public[:])
	return "relay." + hex.EncodeToString(digest[:8])
}

func fixtureLeafDER(t testing.TB, serverName string) []byte {
	return fixtureLeafDERWithDNSNames(t, serverName, []string{serverName})
}

func fixtureLeafDERWithDNSNames(t testing.TB, commonName string, dnsNames []string) []byte {
	return fixtureLeafDERWithOptions(t, commonName, dnsNames, true)
}

func fixtureLeafDERWithOptions(t testing.TB, commonName string, dnsNames []string, isCA bool) []byte {
	return fixtureLeafDERWithUsage(t, commonName, dnsNames, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, isCA)
}

func fixtureLeafDERWithUsage(t testing.TB, commonName string, dnsNames []string, usages []x509.ExtKeyUsage, isCA ...bool) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	certificateAuthority := len(isCA) != 0 && isCA[0]
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: commonName}, DNSNames: dnsNames, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, BasicConstraintsValid: true, IsCA: certificateAuthority}
	if certificateAuthority {
		template.KeyUsage |= x509.KeyUsageCertSign
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}
