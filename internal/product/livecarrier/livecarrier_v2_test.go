// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package livecarrier

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
)

func TestResolveV2AuthorizesOnlyValidatedNetworkCarrier(t *testing.T) {
	policy := fixtureLiveCarrierPolicyV2(t)
	got, err := ResolveV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	if got.CarrierFamily != runtimepolicy.CarrierFamilyTLS13TCP || got.ALPN != "kurd/1" ||
		got.EndpointCount != len(policy.Endpoints) || !got.Networked {
		t.Fatalf("unexpected authority: %+v", got)
	}

	for _, mutate := range []func(*runtimepolicy.PolicyV2){
		func(p *runtimepolicy.PolicyV2) { p.CarrierFamily = "unknown" },
		func(p *runtimepolicy.PolicyV2) { p.WireProtocol = "unknown" },
		func(p *runtimepolicy.PolicyV2) { p.RelayAdmissionDigest[0] ^= 1 },
		func(p *runtimepolicy.PolicyV2) { p.Endpoints = nil },
	} {
		changed := policy.Clone()
		mutate(&changed)
		if authority, err := ResolveV2(changed); err == nil || authority != (LiveAuthorityV2{}) {
			t.Fatalf("invalid policy authorized: authority=%+v err=%v", authority, err)
		}
	}
}

func fixtureLiveCarrierPolicyV2(t testing.TB) runtimepolicy.PolicyV2 {
	t.Helper()
	legacy, err := compiler.Generate(71)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{
		Profile: legacy, ClientMandatoryFeatures: capabilities[:2], RelayMandatoryFeatures: capabilities[:2], SelectedFeatures: capabilities,
	})
	if err != nil {
		t.Fatal(err)
	}
	programBytes, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	clientPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	relayPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := fixtureLiveCarrierLeaf(t, "relay.example")
	policy := runtimepolicy.PolicyV2{
		SchemaVersion: runtimepolicy.SchemaVersionV2, WireProtocol: runtimepolicy.WireProtocolV1,
		CarrierFamily: runtimepolicy.CarrierFamilyTLS13TCP, LiveProgram: programBytes, LiveProgramSHA256: sha256.Sum256(programBytes),
		ClientAuthKeyID: liveCarrierClientKeyID(clientPublic), RelayAuthKeyID: liveCarrierRelayKeyID(relayPublic),
		TLSServerName: "relay.example", TLSLeafDER: leaf, TLSLeafSHA256: sha256.Sum256(leaf),
		Endpoints:  []runtimepolicy.EndpointV2{{Priority: 0, Address: []byte{198, 51, 100, 10}, Family: 4, Port: 443}},
		ClientIPv4: []byte{10, 77, 0, 2}, DNSIPv4: []byte{10, 77, 0, 1},
		Routes: []runtimepolicy.PrefixV2{{Address: []byte{0, 0, 0, 0}, PrefixLen: 0}}, DNSServers: [][]byte{{10, 77, 0, 1}}, MTU: 1280,
		AllowedIPModes:   []runtimepolicy.IPModeV2{runtimepolicy.IPModeIPv4Only},
		AllowedProtocols: []runtimepolicy.PayloadProtocolV2{runtimepolicy.PayloadProtocolTCP, runtimepolicy.PayloadProtocolUDP},
		Limits:           runtimepolicy.LimitsV2{MaxPackets: 1_000, MaxQueuedPackets: 100, MaxFrames: 1_000, MaxMessages: 1_000, MaxIdleSeconds: 30, MaxReconnectAttempts: 3},
		Fallback:         runtimepolicy.FallbackV2{EndpointIndexes: []uint8{0}, TotalAttempts: 3, AttemptTimeoutSeconds: 5, MaxBackoffSeconds: 10},
	}
	copy(policy.ClientAuthPublic[:], clientPublic)
	copy(policy.RelayAuthPublic[:], relayPublic)
	policy.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV2(policy)
	if err != nil {
		t.Fatal(err)
	}
	return policy
}

func fixtureLiveCarrierLeaf(t testing.TB, serverName string) []byte {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: serverName}, DNSNames: []string{serverName},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func liveCarrierClientKeyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return hex.EncodeToString(digest[:16])
}

func liveCarrierRelayKeyID(public ed25519.PublicKey) string {
	digest := sha256.Sum256(public)
	return "relay." + hex.EncodeToString(digest[:8])
}
