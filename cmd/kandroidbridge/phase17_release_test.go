// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	"kurdistan/internal/protocol/liveprogram"
	"kurdistan/internal/protocol/liveprogramcompile"
	"kurdistan/internal/selfhost"
	"kurdistan/internal/transport/tlstcp"
)

func TestReleaseTLSClientConfigPinsExactLeafAndProtocol(t *testing.T) {
	policy, seed, now := releasePolicyFixture(t)
	defer clear(seed)
	config, err := releaseTLSClientConfig(policy, now)
	if err != nil {
		t.Fatal(err)
	}
	if config.MinVersion != tls.VersionTLS13 || config.MaxVersion != tls.VersionTLS13 ||
		config.ServerName != policy.TLSServerName || !config.SessionTicketsDisabled ||
		config.ClientSessionCache != nil || config.InsecureSkipVerify ||
		len(config.NextProtos) != 1 || config.NextProtos[0] != tlstcp.ALPN {
		t.Fatalf("unsafe release TLS config: %+v", config)
	}
	leaf, err := x509.ParseCertificate(policy.TLSLeafDER)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots: config.RootCAs, DNSName: policy.TLSServerName, CurrentTime: now,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err != nil {
		t.Fatalf("exact authorized leaf was not trusted: %v", err)
	}
	if _, err := releaseTLSClientConfig(policy, leaf.NotAfter.Add(time.Second)); err == nil {
		t.Fatal("expired release TLS leaf was accepted")
	}
}

func TestReleaseClientSeedMustMatchSignedPolicy(t *testing.T) {
	policy, seed, _ := releasePolicyFixture(t)
	defer clear(seed)
	if !releaseClientSeedMatchesPolicy(seed, policy) {
		t.Fatal("matching client seed was rejected")
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	wrongSeed := bytes.Clone(wrongPrivate.Seed())
	clear(wrongPrivate)
	defer clear(wrongSeed)
	if releaseClientSeedMatchesPolicy(wrongSeed, policy) {
		t.Fatal("wrong client seed was accepted")
	}
}

func TestClearRuntimePolicyV2WipesRetainedByteMaterial(t *testing.T) {
	policy, seed, _ := releasePolicyFixture(t)
	defer clear(seed)
	program := policy.LiveProgram
	leaf := policy.TLSLeafDER
	endpoint := policy.Endpoints[0].Address
	clearRuntimePolicyV2(&policy)
	if !reflect.DeepEqual(policy, runtimepolicy.PolicyV2{}) || !allZeroBytes(program) || !allZeroBytes(leaf) || !allZeroBytes(endpoint) {
		t.Fatal("release policy byte material was retained")
	}
}

func releasePolicyFixture(t testing.TB) (runtimepolicy.PolicyV2, []byte, time.Time) {
	t.Helper()
	directory := t.TempDir()
	dataDir := filepath.Join(directory, "node")
	recovery := filepath.Join(directory, "recovery.kurd-recovery")
	passphrase := []byte("release fixture recovery passphrase")
	now := time.Unix(1_780_000_000, 0).UTC()
	if _, err := selfhost.Initialize(selfhost.InitOptions{
		DataDir: dataDir, DeploymentName: "release-fixture", Endpoint: "203.0.113.7:443",
		RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivateFixture(&private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{
		Name: "release-device", ValidFor: 12 * time.Hour, Now: now,
		RecipientRequest: requestBytes, LiveProgram: releaseLiveProgramFixture(t),
		RegistryDir: filepath.Join(directory, "recipient-registry"),
	})
	if err != nil {
		t.Fatal(err)
	}
	_, verified, err := selfhost.VerifyLiveBundleForRecipient(issued.Artifact, now, 1, request, private)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := runtimepolicy.DecodeV2At(verified.Profile.Policy, now)
	if err != nil {
		t.Fatal(err)
	}
	return policy, bytes.Clone(private.ClientAuthSeed), now
}

func releaseLiveProgramFixture(t testing.TB) []byte {
	t.Helper()
	model, err := compiler.Generate(1771)
	if err != nil {
		t.Fatal(err)
	}
	capabilities := ir.SecurityCapabilities()
	program, err := liveprogramcompile.CompileV1(liveprogramcompile.InputV1{
		Profile:                 model,
		ClientMandatoryFeatures: append([]string(nil), capabilities[:2]...),
		RelayMandatoryFeatures:  append([]string(nil), capabilities[:2]...),
		SelectedFeatures:        append([]string(nil), capabilities...),
	})
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := liveprogram.EncodeV1(program)
	if err != nil {
		t.Fatal(err)
	}
	return encoded
}

func clearEnrollmentPrivateFixture(private *enrollment.PrivateBundleV1) {
	if private == nil {
		return
	}
	clear(private.RecipientPrivate)
	clear(private.ClientAuthSeed)
	*private = enrollment.PrivateBundleV1{}
}

func allZeroBytes(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
