// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/protocol/liveprogram"
	kruntime "kurdistan/internal/runtime"
	"kurdistan/internal/transport/tlstcp"
)

type releaseRuntimeNetworkFactory struct{}

func newReleaseRuntimeNetworkFactory() androidbridge.RuntimeNetworkFactory {
	return releaseRuntimeNetworkFactory{}
}

func (releaseRuntimeNetworkFactory) Prepare(ctx context.Context, plan sessionplan.PlanV2, clientAuthSeed []byte, endpointIndex uint8) (androidbridge.RuntimeNetworkSession, androidbridge.ErrorCode) {
	if ctx == nil || len(clientAuthSeed) != ed25519.SeedSize {
		return nil, androidbridge.CodePolicyRejected
	}
	policy, err := plan.RuntimePolicyAt(time.Now().UTC())
	defer clearRuntimePolicyV2(&policy)
	if err != nil || !releaseClientSeedMatchesPolicy(clientAuthSeed, policy) {
		return nil, androidbridge.CodePolicyRejected
	}
	return newPlatformRuntimeNetwork(ctx, plan.Clone(), policy, bytes.Clone(clientAuthSeed), endpointIndex)
}

type releaseIdentityV1 struct {
	id   string
	seed []byte
}

func (identity releaseIdentityV1) Local(id string) (ed25519.PrivateKey, error) {
	if id != identity.id || len(identity.seed) != ed25519.SeedSize {
		return nil, errors.New("release identity rejected")
	}
	return ed25519.NewKeyFromSeed(identity.seed), nil
}

type releaseTrustV1 struct {
	id     string
	public [32]byte
}

func (trust releaseTrustV1) Peer(id string) (ed25519.PublicKey, error) {
	if id != trust.id || trust.public == ([32]byte{}) {
		return nil, errors.New("release trust rejected")
	}
	return append(ed25519.PublicKey(nil), trust.public[:]...), nil
}

func releaseTLSClientConfig(policy runtimepolicy.PolicyV2, now time.Time) (*tls.Config, error) {
	if err := runtimepolicy.ValidateV2At(policy, now); err != nil {
		return nil, errors.New("release TLS authority rejected")
	}
	leaf, err := x509.ParseCertificate(policy.TLSLeafDER)
	if err != nil || !bytes.Equal(leaf.Raw, policy.TLSLeafDER) || leaf.VerifyHostname(policy.TLSServerName) != nil ||
		now.Before(leaf.NotBefore) || now.After(leaf.NotAfter) {
		return nil, errors.New("release TLS authority rejected")
	}
	roots := x509.NewCertPool()
	roots.AddCert(leaf)
	return &tls.Config{
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		ServerName: policy.TLSServerName, RootCAs: roots, NextProtos: []string{tlstcp.ALPN},
		SessionTicketsDisabled: true, ClientSessionCache: nil,
	}, nil
}

func releaseClientHandshake(plan sessionplan.PlanV2, policy runtimepolicy.PolicyV2, clientAuthSeed []byte) (*kruntime.ProcessWireClientHandshakeV1, liveprogram.ProgramV1, error) {
	program, err := liveprogram.DecodeV1(policy.LiveProgram)
	if err != nil {
		return nil, liveprogram.ProgramV1{}, errors.New("release Kurd authority rejected")
	}
	config, err := auth.NewProjectedProcessHandshakeConfigV1(policy.ClientAuthKeyID, policy.RelayAuthKeyID, program, policy.CarrierFamily)
	if err != nil {
		return nil, liveprogram.ProgramV1{}, errors.New("release Kurd authority rejected")
	}
	handshake, err := kruntime.NewProcessWireClientHandshakeV1(config, auth.Dependencies{
		Identity: releaseIdentityV1{id: policy.ClientAuthKeyID, seed: clientAuthSeed},
		Trust:    releaseTrustV1{id: policy.RelayAuthKeyID, public: policy.RelayAuthPublic},
	}, plan.Digest)
	if err != nil {
		return nil, liveprogram.ProgramV1{}, errors.New("release Kurd authority rejected")
	}
	return handshake, program, nil
}

func releaseClientSeedMatchesPolicy(seed []byte, policy runtimepolicy.PolicyV2) bool {
	if len(seed) != ed25519.SeedSize {
		return false
	}
	private := ed25519.NewKeyFromSeed(seed)
	defer clear(private)
	return bytes.Equal(private.Public().(ed25519.PublicKey), policy.ClientAuthPublic[:])
}

func clearRuntimePolicyV2(policy *runtimepolicy.PolicyV2) {
	if policy == nil {
		return
	}
	clear(policy.LiveProgram)
	clear(policy.TLSLeafDER)
	for i := range policy.Endpoints {
		clear(policy.Endpoints[i].Address)
	}
	clear(policy.ClientIPv4)
	clear(policy.DNSIPv4)
	clear(policy.ClientIPv6)
	clear(policy.DNSIPv6)
	for i := range policy.Routes {
		clear(policy.Routes[i].Address)
	}
	for i := range policy.DNSServers {
		clear(policy.DNSServers[i])
	}
	clear(policy.Fallback.EndpointIndexes)
	*policy = runtimepolicy.PolicyV2{}
}
