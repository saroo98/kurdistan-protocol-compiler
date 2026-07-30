//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"sort"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/compiler"
	"kurdistan/internal/protocol/ir"
	kurdruntime "kurdistan/internal/runtime"
	"kurdistan/internal/transport/tlstcp"
)

const phase11MaximumPayloadBytes = 32 << 10

type phase11IdentityV1 struct {
	id  string
	key ed25519.PrivateKey
}

func (identity phase11IdentityV1) Local(id string) (ed25519.PrivateKey, error) {
	if id != identity.id || len(identity.key) != ed25519.PrivateKeySize {
		return nil, errors.New("phase11 internal identity rejected")
	}
	return append(ed25519.PrivateKey(nil), identity.key...), nil
}

type phase11TrustV1 struct {
	id  string
	key ed25519.PublicKey
}

func (trust phase11TrustV1) Peer(id string) (ed25519.PublicKey, error) {
	if id != trust.id || len(trust.key) != ed25519.PublicKeySize {
		return nil, errors.New("phase11 internal trust rejected")
	}
	return append(ed25519.PublicKey(nil), trust.key...), nil
}

type phase11SinkV1 struct {
	payload []byte
}

func (sink *phase11SinkV1) Deliver(_ context.Context, payload []byte) error {
	if sink == nil || len(payload) == 0 || len(payload) > phase11MaximumPayloadBytes {
		return errors.New("phase11 internal delivery rejected")
	}
	sink.payload = append([]byte(nil), payload...)
	return nil
}

func phase11RoundTrip(input []byte) ([]byte, androidbridge.ErrorCode) {
	if len(input) == 0 || len(input) > phase11MaximumPayloadBytes {
		return nil, androidbridge.CodeSizeLimit
	}
	clientHandshake, relayHandshake, digest, code := phase11InternalHandshakesV1()
	if code != androidbridge.CodeOK {
		return nil, code
	}
	clientRaw, relayRaw := net.Pipe()
	clientTLS, relayTLS, err := phase11InternalTLSConfigsV1()
	if err != nil {
		_ = clientRaw.Close()
		_ = relayRaw.Close()
		return nil, androidbridge.CodeInternalFailure
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	type carrierResult struct {
		carrier *tlstcp.Conn
		err     error
	}
	relayCarrierResult := make(chan carrierResult, 1)
	go func() {
		carrier, establishErr := tlstcp.Server(ctx, relayRaw, relayTLS, digest, 128<<10)
		relayCarrierResult <- carrierResult{carrier: carrier, err: establishErr}
	}()
	clientCarrier, clientErr := tlstcp.Client(ctx, clientRaw, clientTLS, digest, 128<<10)
	relayResult := <-relayCarrierResult
	if clientErr != nil || relayResult.err != nil {
		if clientCarrier != nil {
			_ = clientCarrier.Close()
		}
		if relayResult.carrier != nil {
			_ = relayResult.carrier.Close()
		}
		return nil, androidbridge.CodeInternalFailure
	}
	sink := &phase11SinkV1{}
	relayDone := make(chan error, 1)
	go func() {
		relayDone <- kurdruntime.RunProcessRelaySessionV1(
			ctx,
			relayResult.carrier,
			relayHandshake,
			digest,
			sink,
		)
	}()
	clientErr = kurdruntime.RunProcessClientSessionV1(
		ctx,
		clientCarrier,
		clientHandshake,
		digest,
		17,
		input,
	)
	relayErr := <-relayDone
	_ = clientCarrier.Close()
	_ = relayResult.carrier.Close()
	if clientErr != nil || relayErr != nil || !bytes.Equal(sink.payload, input) {
		clear(sink.payload)
		return nil, androidbridge.CodeInternalFailure
	}
	return sink.payload, androidbridge.CodeOK
}

func phase11InternalHandshakesV1() (*kurdruntime.ProcessWireClientHandshakeV1, *kurdruntime.ProcessWireRelayHandshakeV1, [32]byte, androidbridge.ErrorCode) {
	generated, err := compiler.Generate(6201)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	generated.Security.TranscriptMode = security.TranscriptCanonicalV1
	generated.Security.NonceMode = "counter_xor_base"
	generated.Security.ReplayPolicy = "ordered_only"
	generated.Security.DowngradePolicy = "strict_suite_and_capabilities"
	generated.Security.CapabilityNegotiationPolicy = "strict_required"
	generated.Security.ProfileCompatibilityPolicy = "strict_schema"
	generated.Security.KeyRotationPolicy = "session_only"
	generated.Security.ConfigValidationPolicy = "strict_required"
	generated.Security.SecureEnvelopeMode = "metadata_authenticated"
	generated.GenerationHash = ""
	generated.GenerationHash, err = ir.CanonicalHash(generated)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	capabilities := append([]string(nil), ir.SecurityCapabilities()...)
	sort.Strings(capabilities)
	if len(capabilities) < 2 {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	floor := append([]string(nil), capabilities[:2]...)
	policy, err := ir.BuildEffectiveSecurityPolicy(generated, floor, floor, floor)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	client, err := auth.NewPeerParameters("runtime-client", generated, policy, policy, capabilities, floor)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	relay, err := auth.NewPeerParameters("runtime-server", generated, policy, policy, capabilities, floor)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	clientSeed := make([]byte, ed25519.SeedSize)
	relaySeed := make([]byte, ed25519.SeedSize)
	for index := range clientSeed {
		clientSeed[index] = byte(index + 1)
		relaySeed[index] = byte(255 - index)
	}
	clientPrivate := ed25519.NewKeyFromSeed(clientSeed)
	relayPrivate := ed25519.NewKeyFromSeed(relaySeed)
	clear(clientSeed)
	clear(relaySeed)
	defer clear(clientPrivate)
	defer clear(relayPrivate)
	config, err := auth.NewProcessHandshakeConfigV1(client, relay, policy, floor)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	digest := sha256.Sum256([]byte("kurdistan-phase11-android-internal-conformance-v1"))
	clientDependencies := auth.Dependencies{
		Identity: phase11IdentityV1{"runtime-client", clientPrivate},
		Trust:    phase11TrustV1{"runtime-server", relayPrivate.Public().(ed25519.PublicKey)},
	}
	relayDependencies := auth.Dependencies{
		Identity: phase11IdentityV1{"runtime-server", relayPrivate},
		Trust:    phase11TrustV1{"runtime-client", clientPrivate.Public().(ed25519.PublicKey)},
	}
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	clientHandshake, err := kurdruntime.NewProcessWireClientHandshakeV1(config, clientDependencies, digest)
	if err != nil {
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	relayHandshake, err := kurdruntime.NewProcessWireRelayHandshakeV1(config, relayDependencies, replay, digest)
	if err != nil {
		clientHandshake.Close()
		return nil, nil, [32]byte{}, androidbridge.CodeInternalFailure
	}
	return clientHandshake, relayHandshake, digest, androidbridge.CodeOK
}

func phase11InternalTLSConfigsV1() (*tls.Config, *tls.Config, error) {
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(91 + index)
	}
	private := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "phase11.android.internal"},
		DNSNames:     []string{"phase11.android.internal"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 64)), template, template, private.Public(), private)
	if err != nil {
		clear(private)
		return nil, nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		clear(private)
		return nil, nil, err
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	return &tls.Config{ServerName: "phase11.android.internal", RootCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}},
		nil
}
