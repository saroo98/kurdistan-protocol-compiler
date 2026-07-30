// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/transport/tlstcp"
)

const phase11RelaySubprocessMarkerV1 = "KURD_PHASE11_RELAY_SUBPROCESS_V1"

func TestPhase11RelaySubprocessV1(t *testing.T) {
	if os.Getenv(phase11RelaySubprocessMarkerV1) == "1" {
		phase11RunRelaySubprocessV1(t)
		return
	}

	command := exec.Command(os.Args[0], "-test.run=^TestPhase11RelaySubprocessV1$")
	command.Env = append(os.Environ(), phase11RelaySubprocessMarkerV1+"=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr strings.Builder
	command.Stderr = &stderr
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	scanner := bufio.NewScanner(stdout)
	if !scanner.Scan() {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("relay process did not publish its loopback address: %s", stderr.String())
	}
	address := strings.TrimSpace(scanner.Text())
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatalf("relay process published a non-loopback address")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	digest := phase11SubprocessDigestV1()
	clientTLS, _ := phase11SubprocessTLSConfigsV1(t)
	carrier, err := tlstcp.Client(ctx, raw, clientTLS, digest, 128<<10)
	if err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	fixture := phase11SubprocessFixtureV1(t)
	config, err := auth.NewProcessHandshakeConfigV1(
		fixture.input.Client,
		fixture.input.Server,
		fixture.input.SelectedPolicy,
		fixture.input.SelectedCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	if err := RunProcessClientSessionV1(ctx, carrier, handshake, digest, 17, []byte("phase11-os-process-delivery")); err != nil {
		_ = command.Process.Kill()
		_ = command.Wait()
		t.Fatal(err)
	}
	if err := command.Wait(); err != nil {
		t.Fatalf("relay process failed: %v: %s", err, stderr.String())
	}
}

func phase11RunRelaySubprocessV1(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	fmt.Fprintln(os.Stdout, listener.Addr().String())

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	raw, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	digest := phase11SubprocessDigestV1()
	_, relayTLS := phase11SubprocessTLSConfigsV1(t)
	carrier, err := tlstcp.Server(ctx, raw, relayTLS, digest, 128<<10)
	if err != nil {
		t.Fatal(err)
	}
	fixture := phase11SubprocessFixtureV1(t)
	config, err := auth.NewProcessHandshakeConfigV1(
		fixture.input.Client,
		fixture.input.Server,
		fixture.input.SelectedPolicy,
		fixture.input.SelectedCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	handshake, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	sink := &phase11RuntimeSinkV1{}
	if err := RunProcessRelaySessionV1(ctx, carrier, handshake, digest, sink); err != nil {
		t.Fatal(err)
	}
	if string(sink.payload) != "phase11-os-process-delivery" {
		t.Fatal("relay process received unexpected application bytes")
	}
}

func phase11SubprocessFixtureV1(t *testing.T) strictSupportFixtureV1 {
	t.Helper()
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
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
	t.Cleanup(func() {
		clear(clientPrivate)
		clear(relayPrivate)
	})
	fixture.input.ClientDependencies = auth.Dependencies{
		Identity: handshakeIdentity{"runtime-client", clientPrivate},
		Trust:    handshakeTrust{"runtime-server", relayPrivate.Public().(ed25519.PublicKey)},
	}
	fixture.input.ServerDependencies = auth.Dependencies{
		Identity: handshakeIdentity{"runtime-server", relayPrivate},
		Trust:    handshakeTrust{"runtime-client", clientPrivate.Public().(ed25519.PublicKey)},
	}
	return fixture
}

func phase11SubprocessTLSConfigsV1(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for index := range seed {
		seed[index] = byte(91 + index)
	}
	private := ed25519.NewKeyFromSeed(seed)
	clear(seed)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(11),
		Subject:      pkix.Name{CommonName: "phase11.process.test"},
		DNSNames:     []string{"phase11.process.test"},
		NotBefore:    time.Unix(1_700_000_000, 0),
		NotAfter:     time.Unix(2_000_000_000, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 64)), template, template, private.Public(), private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(certificate)
	t.Cleanup(func() { clear(private) })
	return &tls.Config{ServerName: "phase11.process.test", RootCAs: roots},
		&tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}
}

func phase11SubprocessDigestV1() [32]byte {
	var digest [32]byte
	for index := range digest {
		digest[index] = byte(index + 101)
	}
	return digest
}
