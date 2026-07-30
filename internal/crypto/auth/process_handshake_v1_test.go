// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package auth

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"kurdistan/internal/crypto/security"
)

func TestProcessHandshakeV1MatchesFrozenFirstContact(t *testing.T) {
	t.Setenv("GODEBUG", "cryptocustomrand=1")
	fixture := newFirstContactFixture(t, security.TranscriptFullBindingV1)
	clientEntropy := bytes.Repeat([]byte{0x31}, 1024)
	relayEntropy := bytes.Repeat([]byte{0x92}, 1024)

	monolithicInput := fixture.input
	monolithicReplay, err := NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	monolithicInput.Replay = monolithicReplay
	want, err := firstContactWithOptions(monolithicInput, executionOptions{
		clientEntropy: bytes.NewReader(clientEntropy),
		serverEntropy: bytes.NewReader(relayEntropy),
	})
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(want.ChannelSecret)

	config, err := NewProcessHandshakeConfigV1(
		fixture.input.Client,
		fixture.input.Server,
		fixture.input.SelectedPolicy,
		fixture.input.SelectedCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := newClientProcessHandshakeV1(config, fixture.input.ClientDependencies, bytes.NewReader(clientEntropy))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	replay, err := NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := newRelayProcessHandshakeV1(config, fixture.input.ServerDependencies, replay, bytes.NewReader(relayEntropy))
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	clientHello, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, err := relay.AcceptClientHello(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	clientFinish, err := client.AcceptServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	serverFinish, relayResult, err := relay.AcceptClientFinish(clientFinish)
	if err != nil {
		t.Fatal(err)
	}
	defer relayResult.Close()
	clientResult, err := client.AcceptServerFinish(serverFinish)
	if err != nil {
		t.Fatal(err)
	}
	defer clientResult.Close()

	clientEvidence, ok := clientResult.EvidenceV1()
	if !ok {
		t.Fatal("client result did not expose conformance evidence")
	}
	relayEvidence, ok := relayResult.EvidenceV1()
	if !ok {
		t.Fatal("relay result did not expose conformance evidence")
	}
	if clientEvidence.Role != ProcessHandshakeClientV1 || relayEvidence.Role != ProcessHandshakeRelayV1 {
		t.Fatalf("unexpected roles: %s/%s", clientEvidence.Role, relayEvidence.Role)
	}
	for index := range want.Messages {
		if !bytes.Equal(clientEvidence.Messages[index], want.Messages[index]) || !bytes.Equal(relayEvidence.Messages[index], want.Messages[index]) {
			t.Fatalf("process-separated wire message %d diverged from frozen first contact", index)
		}
	}
	if clientEvidence.TranscriptHash != want.TranscriptHash || relayEvidence.TranscriptHash != want.TranscriptHash {
		t.Fatal("process-separated transcript diverged from frozen first contact")
	}
	clientContext, ok := clientResult.ContextSnapshotV1()
	if !ok {
		t.Fatal("missing client context")
	}
	relayContext, ok := relayResult.ContextSnapshotV1()
	if !ok {
		t.Fatal("missing relay context")
	}
	wantContext, ok := want.AuthenticatedContextSnapshotV1()
	if !ok {
		t.Fatal("missing monolithic context")
	}
	if !reflect.DeepEqual(clientContext, wantContext) || !reflect.DeepEqual(relayContext, wantContext) {
		t.Fatal("process-separated authenticated context diverged")
	}
	clientSecret, err := clientResult.TakeChannelSecretV1()
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(clientSecret)
	relaySecret, err := relayResult.TakeChannelSecretV1()
	if err != nil {
		t.Fatal(err)
	}
	defer wipe(relaySecret)
	if !bytes.Equal(clientSecret, relaySecret) || !bytes.Equal(clientSecret, want.ChannelSecret) {
		t.Fatal("process-separated channel secret diverged")
	}
	if _, err := clientResult.TakeChannelSecretV1(); err == nil {
		t.Fatal("client channel secret transferred twice")
	}
	if _, ok := clientResult.ContextSnapshotV1(); ok {
		t.Fatal("consumed result retained context")
	}
}

func TestProcessHandshakeV1RejectsOutOfOrderTamperAndReplay(t *testing.T) {
	t.Run("out of order closes client", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
		config, err := NewProcessHandshakeConfigV1(
			fixture.input.Client,
			fixture.input.Server,
			fixture.input.SelectedPolicy,
			fixture.input.SelectedCapabilities,
		)
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClientProcessHandshakeV1(config, fixture.input.ClientDependencies)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		_, err = client.AcceptServerHello([]byte{1})
		assertHandshakeCode(t, err, FailureOutOfOrder)
		_, err = client.Start()
		assertHandshakeCode(t, err, FailureOutOfOrder)
	})

	t.Run("tampered server finish closes client", func(t *testing.T) {
		client, relay := newProcessHandshakePairForTestV1(t)
		clientHello, err := client.Start()
		if err != nil {
			t.Fatal(err)
		}
		serverHello, err := relay.AcceptClientHello(clientHello)
		if err != nil {
			t.Fatal(err)
		}
		clientFinish, err := client.AcceptServerHello(serverHello)
		if err != nil {
			t.Fatal(err)
		}
		serverFinish, relayResult, err := relay.AcceptClientFinish(clientFinish)
		if err != nil {
			t.Fatal(err)
		}
		defer relayResult.Close()
		serverFinish[len(serverFinish)-1] ^= 1
		result, err := client.AcceptServerFinish(serverFinish)
		if result != nil {
			result.Close()
			t.Fatal("tampered server finish produced a result")
		}
		assertHandshakeCode(t, err, FailureKeyConfirmation)
		if _, err := client.AcceptServerFinish(serverFinish); err == nil {
			t.Fatal("closed client accepted a retry")
		}
	})

	t.Run("relay replay cache is process owned", func(t *testing.T) {
		fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
		config, err := NewProcessHandshakeConfigV1(
			fixture.input.Client,
			fixture.input.Server,
			fixture.input.SelectedPolicy,
			fixture.input.SelectedCapabilities,
		)
		if err != nil {
			t.Fatal(err)
		}
		client, err := NewClientProcessHandshakeV1(config, fixture.input.ClientDependencies)
		if err != nil {
			t.Fatal(err)
		}
		defer client.Close()
		clientHello, err := client.Start()
		if err != nil {
			t.Fatal(err)
		}
		replay, err := NewHandshakeReplayCache(64)
		if err != nil {
			t.Fatal(err)
		}
		firstRelay, err := NewRelayProcessHandshakeV1(config, fixture.input.ServerDependencies, replay)
		if err != nil {
			t.Fatal(err)
		}
		defer firstRelay.Close()
		if _, err := firstRelay.AcceptClientHello(clientHello); err != nil {
			t.Fatal(err)
		}
		secondRelay, err := NewRelayProcessHandshakeV1(config, fixture.input.ServerDependencies, replay)
		if err != nil {
			t.Fatal(err)
		}
		defer secondRelay.Close()
		_, err = secondRelay.AcceptClientHello(clientHello)
		assertHandshakeCode(t, err, FailureReplay)
	})
}

func TestProcessHandshakeResultV1CloseWipesSecret(t *testing.T) {
	client, relay := newProcessHandshakePairForTestV1(t)
	clientHello, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, err := relay.AcceptClientHello(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	clientFinish, err := client.AcceptServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	serverFinish, relayResult, err := relay.AcceptClientFinish(clientFinish)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := client.AcceptServerFinish(serverFinish)
	if err != nil {
		t.Fatal(err)
	}
	clientAlias := clientResult.secret
	relayAlias := relayResult.secret
	clientResult.Close()
	relayResult.Close()
	if !allZeroBytesV1(clientAlias) || !allZeroBytesV1(relayAlias) {
		t.Fatal("result close did not wipe retained channel secret")
	}
	if _, err := clientResult.TakeChannelSecretV1(); !errors.Is(err, ErrHandshake) {
		t.Fatalf("closed result returned unexpected error: %v", err)
	}
}

func newProcessHandshakePairForTestV1(t *testing.T) (*ClientProcessHandshakeV1, *RelayProcessHandshakeV1) {
	t.Helper()
	fixture := newFirstContactFixture(t, security.TranscriptCanonicalV1)
	config, err := NewProcessHandshakeConfigV1(
		fixture.input.Client,
		fixture.input.Server,
		fixture.input.SelectedPolicy,
		fixture.input.SelectedCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewClientProcessHandshakeV1(config, fixture.input.ClientDependencies)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	relay, err := NewRelayProcessHandshakeV1(config, fixture.input.ServerDependencies, replay)
	if err != nil {
		client.Close()
		t.Fatal(err)
	}
	t.Cleanup(client.Close)
	t.Cleanup(relay.Close)
	return client, relay
}

func allZeroBytesV1(value []byte) bool {
	for _, item := range value {
		if item != 0 {
			return false
		}
	}
	return true
}
