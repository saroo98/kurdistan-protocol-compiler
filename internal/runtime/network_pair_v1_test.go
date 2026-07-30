// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"errors"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
)

func newNetworkProtectedPairV1(t *testing.T, seed int64) (*NetworkProtectedClientV1, *NetworkProtectedRelayV1, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1) {
	t.Helper()
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, seed, "message_lifetime_bound", 32, 32)
	networkClient, networkRelay, err := NewNetworkProtectedPairV1(client, relay)
	if err != nil {
		t.Fatal(err)
	}
	return networkClient, networkRelay, client, relay
}

func TestNetworkProtectedPairRoundTripV1(t *testing.T) {
	client, relay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9100)
	plaintext := []byte("authenticated-network-record")
	record, err := client.Seal(7, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(record, plaintext) {
		t.Fatal("network seam exposed plaintext")
	}
	delivered, delivery, err := relay.Open(record)
	if err != nil || !bytes.Equal(delivered, plaintext) || delivery == nil {
		t.Fatalf("delivered=%q delivery=%v err=%v", delivered, delivery != nil, err)
	}
	ack, err := delivery.Commit()
	if err != nil || len(ack) == 0 {
		t.Fatalf("ack=%d err=%v", len(ack), err)
	}
	if err := client.AcceptAck(ack); err != nil {
		t.Fatal(err)
	}
	if rawClient.state.life.sendCompleted != 1 || rawRelay.state.life.receiveCompleted != 1 {
		t.Fatalf("commits=%d/%d", rawClient.state.life.sendCompleted, rawRelay.state.life.receiveCompleted)
	}
}

func TestNetworkProtectedPairRejectsReplayTamperAndCrossPairV1(t *testing.T) {
	clientA, relayA, _, _ := newNetworkProtectedPairV1(t, 9101)
	_, relayB, _, _ := newNetworkProtectedPairV1(t, 9102)
	record, err := clientA.Seal(1, []byte("protected"))
	if err != nil {
		t.Fatal(err)
	}
	if payload, ack, err := relayB.Open(record); err == nil || payload != nil || ack != nil {
		t.Fatalf("cross-pair payload=%q delivery=%v err=%v", payload, ack != nil, err)
	}
	tampered := append([]byte(nil), record...)
	tampered[len(tampered)-1] ^= 1
	if payload, ack, err := relayA.Open(tampered); err == nil || payload != nil || ack != nil {
		t.Fatalf("tamper payload=%q delivery=%v err=%v", payload, ack != nil, err)
	}
	payload, delivery, err := relayA.Open(record)
	if err != nil || !bytes.Equal(payload, []byte("protected")) {
		t.Fatalf("valid payload=%q err=%v", payload, err)
	}
	ack, err := delivery.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if err := clientA.AcceptAck(ack); err != nil {
		t.Fatal(err)
	}
	if payload, replayAck, err := relayA.Open(record); !errors.Is(err, security.ErrReplayDuplicate) || payload != nil || replayAck != nil {
		t.Fatalf("replay payload=%q delivery=%v err=%v", payload, replayAck != nil, err)
	}
}

func TestNetworkProtectedPairRequiresDeliveryCommitV1(t *testing.T) {
	client, relay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9106)
	record, err := client.Seal(1, []byte("delivery-required"))
	if err != nil {
		t.Fatal(err)
	}
	payload, delivery, err := relay.Open(record)
	if err != nil || !bytes.Equal(payload, []byte("delivery-required")) || delivery == nil {
		t.Fatalf("payload=%q delivery=%v err=%v", payload, delivery != nil, err)
	}
	if _, next, err := relay.Open(record); !errors.Is(err, ErrSecureChannel) || next != nil {
		t.Fatalf("parallel delivery next=%v err=%v", next, err)
	}
	delivery.Reject()
	if rawClient.State() != auth.StateClosed || rawRelay.State() != auth.StateClosed {
		t.Fatalf("rejected delivery states=%s/%s", rawClient.State(), rawRelay.State())
	}
	if _, err := delivery.Commit(); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("commit after rejection err=%v", err)
	}
}

func TestNetworkProtectedPairSingleConsumptionAndCopyGuardV1(t *testing.T) {
	client, relay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9103)
	if _, _, err := NewNetworkProtectedPairV1(rawClient, rawRelay); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("second network consume err=%v", err)
	}
	if _, _, err := NewInProcessProtectedRelay(rawClient, rawRelay); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("in-process bypass consume err=%v", err)
	}
	clientCopy := *client
	if _, err := clientCopy.Seal(1, []byte("copy")); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("client copy err=%v", err)
	}
	relayCopy := *relay
	if _, _, err := relayCopy.Open([]byte{1}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("relay copy err=%v", err)
	}
}

func TestNetworkProtectedPairTerminalCloseV1(t *testing.T) {
	client, relay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9104)
	closeRecord, err := client.CloseRecord()
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.AcceptClose(closeRecord); err != nil {
		t.Fatal(err)
	}
	if rawClient.State() != auth.StateClosed || rawRelay.State() != auth.StateClosed {
		t.Fatalf("terminal states=%s/%s", rawClient.State(), rawRelay.State())
	}
	if _, err := client.Seal(1, []byte("after-close")); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("post-close err=%v", err)
	}
}

func TestNetworkProtectedPairAbortIsTerminalV1(t *testing.T) {
	client, relay, rawClient, rawRelay := newNetworkProtectedPairV1(t, 9105)
	relay.Abort()
	if rawClient.State() != auth.StateClosed || rawRelay.State() != auth.StateClosed {
		t.Fatalf("relay abort states=%s/%s", rawClient.State(), rawRelay.State())
	}
	if _, err := client.Seal(1, []byte("after-abort")); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("post-abort err=%v", err)
	}
	client.Abort()
}
