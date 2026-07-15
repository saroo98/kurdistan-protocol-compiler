// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"encoding/binary"
	"errors"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/runtime/labfault"
)

func newInProcessProtectedRelayV1(t *testing.T, seed int64, maxKey int) (*InProcessProtectedClientV1, *InProcessProtectedRelayV1, *ClientAuthenticatedEndpointV1, *RelayAuthenticatedEndpointV1) {
	t.Helper()
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, seed, "message_lifetime_bound", 32, maxKey)
	clientEndpoint, relayEndpoint, err := NewInProcessProtectedRelay(client, relay)
	if err != nil {
		t.Fatal(err)
	}
	return clientEndpoint, relayEndpoint, client, relay
}

func newPaddingFaultPairV1(t *testing.T, seed int64) (*InProcessProtectedClientV1, *InProcessProtectedRelayV1) {
	t.Helper()
	_, client, relay := newAuthenticatingFirstRecordPairV1(t, seed, "message_lifetime_bound", 32, 32)
	token, _ := labfault.NewTokenV1("runtime_padding_only_diversity")
	c, r, err := newInProcessProtectedRelayWithLabFaultV1(client, relay, token)
	if err != nil {
		t.Fatal(err)
	}
	return c, r
}

func TestPaddingOnlyDiversityFaultV1(t *testing.T) {
	client, relay := newPaddingFaultPairV1(t, 8520)
	payload := []byte("padding-fault-payload")
	record, err := client.Seal(1, payload)
	if err != nil {
		t.Fatal(err)
	}
	first, err := client.wrapWithPaddingV1(record, []byte{1, 2, 3})
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.wrapWithPaddingV1(record, []byte{4, 5, 6, 7})
	if err != nil {
		t.Fatal(err)
	}
	firstLen := binary.BigEndian.Uint32(first.record[:4])
	secondLen := binary.BigEndian.Uint32(second.record[:4])
	if firstLen != secondLen || !bytes.Equal(first.record[4:4+firstLen], second.record[4:4+secondLen]) || bytes.Equal(first.record, second.record) {
		t.Fatal("wrapper diversity contract failed")
	}
	unused := second.record
	clearPaddingFaultRecordV1(&second)
	if second.record != nil || !bytes.Equal(unused, make([]byte, len(unused))) {
		t.Fatal("unused wrapper not cleared")
	}
	got, ack, err := relay.Deliver(first)
	if err != nil || !bytes.Equal(got, payload) || len(ack.record) == 0 {
		t.Fatalf("delivery=%q ack=%d err=%v", got, len(ack.record), err)
	}
}

func TestPaddingFaultMalformedV1(t *testing.T) {
	client, relay := newPaddingFaultPairV1(t, 8521)
	record, err := client.Seal(1, []byte("malformed"))
	if err != nil {
		t.Fatal(err)
	}
	for _, raw := range [][]byte{{}, {0, 0, 0, 0, 0, 0, 0, 0}, {0, 0, 0, 10, 1}, append([]byte{0, 0, 0, 1, 1, 0, 0, 0, 1, 2}, 9)} {
		candidate := InProcessProtectedRecordV1{owner: client.owner, direction: 1, record: append([]byte(nil), raw...)}
		owned := candidate.record
		got, ack, err := relay.Deliver(candidate)
		if err != ErrRecordInvalid || got != nil || len(ack.record) != 0 || !bytes.Equal(owned, make([]byte, len(owned))) {
			t.Fatalf("malformed err=%v delivery=%q", err, got)
		}
	}
	got, ack, err := relay.Deliver(record)
	if err != ErrRecordInvalid || got != nil || len(ack.record) != 0 {
		t.Fatalf("unwrapped err=%v", err)
	}
}

func TestNormalPaddingControlV1(t *testing.T) {
	client, _, _, _ := newInProcessProtectedRelayV1(t, 8522, 32)
	one, err := client.Seal(1, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	two, err := client.Seal(2, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(one.record, two.record) {
		t.Fatal("normal distinct inputs produced identical records")
	}
}

func TestInProcessProtectedRelayProtectedPathAndAckV1(t *testing.T) {
	clientEndpoint, relayEndpoint, client, relay := newInProcessProtectedRelayV1(t, 8100, 1)
	payload := []byte("relay-only-authenticated-payload")
	for index := 0; index < 2; index++ {
		record, err := clientEndpoint.Seal(1, payload)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Equal(record.record, payload) || bytes.Contains(record.record, payload) {
			t.Fatal("protected relay seam exposed complete plaintext")
		}
		relayEndpoint.owner.mu.Lock()
		if relayEndpoint.owner.sinkBytes != uint64(index*len(payload)) {
			relayEndpoint.owner.mu.Unlock()
			t.Fatal("sink advanced before authenticated delivery")
		}
		relayEndpoint.owner.mu.Unlock()
		header, _, err := parseApplicationRecordV1(record.record, applicationDirectionClientV1, clientEndpoint.owner.channel.context.MaxEnvelopeBytes)
		if err != nil || header.Epoch != uint64(index) {
			t.Fatalf("record %d epoch=%d err=%v", index, header.Epoch, err)
		}
		delivered, ack, err := relayEndpoint.Deliver(record)
		if err != nil || !bytes.Equal(delivered, payload) {
			t.Fatalf("delivery=%q err=%v", delivered, err)
		}
		relayEndpoint.owner.mu.Lock()
		seam := append([]byte(nil), relayEndpoint.owner.lastSeam...)
		seamBytes, sinkBytes := relayEndpoint.owner.seamBytes, relayEndpoint.owner.sinkBytes
		relayEndpoint.owner.mu.Unlock()
		if bytes.Contains(seam, payload) || seamBytes == 0 || sinkBytes != uint64((index+1)*len(payload)) {
			t.Fatalf("seam/sink accounting seam=%d sink=%d", seamBytes, sinkBytes)
		}
		if err := clientEndpoint.AcceptAck(ack); err != nil {
			t.Fatal(err)
		}
	}
	if client.state.life.sendCompleted != 2 || relay.state.life.receiveCompleted != 2 || relay.State() != auth.StateEstablished {
		t.Fatalf("relay lifecycle sends=%d receives=%d state=%s", client.state.life.sendCompleted, relay.state.life.receiveCompleted, relay.State())
	}
}

func TestRuntimeEnforcementBypassGuardV1(t *testing.T) {
	clientA, relayA, _, _ := newInProcessProtectedRelayV1(t, 8101, 8)
	_, relayB, _, _ := newInProcessProtectedRelayV1(t, 8102, 8)
	record, err := clientA.Seal(1, []byte("bypass-guard"))
	if err != nil {
		t.Fatal(err)
	}
	if plaintext, ack, err := relayB.Deliver(record); !errors.Is(err, ErrSecureChannel) || err.Error() != ErrSecureChannel.Error() || plaintext != nil || ack.record != nil {
		t.Fatalf("cross-pair bypass plaintext=%q ack=%x err=%v", plaintext, ack.record, err)
	}
	plaintext, ack, err := relayA.Deliver(record)
	if err != nil || !bytes.Equal(plaintext, []byte("bypass-guard")) {
		t.Fatalf("owner relay delivery=%q err=%v", plaintext, err)
	}
	if err := clientA.AcceptAck(ack); err != nil {
		t.Fatal(err)
	}
	if duplicate, duplicateAck, err := relayA.Deliver(record); !errors.Is(err, security.ErrReplayDuplicate) || err.Error() != security.ErrReplayDuplicate.Error() || duplicate != nil || duplicateAck.record != nil {
		t.Fatalf("replay bypass plaintext=%q ack=%x err=%v", duplicate, duplicateAck.record, err)
	}
}

func TestRelayTamperZeroDeliveryV1(t *testing.T) {
	mutations := []struct {
		name   string
		offset int
	}{
		{"header", 0}, {"epoch-aad", 4}, {"direction-aad", 12}, {"slot-aad", 14}, {"sequence-aad", 16}, {"ciphertext", applicationHeaderBytesV1}, {"tag", -1},
	}
	for index, mutation := range mutations {
		t.Run(mutation.name, func(t *testing.T) {
			clientEndpoint, relayEndpoint, _, relay := newInProcessProtectedRelayV1(t, 8110+int64(index), 8)
			record, err := clientEndpoint.Seal(1, []byte("must-not-deliver"))
			if err != nil {
				t.Fatal(err)
			}
			record.record = append([]byte(nil), record.record...)
			offset := mutation.offset
			if offset < 0 {
				offset = len(record.record) - 1
			}
			record.record[offset] ^= 1
			delivered, ack, err := relayEndpoint.Deliver(record)
			relayEndpoint.owner.mu.Lock()
			sinkBytes := relayEndpoint.owner.sinkBytes
			relayEndpoint.owner.mu.Unlock()
			if err == nil || delivered != nil || ack.record != nil || relay.state.life.receiveCompleted != 0 || sinkBytes != 0 {
				t.Fatalf("tamper delivery=%q ack=%x receive=%d sink=%d err=%v", delivered, ack.record, relay.state.life.receiveCompleted, sinkBytes, err)
			}
		})
	}
}

func TestRelayTamperAckZeroCommitV1(t *testing.T) {
	clientEndpoint, relayEndpoint, client, _ := newInProcessProtectedRelayV1(t, 8119, 8)
	record, err := clientEndpoint.Seal(1, []byte("ack-tamper"))
	if err != nil {
		t.Fatal(err)
	}
	_, ack, err := relayEndpoint.Deliver(record)
	if err != nil {
		t.Fatal(err)
	}
	ack.record = append([]byte(nil), ack.record...)
	ack.record[len(ack.record)-1] ^= 1
	if err := clientEndpoint.AcceptAck(ack); !errors.Is(err, security.ErrAuthenticationFailed) || client.state.life.sendCompleted != 0 || len(client.state.life.outstanding) != 1 {
		t.Fatalf("tampered Ack sends=%d outstanding=%d err=%v", client.state.life.sendCompleted, len(client.state.life.outstanding), err)
	}
}

func TestRelayTamperAckSealFailureZeroSinkV1(t *testing.T) {
	clientEndpoint, relayEndpoint, _, relay := newInProcessProtectedRelayV1(t, 8123, 8)
	record, err := clientEndpoint.Seal(1, []byte("ack-seal-failure"))
	if err != nil {
		t.Fatal(err)
	}
	clientEndpoint.owner.channel.afterSeal = func() error { return errors.New("forced Ack seal failure") }
	delivered, ack, err := relayEndpoint.Deliver(record)
	clientEndpoint.owner.channel.afterSeal = nil
	relayEndpoint.owner.mu.Lock()
	sinkBytes := relayEndpoint.owner.sinkBytes
	relayEndpoint.owner.mu.Unlock()
	if err == nil || delivered != nil || ack.record != nil || sinkBytes != 0 || relay.state.life.receiveCompleted != 1 {
		t.Fatalf("Ack seal failure delivery=%q ack=%x sink=%d receive=%d err=%v", delivered, ack.record, sinkBytes, relay.state.life.receiveCompleted, err)
	}
}

func TestPairOwnershipAndTerminalRelayCloseV1(t *testing.T) {
	clientA, relayA, rawClientA, rawRelayA := newInProcessProtectedRelayV1(t, 8120, 8)
	clientB, relayB, _, _ := newInProcessProtectedRelayV1(t, 8121, 8)
	if _, _, err := NewInProcessProtectedRelay(rawClientA, rawRelayA); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("second consume err=%v", err)
	}
	record, err := clientA.Seal(1, []byte("owned"))
	if err != nil {
		t.Fatal(err)
	}
	if delivered, _, err := relayB.Deliver(record); !errors.Is(err, ErrSecureChannel) || delivered != nil {
		t.Fatalf("cross-pair delivery=%q err=%v", delivered, err)
	}
	wrongRole := record
	wrongRole.direction = 2
	if delivered, _, err := relayA.Deliver(wrongRole); !errors.Is(err, ErrSecureChannel) || delivered != nil {
		t.Fatalf("wrong-role delivery=%q err=%v", delivered, err)
	}
	clientCopy := *clientA
	if _, err := clientCopy.Seal(1, []byte("copy")); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("copied client err=%v", err)
	}
	relayCopy := *relayA
	if _, _, err := relayCopy.Deliver(record); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("copied relay err=%v", err)
	}
	if _, _, err := relayA.Deliver(InProcessProtectedRecordV1{owner: clientB.owner, direction: 1, record: []byte{1}}); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("wrong-role owner err=%v", err)
	}
	closeRecord, err := clientA.Close()
	if err != nil {
		t.Fatal(err)
	}
	closeRecord.record[len(closeRecord.record)-1] ^= 1
	if err := relayA.AcceptClose(closeRecord); !errors.Is(err, security.ErrAuthenticationFailed) {
		t.Fatalf("tampered close err=%v", err)
	}
	if rawClientA.State() != auth.StateClosed || rawRelayA.State() != auth.StateClosed {
		t.Fatalf("terminal states=%s/%s", rawClientA.State(), rawRelayA.State())
	}
	if _, err := clientA.Seal(1, []byte("after-close")); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("post-close send err=%v", err)
	}
}

func TestRelayCloseValidTerminalV1(t *testing.T) {
	clientEndpoint, relayEndpoint, rawClient, rawRelay := newInProcessProtectedRelayV1(t, 8122, 8)
	closeRecord, err := clientEndpoint.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err := relayEndpoint.AcceptClose(closeRecord); err != nil {
		t.Fatal(err)
	}
	if rawClient.State() != auth.StateClosed || rawRelay.State() != auth.StateClosed {
		t.Fatalf("valid close states=%s/%s", rawClient.State(), rawRelay.State())
	}
	if _, err := clientEndpoint.Seal(1, []byte("after-valid-close")); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("valid-close post-use err=%v", err)
	}
}

func TestRelayProtectedPathMultiFragmentV1(t *testing.T) {
	clientEndpoint, relayEndpoint, _, relay := newInProcessProtectedRelayV1(t, 8130, 8)
	payload := []byte("fragmented-relay-payload")
	records, err := clientEndpoint.SealFragments(1, payload, []uint32{5, 7, uint32(len(payload) - 12)})
	if err != nil {
		t.Fatal(err)
	}
	for index, record := range records {
		delivered, ack, err := relayEndpoint.Deliver(record)
		if index < len(records)-1 {
			if err != nil || delivered != nil || ack.record != nil {
				t.Fatalf("pending %d delivery=%q ack=%x err=%v", index, delivered, ack.record, err)
			}
			continue
		}
		if err != nil || !bytes.Equal(delivered, payload) || ack.record == nil {
			t.Fatalf("final delivery=%q ack=%x err=%v", delivered, ack.record, err)
		}
		if err := clientEndpoint.AcceptAck(ack); err != nil {
			t.Fatal(err)
		}
	}
	if relay.state.life.receiveCompleted != 1 {
		t.Fatalf("fragmented receive count=%d", relay.state.life.receiveCompleted)
	}
}
