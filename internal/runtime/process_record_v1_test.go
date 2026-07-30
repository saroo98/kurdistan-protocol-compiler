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

func TestProcessRecordV1BindsCarrierDeliversAndAcknowledges(t *testing.T) {
	client, relay, exporter := newProcessRecordPairV1(t)
	bindProcessRecordPairV1(t, client, relay, exporter)

	record, err := client.Seal(7, []byte("phase11-independent-record"))
	if err != nil {
		t.Fatal(err)
	}
	payload, delivery, err := relay.Open(record)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "phase11-independent-record" {
		t.Fatalf("payload=%q", payload)
	}
	clear(payload)
	ack, err := delivery.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptAck(ack); err != nil {
		t.Fatal(err)
	}
	if _, err := delivery.Commit(); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("delivery committed twice: %v", err)
	}

	closeRecord, err := client.CloseRecord()
	if err != nil {
		t.Fatal(err)
	}
	if err := relay.AcceptClose(closeRecord); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRecordV1FailureMatrixIsTerminal(t *testing.T) {
	t.Run("wrong exporter", func(t *testing.T) {
		client, relay, exporter := newProcessRecordPairV1(t)
		bind, err := client.ProfileBind(exporter)
		if err != nil {
			t.Fatal(err)
		}
		exporter[0] ^= 1
		if ready, err := relay.AcceptProfileBind(bind, exporter); ready != nil || !errors.Is(err, ErrRecordInvalid) {
			t.Fatalf("wrong exporter ready=%x err=%v", ready, err)
		}
		if ready, err := relay.AcceptProfileBind(bind, exporter); ready != nil || !errors.Is(err, ErrSecureChannel) {
			t.Fatalf("closed relay ready=%x err=%v", ready, err)
		}
	})

	t.Run("tampered data", func(t *testing.T) {
		client, relay, exporter := newProcessRecordPairV1(t)
		bindProcessRecordPairV1(t, client, relay, exporter)
		record, err := client.Seal(1, []byte("tamper"))
		if err != nil {
			t.Fatal(err)
		}
		record[len(record)-1] ^= 1
		payload, delivery, err := relay.Open(record)
		clear(payload)
		if delivery != nil || !errors.Is(err, security.ErrAuthenticationFailed) {
			t.Fatalf("tamper delivery=%v err=%v", delivery, err)
		}
		if _, _, err := relay.Open(record); !errors.Is(err, ErrSecureChannel) {
			t.Fatalf("closed relay accepted retry: %v", err)
		}
	})

	t.Run("replay", func(t *testing.T) {
		client, relay, exporter := newProcessRecordPairV1(t)
		bindProcessRecordPairV1(t, client, relay, exporter)
		record, err := client.Seal(2, []byte("once"))
		if err != nil {
			t.Fatal(err)
		}
		payload, delivery, err := relay.Open(record)
		if err != nil {
			t.Fatal(err)
		}
		clear(payload)
		ack, err := delivery.Commit()
		if err != nil {
			t.Fatal(err)
		}
		if err := client.AcceptAck(ack); err != nil {
			t.Fatal(err)
		}
		payload, replayDelivery, err := relay.Open(record)
		clear(payload)
		if replayDelivery != nil || !errors.Is(err, security.ErrReplayDuplicate) {
			t.Fatalf("replay delivery=%v err=%v", replayDelivery, err)
		}
	})

	t.Run("delivery rejection", func(t *testing.T) {
		client, relay, exporter := newProcessRecordPairV1(t)
		bindProcessRecordPairV1(t, client, relay, exporter)
		record, err := client.Seal(3, []byte("sink-fails"))
		if err != nil {
			t.Fatal(err)
		}
		payload, delivery, err := relay.Open(record)
		if err != nil {
			t.Fatal(err)
		}
		clear(payload)
		delivery.Reject()
		if ack, err := delivery.Commit(); ack != nil || !errors.Is(err, ErrSecureChannel) {
			t.Fatalf("rejected delivery ack=%x err=%v", ack, err)
		}
		if _, _, err := relay.Open(record); !errors.Is(err, ErrSecureChannel) {
			t.Fatalf("rejected relay remained usable: %v", err)
		}
		client.Abort()
	})

}

func TestProcessRecordV1RejectsDataBeforeCarrierBinding(t *testing.T) {
	client, relay, _ := newProcessRecordPairV1(t)
	if record, err := client.Seal(1, []byte("early")); record != nil || !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("pre-bind client record=%x err=%v", record, err)
	}
	if payload, delivery, err := relay.Open([]byte{1}); payload != nil || delivery != nil || !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("pre-bind relay payload=%x delivery=%v err=%v", payload, delivery, err)
	}
}

func newProcessRecordPairV1(t *testing.T) (*ProcessClientRecordEndpointV1, *ProcessRelayRecordEndpointV1, [32]byte) {
	t.Helper()
	fixture := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	config, err := auth.NewProcessHandshakeConfigV1(
		fixture.input.Client,
		fixture.input.Server,
		fixture.input.SelectedPolicy,
		fixture.input.SelectedCapabilities,
	)
	if err != nil {
		t.Fatal(err)
	}
	var digest [32]byte
	copy(digest[:], []byte("phase11-process-record-plan-v1"))
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	clientHandshake, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	relayHandshake, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	clientHello, err := clientHandshake.Start()
	if err != nil {
		t.Fatal(err)
	}
	serverHello, err := relayHandshake.AcceptClientHello(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	clientFinish, err := clientHandshake.AcceptServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	serverFinish, relayResult, err := relayHandshake.AcceptClientFinish(clientFinish)
	if err != nil {
		t.Fatal(err)
	}
	clientResult, err := clientHandshake.AcceptServerFinish(serverFinish)
	if err != nil {
		relayResult.Close()
		t.Fatal(err)
	}
	client, err := NewProcessClientRecordEndpointV1(clientResult, digest)
	if err != nil {
		relayResult.Close()
		t.Fatal(err)
	}
	relay, err := NewProcessRelayRecordEndpointV1(relayResult, digest)
	if err != nil {
		client.Abort()
		t.Fatal(err)
	}
	t.Cleanup(client.Abort)
	t.Cleanup(relay.Abort)
	return client, relay, [32]byte{9, 8, 7, 6, 5, 4, 3, 2, 1}
}

func bindProcessRecordPairV1(t *testing.T, client *ProcessClientRecordEndpointV1, relay *ProcessRelayRecordEndpointV1, exporter [32]byte) {
	t.Helper()
	bind, err := client.ProfileBind(exporter)
	if err != nil {
		t.Fatal(err)
	}
	ready, err := relay.AcceptProfileBind(bind, exporter)
	if err != nil {
		t.Fatal(err)
	}
	if err := client.AcceptEngineReady(ready); err != nil {
		t.Fatal(err)
	}
}

func TestProcessRecordV1DistinctEndpointsProduceCompatibleCiphertext(t *testing.T) {
	client, relay, exporter := newProcessRecordPairV1(t)
	bindProcessRecordPairV1(t, client, relay, exporter)
	first, err := client.Seal(10, []byte("one"))
	if err != nil {
		t.Fatal(err)
	}
	second, err := client.Seal(11, []byte("two"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(first, second) {
		t.Fatal("distinct process records reused wire bytes")
	}
	for _, record := range [][]byte{first, second} {
		payload, delivery, err := relay.Open(record)
		if err != nil {
			t.Fatal(err)
		}
		clear(payload)
		ack, err := delivery.Commit()
		if err != nil {
			t.Fatal(err)
		}
		if err := client.AcceptAck(ack); err != nil {
			t.Fatal(err)
		}
	}
}
