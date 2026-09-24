// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"context"
	"encoding/binary"
	"errors"
	"testing"
	"time"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/wirev1"
	"kurdistan/internal/transport/tlstcp"
)

func TestCompleteProcessClientHandshakeV1MalformedPeerOutcomes(t *testing.T) {
	for _, scenario := range []string{"maximum-unexpected-type", "maximum-finish", "wrong-digest", "wrong-flags", "bad-signature"} {
		t.Run(scenario, func(t *testing.T) {
			f := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
			digest := [32]byte{3}
			client, relay := phase11ProcessWireHandshakesV1(t, f, digest)
			carrier, peer := productionTLSFixtureV1(t, digest, 1<<20)
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			done := make(chan error, 1)
			go func() {
				defer relay.Close()
				defer peer.Close()
				ch, e := receiveEncodedProcessFrameV1(ctx, peer)
				if e != nil {
					done <- e
					return
				}
				sh, e := relay.AcceptClientHello(ch)
				clear(ch)
				if e != nil {
					done <- e
					return
				}
				if scenario == "maximum-finish" {
					e = sendEncodedProcessFrameV1(ctx, peer, sh)
					clear(sh)
					if e != nil {
						done <- e
						return
					}
					cf, receiveErr := receiveEncodedProcessFrameV1(ctx, peer)
					if receiveErr != nil {
						done <- receiveErr
						return
					}
					var genuine *auth.ProcessHandshakeResultV1
					sh, genuine, e = relay.AcceptClientFinish(cf)
					clear(cf)
					if genuine != nil {
						genuine.Close()
					}
					if e != nil {
						done <- e
						return
					}
				}
				frame, e := wirev1.Decode(sh)
				clear(sh)
				if e != nil {
					done <- e
					return
				}
				switch scenario {
				case "maximum-finish":
					clear(frame.Payload)
					frame.Payload = make([]byte, wirev1.MaxControlBytes)
					binary.BigEndian.PutUint32(frame.Payload[:4], uint32(len(frame.Payload)-4))
				case "maximum-unexpected-type":
					clear(frame.Payload)
					frame.Type = wirev1.TypeReliableData
					frame.StreamID = 1
					frame.Payload = make([]byte, (1<<20)-wirev1.HeaderBytes)
				case "wrong-digest":
					frame.PlanDigest[0] ^= 1
				case "wrong-flags":
					frame.Flags = 0
				case "bad-signature":
					frame.Payload[len(frame.Payload)-1] ^= 1
				}
				done <- peer.Send(ctx, frame)
				clear(frame.Payload)
			}()
			result, err := CompleteProcessClientHandshakeV1(ctx, carrier, client)
			if result != nil {
				result.Close()
				t.Fatal("malformed peer returned result")
			}
			if err == nil {
				t.Fatal("malformed peer accepted")
			}
			sendErr := <-done
			if scenario == "wrong-digest" {
				// The genuine sender rejects its own mismatched digest, so no wrong
				// digest is claimed to have crossed TLS. Closing the peer then gives
				// the result-only helper its ordinary receive failure.
				if !errors.Is(sendErr, tlstcp.ErrCarrier) {
					t.Fatal("sender digest guard", sendErr)
				}
			} else if sendErr != nil {
				t.Fatal("fixture send", sendErr)
			}
			switch scenario {
			case "maximum-finish":
				var e *auth.HandshakeError
				if !errors.As(err, &e) || e.Code != auth.FailureInvalidEncoding {
					t.Fatal("maximum finish outcome", err)
				}
			case "wrong-digest":
				if !errors.Is(err, ErrProcessSessionV1) {
					t.Fatal("carrier digest outcome", err)
				}
			case "bad-signature":
				var e *auth.HandshakeError
				if !errors.As(err, &e) || e.Code != auth.FailureSignatureInvalid {
					t.Fatal("signature outcome", err)
				}
			default:
				if !errors.Is(err, ErrRecordInvalid) {
					t.Fatal("outer rejection outcome", err)
				}
			}
		})
	}
}

func TestCompleteProcessClientHandshakeV1RealResult(t *testing.T) {
	f := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	digest := [32]byte{3}
	c, r := phase11ProcessWireHandshakesV1(t, f, digest)
	carrier, peer := productionTLSFixtureV1(t, digest, 1<<20)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	peerErr := make(chan error, 1)
	go func() {
		defer r.Close()
		ch, err := receiveEncodedProcessFrameV1(ctx, peer)
		if err != nil {
			peerErr <- err
			return
		}
		sh, err := r.AcceptClientHello(ch)
		clear(ch)
		if err != nil {
			peerErr <- err
			return
		}
		err = sendEncodedProcessFrameV1(ctx, peer, sh)
		clear(sh)
		if err != nil {
			peerErr <- err
			return
		}
		cf, err := receiveEncodedProcessFrameV1(ctx, peer)
		if err != nil {
			peerErr <- err
			return
		}
		sf, result, err := r.AcceptClientFinish(cf)
		clear(cf)
		if err != nil {
			peerErr <- err
			return
		}
		defer result.Close()
		err = sendEncodedProcessFrameV1(ctx, peer, sf)
		clear(sf)
		peerErr <- err
	}()
	result, err := CompleteProcessClientHandshakeV1(ctx, carrier, c)
	if err != nil {
		t.Fatal(err)
	}
	defer result.Close()
	if err := <-peerErr; err != nil {
		t.Fatal(err)
	}
	// The caller, not the result-only exchange, still owns the first secret Take.
	secret, err := result.TakeChannelSecretV1()
	if err != nil || len(secret) == 0 {
		t.Fatalf("fresh result: %v", err)
	}
	clear(secret)
	if _, err := c.Start(); !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("serial wrapper not closed: %v", err)
	}
}

func TestCompleteProcessClientHandshakeV1RejectsNil(t *testing.T) {
	var result *auth.ProcessHandshakeResultV1
	var err error
	result, err = CompleteProcessClientHandshakeV1(nil, nil, nil)
	if result != nil || !errors.Is(err, ErrProcessSessionV1) {
		t.Fatalf("nil arguments: %v", err)
	}
}

func TestProcessClientAttemptReceiverRejectsWrongDigestV1(t *testing.T) {
	f := newStrictSupportFixtureV1(t, security.TranscriptCanonicalV1, "strict_suite_and_capabilities", "strict_required")
	c, r := phase11ProcessWireHandshakesV1(t, f, [32]byte{3})
	defer c.Close()
	defer r.Close()
	ch, err := c.Start()
	if err != nil {
		t.Fatal(err)
	}
	sh, err := r.AcceptClientHello(ch)
	clear(ch)
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wirev1.Decode(sh)
	clear(sh)
	if err != nil {
		t.Fatal(err)
	}
	frame.PlanDigest[0] ^= 1
	wrong, err := wirev1.Encode(frame)
	clear(frame.Payload)
	if err != nil {
		t.Fatal(err)
	}
	response, err := c.AcceptServerHello(wrong)
	clear(wrong)
	if response != nil || !errors.Is(err, ErrRecordInvalid) {
		t.Fatal("receiver digest outcome", err)
	}
}

func TestProcessClientHandshakeWorkspaceV1(t *testing.T) {
	p := testDuplexProgramV1()
	b, err := ProcessClientHandshakeWorkspaceV1(p, "runtime-client", "runtime-server")
	if err != nil || b == 0 {
		t.Fatalf("workspace: %d %v", b, err)
	}
	if n := testing.AllocsPerRun(20, func() { _, _ = ProcessClientHandshakeWorkspaceV1(p, "runtime-client", "runtime-server") }); n != 0 {
		t.Fatalf("allocated: %v", n)
	}
	p.Limits.MaxFrameBytes = 1 << 20
	maximum, err := ProcessClientHandshakeWorkspaceV1(p, "runtime-client", "runtime-server")
	if err != nil || maximum < b {
		t.Fatalf("maximum: %d %v", maximum, err)
	}
	p.Limits.MaxFrameBytes++
	if _, err := ProcessClientHandshakeWorkspaceV1(p, "runtime-client", "runtime-server"); err == nil {
		t.Fatal("unbounded frame accepted")
	}
}
