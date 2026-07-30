// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtime

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	"kurdistan/internal/crypto/auth"
	"kurdistan/internal/crypto/security"
	"kurdistan/internal/protocol/wirev1"
)

func TestProcessWireHandshakeV1EstablishesIndependentRoleResults(t *testing.T) {
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
	copy(digest[:], []byte("phase11-process-wire-plan-v1"))
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	relay, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()

	clientHello, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	assertProcessWireFrameV1(t, clientHello, wirev1.TypeClientHello, digest)
	serverHello, err := relay.AcceptClientHello(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	assertProcessWireFrameV1(t, serverHello, wirev1.TypeServerHello, digest)
	clientFinish, err := client.AcceptServerHello(serverHello)
	if err != nil {
		t.Fatal(err)
	}
	assertProcessWireFrameV1(t, clientFinish, wirev1.TypeClientFinish, digest)
	serverFinish, relayResult, err := relay.AcceptClientFinish(clientFinish)
	if err != nil {
		t.Fatal(err)
	}
	defer relayResult.Close()
	assertProcessWireFrameV1(t, serverFinish, wirev1.TypeServerFinish, digest)
	clientResult, err := client.AcceptServerFinish(serverFinish)
	if err != nil {
		t.Fatal(err)
	}
	defer clientResult.Close()

	clientContext, ok := clientResult.ContextSnapshotV1()
	if !ok {
		t.Fatal("missing client process context")
	}
	relayContext, ok := relayResult.ContextSnapshotV1()
	if !ok || !reflect.DeepEqual(clientContext, relayContext) {
		t.Fatal("client and relay process contexts diverged")
	}
	clientSecret, err := clientResult.TakeChannelSecretV1()
	if err != nil {
		t.Fatal(err)
	}
	defer wipeRuntimeBytesV1(clientSecret)
	relaySecret, err := relayResult.TakeChannelSecretV1()
	if err != nil {
		t.Fatal(err)
	}
	defer wipeRuntimeBytesV1(relaySecret)
	if !bytes.Equal(clientSecret, relaySecret) {
		t.Fatal("client and relay process secrets diverged")
	}
}

func TestProcessWireHandshakeV1RejectsOuterAuthorityMismatch(t *testing.T) {
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
	digest[0] = 1
	digest[1] = 2
	replay, err := auth.NewHandshakeReplayCache(64)
	if err != nil {
		t.Fatal(err)
	}
	client, err := NewProcessWireClientHandshakeV1(config, fixture.input.ClientDependencies, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	relay, err := NewProcessWireRelayHandshakeV1(config, fixture.input.ServerDependencies, replay, digest)
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	clientHello, err := client.Start()
	if err != nil {
		t.Fatal(err)
	}
	frame, err := wirev1.Decode(clientHello)
	if err != nil {
		t.Fatal(err)
	}
	frame.PlanDigest[0] ^= 1
	substituted, err := wirev1.Encode(frame)
	if err != nil {
		t.Fatal(err)
	}
	if response, err := relay.AcceptClientHello(substituted); response != nil || !errors.Is(err, ErrRecordInvalid) {
		t.Fatalf("plan substitution response=%x err=%v", response, err)
	}
	if response, err := relay.AcceptClientHello(clientHello); response != nil || !errors.Is(err, ErrSecureChannel) {
		t.Fatalf("closed relay response=%x err=%v", response, err)
	}
}

func assertProcessWireFrameV1(t *testing.T, encoded []byte, wantType uint8, digest [32]byte) {
	t.Helper()
	frame, err := wirev1.Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(frame.Payload)
	if frame.Type != wantType || frame.Flags != wirev1.FlagCritical || frame.StreamID != 0 ||
		frame.PlanDigest != digest || len(frame.Payload) == 0 {
		t.Fatalf("unexpected process wire frame: %+v", frame)
	}
}
