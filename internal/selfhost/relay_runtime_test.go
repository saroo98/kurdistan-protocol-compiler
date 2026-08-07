// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/product/enrollment"
)

func TestOpenRelayRuntimeSnapshotReturnsOnlyCurrentLiveAuthority(t *testing.T) {
	dataDir, recoveryPath, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivate(private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := CreateProfile(dataDir, CreateProfileOptions{
		Name: "relay-device", ValidFor: 24 * time.Hour, Now: now,
		RecipientRequest: requestBytes, LiveProgram: testLiveProgramV1(t, 1710),
		RegistryDir: filepath.Join(t.TempDir(), "registry"),
	})
	if err != nil {
		t.Fatal(err)
	}

	snapshot, err := OpenRelayRuntimeSnapshotV1(dataDir, now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	status, ok := snapshot.StatusV1()
	if !ok || status.Revision == 0 || status.RelayKeyID == "" || status.TLSKeyID == "" || status.AdmissionCount != 1 || status.Drained {
		t.Fatalf("unexpected relay runtime status: %+v ok=%v", status, ok)
	}
	admission, ok := snapshot.AdmissionByClientKeyIDV1(request.ClientAuthKeyID)
	if !ok || admission.ProfileID != issued.ProfileID || admission.ContentID != issued.ContentID || admission.Generation != issued.Generation ||
		admission.ClientAuthKeyID != request.ClientAuthKeyID || !bytes.Equal(admission.ClientAuthPublic[:], request.ClientAuthPublic) ||
		admission.ValidFrom != now.Unix() || admission.ValidUntil != issued.ValidUntil || len(admission.AssignedIPv4) != 4 ||
		admission.RuntimePolicy.ClientAuthKeyID != request.ClientAuthKeyID || len(admission.StrategyIDs) != 1 ||
		admission.StrategyIDs[0] != "strategy.kurd-tls13-tcp" || len(admission.RelayIDs) != 1 || admission.RelayIDs[0] != status.RelayKeyID {
		t.Fatalf("unexpected relay admission: %+v ok=%v", admission, ok)
	}
	byProfile, ok := snapshot.AdmissionByProfileV1(issued.ContentID, issued.Generation)
	if !ok || byProfile.ClientAuthKeyID != admission.ClientAuthKeyID {
		t.Fatalf("profile-bound relay admission unavailable: %+v ok=%v", byProfile, ok)
	}
	if _, ok := snapshot.AdmissionByProfileV1(issued.ContentID, issued.Generation+1); ok {
		t.Fatal("stale profile generation retained relay authority")
	}

	localOne, err := snapshot.Local(status.RelayKeyID)
	if err != nil || len(localOne) != ed25519.PrivateKeySize || !bytes.Equal(localOne.Public().(ed25519.PublicKey), status.RelayPublic[:]) {
		t.Fatalf("relay identity unavailable: len=%d err=%v", len(localOne), err)
	}
	localOne[0] ^= 1
	localTwo, err := snapshot.Local(status.RelayKeyID)
	if err != nil || bytes.Equal(localOne, localTwo) {
		t.Fatal("relay identity was not defensively copied")
	}
	clear(localOne)
	clear(localTwo)
	peer, err := snapshot.Peer(request.ClientAuthKeyID)
	if err != nil || !bytes.Equal(peer, request.ClientAuthPublic) {
		t.Fatalf("client trust unavailable: err=%v", err)
	}
	peer[0] ^= 1
	peerAgain, err := snapshot.Peer(request.ClientAuthKeyID)
	if err != nil || bytes.Equal(peer, peerAgain) {
		t.Fatal("client trust was not defensively copied")
	}

	tlsConfig, err := snapshot.ServerTLSConfigV1()
	if err != nil || len(tlsConfig.Certificates) != 1 || len(tlsConfig.Certificates[0].Certificate) != 1 || tlsConfig.Certificates[0].PrivateKey == nil {
		t.Fatalf("TLS runtime identity unavailable: err=%v", err)
	}
	admission.AssignedIPv4[0] ^= 1
	admission.RuntimePolicy.LiveProgram[0] ^= 1
	admissionAgain, ok := snapshot.AdmissionByClientKeyIDV1(request.ClientAuthKeyID)
	if !ok || bytes.Equal(admission.AssignedIPv4, admissionAgain.AssignedIPv4) || bytes.Equal(admission.RuntimePolicy.LiveProgram, admissionAgain.RuntimePolicy.LiveProgram) {
		t.Fatal("relay admission was not defensively copied")
	}

	snapshot.Close()
	if _, ok := snapshot.StatusV1(); ok {
		t.Fatal("closed snapshot retained status authority")
	}
	if _, ok := snapshot.AdmissionByClientKeyIDV1(request.ClientAuthKeyID); ok {
		t.Fatal("closed snapshot retained admission authority")
	}
	if _, ok := snapshot.AdmissionByProfileV1(issued.ContentID, issued.Generation); ok {
		t.Fatal("closed snapshot retained profile lookup authority")
	}
	if _, err := snapshot.Local(status.RelayKeyID); !errors.Is(err, ErrRelayRuntimeUnavailable) {
		t.Fatalf("closed relay identity err=%v", err)
	}
	if _, err := snapshot.ServerTLSConfigV1(); !errors.Is(err, ErrRelayRuntimeUnavailable) {
		t.Fatalf("closed TLS identity err=%v", err)
	}
}

func TestOpenRelayRuntimeSnapshotRejectsDrainedOrExpiredState(t *testing.T) {
	dataDir, recoveryPath, passphrase := initializedV2TestState(t)
	now := time.Unix(1_760_000_010, 0).UTC()
	if err := ConfirmRecovery(dataDir, recoveryPath, passphrase, now); err != nil {
		t.Fatal(err)
	}
	if err := SetDrained(dataDir, true, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := OpenRelayRuntimeSnapshotV1(dataDir, now.Add(2*time.Second)); snapshot != nil || !errors.Is(err, ErrDrained) {
		t.Fatalf("drained runtime snapshot=%v err=%v", snapshot, err)
	}
	if err := SetDrained(dataDir, false, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if snapshot, err := OpenRelayRuntimeSnapshotV1(dataDir, now.Add(91*24*time.Hour)); snapshot != nil || !errors.Is(err, ErrTLSUnavailable) {
		t.Fatalf("expired TLS runtime snapshot=%v err=%v", snapshot, err)
	}
}
