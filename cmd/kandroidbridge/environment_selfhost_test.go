//go:build !phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/backup"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/sessionplan"
	"kurdistan/internal/selfhost"
)

func TestReleaseBridgeRestoresVersionedRecipientKeyRecordWithVerifiedProfile(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	request, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{
		Ingress: envelope.IngressFile, Class: envelope.ArtifactSignedPublic, Parts: [][]byte{issued.Artifact},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer clear(request)
	keyRecord, err := hex.DecodeString("4b434b330301016b0400000000000000010000000000000002010161000101000102")
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyRecord)
	payload := backup.Payload{Version: 2, Records: []backup.Record{
		{Kind: backup.RecordNativeProfile, LocalID: "a", Generation: issued.Generation, ExactBytes: request},
		{Kind: backup.RecordLocalAlias, LocalID: "recipient-keys-v3", ExactBytes: keyRecord},
	}}
	encodedPayload, err := androidbridge.EncodeBackupPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedPayload)
	encodedBackup, code := androidbridge.BackupCreate(encodedPayload, passphrase)
	if code != androidbridge.CodeOK {
		t.Fatalf("backup create code=%v", code)
	}
	defer clear(encodedBackup)
	var handles androidbridge.HandleRegistry
	handle, preview, code := androidbridge.BackupOpenPreview(&handles, encodedBackup, passphrase)
	if code != androidbridge.CodeOK {
		t.Fatalf("backup open code=%v", code)
	}
	defer handles.Free(handle)
	defer clear(preview)
	restored, code := androidbridge.BackupRestore(&handles, handle, preview, selfHostedBridgeEnvironment{})
	if code != androidbridge.CodeOK {
		t.Fatalf("backup restore code=%v", code)
	}
	defer clear(restored)
	decoded, err := androidbridge.DecodeBackupPayload(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyReleaseBackupPayload(&decoded)
	if decoded.Version != 2 || len(decoded.Records) != 2 || decoded.Records[1].Kind != backup.RecordLocalAlias {
		t.Fatalf("restored payload=%+v", decoded)
	}
}

func TestReleaseBridgeKeepsNativeProfileIdentityBindingForVersionedBackup(t *testing.T) {
	if err := (selfHostedBridgeEnvironment{}).VerifyBackupRecord(backup.Record{
		Kind: backup.RecordNativeProfile, LocalID: "a", Generation: 1, ExactBytes: []byte("not-a-verify-request"),
	}); err == nil {
		t.Fatal("malformed native profile record was admitted")
	}
}

func destroyReleaseBackupPayload(payload *backup.Payload) {
	for index := range payload.Records {
		clear(payload.Records[index].ExactBytes)
	}
	*payload = backup.Payload{}
}

func TestReleaseBridgeVerifiesAndStagesOwnerSelfHostedProfile(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{Name: "phone", ValidFor: 24 * time.Hour, Now: now})
	if err != nil {
		t.Fatal(err)
	}
	request, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactSignedPublic, Parts: [][]byte{issued.Artifact}})
	if err != nil {
		t.Fatal(err)
	}
	environment := newBridgeEnvironment()
	preview, code := androidbridge.VerifyAndPreview(request, environment)
	if code != androidbridge.CodeOK || !bytes.Equal(preview.Verified.ExactArtifact, issued.Artifact) {
		t.Fatalf("release verification code=%v", code)
	}
	if !preview.Trust.OwnerControlled || preview.Trust.UpdatesEnabled ||
		preview.Trust.DeploymentFingerprint == "" || preview.Trust.RelayEndpoint != "203.0.113.7:443" ||
		preview.Trust.AuthorityScope != "deployment-local" || preview.Trust.UpdateLocation != "" {
		t.Fatalf("release first-trust preview=%+v", preview.Trust)
	}
	defer preview.Destroy()
	session, err := environment.NewActivationSession(preview)
	if err != nil {
		t.Fatal(err)
	}
	defer session.Destroy()
	command, ok := session.Next()
	if !ok || command.Kind != profile.ActivationCommandSnapshot || session.Submit(command, profile.ActivationCommandResult{}) != nil {
		t.Fatal("release activation did not request initial storage snapshot")
	}
	command, ok = session.Next()
	if !ok || command.Kind != profile.ActivationCommandStageCandidate || !bytes.Equal(command.Record.Artifact, issued.Artifact) {
		t.Fatal("release activation did not stage the exact owner artifact")
	}
}

func TestReleaseBridgeOpensProtectedRuntimeFromDeviceRecipientProfile(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("correct horse battery staple")
	now := time.Now().UTC().Truncate(time.Second)
	if _, err := selfhost.Initialize(selfhost.InitOptions{
		DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivateFixture(&private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := enrollment.EncodePrivateBundleV1(private)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(privateBytes)
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{
		Name: "phone", ValidFor: 12 * time.Hour, Now: now,
		RecipientRequest: requestBytes, LiveProgram: releaseLiveProgramFixture(t),
		RegistryDir: filepath.Join(base, "registry"),
	})
	if err != nil {
		t.Fatal(err)
	}
	verifyRequest, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{
		Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact},
	})
	if err != nil {
		t.Fatal(err)
	}
	environment := newBridgeEnvironment()
	var handles androidbridge.HandleRegistry
	verifiedHandle, previewBytes, code := androidbridge.OpenVerifyPreviewWithRecipient(
		&handles, verifyRequest, requestBytes, privateBytes, environment,
	)
	if code != androidbridge.CodeOK || len(previewBytes) == 0 {
		t.Fatalf("recipient verify code=%v", code)
	}
	activationHandle, code := androidbridge.OpenActivation(&handles, verifiedHandle, environment)
	if code != androidbridge.CodeOK {
		t.Fatalf("recipient activation open code=%v", code)
	}
	activationRecord := completeReleaseActivation(t, &handles, activationHandle)
	factory := &releaseFixtureNetworkFactory{network: &releaseFixtureNetwork{fd: 57}}
	runtimeRequest, err := androidbridge.EncodeRuntimeOpenRequestV2(androidbridge.RuntimeOpenRequestV2{
		VerifyRequest: verifyRequest, ActivationRecord: activationRecord,
		RecipientRequest: requestBytes, RecipientPrivate: privateBytes,
		Policy: androidbridge.RuntimePolicyRequest{
			SelectionMode: androidbridge.RuntimeSelectionAutomatic,
			PerAppMode:    androidbridge.RuntimePerAppAllApps,
			IPMode:        androidbridge.RuntimeIPV4Only,
			DNSMode:       androidbridge.RuntimeDNSInternal,
			MTU:           1280,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	runtimeHandle, snapshot, code := androidbridge.OpenRuntimeSessionV2(
		&handles, runtimeRequest, environment, factory, now,
	)
	if code != androidbridge.CodeOK || snapshot.Generation != issued.Generation || snapshot.PlanDigest == ([32]byte{}) {
		t.Fatalf("runtime open code=%v snapshot=%+v", code, snapshot)
	}
	fd, code := androidbridge.RuntimeSocketPrepare(&handles, runtimeHandle)
	if code != androidbridge.CodeOK || fd != 57 || factory.prepared == 0 {
		t.Fatalf("socket prepare fd=%d code=%v", fd, code)
	}
	if code := androidbridge.RuntimeSocketCommitProtected(&handles, runtimeHandle, true); code != androidbridge.CodeOK {
		t.Fatalf("protected commit code=%v", code)
	}
	if code := androidbridge.RuntimeTUNAttach(&handles, runtimeHandle, 73); code != androidbridge.CodeOK {
		t.Fatalf("TUN attach code=%v", code)
	}
	if state, code := androidbridge.RuntimeStatus(&handles, runtimeHandle); code != androidbridge.CodeOK || state != androidbridge.RuntimeStateRunning {
		t.Fatalf("runtime state=%v code=%v", state, code)
	}
	if got := factory.network.calls; !bytes.Equal([]byte(got), []byte("connect,tls,kurd,tun,start")) {
		t.Fatalf("network call order=%q", got)
	}
	if code := androidbridge.RuntimeStop(&handles, runtimeHandle); code != androidbridge.CodeOK || !factory.network.closed {
		t.Fatalf("runtime stop code=%v closed=%t", code, factory.network.closed)
	}

	wrongPrivate := bytes.Clone(privateBytes)
	wrongPrivate[len(wrongPrivate)-1] ^= 1
	defer clear(wrongPrivate)
	badRequest, err := androidbridge.EncodeRuntimeOpenRequestV2(androidbridge.RuntimeOpenRequestV2{
		VerifyRequest: verifyRequest, ActivationRecord: activationRecord,
		RecipientRequest: requestBytes, RecipientPrivate: wrongPrivate,
		Policy: androidbridge.RuntimePolicyRequest{
			SelectionMode: androidbridge.RuntimeSelectionAutomatic,
			PerAppMode:    androidbridge.RuntimePerAppAllApps,
			IPMode:        androidbridge.RuntimeIPV4Only,
			DNSMode:       androidbridge.RuntimeDNSInternal,
			MTU:           1280,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, code := androidbridge.OpenRuntimeSessionV2(&handles, badRequest, environment, factory, now); code == androidbridge.CodeOK {
		t.Fatal("wrong recipient private bundle opened a live runtime session")
	}
}

func completeReleaseActivation(t testing.TB, handles *androidbridge.HandleRegistry, handle androidbridge.Handle) []byte {
	t.Helper()
	var staged []byte
	for {
		next, code := androidbridge.ActivationNextCommand(handles, handle)
		if code != androidbridge.CodeOK {
			t.Fatalf("activation next code=%v", code)
		}
		if next.Kind == androidbridge.ActivationCommandComplete {
			return bytes.Clone(next.Payload)
		}
		var reopened []byte
		if next.Kind == profile.ActivationCommandStageCandidate {
			staged = bytes.Clone(next.Payload)
		}
		if next.Kind == profile.ActivationCommandReopenCandidate {
			reopened = staged
		}
		if code := androidbridge.SubmitActivationCommand(
			handles, handle, next.Sequence, next.Kind, true, nil, nil, reopened,
		); code != androidbridge.CodeOK {
			t.Fatalf("activation submit %s code=%v", next.Kind, code)
		}
	}
}

type releaseFixtureNetworkFactory struct {
	network  *releaseFixtureNetwork
	prepared int
}

func (factory *releaseFixtureNetworkFactory) Prepare(_ context.Context, plan sessionplan.PlanV2, seed []byte, _ uint8) (androidbridge.RuntimeNetworkSession, androidbridge.ErrorCode) {
	factory.prepared++
	defer clear(seed)
	if plan.Digest == ([32]byte{}) || len(seed) == 0 {
		return nil, androidbridge.CodePolicyRejected
	}
	return factory.network, androidbridge.CodeOK
}

type releaseFixtureNetwork struct {
	fd     int
	calls  string
	closed bool
}

func (network *releaseFixtureNetwork) appendCall(value string) {
	if network.calls != "" {
		network.calls += ","
	}
	network.calls += value
}

func (network *releaseFixtureNetwork) SocketFD() (int, androidbridge.ErrorCode) {
	return network.fd, androidbridge.CodeOK
}

func (network *releaseFixtureNetwork) ConnectProtected(context.Context) androidbridge.ErrorCode {
	network.appendCall("connect")
	return androidbridge.CodeOK
}

func (network *releaseFixtureNetwork) AuthenticateTLS(context.Context) androidbridge.ErrorCode {
	network.appendCall("tls")
	return androidbridge.CodeOK
}

func (network *releaseFixtureNetwork) AuthenticateKurd(context.Context) androidbridge.ErrorCode {
	network.appendCall("kurd")
	return androidbridge.CodeOK
}

func (network *releaseFixtureNetwork) AttachTUN(_ context.Context, fd int) androidbridge.ErrorCode {
	if fd != 73 {
		return androidbridge.CodePolicyRejected
	}
	network.appendCall("tun")
	return androidbridge.CodeOK
}

func (network *releaseFixtureNetwork) Start(context.Context) androidbridge.ErrorCode {
	network.appendCall("start")
	return androidbridge.CodeOK
}
func (*releaseFixtureNetwork) Status() androidbridge.ErrorCode { return androidbridge.CodeOK }

func (network *releaseFixtureNetwork) Close() androidbridge.ErrorCode {
	network.closed = true
	return androidbridge.CodeOK
}
