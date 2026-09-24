//go:build !phase9internal || (phase18outputtest && cgo && linux && !android)

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/backup"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
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

func TestRecipientTrustPreviewDestroysDiscardedMutableGraph(t *testing.T) {
	for _, failure := range []bool{false, true} {
		artifact := []byte{1, 2, 3}
		rawProfile := []byte{4, 5, 6}
		owned := profile.OfflineVerifiedArtifact{ExactArtifact: artifact}
		owned.Profile.Policy = rawProfile
		var verifyErr error
		if failure {
			verifyErr = errors.New("verification rejected")
		}
		result, err := recipientTrustPreviewAndDestroy(selfhost.VerifiedBundle{}, owned, verifyErr)
		if (err != nil) != failure {
			t.Fatalf("error parity: %v", err)
		}
		if failure && result != (androidbridge.TrustPreview{}) {
			t.Fatal("failed trust returned result")
		}
		if !bytes.Equal(artifact, make([]byte, len(artifact))) || !bytes.Equal(rawProfile, make([]byte, len(rawProfile))) {
			t.Fatal("discarded verified owner retained bytes")
		}
	}
}

func TestReleaseBridgeKeepsNativeProfileIdentityBindingForVersionedBackup(t *testing.T) {
	if err := (selfHostedBridgeEnvironment{}).VerifyBackupRecord(backup.Record{
		Kind: backup.RecordNativeProfile, LocalID: "a", Generation: 1, ExactBytes: []byte("not-a-verify-request"),
	}); err == nil {
		t.Fatal("malformed native profile record was admitted")
	}
}

func TestReleaseRecipientBackupRevalidatesCredentialsArtifactAndGeneration(t *testing.T) {
	f := newReleaseMaintenanceFixtureAt(t, time.Now().UTC().Add(-time.Minute))
	defer clear(f.current.RecipientPrivate)
	defer clear(f.current.RecipientRequest)
	defer clear(f.current.VerifyRequest)
	defer clear(f.current.ActivationRecord)
	defer clear(f.passphrase)
	environment := selfHostedBridgeEnvironment{}
	preview, code := androidbridge.VerifyAndPreviewWithRecipient(f.current.VerifyRequest,
		f.current.RecipientRequest, f.current.RecipientPrivate, environment)
	if code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	defer preview.Destroy()
	record := backup.Record{Kind: backup.RecordNativeProfile, LocalID: "a", Generation: preview.Verified.Profile.Generation, ExactBytes: f.current.VerifyRequest}
	key := backup.RecipientKeyRecord{SourceVersion: 2, SourceStatus: 4, SourceProfiles: []string{"a"},
		PublicRequest: f.current.RecipientRequest, PrivateBundle: f.current.RecipientPrivate}
	if err := environment.VerifyBackupRecordWithRecipient(record, key); err != nil {
		t.Fatal(err)
	}
	for _, changed := range []string{"generation", "binding", "private", "artifact", "legacy"} {
		t.Run(changed, func(t *testing.T) {
			r, k := record, key
			r.ExactBytes = bytes.Clone(record.ExactBytes)
			k.PrivateBundle = bytes.Clone(key.PrivateBundle)
			defer clear(r.ExactBytes)
			defer clear(k.PrivateBundle)
			switch changed {
			case "generation":
				r.Generation++
			case "binding":
				k.SourceProfiles = []string{"other"}
			case "private":
				k.PrivateBundle[len(k.PrivateBundle)-1] ^= 1
			case "artifact":
				r.ExactBytes[len(r.ExactBytes)-1] ^= 1
			case "legacy":
				k.SourceVersion = 1
			}
			if err := environment.VerifyBackupRecordWithRecipient(r, k); err == nil {
				t.Fatal("changed recipient record accepted")
			}
		})
	}
}

func TestSelfHostedBridgeMaintenanceVerificationUsesSuppliedTimeAndBounds(t *testing.T) {
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	passphrase := []byte("maintenance fixture recovery passphrase")
	now := time.Unix(1_780_000_000, 0).UTC()
	if _, err := selfhost.Initialize(selfhost.InitOptions{
		DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443",
		RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: now,
	}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, now); err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clearEnrollmentPrivateFixture(&private)
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{
		Name: "maintenance-device", ValidFor: 12 * time.Hour, Now: now,
		RecipientRequest: requestBytes, LiveProgram: releaseLiveProgramFixture(t),
		RegistryDir: filepath.Join(base, "registry"),
	})
	if err != nil {
		t.Fatal(err)
	}
	limits := selfhost.LiveMaintenanceLimits{
		OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20,
	}
	environment := selfHostedBridgeEnvironment{}
	credentials := androidbridge.RecipientCredentials{Request: request, Private: private}
	verified, bounds, err := environment.VerifyWithRecipientAt(issued.Artifact, envelope.ArtifactDeviceRecipient, credentials.Clone(), now, limits)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		clear(verified.ExactArtifact)
		clear(verified.ExactSignedObject)
		clear(verified.Profile.Policy)
	}()
	if !bytes.Equal(verified.ExactArtifact, issued.Artifact) || bounds.BudgetBytes != limits.OwnedBudgetBytes || bounds.PeakReservedBytes == 0 {
		t.Fatalf("verified=%t bounds=%+v", bytes.Equal(verified.ExactArtifact, issued.Artifact), bounds)
	}
	if _, _, err := environment.VerifyWithRecipientAt(issued.Artifact, envelope.ArtifactDeviceRecipient, credentials.Clone(), now.Add(13*time.Hour), limits); err == nil {
		t.Fatal("supplied expired time was ignored")
	}
}

func TestSelfHostedBridgeProductionCurrentConsumesCloneAndSuppliedTime(t *testing.T) {
	f := newReleaseMaintenanceFixture(t)
	credentials, code := androidbridge.DecodeRecipientCredentials(f.current.RecipientRequest, f.current.RecipientPrivate)
	if code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	defer credentials.Destroy()
	record, err := androidbridge.DecodeActivationRecord(f.current.ActivationRecord)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(record.Artifact)
	defer clear(record.SignedObject)
	defer clear(record.Profile.Policy)
	limits := selfhost.LiveMaintenanceLimits{OwnedBudgetBytes: 128 << 20, MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20}
	before := bytes.Clone(credentials.Private.RecipientPrivate)
	for _, tc := range []struct {
		name  string
		class envelope.ArtifactClass
		now   time.Time
		good  bool
	}{
		{"current", envelope.ArtifactDeviceRecipient, f.now, true},
		{"expired", envelope.ArtifactDeviceRecipient, f.now.Add(13 * time.Hour), false},
		{"wrong-class", envelope.ArtifactSignedPublic, f.now, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clone := credentials.Clone()
			secret, seed := clone.Private.RecipientPrivate, clone.Private.ClientAuthSeed
			v, err := (selfHostedBridgeEnvironment{}).VerifyProductionCurrentAt(record.Artifact, tc.class, record.State, clone, tc.now, limits)
			if !bytes.Equal(secret, make([]byte, len(secret))) || !bytes.Equal(seed, make([]byte, len(seed))) {
				t.Fatal("environment did not consume clone")
			}
			if !bytes.Equal(credentials.Private.RecipientPrivate, before) {
				t.Fatal("environment wiped source credentials")
			}
			if !tc.good {
				if v != nil {
					v.Destroy()
					t.Fatal("invalid current escaped")
				}
				if err == nil {
					t.Fatal("invalid current accepted")
				}
				return
			}
			if err != nil || v == nil {
				t.Fatalf("missing current: %v", err)
			}
			defer v.Destroy()
			if err := v.WithVerifiedV1(func(got profile.OfflineVerifiedArtifact, state lifecycle.VerifiedState, p runtimepolicy.PolicyV2, end time.Time) error {
				if state != record.State || !bytes.Equal(got.ExactArtifact, record.Artifact) || len(p.LiveProgram) == 0 || !end.After(f.now) {
					t.Fatal("concrete environment lost proof")
				}
				return nil
			}); err != nil {
				t.Fatal(err)
			}
		})
	}
	clone := credentials.Clone()
	_, err = (selfHostedBridgeEnvironment{}).VerifyProductionCurrentAt(nil, envelope.ArtifactSignedPublic, lifecycle.VerifiedState{}, clone, time.Time{}, selfhost.LiveMaintenanceLimits{})
	var verification *selfhost.LiveMaintenanceVerificationError
	if err == nil || errors.As(err, &verification) {
		t.Fatal("wrong class entered expensive selfhost verification")
	}
}

func TestOpenMaintenanceUsesFreshCurrentRecordAndPlatformRegistration(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	var registry androidbridge.HandleRegistry
	platform := &releaseMaintenancePlatform{}
	clockCalls := 0
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, androidbridge.MaintenanceConfigV1{
		Limits: selfhost.LiveMaintenanceLimits{
			MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20,
		},
		OwnedBudgetBytes: 128 << 20,
		Now: func() time.Time {
			clockCalls++
			return fixture.now
		},
	})
	if result != androidbridge.MaintenanceSuccess || handle == 0 {
		t.Fatalf("open handle=%d result=%d", handle, result)
	}
	if platform.registered != 1 || platform.registration.revalidated == 0 {
		t.Fatalf("platform registered=%d revalidated=%d", platform.registered, platform.registration.revalidated)
	}
	if platform.registration.leases != 1 || platform.registration.leaseCloses != 1 || platform.registration.closed != 0 {
		t.Fatalf("leases=%d lease closes=%d registration closes=%d", platform.registration.leases, platform.registration.leaseCloses, platform.registration.closed)
	}
	if clockCalls != 3 {
		t.Fatalf("open clock calls=%d", clockCalls)
	}
	if got := androidbridge.MaintenanceStatusV1(&registry, handle); got != androidbridge.MaintenanceSuccess {
		t.Fatalf("status=%d", got)
	}
	if code := registry.Free(handle); code != androidbridge.CodeOK || platform.registration.closed != 1 {
		t.Fatalf("free code=%v registration closes=%d", code, platform.registration.closed)
	}
}

func TestOpenMaintenanceRejectsCurrentArtifactAboveConfiguredCapBeforePlatformRegistration(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	config := maintenanceConfig(fixture.now)
	config.Limits.MaxArtifactBytes = 1
	var registry androidbridge.HandleRegistry
	platform := &releaseMaintenancePlatform{}
	if handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, config); handle != 0 || result != androidbridge.MaintenanceSizeLimit || platform.registered != 0 {
		t.Fatalf("handle=%d result=%d registered=%d", handle, result, platform.registered)
	}
}

func TestOpenMaintenanceRechecksFreshTimeUnderPublicationFence(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	now := fixture.now
	platform := &releaseMaintenancePlatform{}
	platform.registration.beforeAcquire = func() {
		now = fixture.now.Add(13 * time.Hour)
		platform.registration.beforeAcquire = nil
	}
	var registry androidbridge.HandleRegistry
	config := maintenanceConfig(now)
	config.Now = func() time.Time { return now }
	if handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, config); handle != 0 || result != androidbridge.MaintenanceExpired || platform.registration.closed != 1 {
		t.Fatalf("handle=%d result=%d registration closes=%d", handle, result, platform.registration.closed)
	}
}

func TestMaintenanceCandidateIsOneShotAndShortOutputDoesNotConsume(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	now := fixture.now
	platform := &releaseMaintenancePlatform{}
	var registry androidbridge.HandleRegistry
	config := maintenanceConfig(now)
	config.Now = func() time.Time { return now }
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, config)
	if result != androidbridge.MaintenanceSuccess {
		t.Fatalf("open result=%d", result)
	}
	defer registry.Free(handle)
	currentRequest, err := androidbridge.DecodeVerifyRequest(fixture.current.VerifyRequest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for i := range currentRequest.Parts {
			clear(currentRequest.Parts[i])
		}
	}()
	noChange := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, currentRequest.Parts[0])
	if noChange.Result != androidbridge.MaintenanceNoChange || noChange.Candidate != 0 || noChange.Preview != (selfhost.LiveMaintenancePreviewV1{}) {
		t.Fatalf("no-change metadata=%+v", noChange)
	}

	next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
		ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
		ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = fixture.candidateNow
	candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	if candidate.Result != androidbridge.MaintenanceSuccess || candidate.Candidate == 0 || candidate.Preview.ArtifactLength != uint32(len(next.Artifact)) {
		t.Fatalf("candidate=%+v", candidate)
	}
	if platform.registration.leases != 3 || platform.registration.leaseCloses != 3 {
		t.Fatalf("candidate publication leases=%d closes=%d", platform.registration.leases, platform.registration.leaseCloses)
	}
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate+1, make([]byte, len(next.Artifact))); n != 0 || result != androidbridge.MaintenanceInvalidState {
		t.Fatalf("wrong child n=%d result=%d", n, result)
	}
	short := bytes.Repeat([]byte{0x5a}, len(next.Artifact)-1)
	before := bytes.Clone(short)
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, short); n != 0 || result != androidbridge.MaintenanceSizeLimit || !bytes.Equal(short, before) {
		t.Fatalf("short n=%d result=%d changed=%t", n, result, !bytes.Equal(short, before))
	}
	dst := make([]byte, len(next.Artifact))
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, dst); n != len(next.Artifact) || result != androidbridge.MaintenanceSuccess || !bytes.Equal(dst, next.Artifact) {
		t.Fatalf("materialize n=%d result=%d", n, result)
	}
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, dst); n != 0 || result != androidbridge.MaintenanceInvalidState {
		t.Fatalf("reused n=%d result=%d", n, result)
	}
}

func TestMaintenanceCandidateDeadlineStartsAtVerifiedCompletion(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	now := fixture.now
	platform := &releaseMaintenancePlatform{}
	var registry androidbridge.HandleRegistry
	config := maintenanceConfig(now)
	candidateClock := false
	candidateClockCalls := 0
	completion := fixture.candidateNow.Add(10 * time.Second)
	config.Now = func() time.Time {
		if candidateClock {
			candidateClockCalls++
			if candidateClockCalls == 1 {
				return fixture.candidateNow
			}
			if candidateClockCalls == 2 {
				return completion
			}
		}
		return now
	}
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, config)
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	defer registry.Free(handle)
	next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
		ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
		ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = fixture.candidateNow
	candidateClock = true
	platform.registration.beforeAcquire = func() {
		now = completion.Add(10 * time.Second)
		platform.registration.beforeAcquire = nil
	}
	candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	if candidate.Result != androidbridge.MaintenanceSuccess {
		t.Fatalf("candidate=%+v", candidate)
	}
	if candidateClockCalls != 3 {
		t.Fatalf("candidate clock calls=%d", candidateClockCalls)
	}
	now = completion.Add(59 * time.Second)
	short := bytes.Repeat([]byte{0x5a}, len(next.Artifact)-1)
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, short); n != 0 || result != androidbridge.MaintenanceSizeLimit {
		t.Fatalf("before completion deadline n=%d result=%d", n, result)
	}
	now = completion.Add(61 * time.Second)
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, make([]byte, len(next.Artifact))); n != 0 || result != androidbridge.MaintenanceExpired {
		t.Fatalf("after completion deadline n=%d result=%d", n, result)
	}
}

func TestMaintenanceMaterializeRechecksFreshTimeUnderPublicationFence(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	now := fixture.now
	platform := &releaseMaintenancePlatform{}
	var registry androidbridge.HandleRegistry
	config := maintenanceConfig(now)
	config.Now = func() time.Time { return now }
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, config)
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	defer registry.Free(handle)
	next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
		ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
		ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = fixture.candidateNow
	candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	if candidate.Result != androidbridge.MaintenanceSuccess {
		t.Fatalf("candidate=%+v", candidate)
	}
	platform.registration.beforeAcquire = func() {
		now = fixture.candidateNow.Add(61 * time.Second)
		platform.registration.beforeAcquire = nil
	}
	dst := bytes.Repeat([]byte{0x5a}, len(next.Artifact))
	if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, dst); n != 0 || result != androidbridge.MaintenanceExpired || !bytes.Equal(dst, bytes.Repeat([]byte{0x5a}, len(dst))) {
		t.Fatalf("n=%d result=%d changed=%t", n, result, !bytes.Equal(dst, bytes.Repeat([]byte{0x5a}, len(dst))))
	}
}

func TestMaintenanceRevocationRechecksFreshTimeUnderPublicationFence(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	now := fixture.now
	platform := &releaseMaintenancePlatform{}
	var registry androidbridge.HandleRegistry
	config := maintenanceConfig(now)
	config.Now = func() time.Time { return now }
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, config)
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	defer registry.Free(handle)
	if err := selfhost.RevokeProfile(fixture.dataDir, selfhost.RevokeProfileOptions{
		ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
		Now: fixture.candidateNow,
	}); err != nil {
		t.Fatal(err)
	}
	now = fixture.candidateNow.Add(time.Second)
	publicationPath := filepath.Join(t.TempDir(), "current.cbor")
	if _, err := selfhost.PublishSnapshot(fixture.dataDir, publicationPath, now); err != nil {
		t.Fatal(err)
	}
	publication, err := os.ReadFile(publicationPath)
	if err != nil {
		t.Fatal(err)
	}
	platform.registration.beforeAcquire = func() {
		now = fixture.now.Add(13 * time.Hour)
		platform.registration.beforeAcquire = nil
	}
	if result := androidbridge.SubmitMaintenanceCurrentRevocationV1(&registry, handle, publication); result != androidbridge.MaintenanceExpired {
		t.Fatalf("revocation result=%d", result)
	}
	if status := androidbridge.MaintenanceStatusV1(&registry, handle); status != androidbridge.MaintenanceExpired {
		t.Fatalf("status=%d", status)
	}
}

func TestMaintenanceInvalidOrRolledBackClockTerminallyStopsEveryCandidatePath(t *testing.T) {
	clockCases := []struct {
		name string
		now  func(time.Time) time.Time
	}{
		{name: "zero", now: func(time.Time) time.Time { return time.Time{} }},
		{name: "nonpositive", now: func(time.Time) time.Time { return time.Unix(-1, 0).UTC() }},
		{name: "rollback", now: func(previous time.Time) time.Time { return previous.Add(-time.Second) }},
	}
	for _, path := range []string{"materialize", "revocation"} {
		for _, clockCase := range clockCases {
			t.Run(path+"/"+clockCase.name, func(t *testing.T) {
				fixture := newReleaseMaintenanceFixture(t)
				now := fixture.now
				var registry androidbridge.HandleRegistry
				config := maintenanceConfig(now)
				config.Now = func() time.Time { return now }
				handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, config)
				if result != androidbridge.MaintenanceSuccess {
					t.Fatal(result)
				}
				next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
					ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
					ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
				})
				if err != nil {
					t.Fatal(err)
				}
				now = fixture.candidateNow
				candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
				if candidate.Result != androidbridge.MaintenanceSuccess {
					t.Fatalf("candidate=%+v", candidate)
				}
				now = clockCase.now(fixture.candidateNow)
				if path == "materialize" {
					short := bytes.Repeat([]byte{0x5a}, len(next.Artifact)-1)
					if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, short); n != 0 || result != androidbridge.MaintenanceExpired || !bytes.Equal(short, bytes.Repeat([]byte{0x5a}, len(short))) {
						t.Fatalf("materialize n=%d result=%d", n, result)
					}
				} else if result := androidbridge.SubmitMaintenanceCurrentRevocationV1(&registry, handle, fixture.initialPublication); result != androidbridge.MaintenanceExpired {
					t.Fatalf("revocation result=%d", result)
				}
				now = fixture.candidateNow.Add(time.Second)
				if status := androidbridge.MaintenanceStatusV1(&registry, handle); status != androidbridge.MaintenanceExpired {
					t.Fatalf("restored-clock status=%d", status)
				}
				if n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, make([]byte, len(next.Artifact))); n != 0 || result != androidbridge.MaintenanceExpired {
					t.Fatalf("later materialize n=%d result=%d", n, result)
				}
				if result := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact); result.Result != androidbridge.MaintenanceExpired {
					t.Fatalf("later verify=%d", result.Result)
				}
				if code := registry.Free(handle); code != androidbridge.CodeOK {
					t.Fatal(code)
				}
			})
		}
	}
}

func TestMaintenanceMaterializeAndReleaseRaceHasOneWinner(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	now := fixture.now
	var registry androidbridge.HandleRegistry
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, func() androidbridge.MaintenanceConfigV1 {
		config := maintenanceConfig(now)
		config.Now = func() time.Time { return now }
		return config
	}())
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	defer registry.Free(handle)
	next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
		ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
		ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
	})
	if err != nil {
		t.Fatal(err)
	}
	now = fixture.candidateNow
	candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	if candidate.Result != androidbridge.MaintenanceSuccess {
		t.Fatalf("candidate=%+v", candidate)
	}
	type raceResult struct {
		name   string
		n      int
		result androidbridge.MaintenanceResultV1
		dst    []byte
	}
	start := make(chan struct{})
	results := make(chan raceResult, 2)
	go func() {
		dst := make([]byte, len(next.Artifact))
		<-start
		n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, dst)
		results <- raceResult{name: "materialize", n: n, result: result, dst: dst}
	}()
	go func() {
		<-start
		results <- raceResult{name: "release", result: androidbridge.ReleaseMaintenanceCandidateV1(&registry, handle, candidate.Candidate)}
	}()
	close(start)
	successes := 0
	for range 2 {
		got := <-results
		if got.result == androidbridge.MaintenanceSuccess {
			successes++
			if got.name == "materialize" && (got.n != len(next.Artifact) || !bytes.Equal(got.dst, next.Artifact)) {
				t.Fatalf("successful materialize n=%d exact=%t", got.n, bytes.Equal(got.dst, next.Artifact))
			}
			continue
		}
		if got.n != 0 || (got.result != androidbridge.MaintenanceInvalidState && got.result != androidbridge.MaintenanceResourceLimit) {
			t.Fatalf("loser=%s n=%d result=%d", got.name, got.n, got.result)
		}
	}
	if successes != 1 {
		t.Fatalf("successful racers=%d", successes)
	}
}

func TestMaintenanceCandidateAndNoChangePublicationAreFenced(t *testing.T) {
	for _, noChange := range []bool{false, true} {
		name := "candidate"
		if noChange {
			name = "no-change"
		}
		t.Run(name, func(t *testing.T) {
			fixture := newReleaseMaintenanceFixture(t)
			now := fixture.now
			platform := &releaseMaintenancePlatform{}
			var registry androidbridge.HandleRegistry
			handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, func() androidbridge.MaintenanceConfigV1 {
				config := maintenanceConfig(now)
				config.Now = func() time.Time { return now }
				return config
			}())
			if result != androidbridge.MaintenanceSuccess {
				t.Fatal(result)
			}
			artifact := maintenanceCurrentArtifact(t, fixture.current)
			if !noChange {
				next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
					ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
					ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
				})
				if err != nil {
					t.Fatal(err)
				}
				now = fixture.candidateNow
				artifact = next.Artifact
			}
			platform.registration.invalidateOnAcquire = true
			candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, artifact)
			if candidate.Result != androidbridge.MaintenanceCancelled || candidate.Candidate != 0 || candidate.Preview != (selfhost.LiveMaintenancePreviewV1{}) {
				t.Fatalf("late publication=%+v", candidate)
			}
			if platform.registration.invalidateResult != androidbridge.CodeStateCorrupt {
				t.Fatalf("callback result=%v", platform.registration.invalidateResult)
			}
			if status := androidbridge.MaintenanceStatusV1(&registry, handle); status != androidbridge.MaintenanceCancelled {
				t.Fatalf("status=%d", status)
			}
			if code := registry.Free(handle); code != androidbridge.CodeOK || platform.registration.closed != 1 {
				t.Fatalf("free=%v closes=%d", code, platform.registration.closed)
			}
		})
	}
}

func TestMaintenancePublicationCloseFailureScrubsAndTerminallyFencesMaterialization(t *testing.T) {
	for _, stage := range []string{"before-copy", "short-output", "after-copy"} {
		t.Run(stage, func(t *testing.T) {
			fixture := newReleaseMaintenanceFixture(t)
			now := fixture.now
			platform := &releaseMaintenancePlatform{}
			var registry androidbridge.HandleRegistry
			handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, func() androidbridge.MaintenanceConfigV1 {
				config := maintenanceConfig(now)
				config.Now = func() time.Time { return now }
				return config
			}())
			if result != androidbridge.MaintenanceSuccess {
				t.Fatal(result)
			}
			next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{
				ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase,
				ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir,
			})
			if err != nil {
				t.Fatal(err)
			}
			now = fixture.candidateNow
			candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
			if candidate.Result != androidbridge.MaintenanceSuccess {
				t.Fatalf("candidate=%+v", candidate)
			}
			platform.registration.leaseCloseCode = androidbridge.CodeStateCorrupt
			size := len(next.Artifact)
			if stage == "short-output" {
				size--
			}
			if stage == "before-copy" {
				platform.registration.leaseInvalid = true
			}
			dst := bytes.Repeat([]byte{0x5a}, size)
			n, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, dst)
			if n != 0 || result != androidbridge.MaintenanceInternalFailure {
				t.Fatalf("n=%d result=%d", n, result)
			}
			if stage == "after-copy" {
				if !bytes.Equal(dst, make([]byte, len(dst))) {
					t.Fatal("failed materialization retained artifact bytes")
				}
			} else if !bytes.Equal(dst, bytes.Repeat([]byte{0x5a}, size)) {
				t.Fatal("pre-copy failure changed destination")
			}
			if status := androidbridge.MaintenanceStatusV1(&registry, handle); status != androidbridge.MaintenanceInternalFailure {
				t.Fatalf("status=%d", status)
			}
			if _, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, make([]byte, len(next.Artifact))); result != androidbridge.MaintenanceInternalFailure {
				t.Fatalf("later materialize=%d", result)
			}
			if code := registry.Free(handle); code != androidbridge.CodeStateCorrupt {
				t.Fatalf("free cleanup=%v", code)
			}
		})
	}
}

func maintenanceCurrentArtifact(t testing.TB, current androidbridge.MaintenanceCurrentInputV1) []byte {
	t.Helper()
	request, err := androidbridge.DecodeVerifyRequest(current.VerifyRequest)
	if err != nil || len(request.Parts) != 1 {
		t.Fatalf("current request: %v", err)
	}
	return request.Parts[0]
}

func TestMaintenanceCurrentRecordEveryIdentityLimbIsRequired(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	mutations := map[string]func(*profile.ActivationRecord){
		"artifact":      func(record *profile.ActivationRecord) { record.Artifact[0] ^= 1 },
		"signed object": func(record *profile.ActivationRecord) { record.SignedObject[0] ^= 1 },
		"profile":       func(record *profile.ActivationRecord) { record.Profile.Generation++ },
		"status":        func(record *profile.ActivationRecord) { record.State.Status = lifecycle.Status("other") },
		"profile id":    func(record *profile.ActivationRecord) { record.State.ProfileID += "x" },
		"scope":         func(record *profile.ActivationRecord) { record.State.Scope += "x" },
		"evidence":      func(record *profile.ActivationRecord) { record.State.EvidenceReference += "x" },
		"generation":    func(record *profile.ActivationRecord) { record.State.Generation++ },
		"receipt":       func(record *profile.ActivationRecord) { record.State.Receipt.ContentID += "x" },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			record, err := androidbridge.DecodeActivationRecord(fixture.current.ActivationRecord)
			if err != nil {
				t.Fatal(err)
			}
			mutate(&record)
			encoded, err := androidbridge.EncodeActivationRecord(record)
			if err != nil {
				t.Fatal(err)
			}
			current := fixture.current
			current.ActivationRecord = encoded
			var registry androidbridge.HandleRegistry
			platform := &releaseMaintenancePlatform{}
			if handle, result := androidbridge.OpenMaintenanceV1(&registry, current, selfHostedBridgeEnvironment{}, platform, maintenanceConfig(fixture.now)); handle != 0 || result != androidbridge.MaintenanceInvalidState || platform.registered != 0 {
				t.Fatalf("handle=%d result=%d registered=%d", handle, result, platform.registered)
			}
		})
	}
}

func TestMaintenanceSameScopeCompetesAndSynchronousRegisterInvalidationFailsClosed(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	var registry androidbridge.HandleRegistry
	first, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, maintenanceConfig(fixture.now))
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	if second, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, maintenanceConfig(fixture.now)); second != 0 || result != androidbridge.MaintenanceResourceLimit {
		t.Fatalf("duplicate handle=%d result=%d", second, result)
	}
	if code := registry.Free(first); code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	early := &releaseMaintenancePlatform{invalidateOnRegister: true}
	if handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, early, maintenanceConfig(fixture.now)); handle != 0 || result != androidbridge.MaintenanceCancelled || early.registration.closed != 1 {
		t.Fatalf("early invalidation handle=%d result=%d closes=%d", handle, result, early.registration.closed)
	}
}

func TestMaintenanceRegistryExhaustionReleasesScopeReservation(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	var registry androidbridge.HandleRegistry
	handles := make([]androidbridge.Handle, 0, androidbridge.MaxBridgeHandles)
	for range androidbridge.MaxBridgeHandles {
		handle, code := registry.Open(androidbridge.HandleDiagnostic, &struct{}{})
		if code != androidbridge.CodeOK {
			t.Fatalf("fill registry code=%v", code)
		}
		handles = append(handles, handle)
	}
	if handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, maintenanceConfig(fixture.now)); handle != 0 || result != androidbridge.MaintenanceResourceLimit {
		t.Fatalf("exhausted handle=%d result=%d", handle, result)
	}
	if code := registry.Free(handles[len(handles)-1]); code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	handles = handles[:len(handles)-1]
	maintenance, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, maintenanceConfig(fixture.now))
	if result != androidbridge.MaintenanceSuccess || maintenance == 0 {
		t.Fatalf("scope leaked handle=%d result=%d", maintenance, result)
	}
	if code := registry.Free(maintenance); code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	for _, handle := range handles {
		if code := registry.Free(handle); code != androidbridge.CodeOK {
			t.Fatal(code)
		}
	}
}

func TestMaintenanceExpiryAndCurrentRevocationClearCandidate(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	clock := fixture.now
	var registry androidbridge.HandleRegistry
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, &releaseMaintenancePlatform{}, func() androidbridge.MaintenanceConfigV1 {
		config := maintenanceConfig(clock)
		config.Now = func() time.Time { return clock }
		return config
	}())
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	defer registry.Free(handle)
	next, err := selfhost.RotateProfile(fixture.dataDir, selfhost.RotateProfileOptions{ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase, ValidFor: 12 * time.Hour, Now: fixture.candidateNow, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: fixture.registryDir})
	if err != nil {
		t.Fatal(err)
	}
	clock = fixture.candidateNow
	candidate := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	if candidate.Result != androidbridge.MaintenanceSuccess {
		t.Fatalf("candidate=%+v", candidate)
	}
	if result := androidbridge.SubmitMaintenanceCurrentRevocationV1(&registry, handle, fixture.initialPublication); result != androidbridge.MaintenanceNotAdmitted {
		t.Fatalf("nonrevoking result=%d", result)
	}
	if result := androidbridge.ReleaseMaintenanceCandidateV1(&registry, handle, candidate.Candidate); result != androidbridge.MaintenanceSuccess {
		t.Fatalf("candidate lost after nonrevoking proof: %d", result)
	}
	candidate = androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	clock = fixture.candidateNow.Add(61 * time.Second)
	if _, result := androidbridge.MaterializeMaintenanceCandidateV1(&registry, handle, candidate.Candidate, make([]byte, len(next.Artifact)-1)); result != androidbridge.MaintenanceExpired {
		t.Fatalf("expired short output result=%d", result)
	}
	if result := androidbridge.ReleaseMaintenanceCandidateV1(&registry, handle, candidate.Candidate); result != androidbridge.MaintenanceInvalidState {
		t.Fatalf("expired candidate remained live: %d", result)
	}

	clock = fixture.candidateNow.Add(62 * time.Second)
	candidate = androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, next.Artifact)
	if candidate.Result != androidbridge.MaintenanceSuccess {
		t.Fatalf("replacement candidate=%+v", candidate)
	}
	if err := selfhost.RevokeProfile(fixture.dataDir, selfhost.RevokeProfileOptions{ProfileID: fixture.profileID, RecoveryPath: fixture.recovery, RecoveryPassphrase: fixture.passphrase, Now: clock}); err != nil {
		t.Fatal(err)
	}
	clock = clock.Add(time.Second)
	currentPublicationPath := filepath.Join(t.TempDir(), "current.cbor")
	if _, err := selfhost.PublishSnapshot(fixture.dataDir, currentPublicationPath, clock); err != nil {
		t.Fatal(err)
	}
	currentPublication, err := os.ReadFile(currentPublicationPath)
	if err != nil {
		t.Fatal(err)
	}
	if result := androidbridge.SubmitMaintenanceCurrentRevocationV1(&registry, handle, currentPublication); result != androidbridge.MaintenanceRevoked {
		t.Fatalf("revoking result=%d", result)
	}
	if status := androidbridge.MaintenanceStatusV1(&registry, handle); status != androidbridge.MaintenanceRevoked {
		t.Fatalf("status=%d", status)
	}
	if result := androidbridge.ReleaseMaintenanceCandidateV1(&registry, handle, candidate.Candidate); result != androidbridge.MaintenanceRevoked {
		t.Fatalf("revoked candidate result=%d", result)
	}
}

func TestMaintenanceOneOperationPrecedesInputAndCancellationJoins(t *testing.T) {
	fixture := newReleaseMaintenanceFixture(t)
	platform := newReleaseBlockingPlatform()
	var registry androidbridge.HandleRegistry
	handle, result := androidbridge.OpenMaintenanceV1(&registry, fixture.current, selfHostedBridgeEnvironment{}, platform, maintenanceConfig(fixture.now))
	if result != androidbridge.MaintenanceSuccess {
		t.Fatal(result)
	}
	platform.registration.block = true
	worker := make(chan androidbridge.MaintenanceCandidateResultV1, 1)
	go func() { worker <- androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, []byte{0xff}) }()
	select {
	case <-platform.registration.entered:
	case <-time.After(time.Second):
		t.Fatal("operation did not reach protected revalidation")
	}
	oversizedBacking := make([]byte, 1, envelope.MaxTotalInputBytes)
	if result := androidbridge.VerifyMaintenanceCandidateV1(&registry, handle, oversizedBacking); result.Result != androidbridge.MaintenanceResourceLimit {
		t.Fatalf("competing result=%d", result.Result)
	}
	cancelled := make(chan androidbridge.ErrorCode, 1)
	go func() { cancelled <- registry.Cancel(handle) }()
	select {
	case result := <-worker:
		if result.Result != androidbridge.MaintenanceCancelled {
			t.Fatalf("worker result=%d", result.Result)
		}
	case <-time.After(time.Second):
		t.Fatal("worker was not cancelled")
	}
	select {
	case code := <-cancelled:
		if code != androidbridge.CodeOK {
			t.Fatalf("cancel code=%v", code)
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not join")
	}
	if code := registry.Free(handle); code != androidbridge.CodeOK {
		t.Fatal(code)
	}
}

func maintenanceConfig(now time.Time) androidbridge.MaintenanceConfigV1 {
	return androidbridge.MaintenanceConfigV1{
		Limits:           selfhost.LiveMaintenanceLimits{MaxArtifactBytes: envelope.MaxTotalInputBytes, MaxPublicationBytes: 8 << 20},
		OwnedBudgetBytes: 128 << 20,
		Now:              func() time.Time { return now },
	}
}

type releaseMaintenanceFixture struct {
	now, candidateNow              time.Time
	dataDir, recovery, registryDir string
	passphrase                     []byte
	profileID                      string
	initialPublication             []byte
	current                        androidbridge.MaintenanceCurrentInputV1
}

func newReleaseMaintenanceFixture(t testing.TB) releaseMaintenanceFixture {
	return newReleaseMaintenanceFixtureAt(t, time.Unix(1_780_000_000, 0).UTC())
}

func newReleaseMaintenanceFixtureAt(t testing.TB, setupNow time.Time) releaseMaintenanceFixture {
	return newReleaseMaintenanceFixtureWithProbesAt(t, setupNow, nil)
}

func newReleaseMaintenanceFixtureWithProbesAt(t testing.TB, setupNow time.Time, probes *runtimepolicy.ProbesV1) releaseMaintenanceFixture {
	t.Helper()
	base := t.TempDir()
	dataDir := filepath.Join(base, "node")
	recovery := filepath.Join(base, "offline", "recovery")
	now := setupNow.Add(2 * time.Second)
	passphrase := []byte("maintenance fixture recovery passphrase")
	if _, err := selfhost.Initialize(selfhost.InitOptions{DataDir: dataDir, DeploymentName: "owner-node", Endpoint: "203.0.113.7:443", RecoveryPath: recovery, RecoveryPassphrase: passphrase, Now: setupNow}); err != nil {
		t.Fatal(err)
	}
	if err := selfhost.ConfirmRecovery(dataDir, recovery, passphrase, setupNow); err != nil {
		t.Fatal(err)
	}
	initialPublicationPath := filepath.Join(base, "initial-publication.cbor")
	if _, err := selfhost.PublishSnapshot(dataDir, initialPublicationPath, setupNow.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	initialPublication, err := os.ReadFile(initialPublicationPath)
	if err != nil {
		t.Fatal(err)
	}
	request, private, err := enrollment.Generate(now, 24*time.Hour, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil {
		t.Fatal(err)
	}
	privateBytes, err := enrollment.EncodePrivateBundleV1(private)
	if err != nil {
		t.Fatal(err)
	}
	clearEnrollmentPrivateFixture(&private)
	registryDir := filepath.Join(base, "registry")
	services := &runtimepolicy.ServicesV1{Version: 1, Probes: probes, Update: &runtimepolicy.UpdateV1{
		URL: "https://updates.example/profile", MaxArtifactBytes: 65536, TimeoutMillis: 1000, MinCheckIntervalSeconds: 60,
	}}
	issued, err := selfhost.CreateProfile(dataDir, selfhost.CreateProfileOptions{Name: "maintenance-device", ValidFor: 12 * time.Hour, Now: now, RecipientRequest: requestBytes, LiveProgram: releaseLiveProgramFixture(t), RegistryDir: registryDir, Services: services})
	if err != nil {
		t.Fatal(err)
	}
	verifyRequest, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{Ingress: envelope.IngressFile, Class: envelope.ArtifactDeviceRecipient, Parts: [][]byte{issued.Artifact}})
	if err != nil {
		t.Fatal(err)
	}
	environment := releaseMaintenanceActivationEnvironment{now: now}
	var handles androidbridge.HandleRegistry
	verifiedHandle, _, code := androidbridge.OpenVerifyPreviewWithRecipient(&handles, verifyRequest, requestBytes, privateBytes, environment)
	if code != androidbridge.CodeOK {
		t.Fatalf("verify code=%v", code)
	}
	activationHandle, code := androidbridge.OpenActivation(&handles, verifiedHandle, environment)
	if code != androidbridge.CodeOK {
		t.Fatalf("activation code=%v", code)
	}
	activationRecord := completeReleaseActivation(t, &handles, activationHandle)
	if code := handles.Free(activationHandle); code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	if code := handles.Free(verifiedHandle); code != androidbridge.CodeOK {
		t.Fatal(code)
	}
	return releaseMaintenanceFixture{now: now, candidateNow: now.Add(time.Minute), dataDir: dataDir, recovery: recovery, registryDir: registryDir, passphrase: passphrase, profileID: issued.ProfileID, initialPublication: initialPublication, current: androidbridge.MaintenanceCurrentInputV1{
		VerifyRequest: verifyRequest, ActivationRecord: activationRecord, RecipientRequest: requestBytes, RecipientPrivate: privateBytes,
	}}
}

type releaseMaintenanceActivationEnvironment struct{ now time.Time }

func (e releaseMaintenanceActivationEnvironment) VerifyWithRecipient(artifact []byte, class envelope.ArtifactClass, credentials androidbridge.RecipientCredentials) (profile.OfflineVerifiedArtifact, error) {
	defer credentials.Destroy()
	if class != envelope.ArtifactDeviceRecipient {
		return profile.OfflineVerifiedArtifact{}, errors.New("wrong class")
	}
	_, verified, err := selfhost.VerifyLiveBundleForRecipient(artifact, e.now, 1, credentials.Request, credentials.Private)
	return verified, err
}

func (e releaseMaintenanceActivationEnvironment) NewActivationSession(androidbridge.VerifyPreview) (*profile.ActivationSession, error) {
	return nil, errors.New("recipient required")
}

func (e releaseMaintenanceActivationEnvironment) NewRecipientActivationSession(preview androidbridge.VerifyPreview, credentials androidbridge.RecipientCredentials) (*profile.ActivationSession, error) {
	defer credentials.Destroy()
	return selfhost.NewAndroidLiveActivationSessionForRecipient(preview.Verified.ExactArtifact, e.now, lifecycle.VerifiedState{}, credentials.Request, credentials.Private)
}

type releaseMaintenancePlatform struct {
	registered           int
	invalidateOnRegister bool
	registration         releaseMaintenanceRegistration
}

func (p *releaseMaintenancePlatform) Register(epoch uint64, invalidate func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	if epoch == 0 || invalidate == nil {
		return nil, androidbridge.CodeInvalidArgument
	}
	p.registered++
	p.registration.invalidate = invalidate
	if p.invalidateOnRegister {
		invalidate()
	}
	return &p.registration, androidbridge.CodeOK
}

type releaseMaintenanceRegistration struct {
	revalidated            int
	closed                 int
	leases                 int
	leaseCloses            int
	invalidate             func() androidbridge.ErrorCode
	invalidateOnAcquire    bool
	invalidateOnCurrent    bool
	invalidateOnLeaseClose bool
	invalidateResult       androidbridge.ErrorCode
	leaseCloseCode         androidbridge.ErrorCode
	leaseInvalid           bool
	beforeAcquire          func()
}

func (r *releaseMaintenanceRegistration) Revalidate(context.Context) androidbridge.MaintenanceResultV1 {
	r.revalidated++
	return androidbridge.MaintenanceSuccess
}

func (r *releaseMaintenanceRegistration) AcquirePublication(context.Context) (androidbridge.MaintenancePublicationLeaseV1, androidbridge.MaintenanceResultV1) {
	r.leases++
	if r.beforeAcquire != nil {
		r.beforeAcquire()
	}
	if r.invalidateOnAcquire {
		r.invalidateOnAcquire = false
		r.invalidateResult = r.invalidate()
	}
	return &releaseMaintenanceLease{registration: r}, androidbridge.MaintenanceSuccess
}

func (r *releaseMaintenanceRegistration) Close() androidbridge.ErrorCode {
	r.closed++
	return androidbridge.CodeOK
}

type releaseMaintenanceLease struct {
	registration *releaseMaintenanceRegistration
}

func (l *releaseMaintenanceLease) IsCurrent() bool {
	if l.registration != nil && l.registration.invalidateOnCurrent {
		l.registration.invalidateOnCurrent = false
		l.registration.invalidateResult = l.registration.invalidate()
	}
	return l.registration == nil || !l.registration.leaseInvalid
}
func (l *releaseMaintenanceLease) Close() androidbridge.ErrorCode {
	if l.registration != nil {
		l.registration.leaseCloses++
		if l.registration.invalidateOnLeaseClose {
			l.registration.invalidateOnLeaseClose = false
			l.registration.invalidateResult = l.registration.invalidate()
		}
		if l.registration.leaseCloseCode != androidbridge.CodeOK {
			return l.registration.leaseCloseCode
		}
	}
	return androidbridge.CodeOK
}

type releaseBlockingPlatform struct{ registration *releaseBlockingRegistration }

func newReleaseBlockingPlatform() *releaseBlockingPlatform {
	return &releaseBlockingPlatform{registration: &releaseBlockingRegistration{entered: make(chan struct{}, 1)}}
}

func (p *releaseBlockingPlatform) Register(uint64, func() androidbridge.ErrorCode) (androidbridge.MaintenanceRevisionRegistrationV1, androidbridge.ErrorCode) {
	return p.registration, androidbridge.CodeOK
}

type releaseBlockingRegistration struct {
	block   bool
	entered chan struct{}
}

func (r *releaseBlockingRegistration) Revalidate(ctx context.Context) androidbridge.MaintenanceResultV1 {
	if !r.block {
		return androidbridge.MaintenanceSuccess
	}
	select {
	case r.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return androidbridge.MaintenanceCancelled
}
func (*releaseBlockingRegistration) AcquirePublication(context.Context) (androidbridge.MaintenancePublicationLeaseV1, androidbridge.MaintenanceResultV1) {
	return &releaseMaintenanceLease{}, androidbridge.MaintenanceSuccess
}
func (*releaseBlockingRegistration) Close() androidbridge.ErrorCode { return androidbridge.CodeOK }

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
	assertBootstrapPrivateBindingSuccessV1(t, androidbridge.MaintenanceCurrentInputV1{VerifyRequest: verifyRequest, ActivationRecord: activationRecord, RecipientRequest: requestBytes, RecipientPrivate: privateBytes}, snapshot)
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
