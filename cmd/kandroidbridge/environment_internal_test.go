//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"encoding/hex"
	"testing"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/backup"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
)

func TestInternalEnvironmentRestoresVersionedRecipientKeyRecordWithVerifiedProfile(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), phase8issuance.NewRecipientSealer())
	if err != nil {
		t.Fatal(err)
	}
	request, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{
		Ingress: envelope.IngressFile, Class: envelope.ArtifactSignedPublic, Parts: [][]byte{artifact},
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
		{Kind: backup.RecordNativeProfile, LocalID: "a", Generation: spec.Profile.Generation, ExactBytes: request},
		{Kind: backup.RecordLocalAlias, LocalID: "recipient-keys-v3", ExactBytes: keyRecord},
	}}
	encodedPayload, err := androidbridge.EncodeBackupPayload(payload)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encodedPayload)
	encodedBackup, code := androidbridge.BackupCreate(encodedPayload, []byte("correct horse battery staple"))
	if code != androidbridge.CodeOK {
		t.Fatalf("backup create code=%v", code)
	}
	defer clear(encodedBackup)
	var handles androidbridge.HandleRegistry
	handle, preview, code := androidbridge.BackupOpenPreview(&handles, encodedBackup, []byte("correct horse battery staple"))
	if code != androidbridge.CodeOK {
		t.Fatalf("backup open code=%v", code)
	}
	defer handles.Free(handle)
	defer clear(preview)
	restored, code := androidbridge.BackupRestore(&handles, handle, preview, internalBridgeEnvironment{})
	if code != androidbridge.CodeOK {
		t.Fatalf("backup restore code=%v", code)
	}
	defer clear(restored)
	decoded, err := androidbridge.DecodeBackupPayload(restored)
	if err != nil {
		t.Fatal(err)
	}
	defer destroyInternalBackupPayload(&decoded)
	if decoded.Version != 2 || len(decoded.Records) != 2 || decoded.Records[1].Kind != backup.RecordLocalAlias {
		t.Fatalf("restored payload=%+v", decoded)
	}
}

func TestInternalEnvironmentKeepsNativeProfileVerificationForVersionedBackup(t *testing.T) {
	if err := (internalBridgeEnvironment{}).VerifyBackupRecord(backup.Record{
		Kind: backup.RecordNativeProfile, LocalID: "a", Generation: 1, ExactBytes: []byte("not-a-verify-request"),
	}); err == nil {
		t.Fatal("malformed native profile record was admitted")
	}
}

func destroyInternalBackupPayload(payload *backup.Payload) {
	for index := range payload.Records {
		clear(payload.Records[index].ExactBytes)
	}
	*payload = backup.Payload{}
}

func TestInternalEnvironmentVerifiesAndActivatesEveryFixtureClass(t *testing.T) {
	for _, class := range []envelope.ArtifactClass{
		envelope.ArtifactSignedPublic,
		envelope.ArtifactProviderGroup,
		envelope.ArtifactDeviceRecipient,
		envelope.ArtifactEncryptedBackup,
	} {
		t.Run(string(class), func(t *testing.T) {
			spec := phase8issuance.ValidSpec(class)
			artifact, err := profile.IssueOffline(
				spec,
				phase8issuance.NewIssuer(),
				phase8issuance.NewRecipientSealer(),
			)
			if err != nil {
				t.Fatal(err)
			}
			request, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{
				Ingress: envelope.IngressFile,
				Class:   class,
				Parts:   [][]byte{artifact},
			})
			if err != nil {
				t.Fatal(err)
			}
			var handles androidbridge.HandleRegistry
			verified, _, code := androidbridge.OpenVerifyPreview(&handles, request, environment)
			if code != androidbridge.CodeOK {
				t.Fatalf("verify code=%v", code)
			}
			activation, code := androidbridge.OpenActivation(&handles, verified, environment)
			if code != androidbridge.CodeOK {
				t.Fatalf("activation open code=%v", code)
			}
			var staged []byte
			for {
				next, code := androidbridge.ActivationNextCommand(&handles, activation)
				if code != androidbridge.CodeOK {
					t.Fatalf("next code=%v", code)
				}
				if next.Kind == androidbridge.ActivationCommandComplete {
					record, err := androidbridge.DecodeActivationRecord(next.Payload)
					if err != nil || record.Profile.ContentID != spec.Profile.ContentID {
						t.Fatalf("completion record=%+v err=%v", record.Profile, err)
					}
					break
				}
				switch next.Kind {
				case profile.ActivationCommandStageCandidate:
					staged = append([]byte(nil), next.Payload...)
				case profile.ActivationCommandReopenCandidate:
					code = androidbridge.SubmitActivationCommand(
						&handles,
						activation,
						next.Sequence,
						next.Kind,
						true,
						nil,
						nil,
						staged,
					)
					if code != androidbridge.CodeOK {
						t.Fatalf("reopen submit code=%v", code)
					}
					continue
				}
				code = androidbridge.SubmitActivationCommand(
					&handles,
					activation,
					next.Sequence,
					next.Kind,
					true,
					nil,
					nil,
					nil,
				)
				if code != androidbridge.CodeOK {
					t.Fatalf("%s submit code=%v", next.Kind, code)
				}
			}
		})
	}
}
