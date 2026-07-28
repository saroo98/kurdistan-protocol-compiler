//go:build phase9internal

// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package main

import (
	"testing"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
)

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
