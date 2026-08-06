// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Command phase16androidverify exercises the same bounded Android verification
// and activation bridge used by release builds against one exact self-hosted
// profile artifact. It performs no network request and persists no profile.
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"kurdistan/internal/androidbridge"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/selfhost"
)

type environment struct{ now time.Time }

func (e environment) Verify(artifact []byte, class envelope.ArtifactClass) (profile.OfflineVerifiedArtifact, error) {
	if class != envelope.ArtifactSignedPublic {
		return profile.OfflineVerifiedArtifact{}, errors.New("phase16androidverify: unsupported artifact class")
	}
	return selfhost.VerifyAndroidArtifact(artifact, e.now, 1)
}

func (e environment) TrustPreview(artifact []byte, class envelope.ArtifactClass) (androidbridge.TrustPreview, error) {
	if class != envelope.ArtifactSignedPublic {
		return androidbridge.TrustPreview{}, errors.New("phase16androidverify: unsupported artifact class")
	}
	verified, err := selfhost.VerifyBundle(artifact, e.now, 1)
	if err != nil {
		return androidbridge.TrustPreview{}, err
	}
	return androidbridge.TrustPreview{
		DeploymentFingerprint: verified.RootFingerprint,
		RelayEndpoint:         verified.Endpoint,
		AuthorityScope:        "deployment-local",
		OwnerControlled:       true,
		UpdatesEnabled:        false,
	}, nil
}

func (e environment) NewActivationSession(preview androidbridge.VerifyPreview) (*profile.ActivationSession, error) {
	return selfhost.NewAndroidActivationSession(preview.Verified.ExactArtifact, e.now, lifecycle.VerifiedState{})
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "phase16androidverify:", err)
		os.Exit(1)
	}
}

func run(args []string, output io.Writer) error {
	set := flag.NewFlagSet("phase16androidverify", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	artifactPath := set.String("artifact", "", "exact self-hosted Kurd profile artifact")
	if set.Parse(args) != nil || set.NArg() != 0 || *artifactPath == "" {
		return errors.New("usage: phase16androidverify -artifact FILE")
	}
	artifact, err := os.ReadFile(*artifactPath)
	if err != nil {
		return err
	}
	defer clear(artifact)
	request, err := androidbridge.EncodeVerifyRequest(androidbridge.VerifyRequest{
		Ingress: envelope.IngressFile,
		Class:   envelope.ArtifactSignedPublic,
		Parts:   [][]byte{artifact},
	})
	if err != nil {
		return err
	}
	defer clear(request)
	registry := &androidbridge.HandleRegistry{}
	env := environment{now: time.Now().UTC()}
	previewHandle, previewBytes, code := androidbridge.OpenVerifyPreview(registry, request, env)
	if code != androidbridge.CodeOK {
		return fmt.Errorf("preview failed: %v", code)
	}
	defer registry.Free(previewHandle)
	activationHandle, code := androidbridge.OpenActivation(registry, previewHandle, env)
	if code != androidbridge.CodeOK {
		return fmt.Errorf("activation open failed: %v", code)
	}
	defer registry.Free(activationHandle)
	var staged []byte
	for {
		next, code := androidbridge.ActivationNextCommand(registry, activationHandle)
		if code != androidbridge.CodeOK {
			return fmt.Errorf("activation next failed: %v", code)
		}
		if next.Kind == androidbridge.ActivationCommandComplete {
			result, err := androidbridge.DecodeActivationRecord(next.Payload)
			if err != nil || !bytes.Equal(result.Artifact, artifact) {
				return errors.New("activation result lost exact outer artifact identity")
			}
			verified, err := selfhost.VerifyBundle(artifact, env.now, 1)
			if err != nil {
				return err
			}
			return json.NewEncoder(output).Encode(map[string]any{
				"schema": "phase16-android-exact-profile-verification-v1", "verified": true,
				"activationFinalized": true, "exactOuterBytesPreserved": true,
				"deploymentId": verified.DeploymentID, "rootFingerprint": verified.RootFingerprint,
				"profileId": verified.ProfileID, "contentId": verified.ContentID, "generation": verified.Generation,
				"previewBytes": len(previewBytes),
			})
		}
		var reopened []byte
		switch next.Kind {
		case profile.ActivationCommandSnapshot:
		case profile.ActivationCommandStageCandidate:
			staged = bytes.Clone(next.Payload)
		case profile.ActivationCommandReopenCandidate:
			reopened = staged
		case profile.ActivationCommandMarkActivation, profile.ActivationCommandCommitMarked, profile.ActivationCommandFinalizeActivation:
		default:
			return fmt.Errorf("unexpected activation command %q", next.Kind)
		}
		if code := androidbridge.SubmitActivationCommand(registry, activationHandle, next.Sequence, next.Kind, true, nil, nil, reopened); code != androidbridge.CodeOK {
			return fmt.Errorf("activation submit failed: %v", code)
		}
	}
}
