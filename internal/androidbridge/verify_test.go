// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package androidbridge

import (
	"bytes"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
)

type fixtureVerificationEnvironment struct{}

func (fixtureVerificationEnvironment) Verify(artifact []byte, class envelope.ArtifactClass) (profile.OfflineVerifiedArtifact, error) {
	spec := phase8issuance.ValidSpec(class)
	request := profile.OfflineVerifyRequest{
		Artifact:               artifact,
		Class:                  spec.Class,
		Audience:               spec.Audience,
		Suite:                  spec.Suite,
		IssuerRole:             profile.RoleIssuer,
		IssuerScope:            spec.IssuerScope,
		IssuerKey:              spec.IssuerKey,
		Now:                    spec.Now,
		MinimumGeneration:      spec.MinimumGeneration,
		MinimumSafetyFloor:     spec.Profile.RequiredSafetyFloor,
		MinimumRootEpoch:       spec.Profile.RootEpoch,
		MinimumRevocationEpoch: spec.Profile.RevocationEpoch,
	}
	return profile.VerifyOffline(
		request,
		phase8issuance.NewIndependentVerifier(),
		phase8issuance.NewResolver(class),
		phase8issuance.NewIndependentRecipientOpener(),
	)
}

func (fixtureVerificationEnvironment) TrustPreview([]byte, envelope.ArtifactClass) (TrustPreview, error) {
	return TrustPreview{
		DeploymentFingerprint: "0123456789abcdef",
		RelayEndpoint:         "203.0.113.7:443",
		AuthorityScope:        "deployment-local",
		OwnerControlled:       true,
	}, nil
}

func TestVerifyAndPreviewUsesRealPhase8VerifierAcrossIngressKinds(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	uri, err := envelope.EncodeArtifactURI(artifact)
	if err != nil {
		t.Fatal(err)
	}
	chunks, err := envelope.EncodeQRChunks(artifact, 64)
	if err != nil {
		t.Fatal(err)
	}
	cases := []VerifyRequest{
		{Ingress: envelope.IngressFile, Class: spec.Class, Parts: [][]byte{artifact}},
		{Ingress: envelope.IngressURI, Class: spec.Class, Parts: [][]byte{[]byte(uri)}},
		{Ingress: envelope.IngressClipboard, Class: spec.Class, Parts: [][]byte{[]byte(uri)}},
	}
	qrParts := make([][]byte, len(chunks))
	for index, chunk := range chunks {
		qrParts[index] = []byte(chunk)
	}
	cases = append(cases, VerifyRequest{Ingress: envelope.IngressQRChunks, Class: spec.Class, Parts: qrParts})

	for _, request := range cases {
		encoded, err := EncodeVerifyRequest(request)
		if err != nil {
			t.Fatal(err)
		}
		preview, code := VerifyAndPreview(encoded, fixtureVerificationEnvironment{})
		if code != CodeOK {
			t.Fatalf("%s code=%v", request.Ingress, code)
		}
		if !bytes.Equal(preview.Verified.ExactArtifact, artifact) ||
			preview.Inspection.Generation != spec.Profile.Generation ||
			preview.Inspection.ContentSHA256 == "" {
			t.Fatalf("%s preview=%+v", request.Ingress, preview.Inspection)
		}
		if preview.Trust.DeploymentFingerprint == "" || !preview.Trust.OwnerControlled {
			t.Fatalf("%s missing trust preview: %+v", request.Ingress, preview.Trust)
		}
		if encodedPreview, err := EncodeVerifyPreview(preview); err != nil || len(encodedPreview) == 0 || string(encodedPreview[:4]) != verifyPreviewMagic {
			t.Fatalf("%s encoded preview bytes=%d err=%v", request.Ingress, len(encodedPreview), err)
		}
	}
}

func TestVerifyAndPreviewFailsClosedWithoutTrustAndOnMutation(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := EncodeVerifyRequest(VerifyRequest{
		Ingress: envelope.IngressFile,
		Class:   spec.Class,
		Parts:   [][]byte{artifact},
	})
	if err != nil {
		t.Fatal(err)
	}
	if _, code := VerifyAndPreview(encoded, nil); code != CodeTrustUnavailable {
		t.Fatalf("empty trust code=%v", code)
	}
	for _, index := range []int{0, 4, 5, 6, 7, len(encoded) - 1} {
		mutated := append([]byte(nil), encoded...)
		mutated[index] ^= 0xff
		if _, code := VerifyAndPreview(mutated, fixtureVerificationEnvironment{}); code == CodeOK {
			t.Fatalf("mutation at %d was accepted", index)
		}
	}
}
