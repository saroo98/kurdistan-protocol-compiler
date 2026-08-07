// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile_test

import (
	"bytes"
	"errors"
	"testing"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/testkit/phase8issuance"
)

func TestVerifiedIssuanceIntentBindsExactSigningInput(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	verified, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	if len(verified.SigningInputSHA256()) != 64 {
		t.Fatal("missing signing-input digest")
	}
	inspection := verified.Inspection()
	if inspection.Generation != spec.Profile.Generation || inspection.ValidUntil != spec.Profile.ValidUntil || inspection.Sealed {
		t.Fatalf("unexpected inspection: %#v", inspection)
	}

	mutated := spec
	mutated.Profile.Generation++
	mutated.MinimumGeneration = mutated.Profile.Generation
	next, err := profile.VerifyIssuanceIntent(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if next.SigningInputSHA256() == verified.SigningInputSHA256() {
		t.Fatal("profile mutation did not change authorization subject")
	}
}

func TestVerifiedIssuanceIntentOwnsDefensiveSpecification(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
	verified, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	first := verified.Specification()
	first.Profile.ProfileID = "mutated"
	first.Recipient.Hint = "mutated"
	second := verified.Specification()
	if second.Profile.ProfileID == "mutated" || second.Recipient.Hint == "mutated" {
		t.Fatal("verified issuance intent exposed mutable authority state")
	}
}

func TestVerifiedIssuanceIntentRejectsInvalidSpec(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	spec.MinimumGeneration = spec.Profile.Generation + 1
	verified, err := profile.VerifyIssuanceIntent(spec)
	if err == nil || verified.SigningInputSHA256() != "" {
		t.Fatal("invalid issuance intent accepted")
	}
}

func TestVerifiedIssuedArtifactBindsExactAuthorizedIntent(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	intent, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := profile.VerifyIssuedArtifact(
		intent, artifact, phase8issuance.NewIndependentVerifier(), nil, nil,
	)
	if err != nil {
		t.Fatal(err)
	}
	if verified.ProfileID() != spec.Profile.ProfileID ||
		verified.Generation() != spec.Profile.Generation ||
		verified.SigningInputSHA256() != intent.SigningInputSHA256() ||
		len(verified.ArtifactSHA256()) != 64 {
		t.Fatalf("unexpected finalized artifact: %#v", verified.Inspection())
	}
	copyArtifact := verified.ExactArtifact()
	copyArtifact[0] ^= 1
	if bytes.Equal(copyArtifact, verified.ExactArtifact()) {
		t.Fatal("verified artifact exposed mutable bytes")
	}
}

func TestVerifiedIssuedArtifactRejectsDifferentAuthorizedIntent(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactSignedPublic)
	artifact, err := profile.IssueOffline(spec, phase8issuance.NewIssuer(), nil)
	if err != nil {
		t.Fatal(err)
	}
	other := spec
	other.Profile.Generation++
	other.MinimumGeneration = other.Profile.Generation
	intent, err := profile.VerifyIssuanceIntent(other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := profile.VerifyIssuedArtifact(
		intent, artifact, phase8issuance.NewIndependentVerifier(), nil, nil,
	); err == nil {
		t.Fatal("artifact finalized under a different authorized intent")
	}
}

func TestIssueOfflineCheckedVerifiesSignatureBeforeSealing(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
	intent, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	signer := phase8issuance.NewIssuer()
	verifier := phase8issuance.NewIndependentVerifier()
	sealer := phase8issuance.NewRecipientSealer()
	receipt, err := profile.IssueOfflineChecked(intent, signer, verifier, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if signer.Operations() != 1 || verifier.Operations() != 1 || sealer.Phase8BindingsUsed() != 1 {
		t.Fatalf("operations signer=%d verifier=%d sealer=%d", signer.Operations(), verifier.Operations(), sealer.Phase8BindingsUsed())
	}
	if receipt.ProfileID() != spec.Profile.ProfileID || receipt.Generation() != spec.Profile.Generation ||
		receipt.ValidUntil() != spec.Profile.ValidUntil || receipt.SigningInputSHA256() != intent.SigningInputSHA256() || len(receipt.ArtifactSHA256()) != 64 {
		t.Fatalf("unexpected receipt: %#v", receipt.Inspection())
	}
	artifact := receipt.ExactArtifact()
	artifact[0] ^= 1
	if bytes.Equal(artifact, receipt.ExactArtifact()) {
		t.Fatal("issuer receipt exposed mutable artifact bytes")
	}
	verified, err := profile.VerifyIssuedArtifact(intent, receipt.ExactArtifact(), phase8issuance.NewIndependentVerifier(), phase8issuance.NewResolver(envelope.ArtifactDeviceRecipient), phase8issuance.NewIndependentRecipientOpener())
	if err != nil || verified.ArtifactSHA256() != receipt.ArtifactSHA256() {
		t.Fatalf("recipient verification err=%v", err)
	}
}

func TestIssueOfflineCheckedNeverSealsUnverifiedSignature(t *testing.T) {
	spec := phase8issuance.ValidSpec(envelope.ArtifactDeviceRecipient)
	intent, err := profile.VerifyIssuanceIntent(spec)
	if err != nil {
		t.Fatal(err)
	}
	sealer := phase8issuance.NewRecipientSealer()
	if _, err := profile.IssueOfflineChecked(intent, phase8issuance.NewIssuer(), rejectingVerifier{}, sealer); !errors.Is(err, profile.ErrOfflineIssuance) {
		t.Fatalf("unverified signature error=%v", err)
	}
	if sealer.Phase8BindingsUsed() != 0 {
		t.Fatal("recipient sealer ran before signature verification")
	}
}

type rejectingVerifier struct{}

func (rejectingVerifier) Verify(profile.KeyReference, []byte, []byte) error {
	return errors.New("rejected")
}
