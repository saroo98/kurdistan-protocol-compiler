// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"sort"
	"time"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
)

func encodeBundle(value profileBundle) ([]byte, error) {
	encoded, err := encodeCanonical(value)
	if err != nil || len(encoded) == 0 || len(encoded) > envelope.MaxTotalInputBytes {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func decodeBundle(encoded []byte) (profileBundle, error) {
	var value profileBundle
	if decodeCanonical(encoded, &value, envelope.MaxTotalInputBytes) != nil || value.Version != bundleVersion {
		return profileBundle{}, ErrInvalidInput
	}
	return value, nil
}

// VerifyBundle independently verifies the self-contained deployment root,
// issuer delegation, revocation state, and exact Phase 8 signed profile.
func VerifyBundle(encoded []byte, now time.Time, minimumGeneration uint64) (VerifiedBundle, error) {
	verified, _, _, err := verifyBundleFull(encoded, now, minimumGeneration)
	return verified, err
}

func verifyBundleFull(encoded []byte, now time.Time, minimumGeneration uint64) (VerifiedBundle, profileBundle, profile.OfflineVerifiedArtifact, error) {
	if now.IsZero() || minimumGeneration == 0 {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("time or minimum generation")
	}
	bundle, err := decodeBundle(encoded)
	if err != nil || !validID(bundle.DeploymentID) || !validEndpoint(bundle.Endpoint) ||
		bundle.RootFingerprint != fingerprint(bundle.RootPublicDER) || bundle.RelayKeyID != keyID("relay", bundle.RelayPublic) || len(bundle.RelayPublic) != 32 {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("bundle framing or deployment identity")
	}
	rootPublic, err := parseP256Public(bundle.RootPublicDER)
	if err != nil || len(bundle.Root.Keys) != 1 || bundle.Root.Keys[0].KeyID != keyID("root", bundle.RootPublicDER) {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("root public key")
	}
	issuerPublic, err := parseP256Public(bundle.IssuerPublicDER)
	if err != nil || bundle.IssuerKey.KeyID != keyID("issuer", bundle.IssuerPublicDER) || requireDistinctKeys(bundle.Root.Keys[0].KeyID, bundle.IssuerKey.KeyID, bundle.RelayKeyID) != nil {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("issuer or relay key identity")
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{
		bundle.Root.Keys[0].KeyID: rootPublic,
		bundle.IssuerKey.KeyID:    issuerPublic,
	}}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(bundle.Delegation)
	if err != nil || !bytes.Equal(delegationPayload, bundle.DelegationPayload) ||
		verifier.Verify(bundle.Root.Keys[0], bundle.DelegationPayload, bundle.DelegationSignature) != nil {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("delegation signature")
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(bundle.Revocations)
	if err != nil || !bytes.Equal(revocationPayload, bundle.RevocationPayload) ||
		verifier.Verify(bundle.Root.Keys[0], bundle.RevocationPayload, bundle.RevocationSignature) != nil {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("revocation signature")
	}
	nowUnix := now.UTC().Unix()
	if profile.ValidateIssuerDelegation(bundle.Root, bundle.Delegation, nowUnix, bundle.Delegation.Scope.ProviderID, bundle.Delegation.Scope.LineageID, bundle.Delegation.Scope.ProfileNamespace+"candidate") != nil ||
		bundle.Delegation.IssuerKey != bundle.IssuerKey || bundle.Revocations.RootEpoch != bundle.Root.Epoch ||
		nowUnix < bundle.Revocations.IssuedAt || nowUnix >= bundle.Revocations.ExpiresAt || bundle.Revocations.EmergencyDenied ||
		contains(bundle.Revocations.RevokedIssuerKeyIDs, bundle.IssuerKey.KeyID) {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("delegation or revocation authorization")
	}
	verified, err := profile.VerifyOffline(profile.OfflineVerifyRequest{
		Artifact: bundle.SignedProfile, Class: envelope.ArtifactSignedPublic, Audience: envelope.AudiencePublic,
		Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer, IssuerScope: bundle.Delegation.Scope,
		IssuerKey: bundle.IssuerKey, Now: nowUnix, MinimumGeneration: minimumGeneration,
		MinimumSafetyFloor: 1, MinimumRootEpoch: bundle.Root.Epoch, MinimumRevocationEpoch: bundle.Revocations.Epoch,
	}, verifier, nil, nil)
	if err != nil || contains(bundle.Revocations.RevokedContentIDs, verified.Profile.ContentID) ||
		verified.Profile.RootEpoch != bundle.Root.Epoch || verified.Profile.RevocationEpoch != bundle.Revocations.Epoch ||
		!contains(verified.Profile.RelayIDs, bundle.RelayKeyID) {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("signed profile verification")
	}
	endpoint, err := policyEndpoint(verified.Profile.Policy)
	if err != nil || endpoint != bundle.Endpoint {
		return VerifiedBundle{}, profileBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("profile policy endpoint")
	}
	result := VerifiedBundle{
		DeploymentID: bundle.DeploymentID, Endpoint: bundle.Endpoint,
		ProfileID: verified.Profile.ProfileID, ContentID: verified.Profile.ContentID,
		RootFingerprint: bundle.RootFingerprint, IssuerFingerprint: fingerprint(bundle.IssuerPublicDER),
		RelayKeyID: bundle.RelayKeyID, Generation: verified.Profile.Generation,
		RootEpoch: verified.Profile.RootEpoch, RevocationEpoch: verified.Profile.RevocationEpoch,
		ValidUntil: verified.Profile.ValidUntil,
	}
	return result, bundle, verified, nil
}

// VerifyAndroidArtifact verifies a self-hosted artifact with its embedded
// deployment root and returns the standard Android bridge verification shape.
// ExactArtifact remains the complete self-hosted bundle so durable reopen
// verification cannot lose or substitute its authority chain.
func VerifyAndroidArtifact(encoded []byte, now time.Time, minimumGeneration uint64) (profile.OfflineVerifiedArtifact, error) {
	_, _, verified, err := verifyBundleFull(encoded, now, minimumGeneration)
	if err != nil {
		return profile.OfflineVerifiedArtifact{}, err
	}
	verified.ExactArtifact = bytes.Clone(encoded)
	return verified, nil
}

// NewAndroidActivationSession creates the authoritative activation state
// machine for one self-hosted profile. The outer bundle is independently
// verified on initial admission and exact-byte reopen.
func NewAndroidActivationSession(encoded []byte, now time.Time, current lifecycle.VerifiedState) (*profile.ActivationSession, error) {
	_, bundle, verified, err := verifyBundleFull(encoded, now, 1)
	if err != nil {
		return nil, err
	}
	rootPublic, err := parseP256Public(bundle.RootPublicDER)
	if err != nil {
		return nil, err
	}
	issuerPublic, err := parseP256Public(bundle.IssuerPublicDER)
	if err != nil {
		return nil, err
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{bundle.Root.Keys[0].KeyID: rootPublic, bundle.IssuerKey.KeyID: issuerPublic}}
	request := profile.ActivationRequest{
		Artifact: encoded, Dispatch: verified.Metadata, Now: now.UTC().Unix(), Current: current,
		Root:        bundle.Root,
		Delegation:  profile.SignedIssuerDelegationV1{Artifact: bundle.Delegation, RootKey: bundle.Root.Keys[0], Payload: bundle.DelegationPayload, Signature: bundle.DelegationSignature},
		Revocations: profile.SignedRevocationSetV1{Set: bundle.Revocations, RootKey: bundle.Root.Keys[0], Payload: bundle.RevocationPayload, Signature: bundle.RevocationSignature},
		Verifier:    verifier, ContractVersion: verified.Profile.ContractVersion, MinSafetyFloor: verified.Profile.RequiredSafetyFloor,
		MinRootEpoch: verified.Profile.RootEpoch, MinRevocationEpoch: verified.Profile.RevocationEpoch,
	}
	request.UnwrapSignedObject = func(candidate []byte) ([]byte, error) {
		candidateVerified, candidateBundle, _, err := verifyBundleFull(candidate, now, 1)
		if err != nil || candidateVerified.DeploymentID != bundle.DeploymentID || candidateVerified.RootFingerprint != bundle.RootFingerprint {
			return nil, bundleError("activation outer authority")
		}
		return bytes.Clone(candidateBundle.SignedProfile), nil
	}
	return profile.NewActivationSession(request), nil
}

func bundleError(detail string) error { return fmt.Errorf("%w: %s", ErrInvalidInput, detail) }

func contains(values []string, target string) bool {
	index := sort.SearchStrings(values, target)
	return index < len(values) && values[index] == target
}
