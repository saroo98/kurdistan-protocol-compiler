// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"fmt"
	"net"
	"sort"
	"strconv"
	"time"

	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/lifecycle"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
)

type liveRecipientResolver struct{ binding profile.RecipientBinding }

func (resolver liveRecipientResolver) ResolveRecipient(class envelope.ArtifactClass, hint string) (profile.RecipientBinding, error) {
	return profile.ResolveRecipientBinding([]profile.RecipientBinding{resolver.binding}, class, hint)
}

type activationRecipientOpener struct{ opener *profilehpke.Opener }

func (opener *activationRecipientOpener) OpenOffline(binding profile.RecipientBinding, outerProtected, encapsulation, ciphertext []byte) ([]byte, error) {
	if opener == nil || opener.opener == nil {
		return nil, profile.ErrOfflineVerify
	}
	return opener.opener.OpenOffline(binding, outerProtected, encapsulation, ciphertext)
}

func (opener *activationRecipientOpener) Destroy() {
	if opener == nil || opener.opener == nil {
		return
	}
	opener.opener.Close()
	opener.opener = nil
}

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

func encodeLiveBundle(value liveProfileBundleV2) ([]byte, error) {
	encoded, err := encodeCanonical(value)
	if err != nil || len(encoded) == 0 || len(encoded) > envelope.MaxTotalInputBytes {
		return nil, ErrInvalidInput
	}
	return encoded, nil
}

func decodeLiveBundle(encoded []byte) (liveProfileBundleV2, error) {
	return decodeLiveBundleWithResourceMode(encoded, liveResourceLegacy)
}

// verifyLiveBundleAuthority validates the clear owner authority chain and the
// strict metadata of the sealed native artifact. It deliberately does not
// claim recipient decryptability or inspect protected profile policy.
func verifyLiveBundleAuthority(encoded []byte, now time.Time, minimumGeneration uint64) (liveProfileBundleV2, envelope.ArtifactMetadata, error) {
	return verifyLiveBundleAuthorityWithResourceMode(encoded, now, minimumGeneration, liveResourceLegacy)
}

func verifyLiveBundleAuthorityWithResourceMode(encoded []byte, now time.Time, minimumGeneration uint64, mode liveResourceMode) (liveProfileBundleV2, envelope.ArtifactMetadata, error) {
	return verifyLiveBundleAuthorityCore(encoded, now, minimumGeneration, mode, nil)
}

func verifyLiveBundleAuthorityCore(encoded []byte, now time.Time, minimumGeneration uint64, mode liveResourceMode, diagnostic *liveMaintenanceDiagnostic) (liveProfileBundleV2, envelope.ArtifactMetadata, error) {
	if !mode.valid() {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, ErrInvalidInput
	}
	if now.IsZero() || minimumGeneration == 0 {
		if now.IsZero() {
			diagnostic.fail(LiveMaintenanceExpired)
		} else {
			diagnostic.fail(LiveMaintenanceInvalidRequest)
		}
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("time or minimum generation")
	}
	bundle, err := decodeLiveBundleWithResourceMode(encoded, mode)
	keepBundle := false
	if diagnostic != nil {
		defer func() {
			if !keepBundle {
				destroyMaintenanceBundle(&bundle)
			}
		}()
	}
	if err != nil && mode == liveResourceTypedFirstV1 {
		diagnostic.resource(err)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, err
	}
	if err != nil || !validID(bundle.DeploymentID) || bundle.RootFingerprint != fingerprint(bundle.RootPublicDER) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live bundle framing")
	}
	rootPublic, err := parseP256Public(bundle.RootPublicDER)
	if err != nil || len(bundle.Root.Keys) != 1 || bundle.Root.Keys[0].KeyID != keyID("root", bundle.RootPublicDER) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live root")
	}
	issuerPublic, err := parseP256Public(bundle.IssuerPublicDER)
	if err != nil || bundle.IssuerKey.KeyID != keyID("issuer", bundle.IssuerPublicDER) || bundle.IssuerKey.KeyID == bundle.Root.Keys[0].KeyID {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live issuer")
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{bundle.Root.Keys[0].KeyID: rootPublic, bundle.IssuerKey.KeyID: issuerPublic}}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(bundle.Delegation)
	if diagnostic != nil {
		defer clear(delegationPayload)
	}
	if err != nil || !bytes.Equal(delegationPayload, bundle.DelegationPayload) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live delegation")
	}
	if verifier.Verify(bundle.Root.Keys[0], bundle.DelegationPayload, bundle.DelegationSignature) != nil {
		if sink := diagnostic.sink(nil); sink != nil {
			sink(profile.VerificationRejection{Stage: profile.VerificationStageDelegation, Reason: profile.VerificationReasonSignatureInvalid})
		}
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live delegation")
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(bundle.Revocations)
	if diagnostic != nil {
		defer clear(revocationPayload)
	}
	if err != nil || !bytes.Equal(revocationPayload, bundle.RevocationPayload) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live revocations")
	}
	if verifier.Verify(bundle.Root.Keys[0], bundle.RevocationPayload, bundle.RevocationSignature) != nil {
		if sink := diagnostic.sink(nil); sink != nil {
			sink(profile.VerificationRejection{Stage: profile.VerificationStageRevocations, Reason: profile.VerificationReasonSignatureInvalid})
		}
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live revocations")
	}
	nowUnix := now.UTC().Unix()
	if profile.ValidateIssuerDelegationWithRejection(bundle.Root, bundle.Delegation, nowUnix, bundle.Delegation.Scope.ProviderID, bundle.Delegation.Scope.LineageID, bundle.Delegation.Scope.ProfileNamespace+"candidate", diagnostic.sink(nil)) != nil {
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live authority")
	}
	if bundle.Delegation.IssuerKey != bundle.IssuerKey || bundle.Revocations.RootEpoch != bundle.Root.Epoch {
		diagnostic.fail(LiveMaintenanceProfileMismatch)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live authority")
	}
	if nowUnix < bundle.Revocations.IssuedAt || nowUnix >= bundle.Revocations.ExpiresAt {
		diagnostic.fail(LiveMaintenanceExpired)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live authority")
	}
	if bundle.Revocations.EmergencyDenied || contains(bundle.Revocations.RevokedIssuerKeyIDs, bundle.IssuerKey.KeyID) {
		diagnostic.fail(LiveMaintenanceRevoked)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live authority")
	}
	sealed, err := envelope.ParseSealedProfileOpaque(bundle.SealedProfile)
	if err != nil {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live sealed frame")
	}
	context, err := envelope.DecodeSealProtectedContextV1(sealed.Protected)
	if err != nil || context.SuiteID != envelope.SuiteClassicalV1 || context.ContentType != envelope.SignedObjectContentType ||
		context.Metadata.Class != envelope.ArtifactDeviceRecipient || context.Metadata.AudienceClass != envelope.AudienceProvisionedDevice {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, bundleError("live sealed metadata")
	}
	keepBundle = true
	return bundle, context.Metadata, nil
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

// VerifyLiveAndroidArtifact verifies the clear owner authority envelope, then
// opens and verifies the exact recipient-sealed native profile with the
// device-owned capability. ExactArtifact remains the complete owner bundle.
func VerifyLiveAndroidArtifact(encoded []byte, now time.Time, minimumGeneration uint64, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener) (profile.OfflineVerifiedArtifact, error) {
	return verifyLiveAndroidArtifactWithResourceMode(encoded, now, minimumGeneration, resolver, opener, liveResourceLegacy)
}

func verifyLiveAndroidArtifactWithResourceMode(encoded []byte, now time.Time, minimumGeneration uint64, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener, mode liveResourceMode) (profile.OfflineVerifiedArtifact, error) {
	return verifyLiveAndroidArtifactCore(encoded, now, minimumGeneration, resolver, opener, mode, nil)
}

func verifyLiveAndroidArtifactCore(encoded []byte, now time.Time, minimumGeneration uint64, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener, mode liveResourceMode, diagnostic *liveMaintenanceDiagnostic) (profile.OfflineVerifiedArtifact, error) {
	diagnostic.reset()
	if !validLiveResourceProviders(mode, resolver, opener) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return profile.OfflineVerifiedArtifact{}, ErrInvalidInput
	}
	if mode == liveResourceTypedFirstV1 {
		opener.(*liveResourceRecipientOpener).failure = liveResourceFailureNone
	}
	bundle, metadata, err := verifyLiveBundleAuthorityCore(encoded, now, minimumGeneration, mode, diagnostic)
	if diagnostic != nil {
		defer destroyMaintenanceBundle(&bundle)
	}
	if mode == liveResourceTypedFirstV1 && (err == ErrInvalidInput || err == errLiveResourceSize) {
		return profile.OfflineVerifiedArtifact{}, err
	}
	if err != nil || resolver == nil || opener == nil {
		return profile.OfflineVerifiedArtifact{}, bundleError("live recipient verification")
	}
	rootPublic, err := parseP256Public(bundle.RootPublicDER)
	if err != nil {
		return profile.OfflineVerifiedArtifact{}, bundleError("live root public key")
	}
	issuerPublic, err := parseP256Public(bundle.IssuerPublicDER)
	if err != nil {
		return profile.OfflineVerifiedArtifact{}, bundleError("live issuer public key")
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{
		bundle.Root.Keys[0].KeyID: rootPublic,
		bundle.IssuerKey.KeyID:    issuerPublic,
	}}
	verified, err := profile.VerifyOfflineWithRejection(profile.OfflineVerifyRequest{
		Artifact: bundle.SealedProfile, Class: metadata.Class, Audience: metadata.AudienceClass,
		Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer, IssuerScope: bundle.Delegation.Scope,
		IssuerKey: bundle.IssuerKey, Now: now.UTC().Unix(), MinimumGeneration: minimumGeneration,
		MinimumSafetyFloor: 1, MinimumRootEpoch: bundle.Root.Epoch, MinimumRevocationEpoch: bundle.Revocations.Epoch,
	}, verifier, resolver, opener, diagnostic.sink(opener))
	if err != nil && mode == liveResourceTypedFirstV1 {
		if resourceErr := opener.(*liveResourceRecipientOpener).resourceError(); resourceErr != nil {
			return profile.OfflineVerifiedArtifact{}, resourceErr
		}
	}
	if err != nil {
		return profile.OfflineVerifiedArtifact{}, bundleError("live signed profile verification")
	}
	if contains(bundle.Revocations.RevokedContentIDs, verified.Profile.ContentID) {
		diagnostic.fail(LiveMaintenanceRevoked)
		if diagnostic != nil {
			destroyLiveMaintenanceOffline(&verified)
		}
		return profile.OfflineVerifiedArtifact{}, bundleError("live signed profile verification")
	}
	if verified.Profile.RootEpoch != bundle.Root.Epoch || verified.Profile.RevocationEpoch != bundle.Revocations.Epoch {
		diagnostic.fail(LiveMaintenanceProfileMismatch)
		if diagnostic != nil {
			destroyLiveMaintenanceOffline(&verified)
		}
		return profile.OfflineVerifiedArtifact{}, bundleError("live signed profile verification")
	}
	if diagnostic != nil && diagnostic.expectedProfile != nil {
		p, current := verified.Profile, diagnostic.expectedProfile
		if p.ProfileID != current.ProfileID || p.ProviderID != current.ProviderID || p.LineageID != current.LineageID || p.ContractVersion != current.ContractVersion || p.RevocationScope != current.RevocationScope {
			diagnostic.fail(LiveMaintenanceProfileMismatch)
			destroyLiveMaintenanceOffline(&verified)
			return profile.OfflineVerifiedArtifact{}, bundleError("live runtime policy")
		}
	}
	policy, runtimeDiagnostic, err := runtimepolicy.DecodeRuntimeAtWithDiagnostic(verified.Profile.Policy, now)
	if diagnostic != nil {
		defer destroyMaintenancePolicy(&policy)
	}
	if err != nil || policy.RelayAuthKeyID == "" || !contains(verified.Profile.RelayIDs, policy.RelayAuthKeyID) || runtimepolicy.ValidateRuntimeAgainstEnvelopeAt(policy, verified.Profile, now) != nil {
		if runtimeDiagnostic == runtimepolicy.RuntimeDiagnosticTLSValidityTime {
			diagnostic.fail(LiveMaintenanceExpired)
		}
		diagnostic.fail(LiveMaintenanceIncompatible)
		if diagnostic != nil {
			destroyLiveMaintenanceOffline(&verified)
		}
		return profile.OfflineVerifiedArtifact{}, bundleError("live runtime policy")
	}
	if diagnostic != nil {
		clear(verified.ExactArtifact)
	}
	verified.ExactArtifact = bytes.Clone(encoded)
	return verified, nil
}

// VerifyLiveBundleForRecipient independently reconstructs the exact recipient
// binding from the owner-signed outer authority and the device enrollment
// capability. The request's enrollment expiry is intentionally not reapplied:
// the issued profile's own validity and revocation state are authoritative.
func VerifyLiveBundleForRecipient(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1) (VerifiedBundle, profile.OfflineVerifiedArtifact, error) {
	bundle, _, resolver, opener, err := liveRecipientProviders(encoded, now, minimumGeneration, request, private)
	if err != nil {
		return VerifiedBundle{}, profile.OfflineVerifiedArtifact{}, err
	}
	defer opener.Close()
	verified, err := VerifyLiveAndroidArtifact(encoded, now, minimumGeneration, resolver, opener)
	if err != nil {
		return VerifiedBundle{}, profile.OfflineVerifiedArtifact{}, err
	}
	policy, err := runtimepolicy.DecodeRuntimeAt(verified.Profile.Policy, now)
	if err != nil || len(policy.Endpoints) == 0 {
		return VerifiedBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("live runtime endpoint")
	}
	endpoint := policy.Endpoints[0]
	address := net.IP(endpoint.Address).String()
	if address == "<nil>" {
		return VerifiedBundle{}, profile.OfflineVerifiedArtifact{}, bundleError("live runtime endpoint")
	}
	return VerifiedBundle{
		DeploymentID: bundle.DeploymentID,
		Endpoint:     net.JoinHostPort(address, strconv.Itoa(int(endpoint.Port))),
		ProfileID:    verified.Profile.ProfileID, ContentID: verified.Profile.ContentID,
		RootFingerprint: bundle.RootFingerprint, IssuerFingerprint: fingerprint(bundle.IssuerPublicDER),
		RelayKeyID: policy.RelayAuthKeyID, Generation: verified.Profile.Generation,
		RootEpoch: verified.Profile.RootEpoch, RevocationEpoch: verified.Profile.RevocationEpoch,
		ValidUntil: verified.Profile.ValidUntil,
	}, verified, nil
}

func NewAndroidLiveActivationSessionForRecipient(encoded []byte, now time.Time, current lifecycle.VerifiedState, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1) (*profile.ActivationSession, error) {
	_, _, resolver, opener, err := liveRecipientProviders(encoded, now, 1, request, private)
	if err != nil {
		return nil, err
	}
	ownedOpener := &activationRecipientOpener{opener: opener}
	session, err := NewAndroidLiveActivationSession(encoded, now, current, resolver, ownedOpener)
	if err != nil {
		ownedOpener.Destroy()
		return nil, err
	}
	return session, nil
}

func liveRecipientProviders(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1) (liveProfileBundleV2, envelope.ArtifactMetadata, profile.RecipientResolver, *profilehpke.Opener, error) {
	return liveRecipientProvidersCore(encoded, now, minimumGeneration, request, private, liveResourceLegacy)
}

func liveRecipientProvidersCore(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, mode liveResourceMode) (liveProfileBundleV2, envelope.ArtifactMetadata, profile.RecipientResolver, *profilehpke.Opener, error) {
	return liveRecipientProvidersDiagnosticCore(encoded, now, minimumGeneration, request, private, mode, nil)
}

func liveRecipientProvidersDiagnosticCore(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, mode liveResourceMode, diagnostic *liveMaintenanceDiagnostic) (liveProfileBundleV2, envelope.ArtifactMetadata, profile.RecipientResolver, *profilehpke.Opener, error) {
	bundle, metadata, err := verifyLiveBundleAuthorityCore(encoded, now, minimumGeneration, mode, diagnostic)
	keepBundle := false
	if diagnostic != nil {
		defer func() {
			if !keepBundle {
				destroyMaintenanceBundle(&bundle)
			}
		}()
	}
	if err != nil {
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, err
	}
	if mode == liveResourceTypedFirstV1 && !liveResourceRequestShape(request) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, ErrInvalidInput
	}
	requestBytes, err := enrollment.EncodeRequestV1(request)
	if err != nil || metadata.RecipientHint != request.RequestID || metadata.RecipientEpoch == 0 {
		diagnostic.fail(LiveMaintenanceWrongRecipient)
		clear(requestBytes)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, bundleError("live recipient request")
	}
	clear(requestBytes)
	if mode == liveResourceTypedFirstV1 && !liveResourcePrivateShape(private) {
		diagnostic.fail(LiveMaintenanceInvalidRequest)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, ErrInvalidInput
	}
	privateBytes, err := enrollment.EncodePrivateBundleV1(private)
	clear(privateBytes)
	if err != nil {
		diagnostic.fail(LiveMaintenanceWrongRecipient)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, bundleError("live recipient private capability")
	}
	binding := profile.RecipientBinding{
		Class: envelope.ArtifactDeviceRecipient, ProviderID: bundle.Delegation.Scope.ProviderID,
		LineageID: bundle.Delegation.Scope.LineageID, ProfileNamespace: bundle.Delegation.Scope.ProfileNamespace,
		Hint: request.RequestID, KeyID: request.RecipientKeyID, Epoch: metadata.RecipientEpoch,
	}
	if _, err := profile.ResolveRecipientBinding([]profile.RecipientBinding{binding}, binding.Class, binding.Hint); err != nil {
		diagnostic.fail(LiveMaintenanceWrongRecipient)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, bundleError("live recipient binding")
	}
	opener, err := profilehpke.NewOpener(binding, private.RecipientPrivate)
	if err != nil {
		diagnostic.fail(LiveMaintenanceWrongRecipient)
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, bundleError("live recipient opener")
	}
	keepBundle = true
	return bundle, metadata, liveRecipientResolver{binding: binding}, opener, nil
}

// NewAndroidLiveActivationSession builds the stepwise activation transaction
// for a device-bound live profile. The outer owner authority is revalidated on
// every exact-byte reopen before the native sealed artifact is returned.
func NewAndroidLiveActivationSession(encoded []byte, now time.Time, current lifecycle.VerifiedState, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener) (*profile.ActivationSession, error) {
	request, err := liveActivationRequestWithResourceMode(encoded, now, current, resolver, opener, liveResourceLegacy)
	if err != nil {
		return nil, err
	}
	return profile.NewActivationSession(request), nil
}

func liveActivationRequestWithResourceMode(encoded []byte, now time.Time, current lifecycle.VerifiedState, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener, mode liveResourceMode) (profile.ActivationRequest, error) {
	return liveActivationRequestCore(encoded, now, current, resolver, opener, mode, nil)
}

func liveActivationRequestCore(encoded []byte, now time.Time, current lifecycle.VerifiedState, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener, mode liveResourceMode, diagnostic *liveMaintenanceDiagnostic) (profile.ActivationRequest, error) {
	verified, err := verifyLiveAndroidArtifactCore(encoded, now, 1, resolver, opener, mode, diagnostic)
	if err != nil {
		return profile.ActivationRequest{}, err
	}
	if diagnostic != nil {
		defer destroyLiveMaintenanceOffline(&verified)
	}
	return liveActivationRequestFromVerified(encoded, now, current, resolver, opener, mode, diagnostic, verified)
}

func liveActivationRequestFromVerified(encoded []byte, now time.Time, current lifecycle.VerifiedState, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener, mode liveResourceMode, diagnostic *liveMaintenanceDiagnostic, verified profile.OfflineVerifiedArtifact) (profile.ActivationRequest, error) {
	bundle, metadata, err := verifyLiveBundleAuthorityCore(encoded, now, 1, mode, diagnostic)
	if diagnostic != nil {
		diagnostic.destroyRequest()
		diagnostic.requestBundle = &bundle
	}
	if err != nil {
		return profile.ActivationRequest{}, err
	}
	rootPublic, err := parseP256Public(bundle.RootPublicDER)
	if err != nil {
		return profile.ActivationRequest{}, err
	}
	issuerPublic, err := parseP256Public(bundle.IssuerPublicDER)
	if err != nil {
		return profile.ActivationRequest{}, err
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{bundle.Root.Keys[0].KeyID: rootPublic, bundle.IssuerKey.KeyID: issuerPublic}}
	request := profile.ActivationRequest{
		Artifact: encoded, Dispatch: metadata, Now: now.UTC().Unix(), Current: current,
		Root:        bundle.Root,
		Delegation:  profile.SignedIssuerDelegationV1{Artifact: bundle.Delegation, RootKey: bundle.Root.Keys[0], Payload: bundle.DelegationPayload, Signature: bundle.DelegationSignature},
		Revocations: profile.SignedRevocationSetV1{Set: bundle.Revocations, RootKey: bundle.Root.Keys[0], Payload: bundle.RevocationPayload, Signature: bundle.RevocationSignature},
		Verifier:    verifier, Resolver: resolver, OfflineOpener: opener,
		ContractVersion: verified.Profile.ContractVersion, MinSafetyFloor: verified.Profile.RequiredSafetyFloor,
		MinRootEpoch: verified.Profile.RootEpoch, MinRevocationEpoch: verified.Profile.RevocationEpoch,
		Rejected: diagnostic.sink(opener),
	}
	request.UnwrapArtifact = func(candidate []byte) ([]byte, error) {
		if diagnostic != nil && !bytes.Equal(candidate, encoded) {
			diagnostic.fail(LiveMaintenanceInvalidRequest)
			return nil, bundleError("live activation outer authority")
		}
		candidateBundle, candidateMetadata, err := verifyLiveBundleAuthorityCore(candidate, now, 1, mode, diagnostic)
		if diagnostic != nil {
			defer destroyMaintenanceBundle(&candidateBundle)
		}
		if err != nil || candidateBundle.DeploymentID != bundle.DeploymentID || candidateBundle.RootFingerprint != bundle.RootFingerprint || candidateMetadata != metadata {
			diagnostic.fail(LiveMaintenanceProfileMismatch)
			return nil, bundleError("live activation outer authority")
		}
		return bytes.Clone(candidateBundle.SealedProfile), nil
	}
	return request, nil
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
