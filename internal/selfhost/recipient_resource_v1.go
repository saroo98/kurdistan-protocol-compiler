// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"crypto/ed25519"
	"time"

	"kurdistan/internal/crypto/profilehpke"
	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
	"kurdistan/internal/product/runtimepolicy"
	"kurdistan/internal/protocol/liveprogram"
)

type liveResourceFailure uint8

const (
	liveResourceFailureNone liveResourceFailure = iota
	liveResourceFailureInvalid
	liveResourceFailureSize
)

// This private composition is operation-owned, not an arbitrary interface
// callback. failure is one current OpenOffline result, never a retained history.
// The later maintenance owner must serialize its verification workspace.
// Before a direct profile admission call, that owner must reset failure even
// when verification might reject before OpenOffline. The shared selfhost
// verification core already does so at whole-call entry.
type liveResourceRecipientOpener struct {
	opener  *profilehpke.Opener
	mode    liveResourceMode
	failure liveResourceFailure
}

func liveRecipientProvidersWithResourceMode(encoded []byte, now time.Time, minimumGeneration uint64, request enrollment.PublicRequestV1, private enrollment.PrivateBundleV1, mode liveResourceMode) (liveProfileBundleV2, envelope.ArtifactMetadata, profile.RecipientResolver, *liveResourceRecipientOpener, error) {
	if !mode.valid() {
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, ErrInvalidInput
	}
	b, metadata, resolver, opener, err := liveRecipientProvidersCore(encoded, now, minimumGeneration, request, private, mode)
	if err != nil {
		return liveProfileBundleV2{}, envelope.ArtifactMetadata{}, nil, nil, err
	}
	return b, metadata, resolver, &liveResourceRecipientOpener{opener: opener, mode: mode}, nil
}

func validLiveResourceProviders(mode liveResourceMode, resolver profile.RecipientResolver, opener profile.OfflineRecipientOpener) bool {
	if !mode.valid() {
		return false
	}
	if mode == liveResourceLegacy {
		return true
	}
	owned, ok := opener.(*liveResourceRecipientOpener)
	_, concreteResolver := resolver.(liveRecipientResolver)
	return ok && owned != nil && owned.opener != nil && owned.mode == liveResourceTypedFirstV1 && concreteResolver
}

func liveResourceRequestShape(r enrollment.PublicRequestV1) bool {
	return len(r.RequestID) == 64 && len(r.RecipientKeyID) == 26 && len(r.ClientAuthKeyID) == 32 && len(r.RecipientPublic) == envelope.HPKEP256EncSize && len(r.ClientAuthPublic) == ed25519.PublicKeySize && len(r.Nonce) == 32 && len(r.Signature) == ed25519.SignatureSize
}

func liveResourcePrivateShape(p enrollment.PrivateBundleV1) bool {
	return len(p.RecipientPrivate) == 32 && len(p.ClientAuthSeed) == ed25519.SeedSize
}

func liveResourceError(err error) error {
	if envelope.CodecErrorIs(err, envelope.CodecSizeLimit) || runtimepolicy.IsCategory(err, runtimepolicy.ErrorSize) || liveprogram.IsCategory(err, liveprogram.ErrorSize) {
		return errLiveResourceSize
	}
	return ErrInvalidInput
}

func (o *liveResourceRecipientOpener) resourceError() error {
	if o == nil {
		return nil
	}
	switch o.failure {
	case liveResourceFailureSize:
		return errLiveResourceSize
	case liveResourceFailureInvalid:
		return ErrInvalidInput
	default:
		return nil
	}
}

func (o *liveResourceRecipientOpener) OpenOffline(binding profile.RecipientBinding, protected, encapsulation, ciphertext []byte) ([]byte, error) {
	if o == nil || o.opener == nil || !o.mode.valid() {
		return nil, ErrInvalidInput
	}
	o.failure = liveResourceFailureNone
	if o.mode == liveResourceLegacy {
		return o.opener.OpenOffline(binding, protected, encapsulation, ciphertext)
	}
	if err := envelope.PreflightSealProtectedResourcesV1(protected); err != nil {
		return nil, o.rejectResource(err)
	}
	plaintext, err := o.opener.OpenOffline(binding, protected, encapsulation, ciphertext)
	if err != nil {
		return nil, err
	}
	if err := preflightOpenedLiveResources(plaintext); err != nil {
		clear(plaintext)
		return nil, o.rejectResource(err)
	}
	return plaintext, nil
}

func preflightOpenedLiveResources(plaintext []byte) error {
	payload, err := envelope.PreflightSignedProfileResourcesV1(plaintext)
	defer clear(payload)
	if err != nil {
		return err
	}
	policy, err := envelope.PreflightCanonicalProfileResourcesV1(payload)
	defer clear(policy)
	if err != nil {
		return err
	}
	return runtimepolicy.PreflightRuntimeResourcesV1(policy)
}

func (o *liveResourceRecipientOpener) rejectResource(err error) error {
	o.failure = liveResourceFailureInvalid
	if liveResourceError(err) == errLiveResourceSize {
		o.failure = liveResourceFailureSize
	}
	return o.resourceError()
}

func (o *liveResourceRecipientOpener) Close() {
	if o == nil || o.opener == nil {
		return
	}
	owned := o.opener
	o.opener = nil
	owned.Close()
}

func (o *liveResourceRecipientOpener) Destroy() { o.Close() }
