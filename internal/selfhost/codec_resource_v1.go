// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/x509"
	"errors"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

type liveResourceMode uint8

const (
	liveResourceLegacy liveResourceMode = iota
	liveResourceTypedFirstV1
)

func (m liveResourceMode) valid() bool {
	return m == liveResourceLegacy || m == liveResourceTypedFirstV1
}

var errLiveResourceSize = errors.New("selfhost: resource input size")

func decodeLiveBundleWithResourceMode(encoded []byte, mode liveResourceMode) (liveProfileBundleV2, error) {
	if !mode.valid() {
		return liveProfileBundleV2{}, ErrInvalidInput
	}
	var b liveProfileBundleV2
	if mode == liveResourceLegacy {
		if decodeCanonical(encoded, &b, envelope.MaxTotalInputBytes) != nil || b.Version != liveBundleVersion {
			return liveProfileBundleV2{}, ErrInvalidInput
		}
		return b, nil
	}
	if len(encoded) == 0 || len(encoded) > envelope.MaxTotalInputBytes {
		return liveProfileBundleV2{}, errLiveResourceSize
	}
	if decodeCanonicalFields(encoded, &b, envelope.MaxTotalInputBytes, 256) != nil {
		return liveProfileBundleV2{}, ErrInvalidInput
	}
	if b.Version != liveBundleVersion || !resourceRootShape(b.DeploymentID, b.RootFingerprint, b.Root, b.RootPublicDER) || !resourceKeyShape(b.IssuerKey) || !resourceDERShape(b.IssuerPublicDER) || !resourceRevocationShape(b.Revocations) || !resourceDelegationShape(b.Delegation) || len(b.DelegationSignature) != 64 || len(b.RevocationSignature) != 64 || len(b.DelegationPayload) == 0 || len(b.RevocationPayload) == 0 {
		return liveProfileBundleV2{}, ErrInvalidInput
	}
	if err := envelope.PreflightSealedProfileResourcesV1(b.SealedProfile); err != nil {
		return liveProfileBundleV2{}, liveResourceError(err)
	}
	if err := resourceCanonicalEqual(encoded, b); err != nil {
		return liveProfileBundleV2{}, err
	}
	return b, nil
}

func decodePublicationSnapshotWithResourceMode(encoded []byte, mode liveResourceMode) (publicationSnapshot, error) {
	if !mode.valid() {
		return publicationSnapshot{}, ErrInvalidInput
	}
	var s publicationSnapshot
	if mode == liveResourceLegacy {
		if err := decodeCanonical(encoded, &s, maxStateBytes); err != nil {
			return publicationSnapshot{}, err
		}
		return s, nil
	}
	if len(encoded) == 0 || len(encoded) > maxStateBytes {
		return publicationSnapshot{}, errLiveResourceSize
	}
	if decodeCanonicalFields(encoded, &s, maxStateBytes, 4096) != nil {
		return publicationSnapshot{}, ErrInvalidInput
	}
	if s.Version != 1 || s.Revision == 0 || s.GeneratedAt <= 0 || !resourceRootShape(s.DeploymentID, s.RootFingerprint, s.Root, s.RootPublicDER) || !resourceRevocationShape(s.Revocations) || len(s.RevocationSignature) != 64 || len(s.RevocationPayload) == 0 || len(s.Profiles) > 4096 {
		return publicationSnapshot{}, ErrInvalidInput
	}
	// Profile leaves are not parsed or admitted. Their copies and slice backing
	// are charged to this full typed decode, within the aggregate input ceiling.
	if err := resourceCanonicalEqual(encoded, s); err != nil {
		return publicationSnapshot{}, err
	}
	return s, nil
}

func resourceCanonicalEqual(encoded []byte, value any) error {
	canonical, err := encodeCanonical(value)
	defer clear(canonical)
	if err != nil || !bytes.Equal(encoded, canonical) {
		return ErrInvalidInput
	}
	return nil
}

func resourceID(value string, max int) bool { return len(value) > 0 && len(value) <= max }

func resourceKeyShape(k profile.KeyReference) bool { return resourceID(k.KeyID, 128) }

func resourceDERShape(der []byte) bool {
	// Canonical uncompressed P-256 SPKI only. This is the existing standard
	// parser, invoked only after the exact fixed byte limit, not a DER scanner.
	if len(der) != 91 {
		return false
	}
	key, err := parseP256Public(der)
	if err != nil {
		return false
	}
	canonical, err := x509.MarshalPKIXPublicKey(key)
	return err == nil && bytes.Equal(der, canonical)
}

func resourceRootShape(deployment, fingerprint string, root profile.RootSetArtifact, der []byte) bool {
	return resourceID(deployment, 64) && len(fingerprint) == 64 && resourceID(root.ViewID, 128) && len(root.Keys) == 1 && resourceKeyShape(root.Keys[0]) && resourceDERShape(der)
}

func resourceDelegationShape(d profile.IssuerDelegationArtifact) bool {
	return resourceID(d.RootKeyID, 128) && resourceKeyShape(d.IssuerKey) && resourceID(d.Scope.ProviderID, 128) && resourceID(d.Scope.LineageID, 128) && resourceID(d.Scope.ProfileNamespace, 127)
}

func resourceRevocationShape(r profile.RevocationSetV1) bool {
	if !resourceID(r.Scope, 128) {
		return false
	}
	for _, ids := range [][]string{r.RevokedIssuerKeyIDs, r.RevokedContentIDs} {
		if len(ids) > 256 {
			return false
		}
		for _, id := range ids {
			if !resourceID(id, 128) {
				return false
			}
		}
	}
	return true
}
