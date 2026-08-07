// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"errors"
	"os"
	"path/filepath"

	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

const recipientAuthoritySchemaV1 = "kurd-selfhost-recipient-authority-v1"

type signedRecipientAuthorityV1 struct {
	_         struct{} `cbor:",toarray"`
	Schema    string
	Version   uint64
	Authority profile.ScopedAuthorityArtifact
	Payload   []byte
	Signature []byte
}

func expectedRecipientRegistrarAuthority(state persistedState) profile.ScopedAuthorityArtifact {
	subjectMaterial := []byte("kurdistan-vpn/selfhost-recipient-registrar/v1\x00" + state.DeploymentID + "\x00" + state.RootFingerprint)
	return profile.ScopedAuthorityArtifact{
		Role: profile.RoleRecipientRegistrar, RootEpoch: state.Root.Epoch,
		RootKeyID: state.Root.Keys[0].KeyID,
		SubjectKey: profile.KeyReference{
			KeyID:   keyID("recipient-registrar", subjectMaterial),
			SuiteID: uint16(envelope.SuiteClassicalV1),
		},
		Scope: state.Delegation.Scope, ValidFrom: state.Root.ValidFrom,
		ValidUntil: state.Root.ValidUntil, AuthorizationEpoch: state.Root.Epoch,
	}
}

func encodeSignedRecipientAuthority(state persistedState, rootPrivate *ecdsa.PrivateKey) ([]byte, error) {
	if rootPrivate == nil || len(state.Root.Keys) != 1 {
		return nil, ErrRecipientAuthority
	}
	authority := expectedRecipientRegistrarAuthority(state)
	payload, err := profile.EncodeScopedAuthorityV1(authority)
	if err != nil {
		return nil, ErrRecipientAuthority
	}
	signature, err := (p256Signer{keyID: state.Root.Keys[0].KeyID, key: rootPrivate}).Sign(state.Root.Keys[0], payload)
	if err != nil {
		return nil, ErrRecipientAuthority
	}
	encoded, err := encodeCanonical(signedRecipientAuthorityV1{
		Schema: recipientAuthoritySchemaV1, Version: 1, Authority: authority,
		Payload: payload, Signature: signature,
	})
	if err != nil || len(encoded) == 0 || len(encoded) > 4096 {
		return nil, ErrRecipientAuthority
	}
	return encoded, nil
}

func installRecipientAuthority(dataDir string, encoded []byte, exclusive bool) error {
	if dataDir == "" || len(encoded) == 0 || len(encoded) > 4096 {
		return ErrRecipientAuthority
	}
	path := filepath.Join(dataDir, recipientAuthorityFileName)
	var err error
	if exclusive {
		err = writeSelfhostPrivateFileExclusive(path, encoded)
	} else {
		err = atomicWriteFile(path, encoded, 0o600)
	}
	if err != nil || protectSelfhostPrivatePath(path, false) != nil {
		return ErrRecipientAuthority
	}
	return nil
}

func loadRecipientRegistrarAuthority(dataDir string, state persistedState, now int64) (profile.ScopedAuthorityArtifact, error) {
	path := filepath.Join(dataDir, recipientAuthorityFileName)
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() <= 0 || info.Size() > 4096 || protectSelfhostPrivatePath(path, false) != nil {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	raw, err := os.ReadFile(path)
	if err != nil || int64(len(raw)) != info.Size() {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	var signed signedRecipientAuthorityV1
	if decodeCanonical(raw, &signed, 4096) != nil || signed.Schema != recipientAuthoritySchemaV1 || signed.Version != 1 || len(signed.Signature) != 64 {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	expected := expectedRecipientRegistrarAuthority(state)
	if signed.Authority != expected {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	canonical, err := profile.EncodeScopedAuthorityV1(signed.Authority)
	if err != nil || !bytes.Equal(canonical, signed.Payload) {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	rootPublic, err := parseP256Public(state.RootPublicDER)
	if err != nil {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	verifier := p256Verifier{keys: map[string]*ecdsa.PublicKey{state.Root.Keys[0].KeyID: rootPublic}}
	if verifier.Verify(state.Root.Keys[0], signed.Payload, signed.Signature) != nil ||
		profile.ValidateScopedAuthority(state.Root, signed.Authority, profile.RoleRecipientRegistrar, now) != nil {
		return profile.ScopedAuthorityArtifact{}, ErrRecipientAuthority
	}
	return signed.Authority, nil
}

func removeRecipientAuthority(dataDir string) {
	err := os.Remove(filepath.Join(dataDir, recipientAuthorityFileName))
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return
	}
}
