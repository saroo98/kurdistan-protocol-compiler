// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/fxamacker/cbor/v2"

	"kurdistan/internal/product/enrollment"
	"kurdistan/internal/product/envelope"
	"kurdistan/internal/product/profile"
)

func Initialize(options InitOptions) (InitResult, error) {
	now := options.Now.UTC()
	if !validName(options.DeploymentName) || !validEndpoint(options.Endpoint) || now.IsZero() || !validPassphrase(options.RecoveryPassphrase) ||
		options.DataDir == "" || options.RecoveryPath == "" || recoveryInsideDataDir(options.DataDir, options.RecoveryPath) {
		return InitResult{}, ErrInvalidInput
	}
	if err := os.MkdirAll(filepath.Dir(options.RecoveryPath), 0o700); err != nil {
		return InitResult{}, err
	}
	if _, err := os.Stat(options.RecoveryPath); err == nil {
		return InitResult{}, ErrAlreadyInitialized
	} else if !errors.Is(err, os.ErrNotExist) {
		return InitResult{}, err
	}
	deploymentID, err := randomID("deployment")
	if err != nil {
		return InitResult{}, err
	}
	rootPrivate, rootID, rootPublic, err := newP256Key("root")
	if err != nil {
		return InitResult{}, err
	}
	issuerPrivate, issuerID, issuerPublic, err := newP256Key("issuer")
	if err != nil {
		return InitResult{}, err
	}
	relayPrivate, relayID, relayPublic, err := newRelayKey()
	if err != nil || requireDistinctKeys(rootID, issuerID, relayID) != nil {
		return InitResult{}, ErrInvalidInput
	}
	master, err := randomBytes(32)
	if err != nil {
		return InitResult{}, err
	}
	defer zero(master)
	issuerDER, err := x509.MarshalECPrivateKey(issuerPrivate)
	if err != nil {
		return InitResult{}, err
	}
	issuerSecret, err := sealWithKey(master, issuerDER, []byte(deploymentID+"|"+issuerID))
	zero(issuerDER)
	if err != nil {
		return InitResult{}, err
	}
	relaySecret, err := sealWithKey(master, relayPrivate, []byte(deploymentID+"|"+relayID))
	zero(relayPrivate)
	if err != nil {
		return InitResult{}, err
	}
	tlsName, _, err := net.SplitHostPort(options.Endpoint)
	if err != nil {
		return InitResult{}, ErrInvalidInput
	}
	tlsIdentity, err := newTLSIdentity(master, deploymentID, strings.ToLower(tlsName), 1, now)
	if err != nil {
		return InitResult{}, err
	}
	ipv4Pool, ipv6Pool := defaultAddressPools()
	root := profile.RootSetArtifact{
		Epoch: 1, ViewID: "root-view.1", ValidFrom: now.Unix(),
		ValidUntil: now.AddDate(20, 0, 0).Unix(),
		Keys:       []profile.KeyReference{{KeyID: rootID, SuiteID: uint16(envelope.SuiteClassicalV1)}},
	}
	providerID := "provider." + deploymentID[strings.LastIndex(deploymentID, ".")+1:]
	lineageID := "lineage." + deploymentID[strings.LastIndex(deploymentID, ".")+1:]
	issuerKey := profile.KeyReference{KeyID: issuerID, SuiteID: uint16(envelope.SuiteClassicalV1)}
	delegation := profile.IssuerDelegationArtifact{
		RootEpoch: root.Epoch, RootKeyID: rootID, IssuerKey: issuerKey,
		Scope:     profile.AuthorityScope{ProviderID: providerID, LineageID: lineageID, ProfileNamespace: "profiles."},
		ValidFrom: now.Unix(), ValidUntil: now.AddDate(5, 0, 0).Unix(), DelegationEpoch: 1,
		MaxProfileValiditySecs: uint64(maxProfileValidity / time.Second),
	}
	delegationPayload, err := profile.EncodeIssuerDelegationV1(delegation)
	if err != nil {
		return InitResult{}, err
	}
	delegationSignature, err := (p256Signer{keyID: rootID, key: rootPrivate}).Sign(root.Keys[0], delegationPayload)
	if err != nil {
		return InitResult{}, err
	}
	revocations := profile.RevocationSetV1{
		Version: 1, Scope: "revocation.1", RootEpoch: root.Epoch, Epoch: 1,
		IssuedAt: now.Unix(), ExpiresAt: now.AddDate(5, 0, 0).Unix(),
		MaxOfflineStalenessSecs: uint64(7 * 24 * time.Hour / time.Second),
		RevokedIssuerKeyIDs:     []string{}, RevokedContentIDs: []string{},
	}
	revocationPayload, err := profile.EncodeRevocationSetV1(revocations)
	if err != nil {
		return InitResult{}, err
	}
	revocationSignature, err := (p256Signer{keyID: rootID, key: rootPrivate}).Sign(root.Keys[0], revocationPayload)
	if err != nil {
		return InitResult{}, err
	}
	state := persistedState{
		Schema: stateSchema, Version: stateVersionV2, MigrationEpoch: migrationEpochV2, DeploymentID: deploymentID, DeploymentName: options.DeploymentName,
		Endpoint: options.Endpoint, Root: root, RootPublicDER: rootPublic, RootFingerprint: fingerprint(rootPublic),
		IssuerKey: issuerKey, IssuerPublicDER: issuerPublic, IssuerSecret: issuerSecret,
		RelayEpoch: 1, RelayKeyID: relayID, RelayPublic: relayPublic, RelaySecret: relaySecret, TLS: tlsIdentity,
		Delegation: delegation, DelegationPayload: delegationPayload, DelegationSig: delegationSignature,
		Revocations: revocations, RevocationPayload: revocationPayload, RevocationSig: revocationSignature,
		LastObservedAt: now.Unix(), IPv4Pool: ipv4Pool, IPv6Pool: ipv6Pool, Profiles: []profileRecord{}, Assignments: []addressAssignmentV1{}, RecipientUses: recipientUseLedgerV1{}, Audit: []auditEntry{},
	}
	recipientAuthority, err := encodeSignedRecipientAuthority(state, rootPrivate)
	if err != nil {
		return InitResult{}, err
	}
	rootPrivateDER, err := x509.MarshalECPrivateKey(rootPrivate)
	if err != nil {
		return InitResult{}, err
	}
	recovery, err := sealRecovery(recoveryPayload{
		Schema: recoverySchema, DeploymentID: deploymentID, RootFingerprint: state.RootFingerprint,
		RootPrivateDER: rootPrivateDER, CreatedAt: now.Unix(),
	}, options.RecoveryPassphrase)
	zero(rootPrivateDER)
	if err != nil {
		return InitResult{}, err
	}
	if err := writeExclusive(options.RecoveryPath, recovery, 0o600); err != nil {
		return InitResult{}, err
	}
	if err := initializeStore(options.DataDir, master, state, recipientAuthority); err != nil {
		_ = os.Remove(options.RecoveryPath)
		return InitResult{}, err
	}
	return InitResult{DeploymentID: deploymentID, RootFingerprint: state.RootFingerprint, RecoveryPath: options.RecoveryPath}, nil
}

func ConfirmRecovery(dataDir, recoveryPath string, passphrase []byte, now time.Time) error {
	if now.IsZero() {
		return ErrInvalidInput
	}
	raw, err := os.ReadFile(recoveryPath)
	if err != nil {
		return ErrRecoveryRejected
	}
	payload, err := openRecovery(raw, passphrase)
	if err != nil {
		return ErrRecoveryRejected
	}
	rootPrivate, err := parseP256Private(payload.RootPrivateDER)
	zero(payload.RootPrivateDER)
	if err != nil {
		return ErrRecoveryRejected
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&rootPrivate.PublicKey)
	if err != nil {
		return ErrRecoveryRejected
	}
	var recipientAuthority []byte
	err = withStateTransaction(dataDir, "confirm-recovery", payload.DeploymentID, now.UTC().Unix(), func(state *persistedState, _ []byte) error {
		if payload.DeploymentID != state.DeploymentID || payload.RootFingerprint != state.RootFingerprint ||
			!bytes.Equal(publicDER, state.RootPublicDER) || fingerprint(publicDER) != state.RootFingerprint {
			return ErrRecoveryRejected
		}
		var encodeErr error
		recipientAuthority, encodeErr = encodeSignedRecipientAuthority(*state, rootPrivate)
		if encodeErr != nil {
			return encodeErr
		}
		state.RecoveryConfirmed = true
		return nil
	})
	if err != nil {
		return err
	}
	return installRecipientAuthority(dataDir, recipientAuthority, false)
}

func CreateProfile(dataDir string, options CreateProfileOptions) (IssuedProfile, error) {
	now := options.Now.UTC()
	if !validName(options.Name) || now.IsZero() || options.ValidFor < time.Hour || options.ValidFor > maxProfileValidity {
		return IssuedProfile{}, ErrInvalidInput
	}
	var recipientRequest enrollment.PublicRequestV1
	var err error
	if len(options.RecipientRequest) != 0 {
		recipientRequest, err = enrollment.DecodeAndVerifyRequestV1(options.RecipientRequest, now)
		if err != nil || options.RegistryDir == "" {
			return IssuedProfile{}, ErrInvalidInput
		}
	}
	var result IssuedProfile
	err = withStateTransaction(dataDir, "create-profile", "profile."+options.Name, now.Unix(), func(state *persistedState, master []byte) error {
		if !state.RecoveryConfirmed {
			return ErrRecoveryUnconfirmed
		}
		if state.Drained {
			return ErrDrained
		}
		if len(state.Profiles) >= maxProfiles {
			return ErrInvalidInput
		}
		profileID, err := randomID("profiles." + options.Name)
		if err != nil {
			return err
		}
		var issued IssuedProfile
		var record profileRecord
		if len(options.RecipientRequest) != 0 {
			authority, err := loadRecipientRegistrarAuthority(dataDir, *state, now.Unix())
			if err != nil {
				return err
			}
			nextRecord, _, _, _, err := recipientCapabilityFromRequest(*state, recipientRequest, 1)
			if err != nil || profile.ValidateRecipientTransition(state.Root, authority, nil, nextRecord.binding(), profile.RecipientEnroll, now.Unix()) != nil {
				return ErrInvalidInput
			}
			reservation, err := reserveOwnerRecipientUse(options.RegistryDir, state.RecipientUses.RegistryID, state.DeploymentID, profileID, recipientRequest, now.Unix(), options.ConfirmRecipientReuse)
			if err != nil {
				return err
			}
			issued, record, err = issueLiveProfile(state, master, options.Name, profileID, "", "initial", options.ValidFor, options.LiveProgram, now, recipientRequest, 1, &reservation)
		} else {
			issued, record, err = issueProfile(state, master, options.Name, profileID, "", "initial", options.ValidFor, now)
		}
		if err != nil {
			return err
		}
		state.Profiles = append(state.Profiles, record)
		result = issued
		return nil
	})
	return result, err
}

func RotateProfile(dataDir string, options RotateProfileOptions) (IssuedProfile, error) {
	now := options.Now.UTC()
	if !validID(options.ProfileID) || options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) ||
		now.IsZero() || options.ValidFor < time.Hour || options.ValidFor > maxProfileValidity {
		return IssuedProfile{}, ErrInvalidInput
	}
	var recipientRequest enrollment.PublicRequestV1
	var err error
	if len(options.RecipientRequest) != 0 {
		recipientRequest, err = enrollment.DecodeAndVerifyRequestV1(options.RecipientRequest, now)
		if err != nil || options.RegistryDir == "" {
			return IssuedProfile{}, ErrInvalidInput
		}
	}
	var result IssuedProfile
	err = withStateTransaction(dataDir, "rotate-profile", options.ProfileID, now.Unix(), func(state *persistedState, master []byte) error {
		if !state.RecoveryConfirmed {
			return ErrRecoveryUnconfirmed
		}
		if state.Drained {
			return ErrDrained
		}
		index := profileIndex(state.Profiles, options.ProfileID)
		if index < 0 || state.Profiles[index].Revoked {
			return ErrNotFound
		}
		rootPrivate, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase)
		if err != nil {
			return err
		}
		previous := state.Profiles[index]
		state.Assignments = quarantineProfileAssignments(state.Assignments, previous.ProfileID, now.Unix())
		if err := updateRevocations(state, rootPrivate, now, append(state.Revocations.RevokedContentIDs, previous.ContentID), state.Revocations.EmergencyDenied); err != nil {
			return err
		}
		var issued IssuedProfile
		var record profileRecord
		if len(options.RecipientRequest) != 0 {
			candidateUse := recipientUseRecord(recipientRequest, previous.ProfileID, now.Unix())
			if recipientUseConflicts(state.RecipientUses, candidateUse) {
				return ErrRecipientReplay
			}
			epoch := uint64(1)
			var current *profile.RecipientBinding
			transition := profile.RecipientEnroll
			if previous.Mode == profileModeLive {
				if previous.Recipient.Epoch == ^uint64(0) {
					return ErrInvalidInput
				}
				epoch = previous.Recipient.Epoch + 1
				value := previous.Recipient.binding()
				current = &value
				transition = profile.RecipientRotate
			}
			nextRecord, _, _, _, err := recipientCapabilityFromRequest(*state, recipientRequest, epoch)
			authority, authorityErr := loadRecipientRegistrarAuthority(dataDir, *state, now.Unix())
			if err != nil || authorityErr != nil || profile.ValidateRecipientTransition(state.Root, authority, current, nextRecord.binding(), transition, now.Unix()) != nil {
				return ErrInvalidInput
			}
			reservation, err := reserveOwnerRecipientUse(options.RegistryDir, state.RecipientUses.RegistryID, state.DeploymentID, previous.ProfileID, recipientRequest, now.Unix(), options.ConfirmRecipientReuse)
			if err != nil {
				return err
			}
			issued, record, err = issueLiveProfile(state, master, previous.Name, previous.ProfileID, previous.ContentID, "replacement", options.ValidFor, options.LiveProgram, now, recipientRequest, epoch, &reservation)
		} else if previous.Mode == profileModeLive {
			reused := enrollment.PublicRequestV1{
				RequestID: previous.Recipient.Hint, RecipientKeyID: previous.Recipient.KeyID,
				RecipientPublic: bytes.Clone(previous.RecipientPublic), ClientAuthKeyID: previous.ClientAuthKeyID,
				ClientAuthPublic: bytes.Clone(previous.ClientAuthPublic),
			}
			issued, record, err = issueLiveProfile(state, master, previous.Name, previous.ProfileID, previous.ContentID, "replacement", options.ValidFor, options.LiveProgram, now, reused, previous.Recipient.Epoch, nil)
		} else {
			issued, record, err = issueProfile(state, master, previous.Name, previous.ProfileID, previous.ContentID, "replacement", options.ValidFor, now)
		}
		if err != nil {
			return err
		}
		state.Profiles[index] = record
		result = issued
		return nil
	})
	return result, err
}

func RevokeProfile(dataDir string, options RevokeProfileOptions) error {
	now := options.Now.UTC()
	if !validID(options.ProfileID) || options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) || now.IsZero() {
		return ErrInvalidInput
	}
	return withStateTransaction(dataDir, "revoke-profile", options.ProfileID, now.Unix(), func(state *persistedState, _ []byte) error {
		if !state.RecoveryConfirmed {
			return ErrRecoveryUnconfirmed
		}
		index := profileIndex(state.Profiles, options.ProfileID)
		if index < 0 || state.Profiles[index].Revoked {
			return ErrNotFound
		}
		rootPrivate, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase)
		if err != nil {
			return err
		}
		if err := updateRevocations(state, rootPrivate, now, append(state.Revocations.RevokedContentIDs, state.Profiles[index].ContentID), state.Revocations.EmergencyDenied); err != nil {
			return err
		}
		state.Assignments = quarantineProfileAssignments(state.Assignments, state.Profiles[index].ProfileID, now.Unix())
		state.Profiles[index].Revoked = true
		return nil
	})
}

func SetDrained(dataDir string, drained bool, now time.Time) error {
	now = now.UTC()
	if now.IsZero() {
		return ErrInvalidInput
	}
	action := "resume-node"
	if drained {
		action = "drain-node"
	}
	return withStateTransaction(dataDir, action, "node.runtime", now.Unix(), func(state *persistedState, _ []byte) error {
		state.Drained = drained
		return nil
	})
}

func SetDeploymentDisabled(dataDir string, disabled bool, options RecoveryActionOptions) error {
	now := options.Now.UTC()
	if options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) || now.IsZero() {
		return ErrInvalidInput
	}
	action := "enable-deployment"
	if disabled {
		action = "disable-deployment"
	}
	return withStateTransaction(dataDir, action, "deployment.authority", now.Unix(), func(state *persistedState, _ []byte) error {
		rootPrivate, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase)
		if err != nil {
			return err
		}
		return updateRevocations(state, rootPrivate, now, state.Revocations.RevokedContentIDs, disabled)
	})
}

func RepairClock(dataDir string, options RecoveryActionOptions) error {
	now := options.Now.UTC()
	if options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) || now.IsZero() {
		return ErrInvalidInput
	}
	return withStateTransactionClock(dataDir, "repair-clock", "deployment.clock", now.Unix(), true, func(state *persistedState, _ []byte) error {
		if _, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase); err != nil {
			return err
		}
		state.LastObservedAt = now.Unix()
		return nil
	})
}

func RotateIssuer(dataDir string, options RecoveryActionOptions) (KeyRotationResult, error) {
	now := options.Now.UTC()
	if options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) || now.IsZero() {
		return KeyRotationResult{}, ErrInvalidInput
	}
	var result KeyRotationResult
	err := withStateTransaction(dataDir, "rotate-issuer", "deployment.issuer", now.Unix(), func(state *persistedState, master []byte) error {
		rootPrivate, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase)
		if err != nil {
			return err
		}
		previous := state.IssuerKey.KeyID
		issuerPrivate, issuerID, issuerPublic, err := newP256Key("issuer")
		if err != nil || requireDistinctKeys(state.Root.Keys[0].KeyID, issuerID, state.RelayKeyID) != nil {
			return ErrInvalidInput
		}
		issuerDER, err := x509.MarshalECPrivateKey(issuerPrivate)
		if err != nil {
			return err
		}
		issuerSecret, err := sealWithKey(master, issuerDER, []byte(state.DeploymentID+"|"+issuerID))
		zero(issuerDER)
		if err != nil {
			return err
		}
		state.IssuerKey = profile.KeyReference{KeyID: issuerID, SuiteID: uint16(envelope.SuiteClassicalV1)}
		state.IssuerPublicDER = issuerPublic
		state.IssuerSecret = issuerSecret
		state.Delegation.IssuerKey = state.IssuerKey
		state.Delegation.DelegationEpoch++
		state.Delegation.ValidFrom = now.Unix()
		state.Delegation.ValidUntil = now.AddDate(5, 0, 0).Unix()
		delegationPayload, err := profile.EncodeIssuerDelegationV1(state.Delegation)
		if err != nil {
			return err
		}
		delegationSignature, err := (p256Signer{keyID: state.Root.Keys[0].KeyID, key: rootPrivate}).Sign(state.Root.Keys[0], delegationPayload)
		if err != nil {
			return err
		}
		state.DelegationPayload, state.DelegationSig = delegationPayload, delegationSignature
		state.Revocations.RevokedIssuerKeyIDs = sortedUnique(append(state.Revocations.RevokedIssuerKeyIDs, previous))
		if err := updateRevocations(state, rootPrivate, now, appendAllCurrentContentIDs(state.Revocations.RevokedContentIDs, state.Profiles), state.Revocations.EmergencyDenied); err != nil {
			return err
		}
		state.Assignments = quarantineAllAssignments(state.Assignments, now.Unix())
		revoked := revokeAllProfiles(state.Profiles)
		result = KeyRotationResult{Kind: "issuer", PreviousKeyID: previous, CurrentKeyID: issuerID, DelegationEpoch: state.Delegation.DelegationEpoch, RevocationEpoch: state.Revocations.Epoch, RevokedProfiles: revoked}
		return nil
	})
	return result, err
}

func RotateRelay(dataDir string, options RecoveryActionOptions) (KeyRotationResult, error) {
	now := options.Now.UTC()
	if options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) || now.IsZero() {
		return KeyRotationResult{}, ErrInvalidInput
	}
	var result KeyRotationResult
	err := withStateTransaction(dataDir, "rotate-relay", "deployment.relay", now.Unix(), func(state *persistedState, master []byte) error {
		rootPrivate, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase)
		if err != nil {
			return err
		}
		previous := state.RelayKeyID
		if state.RelayEpoch == ^uint64(0) {
			return ErrInvalidInput
		}
		relayPrivate, relayID, relayPublic, err := newRelayKey()
		if err != nil || requireDistinctKeys(state.Root.Keys[0].KeyID, state.IssuerKey.KeyID, relayID) != nil {
			return ErrInvalidInput
		}
		relaySecret, err := sealWithKey(master, relayPrivate, []byte(state.DeploymentID+"|"+relayID))
		zero(relayPrivate)
		if err != nil {
			return err
		}
		state.RelayEpoch++
		state.RelayKeyID, state.RelayPublic, state.RelaySecret = relayID, relayPublic, relaySecret
		if err := updateRevocations(state, rootPrivate, now, appendAllCurrentContentIDs(state.Revocations.RevokedContentIDs, state.Profiles), state.Revocations.EmergencyDenied); err != nil {
			return err
		}
		state.Assignments = quarantineAllAssignments(state.Assignments, now.Unix())
		revoked := revokeAllProfiles(state.Profiles)
		result = KeyRotationResult{Kind: "relay", PreviousKeyID: previous, CurrentKeyID: relayID, DelegationEpoch: state.Delegation.DelegationEpoch, RevocationEpoch: state.Revocations.Epoch, RelayEpoch: state.RelayEpoch, TLSEpoch: state.TLS.Epoch, RevokedProfiles: revoked}
		return nil
	})
	return result, err
}

func RotateTLS(dataDir string, options RecoveryActionOptions) (KeyRotationResult, error) {
	now := options.Now.UTC()
	if options.RecoveryPath == "" || !validPassphrase(options.RecoveryPassphrase) || now.IsZero() {
		return KeyRotationResult{}, ErrInvalidInput
	}
	var result KeyRotationResult
	err := withStateTransaction(dataDir, "rotate-tls", "deployment.tls", now.Unix(), func(state *persistedState, master []byte) error {
		rootPrivate, err := recoveryRootForState(*state, options.RecoveryPath, options.RecoveryPassphrase)
		if err != nil {
			return err
		}
		if state.TLS.Epoch == ^uint64(0) {
			return ErrInvalidInput
		}
		previous := state.TLS.KeyID
		identity, err := newTLSIdentity(master, state.DeploymentID, state.TLS.SAN, state.TLS.Epoch+1, now)
		if err != nil {
			return err
		}
		state.TLS = identity
		if err := updateRevocations(state, rootPrivate, now, appendAllCurrentContentIDs(state.Revocations.RevokedContentIDs, state.Profiles), state.Revocations.EmergencyDenied); err != nil {
			return err
		}
		state.Assignments = quarantineAllAssignments(state.Assignments, now.Unix())
		revoked := revokeAllProfiles(state.Profiles)
		result = KeyRotationResult{Kind: "tls", PreviousKeyID: previous, CurrentKeyID: identity.KeyID, DelegationEpoch: state.Delegation.DelegationEpoch, RevocationEpoch: state.Revocations.Epoch, RelayEpoch: state.RelayEpoch, TLSEpoch: identity.Epoch, RevokedProfiles: revoked}
		return nil
	})
	return result, err
}

func VerifyBundleAgainstCurrentState(dataDir string, artifact []byte, now time.Time) (VerifiedBundle, error) {
	if now.IsZero() {
		return VerifiedBundle{}, ErrInvalidInput
	}
	verified, err := VerifyBundle(artifact, now.UTC(), 1)
	if err != nil {
		return VerifiedBundle{}, err
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return VerifiedBundle{}, err
	}
	zero(master)
	if state.Drained {
		return VerifiedBundle{}, ErrDrained
	}
	index := profileIndex(state.Profiles, verified.ProfileID)
	if index < 0 {
		return VerifiedBundle{}, ErrNotFound
	}
	record := state.Profiles[index]
	if record.Revoked || record.ContentID != verified.ContentID || record.Generation != verified.Generation ||
		verified.RootFingerprint != state.RootFingerprint || verified.RootEpoch != state.Root.Epoch ||
		verified.RevocationEpoch != state.Revocations.Epoch || artifactDigest(record.Artifact) != artifactDigest(artifact) {
		return VerifiedBundle{}, ErrRollback
	}
	return verified, nil
}

// VerifyLiveBundleAgainstCurrentState confirms that an issuer-verifiable live
// owner bundle is the exact current non-revoked artifact retained by this
// deployment. Recipient decryptability is verified separately on the device.
func VerifyLiveBundleAgainstCurrentState(dataDir string, artifact []byte, now time.Time) (VerifiedBundle, error) {
	if now.IsZero() {
		return VerifiedBundle{}, ErrInvalidInput
	}
	bundle, _, err := verifyLiveBundleAuthority(artifact, now.UTC(), 1)
	if err != nil {
		return VerifiedBundle{}, err
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return VerifiedBundle{}, err
	}
	zero(master)
	if state.Drained {
		return VerifiedBundle{}, ErrDrained
	}
	digest := artifactDigest(artifact)
	for _, record := range state.Profiles {
		if record.Mode != profileModeLive || artifactDigest(record.Artifact) != digest {
			continue
		}
		if record.Revoked || record.Generation == 0 || record.ContentID == "" ||
			bundle.DeploymentID != state.DeploymentID || bundle.RootFingerprint != state.RootFingerprint ||
			bundle.Root.Epoch != state.Root.Epoch || bundle.IssuerKey != state.IssuerKey ||
			bundle.Revocations.Epoch != state.Revocations.Epoch || contains(state.Revocations.RevokedContentIDs, record.ContentID) {
			return VerifiedBundle{}, ErrRollback
		}
		return VerifiedBundle{
			DeploymentID: state.DeploymentID, ProfileID: record.ProfileID, ContentID: record.ContentID,
			RootFingerprint: state.RootFingerprint, IssuerFingerprint: fingerprint(state.IssuerPublicDER),
			RelayKeyID: state.RelayKeyID, Generation: record.Generation, RootEpoch: state.Root.Epoch,
			RevocationEpoch: state.Revocations.Epoch, ValidUntil: record.ValidUntil,
		}, nil
	}
	return VerifiedBundle{}, ErrRollback
}

func issueProfile(state *persistedState, master []byte, name, profileID, previousContentID, updateKind string, validFor time.Duration, now time.Time) (IssuedProfile, profileRecord, error) {
	issuerDER, err := openWithKey(master, state.IssuerSecret, []byte(state.DeploymentID+"|"+state.IssuerKey.KeyID))
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	issuerPrivate, err := parseP256Private(issuerDER)
	zero(issuerDER)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, ErrStateCorrupt
	}
	contentID, err := randomID("content")
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	state.Generation++
	policy, err := encodePolicy(state.Endpoint)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	profileValue := envelope.CanonicalProfileV1{
		ContentID: contentID, ProfileID: profileID,
		LineageID: state.Delegation.Scope.LineageID, ProviderID: state.Delegation.Scope.ProviderID,
		ContractVersion: "product-profile-admission-v1", RevocationScope: state.Revocations.Scope,
		SnapshotMode: "full-snapshot", UpdateKind: updateKind, Generation: state.Generation,
		RequiredSafetyFloor: 1, ValidFrom: now.Unix(), ValidUntil: now.Add(validFor).Unix(),
		RootEpoch: state.Root.Epoch, RevocationEpoch: state.Revocations.Epoch,
		PreviousContentID: previousContentID,
		RelayIDs:          []string{state.RelayKeyID}, StrategyIDs: []string{"strategy.kurd-tls13-tcp"}, Policy: policy,
	}
	spec := profile.OfflineIssuanceSpec{
		Profile: profileValue, Class: envelope.ArtifactSignedPublic, Audience: envelope.AudiencePublic,
		Suite: envelope.SuiteClassicalV1, IssuerRole: profile.RoleIssuer,
		IssuerScope: state.Delegation.Scope, IssuerKey: state.IssuerKey,
		MinimumGeneration: state.Generation, Now: now.Unix(),
	}
	inner, err := profile.IssueOffline(spec, p256Signer{keyID: state.IssuerKey.KeyID, key: issuerPrivate}, nil)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	bundle := profileBundle{
		Version: bundleVersion, DeploymentID: state.DeploymentID, Endpoint: state.Endpoint,
		Root: state.Root, RootPublicDER: state.RootPublicDER, RootFingerprint: state.RootFingerprint,
		IssuerKey: state.IssuerKey, IssuerPublicDER: state.IssuerPublicDER,
		RelayKeyID: state.RelayKeyID, RelayPublic: state.RelayPublic,
		Delegation: state.Delegation, DelegationPayload: state.DelegationPayload, DelegationSignature: state.DelegationSig,
		Revocations: state.Revocations, RevocationPayload: state.RevocationPayload, RevocationSignature: state.RevocationSig,
		SignedProfile: inner,
	}
	artifact, err := encodeBundle(bundle)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	if _, err := VerifyBundle(artifact, now, state.Generation); err != nil {
		return IssuedProfile{}, profileRecord{}, fmt.Errorf("selfhost: verify newly issued bundle: %w", err)
	}
	uri, err := envelope.EncodeArtifactURI(artifact)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	chunks, err := envelope.EncodeQRChunks(artifact, 768)
	if err != nil {
		return IssuedProfile{}, profileRecord{}, err
	}
	record := profileRecord{Name: name, ProfileID: profileID, ContentID: contentID, Generation: state.Generation, Artifact: artifact, CreatedAt: now.Unix(), ValidUntil: profileValue.ValidUntil, Mode: profileModeAuthorityOnly}
	return IssuedProfile{ProfileID: profileID, ContentID: contentID, Generation: state.Generation, Artifact: artifact, URI: uri, QRChunks: chunks}, record, nil
}

func recoveryRootForState(state persistedState, recoveryPath string, passphrase []byte) (*ecdsa.PrivateKey, error) {
	raw, err := os.ReadFile(recoveryPath)
	if err != nil {
		return nil, ErrRecoveryRejected
	}
	payload, err := openRecovery(raw, passphrase)
	if err != nil {
		return nil, ErrRecoveryRejected
	}
	rootPrivate, err := parseP256Private(payload.RootPrivateDER)
	zero(payload.RootPrivateDER)
	if err != nil {
		return nil, ErrRecoveryRejected
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&rootPrivate.PublicKey)
	if err != nil || payload.DeploymentID != state.DeploymentID || payload.RootFingerprint != state.RootFingerprint ||
		!bytes.Equal(publicDER, state.RootPublicDER) || fingerprint(publicDER) != state.RootFingerprint {
		return nil, ErrRecoveryRejected
	}
	return rootPrivate, nil
}

func updateRevocations(state *persistedState, rootPrivate *ecdsa.PrivateKey, now time.Time, revokedContentIDs []string, emergencyDenied bool) error {
	if state == nil || rootPrivate == nil {
		return ErrInvalidInput
	}
	state.Revocations.Epoch++
	state.Revocations.IssuedAt = now.Unix()
	state.Revocations.ExpiresAt = now.AddDate(5, 0, 0).Unix()
	state.Revocations.RevokedContentIDs = sortedUnique(revokedContentIDs)
	state.Revocations.EmergencyDenied = emergencyDenied
	payload, err := profile.EncodeRevocationSetV1(state.Revocations)
	if err != nil {
		return err
	}
	signature, err := (p256Signer{keyID: state.Root.Keys[0].KeyID, key: rootPrivate}).Sign(state.Root.Keys[0], payload)
	if err != nil {
		return err
	}
	state.RevocationPayload = payload
	state.RevocationSig = signature
	return nil
}

func profileIndex(records []profileRecord, profileID string) int {
	for index := range records {
		if records[index].ProfileID == profileID {
			return index
		}
	}
	return -1
}

func appendAllCurrentContentIDs(existing []string, records []profileRecord) []string {
	result := append([]string(nil), existing...)
	for _, record := range records {
		if !record.Revoked {
			result = append(result, record.ContentID)
		}
	}
	return sortedUnique(result)
}

func revokeAllProfiles(records []profileRecord) int {
	count := 0
	for index := range records {
		if !records[index].Revoked {
			records[index].Revoked = true
			count++
		}
	}
	return count
}

func quarantineAllAssignments(assignments []addressAssignmentV1, transitionAt int64) []addressAssignmentV1 {
	result := cloneAssignments(assignments)
	for index := range result {
		if result[index].State == addressStateActive {
			result[index].State = addressStateQuarantined
			result[index].ReleaseAt = transitionAt + int64(addressQuarantine/time.Second)
		}
	}
	return result
}

func LoadStatus(dataDir string) (Status, error) {
	state, master, err := loadState(dataDir)
	if err != nil {
		return Status{}, err
	}
	zero(master)
	revoked := 0
	for _, record := range state.Profiles {
		if record.Revoked {
			revoked++
		}
	}
	return Status{
		DeploymentID: state.DeploymentID, DeploymentName: state.DeploymentName, Endpoint: state.Endpoint,
		RootFingerprint: state.RootFingerprint, Revision: state.Revision, Generation: state.Generation,
		RootEpoch: state.Root.Epoch, RevocationEpoch: state.Revocations.Epoch,
		RecoveryConfirmed: state.RecoveryConfirmed, Drained: state.Drained,
		ProfileCount: len(state.Profiles), RevokedProfileCount: revoked,
	}, nil
}

func ListProfiles(dataDir string) ([]ProfileSummary, error) {
	state, master, err := loadState(dataDir)
	if err != nil {
		return nil, err
	}
	zero(master)
	result := make([]ProfileSummary, 0, len(state.Profiles))
	for _, record := range state.Profiles {
		result = append(result, ProfileSummary{
			Name: record.Name, ProfileID: record.ProfileID, ContentID: record.ContentID,
			Generation: record.Generation, CreatedAt: record.CreatedAt, ValidUntil: record.ValidUntil, Revoked: record.Revoked,
		})
	}
	sort.Slice(result, func(left, right int) bool { return result[left].ProfileID < result[right].ProfileID })
	return result, nil
}

func LoadProfile(dataDir, profileID string) (IssuedProfile, error) {
	if !validID(profileID) {
		return IssuedProfile{}, ErrInvalidInput
	}
	state, master, err := loadState(dataDir)
	if err != nil {
		return IssuedProfile{}, err
	}
	zero(master)
	index := profileIndex(state.Profiles, profileID)
	if index < 0 {
		return IssuedProfile{}, ErrNotFound
	}
	record := state.Profiles[index]
	uri, err := envelope.EncodeArtifactURI(record.Artifact)
	if err != nil {
		return IssuedProfile{}, ErrStateCorrupt
	}
	chunks, err := envelope.EncodeQRChunks(record.Artifact, 768)
	if err != nil {
		return IssuedProfile{}, ErrStateCorrupt
	}
	return IssuedProfile{
		ProfileID: record.ProfileID, ContentID: record.ContentID, Generation: record.Generation, ValidUntil: record.ValidUntil,
		Mode: record.Mode, Sealed: record.Mode == profileModeLive, Connectable: record.Mode == profileModeLive && !record.Revoked, Revoked: record.Revoked,
		Artifact: append([]byte(nil), record.Artifact...), URI: uri, QRChunks: chunks,
	}, nil
}

func encodePolicy(endpoint string) ([]byte, error) {
	mode, err := cbor.CoreDetEncOptions().EncMode()
	if err != nil {
		return nil, err
	}
	return mode.Marshal(map[uint64]any{
		1: endpoint,
		2: "kurd-wire-v1",
		3: "tls13-tcp",
		4: []string{"strategy.kurd-tls13-tcp"},
		5: uint64(1),
	})
}

func policyEndpoint(encoded []byte) (string, error) {
	options := cbor.DecOptions{DupMapKey: cbor.DupMapKeyEnforcedAPF, MaxMapPairs: 16, MaxArrayElements: 16, MaxNestedLevels: 4, IndefLength: cbor.IndefLengthForbidden, TagsMd: cbor.TagsForbidden, UTF8: cbor.UTF8RejectInvalid}
	mode, err := options.DecMode()
	if err != nil {
		return "", fmt.Errorf("%w: policy decoder: %v", ErrInvalidInput, err)
	}
	var fields map[uint64]any
	if err := mode.Unmarshal(encoded, &fields); err != nil {
		return "", fmt.Errorf("%w: policy decode: %v", ErrInvalidInput, err)
	}
	if len(fields) != 5 {
		return "", fmt.Errorf("%w: policy field count %d", ErrInvalidInput, len(fields))
	}
	canonical, err := encodeCanonical(fields)
	if err != nil || !bytes.Equal(canonical, encoded) {
		return "", fmt.Errorf("%w: policy canonical mismatch", ErrInvalidInput)
	}
	endpoint, ok := fields[1].(string)
	if !ok || !validEndpoint(endpoint) {
		return "", fmt.Errorf("%w: policy endpoint type=%T value=%q", ErrInvalidInput, fields[1], endpoint)
	}
	return endpoint, nil
}

func validEndpoint(value string) bool {
	host, portText, err := net.SplitHostPort(value)
	if err != nil || host == "" || len(host) > 253 {
		return false
	}
	port, err := strconv.Atoi(portText)
	if err != nil || port < 1 || port > 65535 {
		return false
	}
	if net.ParseIP(host) != nil {
		return true
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return false
	}
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !(character == '-' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
				return false
			}
		}
	}
	return true
}

func recoveryInsideDataDir(dataDir, recoveryPath string) bool {
	data, err := filepath.Abs(dataDir)
	if err != nil {
		return true
	}
	recovery, err := filepath.Abs(recoveryPath)
	if err != nil {
		return true
	}
	relative, err := filepath.Rel(data, recovery)
	return err != nil || relative == "." || relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator))
}

func writeExclusive(path string, value []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(value); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Sync(); err != nil {
		file.Close()
		_ = os.Remove(path)
		return err
	}
	if err := file.Close(); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(path))
}

func artifactDigest(artifact []byte) string {
	digest := sha256.Sum256(artifact)
	return hex.EncodeToString(digest[:])
}

func sortedUnique(values []string) []string {
	result := append([]string(nil), values...)
	sort.Strings(result)
	unique := result[:0]
	for _, value := range result {
		if len(unique) == 0 || unique[len(unique)-1] != value {
			unique = append(unique, value)
		}
	}
	return unique
}
