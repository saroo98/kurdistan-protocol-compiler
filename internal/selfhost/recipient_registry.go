// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package selfhost

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"sort"

	"kurdistan/internal/product/enrollment"
)

const (
	ownerRecipientRegistrySchema = "kurd-owner-recipient-registry-v1"
	ownerRecipientRegistryKey    = "registry.key"
	ownerRecipientRegistryState  = "registry.kurd-registry"
	ownerRecipientRegistryLock   = ".registry.lock"
	maxOwnerRecipientUses        = maxProfiles * 8
)

type ownerRecipientUseRecordV1 struct {
	_                                                 struct{} `cbor:",toarray"`
	RequestTag, RecipientTag, ClientTag, DeploymentID string
	ProfileID                                         string
	FirstUsedAt                                       int64
}

type ownerRecipientRegistryV1 struct {
	_          struct{} `cbor:",toarray"`
	Schema     string
	Version    uint64
	RegistryID string
	Records    []ownerRecipientUseRecordV1
}

type ownerRecipientRegistryEnvelopeV1 struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Payload []byte
	MAC     []byte
}

type recipientUseReservationV1 struct {
	RegistryID   string
	DeploymentID string
	Record       recipientUseRecordV1
}

func recipientUseRecord(request enrollment.PublicRequestV1, profileID string, firstUsedAt int64) recipientUseRecordV1 {
	return recipientUseRecordV1{
		RequestTag:   recipientUseTag("request", []byte(request.RequestID)),
		RecipientTag: recipientUseTag("recipient-public", request.RecipientPublic),
		ClientTag:    recipientUseTag("client-auth-public", request.ClientAuthPublic),
		ProfileID:    profileID,
		FirstUsedAt:  firstUsedAt,
	}
}

func recipientUseTag(kind string, value []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("kurdistan-vpn/recipient-use/v1\x00"))
	_, _ = digest.Write([]byte(kind))
	_, _ = digest.Write([]byte{0})
	_, _ = digest.Write(value)
	return hex.EncodeToString(digest.Sum(nil))
}

func validateRecipientUseLedger(ledger recipientUseLedgerV1) error {
	if ledger.RegistryID == "" && len(ledger.Records) == 0 {
		return nil
	}
	if !validID(ledger.RegistryID) || len(ledger.Records) == 0 || len(ledger.Records) > maxOwnerRecipientUses {
		return ErrStateCorrupt
	}
	seenRequest, seenRecipient, seenClient := map[string]struct{}{}, map[string]struct{}{}, map[string]struct{}{}
	previous := recipientUseRecordV1{}
	for index, record := range ledger.Records {
		if !validRecipientUseRecord(record) || index > 0 && compareRecipientUseRecord(previous, record) >= 0 {
			return ErrStateCorrupt
		}
		if _, found := seenRequest[record.RequestTag]; found {
			return ErrStateCorrupt
		}
		if _, found := seenRecipient[record.RecipientTag]; found {
			return ErrStateCorrupt
		}
		if _, found := seenClient[record.ClientTag]; found {
			return ErrStateCorrupt
		}
		seenRequest[record.RequestTag], seenRecipient[record.RecipientTag], seenClient[record.ClientTag] = struct{}{}, struct{}{}, struct{}{}
		previous = record
	}
	return nil
}

func appendRecipientUse(ledger recipientUseLedgerV1, registryID string, record recipientUseRecordV1) (recipientUseLedgerV1, error) {
	if ledger.RegistryID != "" && ledger.RegistryID != registryID {
		return recipientUseLedgerV1{}, ErrRecipientRegistry
	}
	result := recipientUseLedgerV1{RegistryID: registryID, Records: append([]recipientUseRecordV1(nil), ledger.Records...)}
	for _, existing := range result.Records {
		if existing.RequestTag == record.RequestTag || existing.RecipientTag == record.RecipientTag || existing.ClientTag == record.ClientTag {
			return recipientUseLedgerV1{}, ErrRecipientReplay
		}
	}
	result.Records = append(result.Records, record)
	sort.Slice(result.Records, func(i, j int) bool { return compareRecipientUseRecord(result.Records[i], result.Records[j]) < 0 })
	if validateRecipientUseLedger(result) != nil {
		return recipientUseLedgerV1{}, ErrRecipientRegistry
	}
	return result, nil
}

func recipientUseConflicts(ledger recipientUseLedgerV1, record recipientUseRecordV1) bool {
	for _, existing := range ledger.Records {
		if existing.RequestTag == record.RequestTag || existing.RecipientTag == record.RecipientTag || existing.ClientTag == record.ClientTag {
			return true
		}
	}
	return false
}

func reserveOwnerRecipientUse(registryDir, expectedRegistryID, deploymentID, profileID string, request enrollment.PublicRequestV1, firstUsedAt int64, confirmation string) (recipientUseReservationV1, error) {
	if registryDir == "" || !validID(deploymentID) || !validID(profileID) || firstUsedAt <= 0 {
		return recipientUseReservationV1{}, ErrInvalidInput
	}
	if expectedRegistryID != "" {
		if _, err := os.Lstat(registryDir); err != nil {
			return recipientUseReservationV1{}, ErrRecipientRegistry
		}
	}
	if err := ensureSelfhostPrivateDirectory(registryDir); err != nil {
		return recipientUseReservationV1{}, ErrRecipientRegistry
	}
	lock := filepath.Join(registryDir, ownerRecipientRegistryLock)
	if err := createSelfhostPrivateDirectory(lock); err != nil {
		if errors.Is(err, ErrBusy) {
			return recipientUseReservationV1{}, ErrBusy
		}
		return recipientUseReservationV1{}, ErrRecipientRegistry
	}
	if err := protectSelfhostPrivatePath(lock, true); err != nil {
		_ = os.Remove(lock)
		return recipientUseReservationV1{}, ErrRecipientRegistry
	}
	defer os.Remove(lock)

	registry, key, err := loadOrInitializeOwnerRecipientRegistry(registryDir, expectedRegistryID)
	if err != nil {
		return recipientUseReservationV1{}, err
	}
	defer zero(key)
	if expectedRegistryID != "" && registry.RegistryID != expectedRegistryID {
		return recipientUseReservationV1{}, ErrRecipientRegistry
	}
	record := recipientUseRecord(request, profileID, firstUsedAt)
	crossDeploymentReuse := false
	for _, existing := range registry.Records {
		matches := existing.RequestTag == record.RequestTag || existing.RecipientTag == record.RecipientTag || existing.ClientTag == record.ClientTag
		if !matches {
			continue
		}
		if existing.DeploymentID == deploymentID {
			return recipientUseReservationV1{}, ErrRecipientReplay
		}
		crossDeploymentReuse = true
	}
	if crossDeploymentReuse && confirmation != "recipient-reuse" {
		return recipientUseReservationV1{}, ErrRecipientReplay
	}
	registry.Records = append(registry.Records, ownerRecipientUseRecordV1{
		RequestTag: record.RequestTag, RecipientTag: record.RecipientTag, ClientTag: record.ClientTag,
		DeploymentID: deploymentID, ProfileID: profileID, FirstUsedAt: firstUsedAt,
	})
	sort.Slice(registry.Records, func(i, j int) bool {
		return compareOwnerRecipientUseRecord(registry.Records[i], registry.Records[j]) < 0
	})
	if validateOwnerRecipientRegistry(registry) != nil || saveOwnerRecipientRegistry(registryDir, key, registry) != nil {
		return recipientUseReservationV1{}, ErrRecipientRegistry
	}
	return recipientUseReservationV1{RegistryID: registry.RegistryID, DeploymentID: deploymentID, Record: record}, nil
}

func releaseOwnerRecipientUse(registryDir string, reservation recipientUseReservationV1) error {
	if registryDir == "" || !validID(reservation.RegistryID) || !validID(reservation.DeploymentID) || !validRecipientUseRecord(reservation.Record) {
		return ErrRecipientRegistry
	}
	if _, err := os.Lstat(registryDir); err != nil || protectSelfhostPrivatePath(registryDir, true) != nil {
		return ErrRecipientRegistry
	}
	lock := filepath.Join(registryDir, ownerRecipientRegistryLock)
	if err := createSelfhostPrivateDirectory(lock); err != nil {
		if errors.Is(err, ErrBusy) {
			return ErrBusy
		}
		return ErrRecipientRegistry
	}
	if err := protectSelfhostPrivatePath(lock, true); err != nil {
		_ = os.Remove(lock)
		return ErrRecipientRegistry
	}
	defer os.Remove(lock)

	registry, key, err := loadOrInitializeOwnerRecipientRegistry(registryDir, reservation.RegistryID)
	if err != nil {
		return err
	}
	defer zero(key)
	target := ownerRecipientUseRecordV1{
		RequestTag: reservation.Record.RequestTag, RecipientTag: reservation.Record.RecipientTag, ClientTag: reservation.Record.ClientTag,
		DeploymentID: reservation.DeploymentID, ProfileID: reservation.Record.ProfileID, FirstUsedAt: reservation.Record.FirstUsedAt,
	}
	index := -1
	for candidateIndex, existing := range registry.Records {
		matchesTag := existing.RequestTag == target.RequestTag || existing.RecipientTag == target.RecipientTag || existing.ClientTag == target.ClientTag
		if existing == target {
			if index >= 0 {
				return ErrRecipientRegistry
			}
			index = candidateIndex
		} else if matchesTag {
			return ErrRecipientRegistry
		}
	}
	if index < 0 {
		return nil
	}
	registry.Records = append(registry.Records[:index], registry.Records[index+1:]...)
	if validateOwnerRecipientRegistry(registry) != nil || saveOwnerRecipientRegistry(registryDir, key, registry) != nil {
		return ErrRecipientRegistry
	}
	return nil
}

func loadOrInitializeOwnerRecipientRegistry(directory, expectedRegistryID string) (ownerRecipientRegistryV1, []byte, error) {
	keyPath := filepath.Join(directory, ownerRecipientRegistryKey)
	statePath := filepath.Join(directory, ownerRecipientRegistryState)
	key, keyErr := os.ReadFile(keyPath)
	stateRaw, stateErr := os.ReadFile(statePath)
	if errors.Is(keyErr, os.ErrNotExist) && errors.Is(stateErr, os.ErrNotExist) && expectedRegistryID == "" {
		key, keyErr = randomBytes(32)
		if keyErr != nil {
			return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
		}
		registry := ownerRecipientRegistryV1{Schema: ownerRecipientRegistrySchema, Version: 1, RegistryID: ownerRecipientRegistryID(key), Records: []ownerRecipientUseRecordV1{}}
		if err := writeSelfhostPrivateFileExclusive(keyPath, key); err != nil {
			zero(key)
			return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
		}
		if err := protectSelfhostPrivatePath(keyPath, false); err != nil {
			zero(key)
			return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
		}
		if err := saveOwnerRecipientRegistry(directory, key, registry); err != nil {
			zero(key)
			return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
		}
		return registry, key, nil
	}
	if keyErr != nil || stateErr != nil || len(key) != 32 {
		zero(key)
		return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
	}
	if protectSelfhostPrivatePath(keyPath, false) != nil || protectSelfhostPrivatePath(statePath, false) != nil {
		zero(key)
		return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
	}
	registry, err := decodeOwnerRecipientRegistry(key, stateRaw)
	if err != nil {
		zero(key)
		return ownerRecipientRegistryV1{}, nil, ErrRecipientRegistry
	}
	return registry, key, nil
}

func decodeOwnerRecipientRegistry(key, stateRaw []byte) (ownerRecipientRegistryV1, error) {
	if len(key) != 32 || len(stateRaw) == 0 || len(stateRaw) > maxStateBytes {
		return ownerRecipientRegistryV1{}, ErrRecipientRegistry
	}
	var envelope ownerRecipientRegistryEnvelopeV1
	if decodeCanonical(stateRaw, &envelope, maxStateBytes) != nil || envelope.Version != 1 || !hmac.Equal(envelope.MAC, ownerRecipientRegistryMAC(key, envelope.Payload)) {
		return ownerRecipientRegistryV1{}, ErrRecipientRegistry
	}
	var registry ownerRecipientRegistryV1
	if decodeCanonical(envelope.Payload, &registry, maxStateBytes) != nil || validateOwnerRecipientRegistry(registry) != nil || registry.RegistryID != ownerRecipientRegistryID(key) {
		return ownerRecipientRegistryV1{}, ErrRecipientRegistry
	}
	return registry, nil
}

func saveOwnerRecipientRegistry(directory string, key []byte, registry ownerRecipientRegistryV1) error {
	payload, err := encodeCanonical(registry)
	if err != nil || len(payload) > maxStateBytes {
		return ErrRecipientRegistry
	}
	envelope, err := encodeCanonical(ownerRecipientRegistryEnvelopeV1{Version: 1, Payload: payload, MAC: ownerRecipientRegistryMAC(key, payload)})
	if err != nil || len(envelope) > maxStateBytes {
		return ErrRecipientRegistry
	}
	path := filepath.Join(directory, ownerRecipientRegistryState)
	if err := atomicWriteFile(path, envelope, 0o600); err != nil {
		return err
	}
	return protectSelfhostPrivatePath(path, false)
}

func validateOwnerRecipientRegistry(registry ownerRecipientRegistryV1) error {
	if registry.Schema != ownerRecipientRegistrySchema || registry.Version != 1 || !validID(registry.RegistryID) || len(registry.Records) > maxOwnerRecipientUses {
		return ErrRecipientRegistry
	}
	for index, record := range registry.Records {
		local := recipientUseRecordV1{RequestTag: record.RequestTag, RecipientTag: record.RecipientTag, ClientTag: record.ClientTag, ProfileID: record.ProfileID, FirstUsedAt: record.FirstUsedAt}
		if !validRecipientUseRecord(local) || !validID(record.DeploymentID) || index > 0 && compareOwnerRecipientUseRecord(registry.Records[index-1], record) >= 0 {
			return ErrRecipientRegistry
		}
	}
	return nil
}

func validRecipientUseRecord(record recipientUseRecordV1) bool {
	return len(record.RequestTag) == 64 && len(record.RecipientTag) == 64 && len(record.ClientTag) == 64 &&
		isLowerHex(record.RequestTag) && isLowerHex(record.RecipientTag) && isLowerHex(record.ClientTag) && validID(record.ProfileID) && record.FirstUsedAt > 0
}

func isLowerHex(value string) bool {
	decoded, err := hex.DecodeString(value)
	return err == nil && hex.EncodeToString(decoded) == value
}

func compareRecipientUseRecord(left, right recipientUseRecordV1) int {
	return bytes.Compare([]byte(left.RequestTag+"\x00"+left.RecipientTag+"\x00"+left.ClientTag+"\x00"+left.ProfileID), []byte(right.RequestTag+"\x00"+right.RecipientTag+"\x00"+right.ClientTag+"\x00"+right.ProfileID))
}

func compareOwnerRecipientUseRecord(left, right ownerRecipientUseRecordV1) int {
	return bytes.Compare([]byte(left.RequestTag+"\x00"+left.RecipientTag+"\x00"+left.ClientTag+"\x00"+left.DeploymentID+"\x00"+left.ProfileID), []byte(right.RequestTag+"\x00"+right.RecipientTag+"\x00"+right.ClientTag+"\x00"+right.DeploymentID+"\x00"+right.ProfileID))
}

func ownerRecipientRegistryID(key []byte) string {
	digest := sha256.New()
	_, _ = digest.Write([]byte("kurdistan-vpn/recipient-registry-id/v1\x00"))
	_, _ = digest.Write(key)
	return "registry." + hex.EncodeToString(digest.Sum(nil)[:8])
}

func ownerRecipientRegistryMAC(key, payload []byte) []byte {
	mac := hmac.New(sha256.New, key)
	_, _ = mac.Write([]byte("kurdistan-vpn/recipient-registry-envelope/v1\x00"))
	_, _ = mac.Write(payload)
	return mac.Sum(nil)
}
