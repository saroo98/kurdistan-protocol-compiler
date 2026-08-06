// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

// Package selfhost implements deployment-local authority and administration
// for an owner-managed Kurd node. It has no cloud, directory, telemetry, or
// product-operated control-plane dependency.
package selfhost

import (
	"errors"
	"time"

	"kurdistan/internal/product/profile"
)

const (
	stateFileName                    = "state.kurd-state"
	masterKeyFileName                = "master.key"
	lockDirectoryName                = ".state.lock"
	publicationCursorFileName        = "publication.cursor"
	stateSchema                      = "kurd-selfhost-state-v1"
	recoverySchema                   = "kurd-selfhost-recovery-v1"
	backupSchema                     = "kurd-selfhost-backup-v1"
	bundleVersion             uint64 = 1
	maxStateBytes                    = 8 << 20
	maxBackupBytes                   = 16 << 20
	maxProfiles                      = 4096
	maxProfileValidity               = 30 * 24 * time.Hour
)

var (
	ErrAlreadyInitialized  = errors.New("selfhost: already initialized")
	ErrInvalidInput        = errors.New("selfhost: invalid input")
	ErrRecoveryUnconfirmed = errors.New("selfhost: recovery artifact is not confirmed")
	ErrRecoveryRejected    = errors.New("selfhost: recovery artifact rejected")
	ErrStateCorrupt        = errors.New("selfhost: state integrity rejected")
	ErrBusy                = errors.New("selfhost: another state transaction is active")
	ErrNotFound            = errors.New("selfhost: record not found")
	ErrRollback            = errors.New("selfhost: rollback rejected")
	ErrDrained             = errors.New("selfhost: node is drained")
	ErrClockUnhealthy      = errors.New("selfhost: clock health rejected")
)

type InitOptions struct {
	DataDir, DeploymentName, Endpoint string
	RecoveryPath                      string
	RecoveryPassphrase                []byte
	Now                               time.Time
}

type InitResult struct {
	DeploymentID, RootFingerprint, RecoveryPath string
}

type CreateProfileOptions struct {
	Name     string
	ValidFor time.Duration
	Now      time.Time
}

type RotateProfileOptions struct {
	ProfileID, RecoveryPath string
	RecoveryPassphrase      []byte
	ValidFor                time.Duration
	Now                     time.Time
}

type RevokeProfileOptions struct {
	ProfileID, RecoveryPath string
	RecoveryPassphrase      []byte
	Now                     time.Time
}

type RecoveryActionOptions struct {
	RecoveryPath       string
	RecoveryPassphrase []byte
	Now                time.Time
}

type KeyRotationResult struct {
	Kind, PreviousKeyID, CurrentKeyID string
	DelegationEpoch, RevocationEpoch  uint64
	RevokedProfiles                   int
}

type IssuedProfile struct {
	ProfileID, ContentID string
	Generation           uint64
	Artifact             []byte
	URI                  string
	QRChunks             []string
}

type VerifiedBundle struct {
	DeploymentID, Endpoint, ProfileID, ContentID string
	RootFingerprint, IssuerFingerprint           string
	RelayKeyID                                   string
	Generation, RootEpoch, RevocationEpoch       uint64
	ValidUntil                                   int64
}

type Status struct {
	DeploymentID, DeploymentName, Endpoint, RootFingerprint string
	Revision, Generation, RootEpoch, RevocationEpoch        uint64
	RecoveryConfirmed, Drained                              bool
	ProfileCount, RevokedProfileCount                       int
}

type ProfileSummary struct {
	Name, ProfileID, ContentID string
	Generation                 uint64
	CreatedAt, ValidUntil      int64
	Revoked                    bool
}

type BackupOptions struct {
	DataDir, Destination string
	Passphrase           []byte
	Now                  time.Time
}

type BackupSummary struct {
	Schema, DeploymentID, Digest, AuditHead string
	Revision, Generation                    uint64
	CreatedAt                               int64
	ProfileCount                            int
}

type RestoreOptions struct {
	BackupPath, DataDir, ExpectedDigest string
	Passphrase                          []byte
	Now                                 time.Time
}

type PublicationSummary struct {
	Schema, DeploymentID, RootFingerprint, Digest string
	Revision, RevocationEpoch                     uint64
	GeneratedAt                                   int64
	ProfileCount                                  int
}

type PublicationDelivery struct {
	Schema                              string
	RequiredRevision, DeliveredRevision uint64
	Digest                              string
	Pending                             bool
}

type publicationOutboxEntry struct {
	_         struct{} `cbor:",toarray"`
	Revision  uint64
	CreatedAt int64
	Action    string
}

type publicationCursorPayload struct {
	_            struct{} `cbor:",toarray"`
	Version      uint64
	DeploymentID string
	Revision     uint64
	Digest       string
}

type publicationCursorEnvelope struct {
	_       struct{} `cbor:",toarray"`
	Payload []byte
	MAC     []byte
}

type sealedSecret struct {
	_          struct{} `cbor:",toarray"`
	Version    uint64
	Nonce      []byte
	Ciphertext []byte
}

type profileRecord struct {
	_                     struct{} `cbor:",toarray"`
	Name, ProfileID       string
	ContentID             string
	Generation            uint64
	Artifact              []byte
	CreatedAt, ValidUntil int64
	Revoked               bool
}

type auditEntry struct {
	_                                       struct{} `cbor:",toarray"`
	Sequence                                uint64
	At                                      int64
	Action, Subject, PreviousDigest, Digest string
}

type persistedState struct {
	_                                struct{} `cbor:",toarray"`
	Schema                           string
	Revision                         uint64
	DeploymentID, DeploymentName     string
	Endpoint                         string
	Root                             profile.RootSetArtifact
	RootPublicDER                    []byte
	RootFingerprint                  string
	IssuerKey                        profile.KeyReference
	IssuerPublicDER                  []byte
	IssuerSecret                     sealedSecret
	RelayKeyID                       string
	RelayPublic                      []byte
	RelaySecret                      sealedSecret
	Delegation                       profile.IssuerDelegationArtifact
	DelegationPayload, DelegationSig []byte
	Revocations                      profile.RevocationSetV1
	RevocationPayload, RevocationSig []byte
	Generation                       uint64
	LastObservedAt                   int64
	RecoveryConfirmed, Drained       bool
	Profiles                         []profileRecord
	Audit                            []auditEntry
	PublicationOutbox                []publicationOutboxEntry
}

type stateEnvelope struct {
	_       struct{} `cbor:",toarray"`
	Version uint64
	Payload []byte
	MAC     []byte
}

type recoveryPayload struct {
	_                                     struct{} `cbor:",toarray"`
	Schema, DeploymentID, RootFingerprint string
	RootPrivateDER                        []byte
	CreatedAt                             int64
}

type recoveryEnvelope struct {
	_                           struct{} `cbor:",toarray"`
	Schema                      string
	KDFMemoryKiB, KDFIterations uint32
	KDFParallelism              uint8
	Salt, Nonce, Ciphertext     []byte
}

type backupPayload struct {
	_                               struct{} `cbor:",toarray"`
	Schema, DeploymentID, AuditHead string
	Revision, Generation            uint64
	CreatedAt                       int64
	MasterKey, StateFile            []byte
}

type backupEnvelope struct {
	_                           struct{} `cbor:",toarray"`
	Schema                      string
	KDFMemoryKiB, KDFIterations uint32
	KDFParallelism              uint8
	Salt, Nonce, Ciphertext     []byte
}

type profileBundle struct {
	_                                      struct{} `cbor:",toarray"`
	Version                                uint64
	DeploymentID, Endpoint                 string
	Root                                   profile.RootSetArtifact
	RootPublicDER                          []byte
	RootFingerprint                        string
	IssuerKey                              profile.KeyReference
	IssuerPublicDER                        []byte
	RelayKeyID                             string
	RelayPublic                            []byte
	Delegation                             profile.IssuerDelegationArtifact
	DelegationPayload, DelegationSignature []byte
	Revocations                            profile.RevocationSetV1
	RevocationPayload, RevocationSignature []byte
	SignedProfile                          []byte
}

type publicationSnapshot struct {
	_                                      struct{} `cbor:",toarray"`
	Version, Revision                      uint64
	GeneratedAt                            int64
	DeploymentID, RootFingerprint          string
	Root                                   profile.RootSetArtifact
	RootPublicDER                          []byte
	Revocations                            profile.RevocationSetV1
	RevocationPayload, RevocationSignature []byte
	Profiles                               [][]byte
}
