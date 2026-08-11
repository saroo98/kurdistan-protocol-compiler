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
	stateFileName                     = "state.kurd-state"
	masterKeyFileName                 = "master.key"
	lockDirectoryName                 = ".state.lock"
	publicationCursorFileName         = "publication.cursor"
	recipientAuthorityFileName        = "recipient-authority.kurd-auth"
	stateSchemaV1                     = "kurd-selfhost-state-v1"
	stateSchemaV2                     = "kurd-selfhost-state-v2"
	stateSchema                       = stateSchemaV2
	recoverySchema                    = "kurd-selfhost-recovery-v1"
	backupSchemaV1                    = "kurd-selfhost-backup-v1"
	backupSchemaV2                    = "kurd-selfhost-backup-v2"
	backupSchemaV3                    = "kurd-selfhost-backup-v3"
	backupSchema                      = backupSchemaV3
	bundleVersion              uint64 = 1
	liveBundleVersion          uint64 = 2
	stateVersionV1             uint64 = 1
	stateVersionV2             uint64 = 2
	migrationEpochV2           uint64 = 1
	maxStateBytes                     = 8 << 20
	maxBackupBytes                    = 16 << 20
	maxProfiles                       = 4096
	maxProfileValidity                = 30 * 24 * time.Hour
)

var (
	ErrAlreadyInitialized      = errors.New("selfhost: already initialized")
	ErrInvalidInput            = errors.New("selfhost: invalid input")
	ErrRecoveryUnconfirmed     = errors.New("selfhost: recovery artifact is not confirmed")
	ErrRecoveryRejected        = errors.New("selfhost: recovery artifact rejected")
	ErrStateCorrupt            = errors.New("selfhost: state integrity rejected")
	ErrBusy                    = errors.New("selfhost: another state transaction is active")
	ErrNotFound                = errors.New("selfhost: record not found")
	ErrRollback                = errors.New("selfhost: rollback rejected")
	ErrDrained                 = errors.New("selfhost: node is drained")
	ErrClockUnhealthy          = errors.New("selfhost: clock health rejected")
	ErrNewerSchema             = errors.New("selfhost: newer schema rejected")
	ErrMigration               = errors.New("selfhost: migration rejected")
	ErrCommitUncertain         = errors.New("selfhost: commit outcome uncertain")
	ErrAddressExhausted        = errors.New("selfhost: address pool exhausted")
	ErrCapacityExhausted       = errors.New("selfhost: capacity exhausted")
	ErrArtifactUnavailable     = errors.New("selfhost: profile artifact unavailable")
	ErrTLSUnavailable          = errors.New("selfhost: tls identity unavailable")
	ErrRecipientReplay         = errors.New("selfhost: recipient capability replay rejected")
	ErrRecipientRegistry       = errors.New("selfhost: recipient registry rejected")
	ErrRecipientAuthority      = errors.New("selfhost: recipient authority rejected")
	ErrRelayRuntimeUnavailable = errors.New("selfhost: relay runtime unavailable")
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
	Name                  string
	ValidFor              time.Duration
	Now                   time.Time
	RecipientRequest      []byte
	LiveProgram           []byte
	RegistryDir           string
	ConfirmRecipientReuse string
}

type RotateProfileOptions struct {
	ProfileID, RecoveryPath string
	RecoveryPassphrase      []byte
	ValidFor                time.Duration
	Now                     time.Time
	RecipientRequest        []byte
	LiveProgram             []byte
	RegistryDir             string
	ConfirmRecipientReuse   string
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
	RelayEpoch, TLSEpoch              uint64
	RevokedProfiles                   int
}

type IssuedProfile struct {
	ProfileID, ContentID string
	Generation           uint64
	ValidUntil           int64
	Mode                 string
	Sealed, Connectable  bool
	Revoked              bool
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
	DataDir, Destination, RegistryDir string
	Passphrase                        []byte
	Now                               time.Time
}

type BackupSummary struct {
	Schema, DeploymentID, Digest, AuditHead string
	Revision, Generation                    uint64
	CreatedAt                               int64
	ProfileCount                            int
}

type RestoreOptions struct {
	BackupPath, DataDir, RegistryDir, ExpectedDigest string
	Passphrase                                       []byte
	Now                                              time.Time
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
	Mode                  string
	Recipient             recipientBindingRecord
	RecipientPublic       []byte
	ClientAuthKeyID       string
	ClientAuthPublic      []byte
	RuntimePolicy         []byte
	RelayAdmissionDigest  []byte
	AssignedIPv4          []byte
	AssignedIPv6          []byte
}

const (
	profileModeAuthorityOnly = "authority-only"
	profileModeLive          = "live"
	addressStateActive       = "active"
	addressStateQuarantined  = "quarantined"
)

type recipientBindingRecord struct {
	_                                       struct{} `cbor:",toarray"`
	Class, ProviderID, LineageID, Namespace string
	Hint, KeyID                             string
	Epoch                                   uint64
	Revoked                                 bool
}

type tlsIdentityV1 struct {
	_                   struct{} `cbor:",toarray"`
	Epoch               uint64
	KeyID               string
	Serial              []byte
	NotBefore, NotAfter int64
	SAN                 string
	LeafDER, LeafDigest []byte
	SealedSeed          sealedSecret
}

type addressPoolV1 struct {
	_              struct{} `cbor:",toarray"`
	Family         uint8
	Network        []byte
	PrefixLength   uint8
	ServerDNS      []byte
	Enabled        bool
	NextHostOffset uint64
}

type addressAssignmentV1 struct {
	_                                        struct{} `cbor:",toarray"`
	Family                                   uint8
	Address                                  []byte
	ProfileID, ContentID                     string
	Generation                               uint64
	State                                    string
	AssignedAt, ProfileValidUntil, ReleaseAt int64
}

type recipientUseRecordV1 struct {
	_                                   struct{} `cbor:",toarray"`
	RequestTag, RecipientTag, ClientTag string
	ProfileID                           string
	FirstUsedAt                         int64
}

type recipientUseLedgerV1 struct {
	_          struct{} `cbor:",toarray"`
	RegistryID string
	Records    []recipientUseRecordV1
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
	Version, MigrationEpoch          uint64
	Revision                         uint64
	Generation                       uint64
	LastObservedAt                   int64
	DeploymentID, DeploymentName     string
	Endpoint                         string
	Root                             profile.RootSetArtifact
	RootPublicDER                    []byte
	RootFingerprint                  string
	IssuerKey                        profile.KeyReference
	IssuerPublicDER                  []byte
	IssuerSecret                     sealedSecret
	RelayEpoch                       uint64
	RelayKeyID                       string
	RelayPublic                      []byte
	RelaySecret                      sealedSecret
	TLS                              tlsIdentityV1
	Delegation                       profile.IssuerDelegationArtifact
	DelegationPayload, DelegationSig []byte
	Revocations                      profile.RevocationSetV1
	RevocationPayload, RevocationSig []byte
	RecoveryConfirmed, Drained       bool
	IPv4Pool, IPv6Pool               addressPoolV1
	Profiles                         []profileRecord
	Assignments                      []addressAssignmentV1
	RecipientUses                    recipientUseLedgerV1
	Audit                            []auditEntry
	PublicationOutbox                []publicationOutboxEntry
}

// persistedStateV1 and profileRecordV1 freeze the exact Phase 16 array layouts.
// They are decode-only migration inputs and must never gain fields.
type profileRecordV1 struct {
	_                     struct{} `cbor:",toarray"`
	Name, ProfileID       string
	ContentID             string
	Generation            uint64
	Artifact              []byte
	CreatedAt, ValidUntil int64
	Revoked               bool
}

type persistedStateV1 struct {
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
	Profiles                         []profileRecordV1
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

type backupPayloadV1 struct {
	_                               struct{} `cbor:",toarray"`
	Schema, DeploymentID, AuditHead string
	Revision, Generation            uint64
	CreatedAt                       int64
	MasterKey, StateFile            []byte
}

type backupPayloadV2 struct {
	_                               struct{} `cbor:",toarray"`
	Schema, DeploymentID, AuditHead string
	Revision, Generation            uint64
	CreatedAt                       int64
	StateVersion, MigrationEpoch    uint64
	MasterKey, StateFile            []byte
}

type backupPayload struct {
	_                               struct{} `cbor:",toarray"`
	Schema, DeploymentID, AuditHead string
	Revision, Generation            uint64
	CreatedAt                       int64
	StateVersion, MigrationEpoch    uint64
	MasterKey, StateFile            []byte
	RecipientRegistryKey            []byte
	RecipientRegistryState          []byte
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

type liveProfileBundleV2 struct {
	_                                      struct{} `cbor:",toarray"`
	Version                                uint64
	DeploymentID                           string
	Root                                   profile.RootSetArtifact
	RootPublicDER                          []byte
	RootFingerprint                        string
	IssuerKey                              profile.KeyReference
	IssuerPublicDER                        []byte
	Delegation                             profile.IssuerDelegationArtifact
	DelegationPayload, DelegationSignature []byte
	Revocations                            profile.RevocationSetV1
	RevocationPayload, RevocationSignature []byte
	SealedProfile                          []byte
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
