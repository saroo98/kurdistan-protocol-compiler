// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"kurdistan/internal/product/profile"
)

const (
	StateVersion                  = "kurdistan-control-plane-state-v1"
	MinApprovalQuorum             = 2
	MaxOperations                 = 512
	MaxProfiles                   = 512
	MaxRelays                     = 512
	MaxEmergencyAuthorities       = 512
	MaxPublications               = 128
	MaxAuditEntries               = 4096
	MaxOutboxEvents               = 2048
	MaxIdempotencyKeys            = 2048
	MaxEffectAttempts             = 3
	ReservedSafetyOperations      = 16
	ReservedSafetyIdempotencyKeys = ReservedSafetyOperations * (4 + MaxEffectAttempts)
	ReservedSafetyAuditEntries    = ReservedSafetyOperations * (4 + MaxEffectAttempts)
	ReservedSafetyOutboxEvents    = ReservedSafetyOperations
)

type Duty string

const (
	DutyRequest Duty = "request"
	DutyApprove Duty = "approve"
	DutyExecute Duty = "execute"
	DutyPublish Duty = "publish"
	DutyRecover Duty = "recover"
	DutyAudit   Duty = "audit"
)

type Actor struct {
	ID            string
	AuthorityRole profile.AuthorityRole
	Duties        []Duty
}

func (actor Actor) has(duty Duty) bool {
	for _, candidate := range actor.Duties {
		if candidate == duty {
			return true
		}
	}
	return false
}

type Action string

const (
	ActionPrepareProfileIssue  Action = "prepare-profile-issue"
	ActionPrepareProfileRotate Action = "prepare-profile-rotate"
	ActionIssueProfile         Action = "issue-profile"
	ActionRotateProfile        Action = "rotate-profile"
	ActionRevokeProfile        Action = "revoke-profile"
	ActionPublishSnapshot      Action = "publish-snapshot"
	ActionEnrollRelay          Action = "enroll-relay"
	ActionPromoteRelay         Action = "promote-relay"
	ActionDrainRelay           Action = "drain-relay"
	ActionRetireRelay          Action = "retire-relay"
	ActionQuarantineRelay      Action = "quarantine-relay"
	ActionRevokeRelay          Action = "revoke-relay"
	ActionEmergencyDeny        Action = "emergency-deny"
	ActionEmergencyNarrow      Action = "emergency-narrow"
)

type OperationState string

const (
	OperationPending  OperationState = "pending"
	OperationApproved OperationState = "approved"
	OperationExecuted OperationState = "executed"
	OperationRejected OperationState = "rejected"
)

type PublicationInput struct {
	Version        uint64
	RootVersion    uint64
	SnapshotDigest string
	TargetsDigest  string
	ValidUntil     int64
}

type Operation struct {
	ID                     string
	Action                 Action
	TargetID               string
	ParentOperationID      string
	SubjectDigest          string
	ScopeDigest            string
	AuthorityScopeDigest   string
	AuthorityRootDigest    string
	ExpectedArtifactDigest string
	RequesterID            string
	ApproverIDs            []string
	State                  OperationState
	ExpectedRevision       uint64
	ExpectedEpoch          uint64
	ResultEpoch            uint64
	CreatedAt              int64
	ExpiresAt              int64
	ExecutedAt             int64
	Publication            *PublicationInput
}

type RelayState string

const (
	RelayEnrolled    RelayState = "enrolled"
	RelayCanary      RelayState = "canary"
	RelayActive      RelayState = "active"
	RelayDraining    RelayState = "draining"
	RelayRetired     RelayState = "retired"
	RelayQuarantined RelayState = "quarantined"
	RelayRevoked     RelayState = "revoked"
)

type RelayRecord struct {
	ID             string
	State          RelayState
	Epoch          uint64
	IdentityDigest string
	PlanDigest     string
	UpdatedAt      int64
}

type ProfileState string

const (
	ProfileIssued  ProfileState = "issued"
	ProfileRevoked ProfileState = "revoked"
)

type ProfileRecord struct {
	ID               string
	State            ProfileState
	Generation       uint64
	ArtifactDigest   string
	RevocationDigest string
	ScopeDigest      string
	UpdatedAt        int64
}

type Publication struct {
	Version        uint64
	RootVersion    uint64
	SnapshotDigest string
	TargetsDigest  string
	ValidUntil     int64
	PublishedAt    int64
}

type EmergencyRestriction struct {
	ScopeDigest string
	Epoch       uint64
	Narrowed    bool
	ValidUntil  int64
	AppliedAt   int64
}

// EmergencyAuthorityRecord is the durable exact-current authority identity
// for one emergency scope. Revocation is terminal for that scope.
type EmergencyAuthorityRecord struct {
	ScopeDigest        string
	RootSetDigest      string
	RootEpoch          uint64
	RootKeyID          string
	RootKeySuiteID     uint16
	AuthorizationEpoch uint64
	DelegationDigest   string
	KeyID              string
	KeySuiteID         uint16
	Revoked            bool
	RevocationDigest   string
	ValidFrom          int64
	ValidUntil         int64
	UpdatedAt          int64
}

type AuditEntry struct {
	Sequence     uint64
	At           int64
	ActorDigest  string
	Action       string
	TargetDigest string
	Result       string
	PreviousHash string
	Hash         string
}

type OutboxEvent struct {
	ID            string
	Sequence      uint64
	OperationID   string
	Kind          string
	SubjectDigest string
	CreatedAt     int64
	DeliveredAt   int64
	Attempts      uint32
	LastAttemptAt int64
	FailedAt      int64
	OutcomeDigest string
}

type Receipt struct {
	OperationID string
	State       OperationState
	Revision    uint64
	Sequence    uint64
}

type State struct {
	Version              string                              `json:"version"`
	Revision             uint64                              `json:"revision"`
	NextSequence         uint64                              `json:"next_sequence"`
	Operations           map[string]Operation                `json:"operations"`
	Profiles             map[string]ProfileRecord            `json:"profiles"`
	Relays               map[string]RelayRecord              `json:"relays"`
	Publications         []Publication                       `json:"publications"`
	EmergencyAuthorities map[string]EmergencyAuthorityRecord `json:"emergency_authorities"`
	Restrictions         map[string]EmergencyRestriction     `json:"restrictions"`
	Outbox               []OutboxEvent                       `json:"outbox"`
	Audit                []AuditEntry                        `json:"audit"`
	Idempotency          map[string]Receipt                  `json:"idempotency"`
}

func NewState() State {
	return State{
		Version:              StateVersion,
		NextSequence:         1,
		Operations:           make(map[string]Operation),
		Profiles:             make(map[string]ProfileRecord),
		Relays:               make(map[string]RelayRecord),
		EmergencyAuthorities: make(map[string]EmergencyAuthorityRecord),
		Restrictions:         make(map[string]EmergencyRestriction),
		Idempotency:          make(map[string]Receipt),
	}
}

func (state State) clone() State {
	cloned := state
	cloned.Operations = cloneMap(state.Operations)
	cloned.Profiles = cloneMap(state.Profiles)
	cloned.Relays = cloneMap(state.Relays)
	cloned.EmergencyAuthorities = cloneMap(state.EmergencyAuthorities)
	cloned.Restrictions = cloneMap(state.Restrictions)
	cloned.Idempotency = cloneMap(state.Idempotency)
	cloned.Publications = append([]Publication(nil), state.Publications...)
	cloned.Outbox = append([]OutboxEvent(nil), state.Outbox...)
	cloned.Audit = append([]AuditEntry(nil), state.Audit...)
	for id, operation := range cloned.Operations {
		operation.ApproverIDs = append([]string(nil), operation.ApproverIDs...)
		if operation.Publication != nil {
			publication := *operation.Publication
			operation.Publication = &publication
		}
		cloned.Operations[id] = operation
	}
	return cloned
}

func cloneMap[K comparable, V any](source map[K]V) map[K]V {
	cloned := make(map[K]V, len(source))
	for key, value := range source {
		cloned[key] = value
	}
	return cloned
}

func clonePublicationInput(input *PublicationInput) *PublicationInput {
	if input == nil {
		return nil
	}
	cloned := *input
	return &cloned
}

var identifierRE = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{2,127}$`)
var digestRE = regexp.MustCompile(`^[0-9a-f]{64}$`)

func validID(value string) bool {
	return identifierRE.MatchString(value)
}

func validDigest(value string) bool {
	return digestRE.MatchString(value)
}

func DigestLabel(label string) string {
	sum := sha256.Sum256([]byte(label))
	return hex.EncodeToString(sum[:])
}

func normalizeDuties(duties []Duty) ([]Duty, error) {
	if len(duties) == 0 || len(duties) > 8 {
		return nil, ErrInvalidInput
	}
	seen := make(map[Duty]struct{}, len(duties))
	normalized := append([]Duty(nil), duties...)
	for _, duty := range normalized {
		switch duty {
		case DutyRequest, DutyApprove, DutyExecute, DutyPublish, DutyRecover, DutyAudit:
		default:
			return nil, ErrInvalidInput
		}
		if _, duplicate := seen[duty]; duplicate {
			return nil, ErrInvalidInput
		}
		seen[duty] = struct{}{}
	}
	sort.Slice(normalized, func(i, j int) bool { return normalized[i] < normalized[j] })
	return normalized, nil
}

func ValidateActor(actor Actor) error {
	if !validID(actor.ID) {
		return fmt.Errorf("%w: malformed actor", ErrInvalidInput)
	}
	if _, err := normalizeDuties(actor.Duties); err != nil {
		return fmt.Errorf("%w: duties", err)
	}
	switch actor.AuthorityRole {
	case profile.RoleRoot, profile.RoleIssuer, profile.RoleProvider,
		profile.RoleRecipientRegistrar, profile.RoleEmergency, profile.RoleRelay,
		profile.RoleAppRelease, profile.RoleDeviceWrap, profile.RoleBackup,
		profile.RoleOperator:
	default:
		return fmt.Errorf("%w: missing authority role", ErrInvalidInput)
	}
	return nil
}

func ValidateOperation(operation Operation) error {
	if !validID(operation.ID) || !validID(operation.TargetID) ||
		!validDigest(operation.SubjectDigest) || !validDigest(operation.ScopeDigest) ||
		!validID(operation.RequesterID) ||
		operation.CreatedAt <= 0 || operation.ExpiresAt <= operation.CreatedAt {
		return ErrInvalidInput
	}
	if operation.ParentOperationID != "" && !validID(operation.ParentOperationID) {
		return ErrInvalidInput
	}
	switch operation.Action {
	case ActionPrepareProfileIssue, ActionPrepareProfileRotate, ActionIssueProfile, ActionRotateProfile, ActionRevokeProfile,
		ActionPublishSnapshot, ActionEnrollRelay, ActionPromoteRelay,
		ActionDrainRelay, ActionRetireRelay, ActionQuarantineRelay,
		ActionRevokeRelay, ActionEmergencyDeny, ActionEmergencyNarrow:
	default:
		return ErrInvalidInput
	}
	switch operation.State {
	case OperationPending, OperationApproved, OperationExecuted, OperationRejected:
	default:
		return ErrInvalidInput
	}
	if len(operation.ApproverIDs) > 8 {
		return ErrInvalidInput
	}
	seen := make(map[string]struct{}, len(operation.ApproverIDs))
	for _, approver := range operation.ApproverIDs {
		if !validID(approver) || approver == operation.RequesterID {
			return ErrInvalidInput
		}
		if _, duplicate := seen[approver]; duplicate {
			return ErrInvalidInput
		}
		seen[approver] = struct{}{}
	}
	switch operation.State {
	case OperationPending:
		if len(operation.ApproverIDs) >= MinApprovalQuorum || operation.ExecutedAt != 0 {
			return ErrInvalidInput
		}
	case OperationApproved:
		if len(operation.ApproverIDs) < MinApprovalQuorum || operation.ExecutedAt != 0 {
			return ErrInvalidInput
		}
	case OperationExecuted:
		if len(operation.ApproverIDs) < MinApprovalQuorum ||
			operation.ExecutedAt < operation.CreatedAt ||
			operation.ExecutedAt >= operation.ExpiresAt {
			return ErrInvalidInput
		}
	case OperationRejected:
		if operation.ExecutedAt != 0 {
			return ErrInvalidInput
		}
	}
	if operation.Action == ActionPublishSnapshot {
		if operation.Publication == nil {
			return ErrInvalidInput
		}
		if err := ValidatePublicationInput(*operation.Publication); err != nil {
			return err
		}
	} else if operation.Publication != nil {
		return ErrInvalidInput
	}
	switch operation.Action {
	case ActionPrepareProfileIssue, ActionIssueProfile:
		if operation.ExpectedArtifactDigest != "" {
			return ErrInvalidInput
		}
	case ActionPrepareProfileRotate, ActionRotateProfile, ActionRevokeProfile:
		if !validDigest(operation.ExpectedArtifactDigest) {
			return ErrInvalidInput
		}
	case ActionEmergencyDeny, ActionEmergencyNarrow:
		if !validDigest(operation.AuthorityScopeDigest) ||
			!validDigest(operation.AuthorityRootDigest) ||
			!validDigest(operation.ExpectedArtifactDigest) {
			return ErrInvalidInput
		}
	default:
		if operation.AuthorityScopeDigest != "" ||
			operation.AuthorityRootDigest != "" ||
			operation.ExpectedArtifactDigest != "" {
			return ErrInvalidInput
		}
	}
	if operation.Action != ActionIssueProfile && operation.Action != ActionRotateProfile && operation.ParentOperationID != "" {
		return ErrInvalidInput
	}
	if operation.Action == ActionPublishSnapshot {
		if operation.ResultEpoch != 0 {
			return ErrInvalidInput
		}
	} else if operation.ResultEpoch == 0 {
		return ErrInvalidInput
	}
	return nil
}

func isSafetyAction(action Action) bool {
	switch action {
	case ActionRevokeProfile, ActionQuarantineRelay, ActionRevokeRelay,
		ActionEmergencyDeny, ActionEmergencyNarrow:
		return true
	default:
		return false
	}
}

func ValidatePublicationInput(publication PublicationInput) error {
	if publication.Version == 0 || publication.RootVersion == 0 ||
		!validDigest(publication.SnapshotDigest) ||
		!validDigest(publication.TargetsDigest) ||
		publication.ValidUntil <= 0 {
		return ErrInvalidInput
	}
	return nil
}

func containsForbiddenText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{
		"payload", "plaintext", "ciphertext", "private_key", "secret",
		"credential", "token", "destination", "endpoint", "raw_profile",
		"client_ip", "android_id", "serial_number",
	} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
