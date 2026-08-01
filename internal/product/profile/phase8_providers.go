// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"errors"
	"fmt"
	"strings"

	"kurdistan/internal/product/envelope"
)

var (
	ErrUnauthorizedRole    = errors.New("profile: authority role is not permitted for operation")
	ErrInvalidDelegation   = errors.New("profile: delegation is invalid")
	ErrMonotonicTransition = errors.New("profile: monotonic transition is invalid")
	ErrRecipientResolution = errors.New("profile: recipient hint did not resolve exactly once")
	ErrEmergencyAuthority  = errors.New("profile: emergency authority is invalid")
)

// AuthorityRole is deliberately capability-specific. A role name grants only
// the operations listed by AuthorizeRoleOperation.
type AuthorityRole string

const (
	RoleRoot               AuthorityRole = "root"
	RoleIssuer             AuthorityRole = "issuer"
	RoleProvider           AuthorityRole = "provider"
	RoleRecipientRegistrar AuthorityRole = "recipient-registrar"
	RoleEmergency          AuthorityRole = "emergency"
	RoleRelay              AuthorityRole = "relay"
	RoleAppRelease         AuthorityRole = "app-release"
	RoleDeviceWrap         AuthorityRole = "device-wrap"
	RoleBackup             AuthorityRole = "backup"
	RoleOperator           AuthorityRole = "operator"
)

type AuthorityOperation string

const (
	OperationUpdateRoot          AuthorityOperation = "update-root"
	OperationDelegateIssuer      AuthorityOperation = "delegate-issuer"
	OperationDelegateProvider    AuthorityOperation = "delegate-provider"
	OperationDelegateRegistrar   AuthorityOperation = "delegate-recipient-registrar"
	OperationDelegateEmergency   AuthorityOperation = "delegate-emergency"
	OperationIssueProfile        AuthorityOperation = "issue-profile"
	OperationAuthenticateProfile AuthorityOperation = "authenticate-profile"
	OperationAuthorizeGroup      AuthorityOperation = "authorize-provider-group"
	OperationRevokeGroup         AuthorityOperation = "revoke-provider-group"
	OperationEnrollDevice        AuthorityOperation = "enroll-device-recipient"
	OperationRotateDevice        AuthorityOperation = "rotate-device-recipient"
	OperationRevokeDevice        AuthorityOperation = "revoke-device-recipient"
	OperationEnrollBackup        AuthorityOperation = "enroll-backup-recipient"
	OperationRotateBackup        AuthorityOperation = "rotate-backup-recipient"
	OperationRevokeBackup        AuthorityOperation = "revoke-backup-recipient"
	OperationEmergencyDeny       AuthorityOperation = "emergency-deny"
	OperationEmergencyNarrow     AuthorityOperation = "emergency-narrow"
	OperationAuthenticateRelay   AuthorityOperation = "authenticate-relay"
	OperationSignAppRelease      AuthorityOperation = "sign-app-release"
	OperationWrapDevice          AuthorityOperation = "wrap-device-key"
	OperationWrapBackup          AuthorityOperation = "wrap-backup-key"
	OperationExecuteCeremony     AuthorityOperation = "execute-ceremony"
)

// AuthorizeRoleOperation is the single fail-closed role matrix.
func AuthorizeRoleOperation(role AuthorityRole, operation AuthorityOperation) error {
	allowed := false
	switch role {
	case RoleRoot:
		allowed = operation == OperationUpdateRoot || operation == OperationDelegateIssuer || operation == OperationDelegateProvider || operation == OperationDelegateRegistrar || operation == OperationDelegateEmergency
	case RoleIssuer:
		allowed = operation == OperationIssueProfile || operation == OperationAuthenticateProfile
	case RoleProvider:
		allowed = operation == OperationAuthorizeGroup || operation == OperationRevokeGroup
	case RoleRecipientRegistrar:
		allowed = operation == OperationEnrollDevice || operation == OperationRotateDevice || operation == OperationRevokeDevice || operation == OperationEnrollBackup || operation == OperationRotateBackup || operation == OperationRevokeBackup
	case RoleEmergency:
		allowed = operation == OperationEmergencyDeny || operation == OperationEmergencyNarrow
	case RoleRelay:
		allowed = operation == OperationAuthenticateRelay
	case RoleAppRelease:
		allowed = operation == OperationSignAppRelease
	case RoleDeviceWrap:
		allowed = operation == OperationWrapDevice
	case RoleBackup:
		allowed = operation == OperationWrapBackup
	case RoleOperator:
		allowed = operation == OperationExecuteCeremony
	}
	if !allowed {
		return fmt.Errorf("%w: %s cannot %s", ErrUnauthorizedRole, role, operation)
	}
	return nil
}

// AuthorityScope binds a delegation to one provider, lineage, and profile
// namespace. Prefix matching is only used after validating a non-empty,
// slash-terminated namespace.
type AuthorityScope struct {
	ProviderID       string
	LineageID        string
	ProfileNamespace string
}

func (s AuthorityScope) validate() error {
	if !boundedID(s.ProviderID) || !boundedID(s.LineageID) || !validProfileNamespace(s.ProfileNamespace) {
		return fmt.Errorf("%w: malformed authority scope", ErrInvalidDelegation)
	}
	return nil
}

func validProfileNamespace(namespace string) bool {
	delimiter := "/"
	if strings.HasSuffix(namespace, ".") {
		delimiter = "."
	} else if !strings.HasSuffix(namespace, "/") {
		return false
	}
	if namespace != strings.TrimSpace(namespace) {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(namespace, delimiter), delimiter)
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		if !boundedID(part) {
			return false
		}
	}
	return true
}

func (s AuthorityScope) contains(providerID, lineageID, profileID string) bool {
	return providerID == s.ProviderID && lineageID == s.LineageID && strings.HasPrefix(profileID, s.ProfileNamespace) && len(profileID) > len(s.ProfileNamespace)
}

func scopeWithin(outer, inner AuthorityScope) bool {
	return outer.ProviderID == inner.ProviderID && outer.LineageID == inner.LineageID && strings.HasPrefix(inner.ProfileNamespace, outer.ProfileNamespace)
}

// KeyReference is an opaque operation handle. It intentionally contains no
// private or public key bytes.
type KeyReference struct {
	KeyID   string
	SuiteID uint16
}

func (k KeyReference) validate() error {
	if !boundedID(k.KeyID) || k.SuiteID != uint16(envelope.SuiteClassicalV1) {
		return errors.New("profile: key reference is invalid")
	}
	return nil
}

// RootSetArtifact is the authenticated root-set state consumed by a verifier.
type RootSetArtifact struct {
	Epoch                 uint64
	ViewID                string
	ValidFrom, ValidUntil int64
	Keys                  []KeyReference
}

func ValidateRootSet(root RootSetArtifact) error {
	if root.Epoch == 0 || !boundedID(root.ViewID) || root.ValidFrom <= 0 || root.ValidUntil <= root.ValidFrom || len(root.Keys) == 0 || len(root.Keys) > 16 {
		return errors.New("profile: root-set artifact is malformed")
	}
	seen := make(map[string]struct{}, len(root.Keys))
	for _, key := range root.Keys {
		if err := key.validate(); err != nil {
			return err
		}
		if _, duplicate := seen[key.KeyID]; duplicate {
			return errors.New("profile: root-set key ID collision")
		}
		seen[key.KeyID] = struct{}{}
	}
	return nil
}

func rootContains(root RootSetArtifact, keyID string) bool {
	for _, key := range root.Keys {
		if key.KeyID == keyID {
			return true
		}
	}
	return false
}

// rootContainsReference requires an exact opaque key-reference match. Key IDs
// alone are not sufficient at a verification boundary because the suite is an
// authenticated part of the signing capability.
func rootContainsReference(root RootSetArtifact, reference KeyReference) bool {
	for _, key := range root.Keys {
		if key == reference {
			return true
		}
	}
	return false
}

func sameRootSet(left, right RootSetArtifact) bool {
	if left.Epoch != right.Epoch || left.ViewID != right.ViewID || left.ValidFrom != right.ValidFrom || left.ValidUntil != right.ValidUntil || len(left.Keys) != len(right.Keys) {
		return false
	}
	for i := range left.Keys {
		if left.Keys[i] != right.Keys[i] {
			return false
		}
	}
	return true
}

func validateActiveRootSet(root RootSetArtifact, now int64) error {
	if err := ValidateRootSet(root); err != nil {
		return err
	}
	if now < root.ValidFrom || now >= root.ValidUntil {
		return fmt.Errorf("%w: root set is not active", ErrInvalidDelegation)
	}
	return nil
}

// ValidateRootSetUpdate requires prior-policy authorization and exactly one
// monotonic epoch step. Equal-epoch differences are conflicting views.
func ValidateRootSetUpdate(current, next RootSetArtifact, authorizerKeyID string) error {
	if err := ValidateRootSet(current); err != nil {
		return err
	}
	if err := ValidateRootSet(next); err != nil {
		return err
	}
	if next.Epoch <= current.Epoch {
		return fmt.Errorf("%w: root rollback or equal-epoch conflict", ErrMonotonicTransition)
	}
	if next.Epoch != current.Epoch+1 {
		return fmt.Errorf("%w: skipped root epoch", ErrMonotonicTransition)
	}
	if !rootContains(current, authorizerKeyID) {
		return fmt.Errorf("%w: root update lacks prior-policy authorization", ErrUnauthorizedRole)
	}
	return nil
}

// ValidateRootView rejects split views for one epoch and rollback relative to
// the caller's last trusted observation. Identical views are idempotent.
func ValidateRootView(lastTrusted, observed RootSetArtifact) error {
	if err := ValidateRootSet(lastTrusted); err != nil {
		return err
	}
	if err := ValidateRootSet(observed); err != nil {
		return err
	}
	if observed.Epoch < lastTrusted.Epoch {
		return fmt.Errorf("%w: root view rollback", ErrMonotonicTransition)
	}
	if observed.Epoch == lastTrusted.Epoch && !sameRootSet(lastTrusted, observed) {
		return fmt.Errorf("%w: conflicting root view", ErrMonotonicTransition)
	}
	return nil
}

// IssuerDelegationArtifact is a root-authorized, scoped, expiring issuer
// capability. It grants no recipient-membership authority.
type IssuerDelegationArtifact struct {
	RootEpoch              uint64
	RootKeyID              string
	IssuerKey              KeyReference
	Scope                  AuthorityScope
	ValidFrom, ValidUntil  int64
	DelegationEpoch        uint64
	MaxProfileValiditySecs uint64
	Revoked                bool
}

func ValidateIssuerDelegation(root RootSetArtifact, delegation IssuerDelegationArtifact, now int64, providerID, lineageID, profileID string) error {
	if err := validateActiveRootSet(root, now); err != nil {
		return err
	}
	if delegation.RootEpoch != root.Epoch || !rootContains(root, delegation.RootKeyID) {
		return fmt.Errorf("%w: unknown root or epoch", ErrInvalidDelegation)
	}
	if err := delegation.IssuerKey.validate(); err != nil {
		return err
	}
	if rootContains(root, delegation.IssuerKey.KeyID) || delegation.IssuerKey.KeyID == delegation.RootKeyID {
		return fmt.Errorf("%w: issuer/root key-ID collision", ErrInvalidDelegation)
	}
	if err := delegation.Scope.validate(); err != nil {
		return err
	}
	if delegation.DelegationEpoch == 0 || delegation.MaxProfileValiditySecs == 0 || delegation.Revoked || now < delegation.ValidFrom || now >= delegation.ValidUntil || delegation.ValidUntil <= delegation.ValidFrom {
		return fmt.Errorf("%w: issuer delegation is expired, revoked, or malformed", ErrInvalidDelegation)
	}
	if !delegation.Scope.contains(providerID, lineageID, profileID) {
		return fmt.Errorf("%w: profile is outside issuer scope", ErrInvalidDelegation)
	}
	return nil
}

// ScopedAuthorityArtifact authorizes either Provider group membership or
// Recipient Registrar device/backup membership, never both.
type ScopedAuthorityArtifact struct {
	Role                  AuthorityRole
	RootEpoch             uint64
	RootKeyID             string
	SubjectKey            KeyReference
	Scope                 AuthorityScope
	ValidFrom, ValidUntil int64
	AuthorizationEpoch    uint64
	Revoked               bool
}

func ValidateScopedAuthority(root RootSetArtifact, authority ScopedAuthorityArtifact, expectedRole AuthorityRole, now int64) error {
	if err := validateActiveRootSet(root, now); err != nil {
		return err
	}
	if expectedRole != RoleProvider && expectedRole != RoleRecipientRegistrar {
		return fmt.Errorf("%w: unsupported scoped authority role", ErrInvalidDelegation)
	}
	if authority.Role != expectedRole || authority.RootEpoch != root.Epoch || !rootContains(root, authority.RootKeyID) {
		return fmt.Errorf("%w: wrong role, root, or epoch", ErrInvalidDelegation)
	}
	if err := authority.SubjectKey.validate(); err != nil {
		return err
	}
	if rootContains(root, authority.SubjectKey.KeyID) || authority.SubjectKey.KeyID == authority.RootKeyID {
		return fmt.Errorf("%w: scoped authority/root key-ID collision", ErrInvalidDelegation)
	}
	if err := authority.Scope.validate(); err != nil {
		return err
	}
	if authority.AuthorizationEpoch == 0 || authority.Revoked || now < authority.ValidFrom || now >= authority.ValidUntil || authority.ValidUntil <= authority.ValidFrom {
		return fmt.Errorf("%w: scoped authority is expired, revoked, or malformed", ErrInvalidDelegation)
	}
	return nil
}

// The provider interfaces expose operations and opaque handles only.
type Signer interface {
	Sign(KeyReference, []byte) ([]byte, error)
}

type Verifier interface {
	Verify(KeyReference, []byte, []byte) error
}

type RecipientSealer interface {
	Seal(RecipientBinding, []byte) (encapsulation, ciphertext []byte, err error)
}

type RecipientOpener interface {
	Open(RecipientBinding, []byte, []byte) ([]byte, error)
}

type LocalWrapper interface {
	Wrap(KeyReference, []byte) ([]byte, error)
	Unwrap(KeyReference, []byte) ([]byte, error)
}

type MonotonicStateProvider interface {
	Load(string) (epoch uint64, valueDigest string, found bool, err error)
	CompareAndAdvance(string, uint64, uint64, string) error
}

type RecipientResolver interface {
	ResolveRecipient(envelope.ArtifactClass, string) (RecipientBinding, error)
}

// MaxRecipientBindingCandidates bounds resolver work before any binding scan
// or provider operation. The exact boundary is accepted; zero and one-over are
// rejected fail-closed.
const MaxRecipientBindingCandidates = 256

// RecipientBinding contains routing and opaque provider handles, never key
// bytes. The authenticated class is part of the lookup key.
type RecipientBinding struct {
	Class                 envelope.ArtifactClass
	ProviderID, LineageID string
	ProfileNamespace      string
	Hint, KeyID           string
	Epoch                 uint64
	Revoked               bool
}

func (binding RecipientBinding) validate() error {
	audience := ""
	switch binding.Class {
	case envelope.ArtifactProviderGroup:
		audience = envelope.AudienceProvisionedGroup
	case envelope.ArtifactDeviceRecipient:
		audience = envelope.AudienceProvisionedDevice
	case envelope.ArtifactEncryptedBackup:
		audience = envelope.AudienceProvisionedBackupKey
	default:
		return errors.New("profile: recipient binding has a non-recipient class")
	}
	if err := envelope.ValidateArtifactMetadata(envelope.ArtifactMetadata{Class: binding.Class, AudienceClass: audience, RecipientHint: binding.Hint, RecipientEpoch: binding.Epoch}); err != nil {
		return err
	}
	if !boundedID(binding.ProviderID) || !boundedID(binding.LineageID) || !boundedID(binding.KeyID) || !validProfileNamespace(binding.ProfileNamespace) {
		return errors.New("profile: recipient binding scope or handle is invalid")
	}
	return nil
}

type RecipientTransition string

const (
	RecipientEnroll RecipientTransition = "enroll"
	RecipientRotate RecipientTransition = "rotate"
	RecipientRevoke RecipientTransition = "revoke"
)

func operationForRecipient(class envelope.ArtifactClass, transition RecipientTransition) (AuthorityRole, AuthorityOperation, error) {
	if class == envelope.ArtifactProviderGroup {
		switch transition {
		case RecipientEnroll, RecipientRotate:
			return RoleProvider, OperationAuthorizeGroup, nil
		case RecipientRevoke:
			return RoleProvider, OperationRevokeGroup, nil
		}
		return "", "", errors.New("profile: unsupported provider-group transition")
	}
	if class == envelope.ArtifactDeviceRecipient {
		switch transition {
		case RecipientEnroll:
			return RoleRecipientRegistrar, OperationEnrollDevice, nil
		case RecipientRotate:
			return RoleRecipientRegistrar, OperationRotateDevice, nil
		case RecipientRevoke:
			return RoleRecipientRegistrar, OperationRevokeDevice, nil
		}
	}
	if class == envelope.ArtifactEncryptedBackup {
		switch transition {
		case RecipientEnroll:
			return RoleRecipientRegistrar, OperationEnrollBackup, nil
		case RecipientRotate:
			return RoleRecipientRegistrar, OperationRotateBackup, nil
		case RecipientRevoke:
			return RoleRecipientRegistrar, OperationRevokeBackup, nil
		}
	}
	return "", "", errors.New("profile: unsupported recipient transition")
}

// ValidateRecipientTransition enforces role, scope, class, and an exact +1
// epoch step before any state mutation.
func ValidateRecipientTransition(root RootSetArtifact, authority ScopedAuthorityArtifact, current *RecipientBinding, next RecipientBinding, transition RecipientTransition, now int64) error {
	requiredRole, operation, err := operationForRecipient(next.Class, transition)
	if err != nil {
		return err
	}
	if err := AuthorizeRoleOperation(authority.Role, operation); err != nil {
		return err
	}
	if authority.Role != requiredRole {
		return fmt.Errorf("%w: wrong recipient authority", ErrUnauthorizedRole)
	}
	if err := ValidateScopedAuthority(root, authority, requiredRole, now); err != nil {
		return err
	}
	if err := next.validate(); err != nil {
		return err
	}
	if !scopeWithin(authority.Scope, AuthorityScope{ProviderID: next.ProviderID, LineageID: next.LineageID, ProfileNamespace: next.ProfileNamespace}) {
		return fmt.Errorf("%w: recipient is outside delegated scope", ErrInvalidDelegation)
	}
	if transition == RecipientEnroll {
		if current != nil || next.Epoch != 1 || next.Revoked {
			return fmt.Errorf("%w: enrollment must create epoch one", ErrMonotonicTransition)
		}
		return nil
	}
	if current == nil {
		return fmt.Errorf("%w: rotation or revocation lacks current state", ErrMonotonicTransition)
	}
	if err := current.validate(); err != nil {
		return err
	}
	if current.Class != next.Class || current.ProviderID != next.ProviderID || current.LineageID != next.LineageID || current.ProfileNamespace != next.ProfileNamespace {
		return fmt.Errorf("%w: recipient class or scope changed", ErrMonotonicTransition)
	}
	if current.Revoked || next.Epoch != current.Epoch+1 {
		return fmt.Errorf("%w: stale, skipped, conflicting, or post-revocation epoch", ErrMonotonicTransition)
	}
	if transition == RecipientRotate {
		if next.Revoked || (next.Hint == current.Hint && next.KeyID == current.KeyID) {
			return fmt.Errorf("%w: rotation did not replace recipient capability", ErrMonotonicTransition)
		}
		return nil
	}
	if transition == RecipientRevoke && !next.Revoked {
		return fmt.Errorf("%w: revocation did not enter denied state", ErrMonotonicTransition)
	}
	return nil
}

// ResolveRecipientBinding performs exact class-plus-hint resolution and
// returns one opaque binding or fails. It never returns a candidate list.
func ResolveRecipientBinding(bindings []RecipientBinding, class envelope.ArtifactClass, hint string) (RecipientBinding, error) {
	if len(bindings) == 0 || len(bindings) > MaxRecipientBindingCandidates {
		return RecipientBinding{}, fmt.Errorf("%w: candidate count=%d", ErrRecipientResolution, len(bindings))
	}
	var matched RecipientBinding
	matches := 0
	for _, binding := range bindings {
		if binding.Class != class || binding.Hint != hint {
			continue
		}
		if err := binding.validate(); err != nil || binding.Revoked {
			return RecipientBinding{}, fmt.Errorf("%w: invalid or revoked binding", ErrRecipientResolution)
		}
		matched = binding
		matches++
	}
	if matches != 1 {
		return RecipientBinding{}, fmt.Errorf("%w: class=%s matches=%d", ErrRecipientResolution, class, matches)
	}
	return matched, nil
}

// ResolveRecipientForMetadata resolves one recipient capability and requires
// every recipient dispatch selector authenticated in the outer metadata.
func ResolveRecipientForMetadata(resolver RecipientResolver, metadata envelope.ArtifactMetadata) (RecipientBinding, error) {
	binding, err := resolver.ResolveRecipient(metadata.Class, metadata.RecipientHint)
	if err != nil {
		return RecipientBinding{}, err
	}
	if err := binding.validate(); err != nil {
		return RecipientBinding{}, fmt.Errorf("%w: resolver returned malformed binding: %v", ErrRecipientResolution, err)
	}
	if binding.Revoked || binding.Class != metadata.Class || binding.Hint != metadata.RecipientHint || binding.Epoch != metadata.RecipientEpoch {
		return RecipientBinding{}, fmt.Errorf("%w: resolver returned mismatched or revoked binding", ErrRecipientResolution)
	}
	return binding, nil
}

// RecipientBindingContainsProfile requires the recipient capability to cover
// the canonical profile identity before the profile can reach activation or an
// offline verification result.
func RecipientBindingContainsProfile(binding RecipientBinding, profileValue envelope.CanonicalProfileV1) bool {
	if err := binding.validate(); err != nil || binding.Revoked {
		return false
	}
	return (AuthorityScope{
		ProviderID:       binding.ProviderID,
		LineageID:        binding.LineageID,
		ProfileNamespace: binding.ProfileNamespace,
	}).contains(profileValue.ProviderID, profileValue.LineageID, profileValue.ProfileID)
}

// OpenResolvedRecipient resolves exactly one binding before invoking the
// opener. Unknown or colliding hints cause zero open attempts.
func OpenResolvedRecipient(resolver RecipientResolver, opener RecipientOpener, class envelope.ArtifactClass, hint string, encapsulation, ciphertext []byte) ([]byte, error) {
	binding, err := resolver.ResolveRecipient(class, hint)
	if err != nil {
		return nil, err
	}
	if err := binding.validate(); err != nil {
		return nil, fmt.Errorf("%w: resolver returned malformed binding: %v", ErrRecipientResolution, err)
	}
	if binding.Revoked || binding.Class != class || binding.Hint != hint {
		return nil, fmt.Errorf("%w: resolver returned mismatched or revoked binding", ErrRecipientResolution)
	}
	return opener.Open(binding, encapsulation, ciphertext)
}

// OpenResolvedRecipientForMetadata retains the resolved capability for the
// caller and binds all authenticated recipient selectors before any opener use.
func OpenResolvedRecipientForMetadata(resolver RecipientResolver, opener RecipientOpener, metadata envelope.ArtifactMetadata, encapsulation, ciphertext []byte) ([]byte, RecipientBinding, error) {
	binding, err := ResolveRecipientForMetadata(resolver, metadata)
	if err != nil {
		return nil, RecipientBinding{}, err
	}
	opened, err := opener.Open(binding, encapsulation, ciphertext)
	if err != nil {
		return nil, RecipientBinding{}, err
	}
	return opened, binding, nil
}

type EmergencyActionKind string

const (
	EmergencyDeny   EmergencyActionKind = "deny"
	EmergencyNarrow EmergencyActionKind = "narrow"
)

type EmergencyAuthorityArtifact struct {
	Key                   KeyReference
	Scope                 AuthorityScope
	ValidFrom, ValidUntil int64
	AuthorizationEpoch    uint64
	Revoked               bool
}

type EmergencyAction struct {
	Kind                  EmergencyActionKind
	Scope                 AuthorityScope
	Epoch                 uint64
	ValidFrom, ValidUntil int64
}

// ValidateEmergencyAction permits only expiring deny/narrow actions, exact
// monotonic advancement, and scope reduction.
func ValidateEmergencyAction(authority EmergencyAuthorityArtifact, currentEpoch uint64, action EmergencyAction, now int64) error {
	if err := validateEmergencyAuthority(authority, now); err != nil {
		return err
	}
	if action.Kind != EmergencyDeny && action.Kind != EmergencyNarrow {
		return fmt.Errorf("%w: operation is not deny-only", ErrEmergencyAuthority)
	}
	if err := action.Scope.validate(); err != nil {
		return fmt.Errorf("%w: malformed action scope: %v", ErrEmergencyAuthority, err)
	}
	if action.Epoch != currentEpoch+1 || action.Epoch == 0 || action.ValidFrom < authority.ValidFrom || action.ValidUntil > authority.ValidUntil || action.ValidUntil <= action.ValidFrom || now < action.ValidFrom || now >= action.ValidUntil {
		return fmt.Errorf("%w: action is stale, skipped, or outside validity", ErrEmergencyAuthority)
	}
	if !scopeWithin(authority.Scope, action.Scope) {
		return fmt.Errorf("%w: action expands authority scope", ErrEmergencyAuthority)
	}
	if action.Kind == EmergencyNarrow && action.Scope == authority.Scope {
		return fmt.Errorf("%w: narrow action did not reduce scope", ErrEmergencyAuthority)
	}
	return nil
}

func validateEmergencyAuthority(authority EmergencyAuthorityArtifact, now int64) error {
	if err := authority.Key.validate(); err != nil || authority.AuthorizationEpoch == 0 || authority.Revoked || now < authority.ValidFrom || now >= authority.ValidUntil || authority.ValidUntil <= authority.ValidFrom {
		return fmt.Errorf("%w: authority is expired, revoked, or malformed", ErrEmergencyAuthority)
	}
	if err := authority.Scope.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrEmergencyAuthority, err)
	}
	return nil
}
