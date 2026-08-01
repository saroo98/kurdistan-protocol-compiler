// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package controlplane

import (
	"fmt"

	"kurdistan/internal/product/profile"
)

// InstallEmergencyAuthority atomically installs an initial root-authenticated
// emergency authority or its exact next replacement for one durable scope.
func (service *Service) InstallEmergencyAuthority(
	actor Actor,
	trusted profile.VerifiedEmergencyAuthority,
	expectedRevision uint64,
	now int64,
) (EmergencyAuthorityRecord, error) {
	if err := ValidateActor(actor); err != nil ||
		actor.AuthorityRole != profile.RoleRoot ||
		!actor.has(DutyExecute) {
		return EmergencyAuthorityRecord{}, ErrUnauthorized
	}
	binding, err := trusted.CurrentBinding(now)
	if err != nil {
		return EmergencyAuthorityRecord{}, fmt.Errorf("%w: emergency authority verification failed", ErrInvalidInput)
	}
	scopeDigest := emergencyScopeDigest(binding.Scope)
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		if len(state.Audit) >= MaxAuditEntries {
			return ErrConflict
		}
		current, exists := state.EmergencyAuthorities[scopeDigest]
		if !exists {
			if binding.AuthorizationEpoch != 1 ||
				binding.PreviousDelegationSHA256 != "" {
				return ErrConflict
			}
		} else {
			if current.Revoked ||
				binding.AuthorizationEpoch != current.AuthorizationEpoch+1 ||
				binding.RootSetSHA256 != current.RootSetDigest ||
				binding.RootEpoch != current.RootEpoch ||
				binding.RootKeyID != current.RootKeyID ||
				binding.RootKeySuiteID != current.RootKeySuiteID ||
				binding.PreviousDelegationSHA256 != current.DelegationDigest ||
				binding.DelegationSHA256 == current.DelegationDigest {
				return ErrConflict
			}
		}
		state.EmergencyAuthorities[scopeDigest] = EmergencyAuthorityRecord{
			ScopeDigest:        scopeDigest,
			RootSetDigest:      binding.RootSetSHA256,
			RootEpoch:          binding.RootEpoch,
			RootKeyID:          binding.RootKeyID,
			RootKeySuiteID:     binding.RootKeySuiteID,
			AuthorizationEpoch: binding.AuthorizationEpoch,
			DelegationDigest:   binding.DelegationSHA256,
			KeyID:              binding.Key.KeyID,
			KeySuiteID:         binding.Key.SuiteID,
			ValidFrom:          binding.ValidFrom,
			ValidUntil:         binding.ValidUntil,
			UpdatedAt:          now,
		}
		if err := appendAudit(state, now, actor.ID, "install-emergency-authority", scopeDigest, "installed"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return EmergencyAuthorityRecord{}, err
	}
	return next.EmergencyAuthorities[scopeDigest], nil
}

// RevokeEmergencyAuthority atomically applies a root-authenticated terminal
// revocation to the exact currently installed emergency authority.
func (service *Service) RevokeEmergencyAuthority(
	actor Actor,
	verified profile.VerifiedEmergencyAuthorityRevocation,
	expectedRevision uint64,
	now int64,
) (EmergencyAuthorityRecord, error) {
	if err := ValidateActor(actor); err != nil ||
		actor.AuthorityRole != profile.RoleRoot ||
		!actor.has(DutyExecute) {
		return EmergencyAuthorityRecord{}, ErrUnauthorized
	}
	previous := verified.PreviousBinding()
	if now < verified.EffectiveAt() || now >= previous.ValidUntil {
		return EmergencyAuthorityRecord{}, ErrExpired
	}
	scopeDigest := emergencyScopeDigest(previous.Scope)
	next, err := service.store.Update(expectedRevision, func(state *State) error {
		if len(state.Audit) >= MaxAuditEntries {
			return ErrConflict
		}
		current, exists := state.EmergencyAuthorities[scopeDigest]
		if !exists || current.Revoked ||
			!recordMatchesBinding(current, previous) ||
			verified.AuthorizationEpoch() != current.AuthorizationEpoch+1 ||
			!validDigest(verified.RevocationSHA256()) {
			return ErrConflict
		}
		current.AuthorizationEpoch = verified.AuthorizationEpoch()
		current.Revoked = true
		current.RevocationDigest = verified.RevocationSHA256()
		current.UpdatedAt = now
		state.EmergencyAuthorities[scopeDigest] = current
		if err := appendAudit(state, now, actor.ID, "revoke-emergency-authority", scopeDigest, "revoked"); err != nil {
			return err
		}
		return nil
	})
	if err != nil {
		return EmergencyAuthorityRecord{}, err
	}
	return next.EmergencyAuthorities[scopeDigest], nil
}

func emergencyScopeDigest(scope profile.AuthorityScope) string {
	return DigestLabel(scope.ProviderID + "|" + scope.LineageID + "|" + scope.ProfileNamespace)
}

func recordMatchesBinding(record EmergencyAuthorityRecord, binding profile.EmergencyAuthorityBinding) bool {
	return !record.Revoked &&
		record.RootSetDigest == binding.RootSetSHA256 &&
		record.RootEpoch == binding.RootEpoch &&
		record.RootKeyID == binding.RootKeyID &&
		record.RootKeySuiteID == binding.RootKeySuiteID &&
		record.AuthorizationEpoch == binding.AuthorizationEpoch &&
		record.DelegationDigest == binding.DelegationSHA256 &&
		record.KeyID == binding.Key.KeyID &&
		record.KeySuiteID == binding.Key.SuiteID &&
		record.ScopeDigest == emergencyScopeDigest(binding.Scope) &&
		record.ValidFrom == binding.ValidFrom &&
		record.ValidUntil == binding.ValidUntil
}
