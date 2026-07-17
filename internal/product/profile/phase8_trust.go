// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package profile

import (
	"errors"
	"fmt"

	"kurdistan/internal/product/envelope"
)

const (
	SnapshotFull  = "full-snapshot"
	UpdateInitial = "initial"
	UpdateReplace = "replacement"
	UpdateRemove  = "removal"
	UpdateMigrate = "provider-migration"
)

// ArtifactTrust is authenticated metadata required of a future Phase 8
// artifact. This package validates its contract and binding, not proof.
type ArtifactTrust struct {
	Artifact                 envelope.ArtifactMetadata
	ContentID, LineageID     string
	ProviderID               string
	ProfileID                string
	ContractVersion          string
	RevocationScope          string
	PreviousContentID        string
	PreviousProviderID       string
	SnapshotMode, UpdateKind string
	Generation               uint64
	RequiredSafetyFloor      uint64
	ValidFrom, ValidUntil    int64
	Authority                AuthorityEvidence
	Envelope                 envelope.Metadata
	RootEpoch                uint64
	RevocationEpoch          uint64
}

// ValidateArtifactTrust prevents artifact class, lineage, epoch, and update
// metadata from being treated as interchangeable authority.
func ValidateArtifactTrust(c Candidate, trust ArtifactTrust) error {
	if err := envelope.ValidateArtifactMetadata(trust.Artifact); err != nil {
		return fmt.Errorf("profile: artifact metadata: %w", err)
	}
	for _, field := range []struct {
		name, value string
	}{
		{"content_id", trust.ContentID},
		{"lineage_id", trust.LineageID},
		{"provider_id", trust.ProviderID},
		{"profile_id", trust.ProfileID},
		{"revocation_scope", trust.RevocationScope},
	} {
		if !boundedID(field.value) {
			return fmt.Errorf("profile: %s is missing or invalid", field.name)
		}
	}
	if trust.SnapshotMode != SnapshotFull {
		return errors.New("profile: only full-snapshot artifacts are admitted")
	}
	if trust.Generation == 0 || trust.RootEpoch == 0 || trust.RevocationEpoch == 0 {
		return errors.New("profile: artifact generation or epoch binding is missing or inconsistent")
	}
	if trust.ProfileID != c.ProfileID ||
		trust.ContractVersion != c.ContractVersion ||
		trust.RevocationScope != c.RevocationScope ||
		trust.Generation != c.Generation ||
		trust.RequiredSafetyFloor != c.RequiredSafetyFloor ||
		trust.ValidFrom != c.ValidFrom ||
		trust.ValidUntil != c.ValidUntil ||
		trust.Authority != c.Authority ||
		trust.Envelope != c.Envelope {
		return errors.New("profile: artifact trust is not bound to the complete candidate identity")
	}
	if trust.PreviousContentID != "" && !boundedID(trust.PreviousContentID) {
		return errors.New("profile: previous content identity is invalid")
	}
	if trust.PreviousProviderID != "" && !boundedID(trust.PreviousProviderID) {
		return errors.New("profile: previous provider identity is invalid")
	}
	switch trust.UpdateKind {
	case UpdateInitial:
		if trust.PreviousContentID != "" || trust.PreviousProviderID != "" {
			return errors.New("profile: initial snapshot cannot claim predecessor state")
		}
	case UpdateReplace, UpdateRemove:
		if trust.PreviousContentID == "" || trust.PreviousContentID == trust.ContentID || trust.PreviousProviderID != "" {
			return errors.New("profile: replacement or removal requires one distinct content predecessor")
		}
	case UpdateMigrate:
		if trust.PreviousContentID == "" || trust.PreviousContentID == trust.ContentID || trust.PreviousProviderID == "" || trust.PreviousProviderID == trust.ProviderID {
			return errors.New("profile: provider migration requires distinct content and provider predecessors")
		}
	default:
		return errors.New("profile: unknown artifact update kind")
	}
	return nil
}

// SameGenerationIdentity reports whether two validated artifacts are the same
// authenticated snapshot for equal-generation idempotence. Artifact equality
// includes its class-sensitive recipient epoch, so an epoch change conflicts.
func SameGenerationIdentity(a, b ArtifactTrust) bool {
	return a.Generation == b.Generation &&
		a.ContentID == b.ContentID &&
		a.LineageID == b.LineageID &&
		a.ProviderID == b.ProviderID &&
		a.ProfileID == b.ProfileID &&
		a.ContractVersion == b.ContractVersion &&
		a.RevocationScope == b.RevocationScope &&
		a.PreviousContentID == b.PreviousContentID &&
		a.PreviousProviderID == b.PreviousProviderID &&
		a.SnapshotMode == b.SnapshotMode &&
		a.UpdateKind == b.UpdateKind &&
		a.RequiredSafetyFloor == b.RequiredSafetyFloor &&
		a.ValidFrom == b.ValidFrom &&
		a.ValidUntil == b.ValidUntil &&
		a.Authority == b.Authority &&
		a.Envelope == b.Envelope &&
		a.RootEpoch == b.RootEpoch &&
		a.RevocationEpoch == b.RevocationEpoch &&
		a.Artifact == b.Artifact
}
