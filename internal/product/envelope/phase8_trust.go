// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strings"
)

// ErrLegacyEnvelopeNotPromotable prevents metadata accepted through the pinned
// predecessor Parse API from being upgraded into Phase 8 artifact authority.
var ErrLegacyEnvelopeNotPromotable = errors.New("envelope: legacy parsed metadata is not promotable to Phase 8 artifact authority")

// ArtifactClass identifies a future artifact trust/confidentiality contract.
// It selects neither a wire encoding nor a cryptographic construction.
type ArtifactClass string

const (
	ArtifactSignedPublic         ArtifactClass = "signed-public"
	ArtifactProviderGroup        ArtifactClass = "provider-group-recipient"
	ArtifactDeviceRecipient      ArtifactClass = "device-recipient"
	ArtifactEncryptedBackup      ArtifactClass = "encrypted-backup"
	AudiencePublic               string        = "public"
	AudienceProvisionedGroup     string        = "provisioned-group"
	AudienceProvisionedDevice    string        = "provisioned-device"
	AudienceProvisionedBackupKey string        = "provisioned-backup-recipient"
)

// ArtifactMetadata is the visible contract-only routing surface of a future
// artifact. RecipientHint is opaque and rotation-capable, not a device identity
// or an unlinkability claim.
type ArtifactMetadata struct {
	Class          ArtifactClass
	AudienceClass  string
	RecipientHint  string
	RecipientEpoch uint64
}

// ParseArtifactLink is the strict Phase 8 admission entry point. Legacy Parse
// remains the pinned metadata predecessor and must not be used to grant Phase 8
// artifact authority.
func ParseArtifactLink(link string) (Envelope, error) {
	u, err := url.Parse(link)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: parse artifact link: %w", err)
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return Envelope{}, fmt.Errorf("envelope: artifact query: %w", err)
	}
	allowed := map[string]struct{}{"exp": {}, "rev": {}, "compat": {}, "seal": {}}
	keys := make([]string, 0, len(q))
	for key := range q {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		values := q[key]
		if _, ok := allowed[key]; !ok {
			return Envelope{}, fmt.Errorf("envelope: unknown artifact query parameter %q", key)
		}
		if len(values) != 1 {
			return Envelope{}, fmt.Errorf("envelope: artifact query parameter %q must occur exactly once", key)
		}
	}
	return Parse(link)
}

// PromoteLegacyEnvelope always fails. Phase 8 admission must begin from the
// original link through ParseArtifactLink so ambiguous query bytes are retained
// for strict validation.
func PromoteLegacyEnvelope(Envelope) error {
	return ErrLegacyEnvelopeNotPromotable
}

// ValidateArtifactMetadata rejects class/audience authority laundering.
func ValidateArtifactMetadata(m ArtifactMetadata) error {
	wantAudience := ""
	switch m.Class {
	case ArtifactSignedPublic:
		wantAudience = AudiencePublic
	case ArtifactProviderGroup:
		wantAudience = AudienceProvisionedGroup
	case ArtifactDeviceRecipient:
		wantAudience = AudienceProvisionedDevice
	case ArtifactEncryptedBackup:
		wantAudience = AudienceProvisionedBackupKey
	default:
		return errors.New("envelope: unknown artifact class")
	}
	if m.AudienceClass != wantAudience {
		return errors.New("envelope: artifact class and audience do not match")
	}
	if m.Class == ArtifactSignedPublic {
		if m.RecipientHint != "" {
			return errors.New("envelope: public artifact cannot carry a recipient hint")
		}
		if m.RecipientEpoch != 0 {
			return errors.New("envelope: public artifact cannot carry a recipient epoch")
		}
		return nil
	}
	if !boundedRoutingHint(m.RecipientHint) {
		return errors.New("envelope: recipient artifact requires a bounded opaque routing hint")
	}
	if m.RecipientEpoch == 0 {
		return errors.New("envelope: recipient artifact requires a nonzero recipient epoch")
	}
	return nil
}

func boundedRoutingHint(v string) bool {
	if v != strings.TrimSpace(v) || len(v) < 8 || len(v) > 64 {
		return false
	}
	for _, r := range v {
		if !(r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}
