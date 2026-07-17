// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package envelope

import (
	"strings"
	"testing"
)

func TestParseArtifactLinkRejectsAmbiguousOrUnknownQueryParameters(t *testing.T) {
	link, err := Format(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseArtifactLink(link); err != nil {
		t.Fatal(err)
	}
	for name, candidate := range map[string]string{
		"unknown":   link + "&recipient=attacker-controlled",
		"duplicate": link + "&rev=second-scope",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseArtifactLink(candidate); err == nil {
				t.Fatal("accepted ambiguous trust metadata")
			}
		})
	}
}

func TestParseArtifactLinkSelectsErrorsDeterministically(t *testing.T) {
	link, err := Format(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	candidate := link + "&z_unknown=1&a_unknown=2&compat=duplicate"
	const want = `unknown artifact query parameter "a_unknown"`
	for i := 0; i < 100; i++ {
		_, err := ParseArtifactLink(candidate)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Fatalf("iteration %d error = %v, want categorical error containing %q", i, err, want)
		}
	}
}

func TestLegacyParseCannotBypassPhase8StrictAdmission(t *testing.T) {
	link, err := Format(validEnvelope())
	if err != nil {
		t.Fatal(err)
	}
	ambiguous := link + "&recipient=ignored-by-legacy-parser"
	legacy, err := Parse(ambiguous)
	if err != nil {
		t.Fatalf("test requires the pinned predecessor to demonstrate its weaker parse: %v", err)
	}
	if err := PromoteLegacyEnvelope(legacy); err != ErrLegacyEnvelopeNotPromotable {
		t.Fatalf("legacy metadata promotion err = %v", err)
	}
	if _, err := ParseArtifactLink(ambiguous); err == nil {
		t.Fatal("strict Phase 8 admission accepted metadata discarded by legacy Parse")
	}
}

func TestArtifactMetadataRejectsAuthorityLaundering(t *testing.T) {
	valid := []ArtifactMetadata{
		{Class: ArtifactSignedPublic, AudienceClass: AudiencePublic},
		{Class: ArtifactProviderGroup, AudienceClass: AudienceProvisionedGroup, RecipientHint: "rotating_hint_01", RecipientEpoch: 1},
		{Class: ArtifactDeviceRecipient, AudienceClass: AudienceProvisionedDevice, RecipientHint: "rotating_hint_02", RecipientEpoch: 1},
		{Class: ArtifactEncryptedBackup, AudienceClass: AudienceProvisionedBackupKey, RecipientHint: "rotating_hint_03", RecipientEpoch: 1},
	}
	for _, m := range valid {
		if err := ValidateArtifactMetadata(m); err != nil {
			t.Fatalf("ValidateArtifactMetadata(%+v): %v", m, err)
		}
	}
	invalid := []ArtifactMetadata{
		{Class: ArtifactClass("unknown"), AudienceClass: AudiencePublic},
		{Class: ArtifactSignedPublic, AudienceClass: AudienceProvisionedDevice},
		{Class: ArtifactSignedPublic, AudienceClass: AudiencePublic, RecipientHint: "stable_device_id"},
		{Class: ArtifactSignedPublic, AudienceClass: AudiencePublic, RecipientEpoch: 1},
		{Class: ArtifactProviderGroup, AudienceClass: AudienceProvisionedGroup, RecipientHint: "rotating_hint_01"},
		{Class: ArtifactDeviceRecipient, AudienceClass: AudienceProvisionedDevice, RecipientHint: "rotating_hint_02"},
		{Class: ArtifactEncryptedBackup, AudienceClass: AudienceProvisionedBackupKey, RecipientHint: "rotating_hint_03"},
		{Class: ArtifactDeviceRecipient, AudienceClass: AudienceProvisionedDevice},
		{Class: ArtifactEncryptedBackup, AudienceClass: AudienceProvisionedGroup, RecipientHint: "rotating_hint_03", RecipientEpoch: 1},
	}
	for _, m := range invalid {
		if err := ValidateArtifactMetadata(m); err == nil {
			t.Fatalf("accepted authority-laundering metadata: %+v", m)
		}
	}
}
