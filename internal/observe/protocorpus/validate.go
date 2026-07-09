// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package protocorpus

import (
	"fmt"
	"regexp"
	"strings"
)

var safeTokenRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]*$`)

func ValidateManifest(manifest CorpusManifest) error {
	if manifest.Version != CorpusSchemaVersion {
		return fmt.Errorf("%w: version %s", ErrInvalidCorpus, manifest.Version)
	}
	if manifest.FeatureSchemaVersion != FeatureSchemaVersion {
		return fmt.Errorf("%w: feature schema %s", ErrInvalidCorpus, manifest.FeatureSchemaVersion)
	}
	if len(manifest.Entries) == 0 {
		return fmt.Errorf("%w: no entries", ErrInvalidCorpus)
	}
	seen := map[string]bool{}
	for _, entry := range manifest.Entries {
		if err := ValidateEntry(entry); err != nil {
			return err
		}
		if seen[entry.Name] {
			return fmt.Errorf("%w: duplicate entry %s", ErrInvalidCorpus, entry.Name)
		}
		seen[entry.Name] = true
	}
	return nil
}

func ValidateEntry(entry ProtocolShapeEntry) error {
	if !safeToken(entry.Name) {
		return fmt.Errorf("%w: unsafe entry name %q", ErrInvalidCorpus, entry.Name)
	}
	if !containsFamily(entry.Family) {
		return fmt.Errorf("%w: family %s", ErrInvalidCorpus, entry.Family)
	}
	if !containsString(SupportedSizeBuckets(), entry.FirstFlightBucket) {
		return fmt.Errorf("%w: first flight bucket %s", ErrInvalidCorpus, entry.FirstFlightBucket)
	}
	if !safeToken(entry.FirstNPacketBucket) || !safeToken(entry.FragmentRhythm) || !safeToken(entry.ControlRichness) {
		return fmt.Errorf("%w: unsafe shape token", ErrInvalidCorpus)
	}
	if !containsString(SupportedMetadataExposureBuckets(), entry.MetadataExposure) {
		return fmt.Errorf("%w: metadata exposure %s", ErrInvalidCorpus, entry.MetadataExposure)
	}
	if len(entry.Phases) == 0 {
		return fmt.Errorf("%w: entry %s has no phases", ErrInvalidCorpus, entry.Name)
	}
	for _, bucket := range entry.FrameSizeBuckets {
		if !containsString(SupportedSizeBuckets(), bucket) {
			return fmt.Errorf("%w: frame size bucket %s", ErrInvalidCorpus, bucket)
		}
	}
	for _, phase := range entry.Phases {
		if err := ValidatePhase(phase); err != nil {
			return fmt.Errorf("%s: %w", entry.Name, err)
		}
	}
	if report := ValidateRedaction(entry); !report.Passed {
		return fmt.Errorf("%w: unsafe corpus fields %v", ErrTraceLeak, report.Findings)
	}
	return nil
}

func ValidatePhase(phase PhaseDescriptor) error {
	if !containsPhase(phase.Phase) {
		return fmt.Errorf("%w: phase %s", ErrInvalidCorpus, phase.Phase)
	}
	if !safeToken(phase.MessageCountBucket) {
		return fmt.Errorf("%w: message count bucket %s", ErrInvalidCorpus, phase.MessageCountBucket)
	}
	if !containsString(SupportedDirectionPatterns(), phase.DirectionPattern) {
		return fmt.Errorf("%w: direction pattern %s", ErrInvalidCorpus, phase.DirectionPattern)
	}
	if !containsString(SupportedRoundTripBuckets(), phase.RoundTripBucket) {
		return fmt.Errorf("%w: round trip bucket %s", ErrInvalidCorpus, phase.RoundTripBucket)
	}
	for _, field := range phase.Fields {
		if err := ValidateField(field); err != nil {
			return err
		}
	}
	return nil
}

func ValidateField(field FieldDescriptor) error {
	if !containsFieldKind(field.Kind) {
		return fmt.Errorf("%w: field kind %s", ErrInvalidCorpus, field.Kind)
	}
	if !containsVisibility(field.Visibility) {
		return fmt.Errorf("%w: visibility %s", ErrInvalidCorpus, field.Visibility)
	}
	if !containsString(SupportedSizeBuckets(), field.SizeBucket) {
		return fmt.Errorf("%w: field size bucket %s", ErrInvalidCorpus, field.SizeBucket)
	}
	if !safeToken(field.PositionBucket) || !safeToken(field.SafeValueClass) {
		return fmt.Errorf("%w: unsafe field descriptor", ErrInvalidCorpus)
	}
	return nil
}

func safeToken(value string) bool {
	return value != "" && safeTokenRE.MatchString(value) && !unsafeText(value)
}

func unsafeText(value string) bool {
	lower := strings.ToLower(value)
	if lower == string(FieldAuthTagLike) {
		return false
	}
	for _, marker := range []string{"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes", "auth_tag", "nonce_base", "secret", "private_key", "session_secret", "destination_address", "proxy_ip", "server_ip"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func containsFamily(value ProtocolFamily) bool {
	for _, candidate := range SupportedFamilies() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsPhase(value ProtocolPhase) bool {
	for _, candidate := range SupportedPhases() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsFieldKind(value FieldKind) bool {
	for _, candidate := range SupportedFieldKinds() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsVisibility(value VisibilityClass) bool {
	for _, candidate := range SupportedVisibilityClasses() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsString(values []string, value string) bool {
	for _, candidate := range values {
		if candidate == value {
			return true
		}
	}
	return false
}
