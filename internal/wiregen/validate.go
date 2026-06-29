// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"fmt"
	"regexp"
	"strings"

	"kurdistan/internal/protocorpus"
)

var safeTokenRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]*$`)

func ValidatePolicy(policy WireShapePolicy, corpus protocorpus.CorpusManifest) error {
	if policy.Version != PolicyVersion {
		return fmt.Errorf("%w: version %s", ErrInvalidPolicy, policy.Version)
	}
	if policy.CorpusVersion != string(corpus.Version) {
		return fmt.Errorf("%w: corpus version %s", ErrInvalidPolicy, policy.CorpusVersion)
	}
	if !safeToken(policy.PolicyID) || !safeToken(policy.SelectedCorpusEntry) {
		return fmt.Errorf("%w: unsafe policy id or corpus entry", ErrInvalidPolicy)
	}
	entry, ok := corpusEntryByName(corpus, policy.SelectedCorpusEntry)
	if !ok {
		return fmt.Errorf("%w: selected corpus entry missing", ErrInvalidPolicy)
	}
	if entry.Family != policy.SelectedFamily {
		return fmt.Errorf("%w: selected family mismatch", ErrInvalidPolicy)
	}
	if !containsFamily(policy.SelectedFamily) {
		return fmt.Errorf("%w: unsupported family %s", ErrInvalidPolicy, policy.SelectedFamily)
	}
	if err := validatePhasePlan(policy.PhasePlan); err != nil {
		return err
	}
	if err := validateFieldLayout(policy.FieldLayoutPlan); err != nil {
		return err
	}
	if err := validateFirstFlight(policy.FirstFlightPlan); err != nil {
		return err
	}
	if policy.FirstNPlan.N <= 0 || policy.FirstNPlan.N > 16 || !safeToken(policy.FirstNPlan.ShapeClass) || !safeToken(policy.FirstNPlan.DirectionClass) || !safeToken(policy.FirstNPlan.SizeClass) {
		return fmt.Errorf("%w: invalid first-n plan", ErrInvalidPolicy)
	}
	if err := validateFrameSize(policy.FrameSizePlan); err != nil {
		return err
	}
	if err := validateFragment(policy.FragmentRhythmPlan); err != nil {
		return err
	}
	if !safeToken(policy.ControlPlan.Richness) || policy.ControlPlan.PreDataControls < 0 || policy.ControlPlan.PreDataControls > 8 || !safeToken(policy.ControlPlan.InterleaveClass) || !safeToken(policy.ControlPlan.CloseClass) || !safeToken(policy.ControlPlan.ResetClass) {
		return fmt.Errorf("%w: invalid control plan", ErrInvalidPolicy)
	}
	if !containsString(protocorpus.SupportedMetadataExposureBuckets(), policy.MetadataExposurePlan.ExposureClass) {
		return fmt.Errorf("%w: invalid metadata exposure", ErrInvalidPolicy)
	}
	if !safeToken(policy.LengthAlonePlan.TriggerClass) {
		return fmt.Errorf("%w: invalid length-alone trigger", ErrInvalidPolicy)
	}
	expected, err := PolicyHash(policy)
	if err != nil {
		return err
	}
	if expected != policy.PolicyHash {
		return fmt.Errorf("%w: policy hash mismatch", ErrInvalidPolicy)
	}
	if report := ValidateRedaction(policy); !report.Passed {
		return fmt.Errorf("%w: %v", ErrTraceLeak, report.Findings)
	}
	return nil
}

func validatePhasePlan(plan PhasePlan) error {
	if len(plan.PhaseSequence) == 0 || !containsString(protocorpus.SupportedRoundTripBuckets(), plan.HandshakeRTTBucket) || !containsString(protocorpus.SupportedDirectionPatterns(), plan.DirectionPattern) {
		return fmt.Errorf("%w: invalid phase plan", ErrInvalidPolicy)
	}
	for _, phase := range plan.PhaseSequence {
		if !containsPhase(phase) {
			return fmt.Errorf("%w: unsupported phase %s", ErrInvalidPolicy, phase)
		}
	}
	return nil
}

func validateFieldLayout(plan FieldLayoutPlan) error {
	if !safeToken(plan.LayoutClass) || len(plan.FieldOrder) == 0 || !safeToken(plan.PayloadPosition) {
		return fmt.Errorf("%w: invalid field layout", ErrInvalidPolicy)
	}
	for _, field := range plan.FieldOrder {
		if !containsField(field) {
			return fmt.Errorf("%w: unsupported field %s", ErrInvalidPolicy, field)
		}
		if !containsVisibility(plan.VisibilityByField[field]) || !containsString(protocorpus.SupportedSizeBuckets(), plan.SizeBucketByField[field]) {
			return fmt.Errorf("%w: invalid field metadata %s", ErrInvalidPolicy, field)
		}
	}
	return nil
}

func validateFirstFlight(plan FirstFlightPlan) error {
	if !safeToken(plan.PacketCountBucket) || !containsString(protocorpus.SupportedDirectionPatterns(), plan.DirectionPattern) || len(plan.SizeBuckets) == 0 {
		return fmt.Errorf("%w: invalid first-flight plan", ErrInvalidPolicy)
	}
	for _, bucket := range plan.SizeBuckets {
		if !containsString(protocorpus.SupportedSizeBuckets(), bucket) {
			return fmt.Errorf("%w: invalid first-flight size bucket %s", ErrInvalidPolicy, bucket)
		}
	}
	return nil
}

func validateFrameSize(plan FrameSizePlan) error {
	if !safeToken(plan.Strategy) || !safeToken(plan.PaddingBudget) || !safeToken(plan.PayloadSplit) || len(plan.SizeBuckets) == 0 {
		return fmt.Errorf("%w: invalid frame-size plan", ErrInvalidPolicy)
	}
	for _, bucket := range plan.SizeBuckets {
		if !containsString(protocorpus.SupportedSizeBuckets(), bucket) {
			return fmt.Errorf("%w: invalid frame size bucket %s", ErrInvalidPolicy, bucket)
		}
	}
	return nil
}

func validateFragment(plan FragmentRhythmPlan) error {
	if !safeToken(plan.Strategy) || !safeToken(plan.ReassemblyPattern) || len(plan.FragmentBuckets) == 0 {
		return fmt.Errorf("%w: invalid fragment rhythm", ErrInvalidPolicy)
	}
	for _, bucket := range plan.FragmentBuckets {
		if !containsString(protocorpus.SupportedSizeBuckets(), bucket) {
			return fmt.Errorf("%w: invalid fragment bucket %s", ErrInvalidPolicy, bucket)
		}
	}
	return nil
}

func safeToken(value string) bool {
	return value != "" && safeTokenRE.MatchString(value) && !unsafeText(value)
}

func unsafeText(value string) bool {
	lower := strings.ToLower(value)
	if lower == string(protocorpus.FieldAuthTagLike) {
		return false
	}
	for _, marker := range []string{"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes", "auth_tag", "nonce_base", "secret", "derived_key", "client_write_key", "server_write_key", "proof_material", "private_key", "session_secret", "destination_address", "proxy_ip", "server_ip", "domain", "sni", "host_header"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}

func corpusEntryByName(corpus protocorpus.CorpusManifest, name string) (protocorpus.ProtocolShapeEntry, bool) {
	for _, entry := range corpus.Entries {
		if entry.Name == name {
			return entry, true
		}
	}
	return protocorpus.ProtocolShapeEntry{}, false
}

func containsFamily(value protocorpus.ProtocolFamily) bool {
	for _, candidate := range protocorpus.SupportedFamilies() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsPhase(value protocorpus.ProtocolPhase) bool {
	for _, candidate := range protocorpus.SupportedPhases() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsField(value protocorpus.FieldKind) bool {
	for _, candidate := range protocorpus.SupportedFieldKinds() {
		if candidate == value {
			return true
		}
	}
	return false
}

func containsVisibility(value protocorpus.VisibilityClass) bool {
	for _, candidate := range protocorpus.SupportedVisibilityClasses() {
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
