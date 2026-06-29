// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wirefeatures

import (
	"fmt"
	"regexp"
	"strings"
)

var safeTokenRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_\-]*$`)

func ValidateVector(vector WireFeatureVector) error {
	required := []string{
		vector.ProfileID,
		vector.Scenario,
		vector.Backend,
		vector.PhaseShape,
		vector.FieldLayoutClass,
		vector.FirstFlightBucket,
		vector.FirstNPacketShape,
		vector.DirectionPattern,
		vector.FragmentRhythm,
		vector.ControlRichness,
		vector.MetadataExposure,
		vector.PayloadVisibility,
		vector.SequenceBehavior,
		vector.BackpressurePattern,
		vector.ResetClosePattern,
		vector.ErrorMappingPattern,
		vector.ByteShapeHash,
	}
	for _, value := range required {
		if value == "" || unsafeText(value) {
			return fmt.Errorf("%w: unsafe or empty feature %q", ErrInvalidFeature, value)
		}
	}
	if !validSizeBucket(vector.FirstFlightBucket) {
		return fmt.Errorf("%w: first flight bucket %s", ErrInvalidFeature, vector.FirstFlightBucket)
	}
	if vector.PayloadLogged || vector.SecretLogged {
		return fmt.Errorf("%w: hygiene leak flags", ErrTraceLeak)
	}
	for _, value := range []string{vector.WirePolicyID, vector.WirePolicyHash, vector.WireSelectedFamily, vector.WireCorpusEntry} {
		if value != "" && unsafeText(value) {
			return fmt.Errorf("%w: unsafe wiregen metadata %q", ErrInvalidFeature, value)
		}
	}
	for _, bucket := range vector.FrameSizeBuckets {
		if !validSizeBucket(bucket) {
			return fmt.Errorf("%w: frame size bucket %s", ErrInvalidFeature, bucket)
		}
	}
	return nil
}

func safeToken(value string) bool {
	return value != "" && safeTokenRE.MatchString(value) && !unsafeText(value)
}

func unsafeText(value string) bool {
	lower := strings.ToLower(value)
	for _, marker := range []string{"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes", "auth_tag", "nonce_base", "secret", "derived_key", "client_write_key", "server_write_key", "proof_material", "private_key", "session_secret", "destination_address", "proxy_ip", "server_ip"} {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	return false
}
