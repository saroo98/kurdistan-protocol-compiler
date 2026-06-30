// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package hostdetect

import (
	"encoding/json"
	"fmt"
	"strings"
)

var forbiddenMarkers = []string{
	"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes",
	"destination_address", "endpoint", "real_host", "proxy_ip", "server_ip", "domain", "sni", "host_header", "url", "ip_address",
	"secret", "derived_key", "client_write_key", "server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
}

func ValidateObservation(observation HostObservation) error {
	if observation.Version != string(Version) || observation.ObservationID == "" || observation.DatasetRecordID == "" || observation.SyntheticHostID == "" {
		return ErrInvalidObservation
	}
	if !strings.HasPrefix(string(observation.SyntheticHostID), "host_") {
		return ErrInvalidObservation
	}
	if strings.Contains(string(observation.SyntheticHostID), ".") || strings.Contains(string(observation.SyntheticHostID), "://") {
		return ErrTraceLeak
	}
	for _, value := range []string{observation.ProfileID, observation.Scenario, observation.SelectedFamily} {
		if strings.Contains(value, "://") || strings.Contains(value, ".example") || strings.Contains(value, "127.0.0.1") {
			return ErrTraceLeak
		}
	}
	if observation.PayloadLogged || observation.SecretLogged {
		return ErrTraceLeak
	}
	return ScanForLeak(observation)
}

func ValidateObservationSet(set HostObservationSet) error {
	if set.Version != string(Version) || set.ObservationCount != len(set.Observations) || set.DatasetHash != ObservationSetHash(set.Observations) {
		return ErrInvalidObservation
	}
	if set.PayloadLogged || set.SecretLogged {
		return ErrTraceLeak
	}
	for _, observation := range set.Observations {
		if err := ValidateObservation(observation); err != nil {
			return err
		}
	}
	return nil
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	lower := strings.ToLower(string(raw))
	for _, marker := range forbiddenMarkers {
		if strings.Contains(lower, `"`+marker+`"`) || strings.Contains(lower, marker+":") {
			return fmt.Errorf("%w: %s", ErrTraceLeak, marker)
		}
	}
	return nil
}

func ValidateSummary(summary HostDetectSummary) error {
	if summary.Version != string(Version) || summary.PayloadLogged || summary.SecretLogged {
		return ErrInvalidReport
	}
	if err := ValidateObservationSet(summary.ObservationSet); err != nil {
		return err
	}
	if summary.Detection.Conclusion != "passed" || summary.Resistance.Conclusion != "passed" || summary.Collapse.Conclusion != "passed" {
		return ErrInvalidReport
	}
	return nil
}
