// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package relayfleet

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

var relayIDRE = regexp.MustCompile(`^relay_[0-9]{4}$`)

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes",
	"destination_address", "endpoint", "real_host", "proxy_ip", "server_ip", "domain", "sni", "host_header", "url", "ip_address",
	"cloud_provider", "aws", "gcp", "azure", "region", "instance_id", "credential",
	"secret", "derived_key", "client_write_key", "server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
}

func ValidateRelay(relay SyntheticRelay) error {
	if !relayIDRE.MatchString(string(relay.RelayID)) || !supportedState(relay.State) || !supportedClass(relay.RelayClass) {
		return ErrInvalidRelay
	}
	if relay.ProfileID == "" || relay.ProfileSeed == 0 || relay.WirePolicyHash == "" || relay.SelectedFamily == "" || relay.SyntheticHostID == "" {
		return ErrInvalidRelay
	}
	if strings.Contains(relay.SyntheticHostID, ".") || strings.Contains(relay.SyntheticHostID, "://") {
		return ErrTraceLeak
	}
	if relay.PayloadLogged || relay.SecretLogged {
		return ErrTraceLeak
	}
	return ScanForLeak(relay)
}

func ValidateFleet(fleet RelayFleet) error {
	if fleet.Version != string(Version) || fleet.FleetID == "" || len(fleet.Relays) == 0 || fleet.PayloadLogged || fleet.SecretLogged {
		return ErrInvalidFleet
	}
	if err := ValidatePolicy(fleet.Policy); err != nil {
		return err
	}
	if activeRelayCount(fleet.Relays) > fleet.Policy.MaxActiveRelays {
		return ErrInvalidFleet
	}
	seen := map[RelayID]bool{}
	for _, relay := range fleet.Relays {
		if seen[relay.RelayID] {
			return ErrInvalidFleet
		}
		seen[relay.RelayID] = true
		if err := ValidateRelay(relay); err != nil {
			return err
		}
	}
	expected := FleetHash(RelayFleet{Version: fleet.Version, FleetID: fleet.FleetID, Relays: fleet.Relays, Policy: fleet.Policy})
	if fleet.FleetHash != expected {
		return ErrInvalidFleet
	}
	return ScanForLeak(fleet)
}

func ValidateSummary(summary RelayFleetSummary) error {
	if summary.Version != string(Version) || summary.PayloadLogged || summary.SecretLogged {
		return ErrInvalidReport
	}
	if err := ValidateFleet(summary.Fleet); err != nil {
		return err
	}
	if summary.Assignment.Conclusion != "passed" || summary.BurnRisk.Conclusion != "passed" || summary.Collapse.PayloadLogged || summary.Parity.Conclusion != "passed" {
		return ErrInvalidReport
	}
	for _, event := range summary.ChurnEvents {
		if event.PayloadLogged || event.SecretLogged {
			return ErrTraceLeak
		}
		if err := ScanForLeak(event); err != nil {
			return err
		}
	}
	for _, event := range summary.MigrationEvents {
		if err := ValidateMigrationEvent(summary.Fleet, event); err != nil {
			return err
		}
	}
	return ScanForLeak(summary)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	var findings []string
	scan(decoded, "", &findings)
	if len(findings) > 0 {
		return fmt.Errorf("%w: %s", ErrTraceLeak, strings.Join(findings, ","))
	}
	return nil
}

func scan(value any, path string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if forbiddenKey(lower) {
				*findings = append(*findings, key)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			scan(child, lower, findings)
		}
	case []any:
		for _, child := range v {
			scan(child, path, findings)
		}
	case string:
		lower := strings.ToLower(v)
		for _, marker := range forbiddenMarkers {
			if marker == "payload" || marker == "secret" || marker == "nonce" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func forbiddenKey(key string) bool {
	for _, marker := range forbiddenMarkers {
		if key == marker || strings.Contains(key, marker) {
			switch key {
			case "payload_logged", "secret_logged":
				return false
			}
			return true
		}
	}
	return false
}
