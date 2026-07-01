// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package concretelocaladapter

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

var ErrRefuseOverwrite = errors.New("refusing to overwrite existing concrete local adapter fixture")

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "packet_capture", "pcap",
	"endpoint", "resolver", "dns_query", "domain", "url", "sni", "host_header", "client_ip", "server_ip",
	"secret", "key", "nonce", "auth_tag", "proof_material", "ciphertext", "plaintext", "private_key",
	"deployment_token", "cloud_credential", "guaranteed_bypass", "undetectable",
}

func ValidateFixtureSet(set SocketFixtureSet) error {
	if set.Version != Version || set.FixtureID == "" || set.PayloadLogged || set.SecretLogged || set.Conclusion != "passed" {
		return fmt.Errorf("%w: invalid fixture metadata", ErrInvalidConfig)
	}
	if err := ValidateBindConfig(set.BindConfig); err != nil {
		return err
	}
	if len(set.Scenarios) < 8 || len(set.Summaries) != len(set.Scenarios) {
		return fmt.Errorf("%w: incomplete scenario coverage", ErrInvalidConfig)
	}
	if set.Misuse.Conclusion != "passed" || set.Parity.Conclusion != "passed" || set.Collapse.Conclusion != "passed" {
		return fmt.Errorf("%w: failed fixture reports", ErrInvalidConfig)
	}
	for _, summary := range set.Summaries {
		if !summary.Completed || summary.PayloadLogged || summary.SecretLogged || summary.SummaryHash != HashValue(summaryHashInput(summary)) {
			return fmt.Errorf("%w: invalid summary %s", ErrInvalidConfig, summary.Scenario)
		}
	}
	if set.FixtureHash != "" && set.FixtureHash != HashValue(fixtureHashInput(set)) {
		return fmt.Errorf("%w: fixture hash mismatch", ErrInvalidConfig)
	}
	return ScanForLeak(set)
}

func ScanForLeak(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	findings := []string{}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err == nil {
		scanValue(decoded, "", &findings)
	}
	findings = uniqueStrings(findings)
	if len(findings) > 0 {
		return fmt.Errorf("%w: %s", ErrUnsafeMetadata, strings.Join(findings, ","))
	}
	return nil
}

func scanValue(value any, parentKey string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := normalize(key)
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			if lower == "payload_logged" || lower == "secret_logged" || lower == "forbidden" || lower == "forbidden_scopes" || lower == "expected_events" {
				scanValue(child, lower, findings)
				continue
			}
			if lower == "host" && child == "127.0.0.1" {
				continue
			}
			for _, marker := range forbiddenMarkers {
				if lower == marker || strings.Contains(lower, marker) {
					*findings = append(*findings, marker)
				}
			}
			scanValue(child, lower, findings)
		}
	case []any:
		for _, child := range v {
			scanValue(child, parentKey, findings)
		}
	case string:
		if parentKey == "forbidden" || parentKey == "forbidden_scopes" || parentKey == "expected_events" {
			return
		}
		lower := normalize(v)
		for _, marker := range forbiddenMarkers {
			if marker == "payload" || marker == "key" || marker == "secret" || marker == "endpoint" || marker == "domain" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func normalize(value string) string {
	value = strings.ToLower(value)
	replacer := strings.NewReplacer(" ", "_", "-", "_", ".", "_", "/", "_")
	return replacer.Replace(value)
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func LoadFixtureSet(path string) (SocketFixtureSet, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return SocketFixtureSet{}, err
	}
	var set SocketFixtureSet
	if err := json.Unmarshal(raw, &set); err != nil {
		return SocketFixtureSet{}, err
	}
	return set, ValidateFixtureSet(set)
}

func CompareFixtureSets(oldSet, newSet SocketFixtureSet) FixtureComparisonReport {
	report := FixtureComparisonReport{Version: Version, OldHash: oldSet.FixtureHash, NewHash: newSet.FixtureHash, Conclusion: "passed"}
	if err := ValidateFixtureSet(oldSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if err := ValidateFixtureSet(newSet); err != nil {
		report.UnexpectedDrift = append(report.UnexpectedDrift, err.Error())
	}
	if oldSet.FixtureHash != newSet.FixtureHash {
		report.UnexpectedDrift = append(report.UnexpectedDrift, "fixture_hash_changed")
	}
	if oldSet.PayloadLogged || newSet.PayloadLogged {
		report.PayloadLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "payload_logged")
	}
	if oldSet.SecretLogged || newSet.SecretLogged {
		report.SecretLogged = true
		report.UnexpectedDrift = append(report.UnexpectedDrift, "secret_logged")
	}
	if len(report.UnexpectedDrift) > 0 {
		report.Conclusion = "failed"
	}
	return report
}
