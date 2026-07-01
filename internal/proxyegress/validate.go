// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package proxyegress

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
)

func ValidateFixtureSet(set EgressFixtureSet) error {
	if set.Version != Version {
		return safeError("unknown_schema")
	}
	if len(set.Scenarios) < 12 || len(set.Requests) == 0 || len(set.Targets) == 0 || len(set.Mappings) == 0 {
		return safeError("incomplete_fixture_set")
	}
	for _, req := range set.Requests {
		if err := ValidateRequestDescriptor(req); err != nil {
			return err
		}
	}
	for _, target := range set.Targets {
		if err := ValidateTargetDescriptor(target); err != nil {
			return err
		}
	}
	for _, mapping := range set.Mappings {
		if err := ValidateMappingPlan(mapping); err != nil {
			return err
		}
	}
	if !IsolationPreserved(set.Mappings) {
		return safeError("stream_isolation_broken")
	}
	if set.PayloadLogged || set.SecretLogged {
		return safeError("unsafe_trace_flags")
	}
	return ScanForLeak(set)
}

func ScanMisuse(value any) EgressMisuseReport {
	report := EgressMisuseReport{Version: Version, ObjectsScanned: 1, Conclusion: "passed"}
	if err := ScanForLeak(value); err != nil {
		report.SuspiciousMetrics = append(report.SuspiciousMetrics, err.Error())
	}
	report.SuspiciousMetrics = uniqueSorted(report.SuspiciousMetrics)
	if len(report.SuspiciousMetrics) > 0 || report.PayloadLogged || report.SecretLogged {
		report.Conclusion = "failed"
	}
	return report
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
	return scanValue(decoded, "")
}

func scanValue(value any, path string) error {
	switch typed := value.(type) {
	case map[string]any:
		for key, val := range typed {
			normalized := strings.ToLower(key)
			if isAllowedHygieneKey(normalized) {
				if b, ok := val.(bool); ok && b {
					return fmt.Errorf("unsafe true hygiene flag %s", key)
				}
			} else if isForbiddenToken(normalized) {
				return fmt.Errorf("forbidden proxyegress field %s", key)
			}
			if err := scanValue(val, key); err != nil {
				return err
			}
		}
	case []any:
		for _, item := range typed {
			if err := scanValue(item, path); err != nil {
				return err
			}
		}
	case string:
		normalized := strings.ToLower(typed)
		if strings.HasPrefix(path, "forbidden") || path == "notes" {
			return nil
		}
		if isForbiddenToken(normalized) {
			return fmt.Errorf("forbidden proxyegress value in %s", path)
		}
	default:
		if reflect.ValueOf(value).Kind() == reflect.Bool && path != "" {
			return nil
		}
	}
	return nil
}

func isAllowedHygieneKey(key string) bool {
	return key == "payload_logged" || key == "secret_logged"
}

func isForbiddenToken(value string) bool {
	for _, token := range []string{
		"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext",
		"pcap", "packet_dump", "capture_bytes", "packet_capture", "destination_address", "endpoint",
		"real_host", "proxy_ip", "server_ip", "client_ip", "domain", "sni", "host_header", "url", "uri",
		"ip_address", "dns_query", "resolver", "resolver_ip", "nameserver", "cloud_provider", "aws", "gcp",
		"azure", "region", "instance_id", "credential", "account_id", "phone_number", "sim_id", "imsi",
		"imei", "device_id", "precise_location", "gps", "latitude", "longitude", "secret", "derived_key",
		"client_write_key", "server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material",
		"private_key", "session_secret",
	} {
		if value == token || strings.Contains(value, token) {
			return true
		}
	}
	return false
}
