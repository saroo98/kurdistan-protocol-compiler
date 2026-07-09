// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package wiregen

import (
	"encoding/json"
	"strings"
)

type RedactionReport struct {
	Passed   bool     `json:"passed"`
	Findings []string `json:"findings,omitempty"`
}

func ValidateRedaction(value any) RedactionReport {
	raw, err := json.Marshal(value)
	if err != nil {
		return RedactionReport{Passed: false, Findings: []string{"marshal_failed"}}
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return RedactionReport{Passed: false, Findings: []string{"invalid_json"}}
	}
	findings := []string{}
	scanValue(decoded, &findings)
	return RedactionReport{Passed: len(findings) == 0, Findings: uniqueStrings(findings)}
}

func scanValue(value any, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			if unsafeKey(strings.ToLower(key)) {
				*findings = append(*findings, key)
			}
			if (strings.ToLower(key) == "payload_logged" || strings.ToLower(key) == "secret_logged") && child == true {
				*findings = append(*findings, key+"_true")
			}
			scanValue(child, findings)
		}
	case []any:
		for _, child := range v {
			scanValue(child, findings)
		}
	case string:
		if unsafeText(v) {
			*findings = append(*findings, v)
		}
	}
}

func unsafeKey(key string) bool {
	for _, marker := range []string{"raw_payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes", "auth_tag", "nonce_base", "secret", "derived_key", "client_write_key", "server_write_key", "proof_material", "private_key", "session_secret", "destination_address", "proxy_ip", "server_ip", "domain", "sni", "host_header"} {
		if key == marker || strings.Contains(key, marker) {
			switch key {
			case "auth_tag_like", "payload_position", "payload_split", "payload_logged", "secret_logged":
				return false
			}
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(values))
	for _, value := range values {
		if seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}
