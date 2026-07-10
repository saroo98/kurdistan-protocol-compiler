// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package fixtures

import (
	"encoding/json"
	"strings"
)

var forbiddenFixtureMarkers = []string{
	"raw_payload",
	"raw_bytes",
	"encoded_bytes",
	"decoded_bytes",
	"ciphertext",
	"plaintext",
	"auth_tag",
	"nonce_base",
	"secret",
	"derived_key",
	"client_write_key",
	"server_write_key",
	"proof_material",
	"private_key",
	"session_secret",
}

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
	scanFixtureValue(decoded, &findings)
	return RedactionReport{Passed: len(findings) == 0, Findings: uniqueStrings(findings)}
}

func ScanFixtureJSON(raw []byte) RedactionReport {
	if len(raw) > 1<<20 {
		raw = raw[:1<<20]
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return RedactionReport{Passed: false, Findings: []string{"invalid_json"}}
	}
	findings := []string{}
	scanFixtureValue(decoded, &findings)
	return RedactionReport{Passed: len(findings) == 0, Findings: uniqueStrings(findings)}
}

func scanFixtureValue(value any, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for key, child := range v {
			lower := strings.ToLower(key)
			if forbiddenFixtureKey(lower) {
				*findings = append(*findings, key)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, key+"_true")
			}
			scanFixtureValue(child, findings)
		}
	case []any:
		for _, child := range v {
			scanFixtureValue(child, findings)
		}
	case string:
		lower := strings.ToLower(v)
		for _, marker := range forbiddenFixtureMarkers {
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func forbiddenFixtureKey(key string) bool {
	for _, marker := range forbiddenFixtureMarkers {
		if key == marker || strings.Contains(key, marker) {
			switch key {
			case "payload_logged", "secret_logged", "payload_hygiene", "secret_hygiene":
				return false
			}
			return true
		}
	}
	return false
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
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
