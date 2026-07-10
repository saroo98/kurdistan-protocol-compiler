// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package transportbundle

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf8"
)

var forbiddenMarkers = []string{
	"raw_payload", "payload", "raw_bytes", "encoded_bytes", "decoded_bytes", "ciphertext", "plaintext", "pcap", "packet_dump", "capture_bytes",
	"destination_address", "endpoint", "real_host", "proxy_ip", "server_ip", "domain", "sni", "host_header", "url", "uri", "ip_address",
	"dns_query", "resolver", "resolver_ip", "nameserver", "cloud_provider", "aws", "gcp", "azure", "region", "instance_id", "credential",
	"secret", "derived_key", "client_write_key", "server_write_key", "nonce", "nonce_base", "auth_tag", "proof_material", "private_key", "session_secret",
}

func ForbiddenMarkers() []string {
	return append([]string(nil), forbiddenMarkers...)
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
	findings := []string{}
	scanLeakValue(decoded, "", &findings)
	if len(findings) > 0 {
		sort.Strings(findings)
		return fmt.Errorf("%w: %s", ErrUnsafeBundle, strings.Join(uniqueStrings(findings), ","))
	}
	return nil
}

func scanLeakValue(value any, key string, findings *[]string) {
	switch v := value.(type) {
	case map[string]any:
		for childKey, child := range v {
			lower := strings.ToLower(childKey)
			if forbiddenBundleKey(lower) {
				*findings = append(*findings, childKey)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				*findings = append(*findings, lower+"_true")
			}
			scanLeakValue(child, childKey, findings)
		}
	case []any:
		for _, child := range v {
			scanLeakValue(child, key, findings)
		}
	case string:
		if !utf8.ValidString(v) {
			*findings = append(*findings, "invalid_utf8")
			return
		}
		lower := strings.ToLower(v)
		for _, marker := range forbiddenMarkers {
			if marker == "payload" || marker == "secret" || marker == "domain" || marker == "nonce" || marker == "url" || marker == "uri" || marker == "region" {
				continue
			}
			if strings.Contains(lower, marker) {
				*findings = append(*findings, marker)
			}
		}
	}
}

func forbiddenBundleKey(key string) bool {
	for _, marker := range forbiddenMarkers {
		if key == marker || strings.Contains(key, marker) {
			switch key {
			case "payload_logged", "secret_logged", "metadata_risk_bucket", "selected_corpus_entry", "decision_input_matches", "fallback_hints", "fallback_hint_count":
				return false
			}
			return true
		}
	}
	return false
}

func WriteJSON(path string, value any, force bool) error {
	if !force {
		if _, err := os.Stat(path); err == nil {
			return ErrRefuseOverwrite
		}
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil && filepath.Dir(path) != "." {
		return err
	}
	if err := ScanForLeak(value); err != nil {
		return err
	}
	raw, err := StableJSON(value)
	if err != nil {
		return err
	}
	return os.WriteFile(path, raw, 0o600)
}

func uniqueStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		if !seen[value] {
			seen[value] = true
			out = append(out, value)
		}
	}
	sort.Strings(out)
	return out
}
