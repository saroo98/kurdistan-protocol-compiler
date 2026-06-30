// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package localproxyingressadversary

import (
	"encoding/json"
	"fmt"
	"strings"
)

var adversarialForbiddenFields = []string{
	"raw_payload",
	"payload",
	"raw_bytes",
	"encoded_bytes",
	"decoded_bytes",
	"ciphertext",
	"plaintext",
	"pcap",
	"packet_dump",
	"capture_bytes",
	"destination_address",
	"endpoint",
	"real_host",
	"proxy_ip",
	"server_ip",
	"domain",
	"sni",
	"host_header",
	"url",
	"uri",
	"ip_address",
	"dns_query",
	"resolver",
	"cloud_provider",
	"aws",
	"gcp",
	"azure",
	"region",
	"instance_id",
	"credential",
	"secret",
	"derived_key",
	"client_write_key",
	"server_write_key",
	"nonce",
	"nonce_base",
	"auth_tag",
	"proof_material",
	"private_key",
	"session_secret",
}

func ForbiddenFixtureFields() []string {
	return append([]string(nil), adversarialForbiddenFields...)
}

func ScanFixtureHygiene(value any) error {
	return scanSafeFixture(value)
}

func scanSafeFixture(value any) error {
	raw, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var decoded any
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	return scanFixtureValue(decoded, "")
}

func scanFixtureValue(value any, key string) error {
	switch v := value.(type) {
	case map[string]any:
		for childKey, child := range v {
			lower := strings.ToLower(childKey)
			if forbiddenFixtureKey(lower) {
				return fmt.Errorf("%w: forbidden fixture field", ErrUnsafeFixture)
			}
			if (lower == "payload_logged" || lower == "secret_logged") && child == true {
				return fmt.Errorf("%w: hygiene flag set", ErrUnsafeFixture)
			}
			if err := scanFixtureValue(child, lower); err != nil {
				return err
			}
		}
	case []any:
		for _, child := range v {
			if err := scanFixtureValue(child, key); err != nil {
				return err
			}
		}
	case string:
		if unsafeFixtureValue(v) {
			return fmt.Errorf("%w: forbidden fixture value", ErrUnsafeFixture)
		}
	}
	return nil
}

func forbiddenFixtureKey(key string) bool {
	switch key {
	case "payload_logged", "secret_logged", "payload_hygiene", "secret_hygiene":
		return false
	}
	for _, marker := range adversarialForbiddenFields {
		if key == marker || strings.Contains(key, marker) {
			return true
		}
	}
	return false
}

func unsafeFixtureValue(value string) bool {
	lower := strings.ToLower(strings.TrimSpace(value))
	if lower == "" {
		return false
	}
	for _, r := range value {
		if r < 32 {
			return true
		}
	}
	if strings.Contains(lower, "://") || strings.HasPrefix(lower, "www.") || strings.Contains(lower, "@") {
		return true
	}
	if strings.Count(lower, ".") >= 2 && strings.Contains(lower, " ") == false {
		return true
	}
	return false
}
