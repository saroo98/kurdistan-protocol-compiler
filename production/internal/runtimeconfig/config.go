// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeconfig

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"strings"
	"time"

	"kurdistan/production/internal/kmsprovider"
)

const (
	Schema   = "phase16-operator-runtime-config-v1"
	MaxBytes = 256 << 10
)

var (
	ErrInvalid = errors.New("runtimeconfig: invalid configuration")
	envRE      = regexp.MustCompile(`^(qualification|production)$`)
	addressRE  = regexp.MustCompile(`^:[1-9][0-9]{1,4}$`)
	databaseRE = regexp.MustCompile(`^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/instances/[a-z][a-z0-9-]{1,28}[a-z0-9]/databases/[a-z][a-z0-9_-]{1,28}[a-z0-9]$`)
)

type Config struct {
	Schema                      string       `json:"schema"`
	Environment                 string       `json:"environment"`
	ListenAddress               string       `json:"listen_address"`
	SpannerDatabase             string       `json:"spanner_database"`
	IAPAudience                 string       `json:"iap_audience"`
	Issuers                     []string     `json:"issuers"`
	AuthorizedParties           []string     `json:"authorized_parties"`
	ActorKeyBase64              string       `json:"actor_key_base64"`
	EntitlementsBase64          string       `json:"entitlements_base64"`
	PrivilegedMaximumAgeSeconds int64        `json:"privileged_maximum_age_seconds"`
	TokenReplayTimeoutSeconds   int64        `json:"token_replay_timeout_seconds"`
	KMSRequestTimeoutSeconds    int64        `json:"kms_request_timeout_seconds"`
	AuthoritySourceKeyVersion   string       `json:"authority_source_key_version"`
	KMSBindings                 []KMSBinding `json:"kms_bindings"`
}

type KMSBinding struct {
	KeyID             string `json:"key_id"`
	VersionResource   string `json:"version_resource"`
	ExpectedProjectID string `json:"expected_project_id"`
	Role              string `json:"role"`
}

func Parse(raw []byte) (Config, error) {
	if len(raw) == 0 || len(raw) > MaxBytes || !uniqueJSONKeys(raw) {
		return Config{}, ErrInvalid
	}
	var config Config
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&config); err != nil {
		return Config{}, ErrInvalid
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return Config{}, ErrInvalid
	}
	if err := config.Validate(); err != nil {
		return Config{}, err
	}
	return config, nil
}

func (config Config) Validate() error {
	if config.Schema != Schema || !envRE.MatchString(config.Environment) || !addressRE.MatchString(config.ListenAddress) ||
		!databaseRE.MatchString(config.SpannerDatabase) || !bounded(config.IAPAudience, 8, 512) ||
		len(config.Issuers) == 0 || len(config.Issuers) > 4 || len(config.AuthorizedParties) == 0 || len(config.AuthorizedParties) > 8 ||
		config.PrivilegedMaximumAgeSeconds < 60 || config.PrivilegedMaximumAgeSeconds > 900 ||
		config.TokenReplayTimeoutSeconds < 1 || config.TokenReplayTimeoutSeconds > 10 ||
		config.KMSRequestTimeoutSeconds < 1 || config.KMSRequestTimeoutSeconds > 30 ||
		len(config.KMSBindings) == 0 || len(config.KMSBindings) > 16 || !strings.Contains(config.AuthoritySourceKeyVersion, "/cryptoKeyVersions/") {
		return ErrInvalid
	}
	if _, err := config.ActorKey(); err != nil {
		return err
	}
	if _, err := config.Entitlements(); err != nil {
		return err
	}
	seen := make(map[string]struct{}, len(config.Issuers)+len(config.AuthorizedParties)+len(config.KMSBindings))
	for _, values := range [][]string{config.Issuers, config.AuthorizedParties} {
		for _, value := range values {
			if !bounded(value, 3, 512) {
				return ErrInvalid
			}
			key := strings.ToLower(value)
			if _, exists := seen[key]; exists {
				return ErrInvalid
			}
			seen[key] = struct{}{}
		}
	}
	bindings := make([]kmsprovider.Binding, 0, len(config.KMSBindings))
	for _, item := range config.KMSBindings {
		bindings = append(bindings, kmsprovider.Binding{
			KeyID: item.KeyID, VersionResource: item.VersionResource,
			ExpectedProjectID: item.ExpectedProjectID, Role: kmsprovider.KeyRole(item.Role),
		})
	}
	if _, err := kmsprovider.NewCatalog(bindings); err != nil {
		return ErrInvalid
	}
	return nil
}

func (config Config) ActorKey() ([]byte, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(config.ActorKeyBase64)
	if err != nil || len(value) != 32 {
		return nil, ErrInvalid
	}
	return value, nil
}

func (config Config) Entitlements() ([]byte, error) {
	value, err := base64.StdEncoding.Strict().DecodeString(config.EntitlementsBase64)
	if err != nil || len(value) == 0 || len(value) > MaxBytes {
		return nil, ErrInvalid
	}
	return value, nil
}

func (config Config) Catalog() (*kmsprovider.Catalog, error) {
	bindings := make([]kmsprovider.Binding, 0, len(config.KMSBindings))
	for _, item := range config.KMSBindings {
		bindings = append(bindings, kmsprovider.Binding{
			KeyID: item.KeyID, VersionResource: item.VersionResource,
			ExpectedProjectID: item.ExpectedProjectID, Role: kmsprovider.KeyRole(item.Role),
		})
	}
	return kmsprovider.NewCatalog(bindings)
}

func (config Config) TokenReplayTimeout() time.Duration {
	return time.Duration(config.TokenReplayTimeoutSeconds) * time.Second
}

func (config Config) KMSRequestTimeout() time.Duration {
	return time.Duration(config.KMSRequestTimeoutSeconds) * time.Second
}

func bounded(value string, minimum, maximum int) bool {
	return len(value) >= minimum && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}

func uniqueJSONKeys(raw []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	var stack []map[string]struct{}
	expectingKey := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			return len(stack) == 0
		}
		if err != nil {
			return false
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{':
				stack = append(stack, make(map[string]struct{}))
				expectingKey = true
			case '}':
				if len(stack) == 0 {
					return false
				}
				stack = stack[:len(stack)-1]
				expectingKey = len(stack) > 0
			}
		case string:
			if expectingKey && len(stack) > 0 {
				if _, duplicate := stack[len(stack)-1][value]; duplicate {
					return false
				}
				stack[len(stack)-1][value] = struct{}{}
				expectingKey = false
			} else if len(stack) > 0 {
				expectingKey = true
			}
		default:
			if len(stack) > 0 {
				expectingKey = true
			}
		}
	}
}
