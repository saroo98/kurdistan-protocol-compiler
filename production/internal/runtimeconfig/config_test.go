// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package runtimeconfig

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

func validConfig(t *testing.T) []byte {
	t.Helper()
	entitlements := `{"schema":"phase16-entitlements-v1","environment":"qualification","version":"v1","assignments":[{"actor_id":"actor-0123456789abcdef0123456789abcdef","roles":["viewer"]}]}`
	value := Config{
		Schema: Schema, Environment: "qualification", ListenAddress: ":8080",
		SpannerDatabase: "projects/kvpn-qual-control/instances/authority/databases/authority",
		IAPAudience:     "phase16-api", Issuers: []string{"https://cloud.google.com/iap"}, AuthorizedParties: []string{"iap-client"},
		ActorKeyBase64:              base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))),
		EntitlementsBase64:          base64.StdEncoding.EncodeToString([]byte(entitlements)),
		PrivilegedMaximumAgeSeconds: 300, TokenReplayTimeoutSeconds: 5, KMSRequestTimeoutSeconds: 10,
		AuthoritySourceKeyVersion: "projects/kvpn-qual-trust/locations/europe-west2/keyRings/authority/cryptoKeys/staging/cryptoKeyVersions/1",
		KMSBindings:               []KMSBinding{{KeyID: "issuer-key", VersionResource: "projects/kvpn-qual-trust/locations/europe-west2/keyRings/authority/cryptoKeys/issuer/cryptoKeyVersions/1", ExpectedProjectID: "kvpn-qual-trust", Role: "issuer"}},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseAcceptsStrictRuntimeConfig(t *testing.T) {
	config, err := Parse(validConfig(t))
	if err != nil {
		t.Fatal(err)
	}
	if config.Environment != "qualification" || config.ListenAddress != ":8080" {
		t.Fatalf("unexpected config: %#v", config)
	}
}

func TestParseRejectsDuplicateUnknownAndWeakSecretMaterial(t *testing.T) {
	valid := validConfig(t)
	for name, raw := range map[string][]byte{
		"duplicate": append(valid[:len(valid)-1], []byte(`,"schema":"phase16-operator-runtime-config-v1"}`)...),
		"unknown":   append(valid[:len(valid)-1], []byte(`,"unknown":true}`)...),
		"weak key":  []byte(strings.Replace(string(valid), base64.StdEncoding.EncodeToString([]byte(strings.Repeat("a", 32))), "YQ==", 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Parse(raw); err == nil {
				t.Fatal("invalid runtime configuration accepted")
			}
		})
	}
}
