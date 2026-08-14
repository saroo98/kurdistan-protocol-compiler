// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package phase17qualification

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

func TestVerifyOwnerVPSPreflightBindsFreshNonceAndEnvironment(t *testing.T) {
	environmentDigest := strings.Repeat("a", 64)
	raw := validOwnerVPSPreflightRaw(environmentDigest)
	want := sha256.Sum256(raw)
	digest, err := VerifyOwnerVPSPreflight(raw, environmentDigest)
	if err != nil {
		t.Fatal(err)
	}
	if digest != hex.EncodeToString(want[:]) {
		t.Fatalf("digest=%q", digest)
	}

	for name, changed := range map[string][]byte{
		"wrong environment": []byte(strings.Replace(string(raw), environmentDigest, strings.Repeat("b", 64), 1)),
		"invalid nonce":     []byte(strings.Replace(string(raw), strings.Repeat("1", 32), "reused", 1)),
		"failed status":     []byte(strings.Replace(string(raw), `"status":"PASS"`, `"status":"FAIL"`, 1)),
		"clock unchecked":   []byte(strings.Replace(string(raw), `"hostClockToVps":true`, `"hostClockToVps":false`, 1)),
		"raw log retained":  []byte(strings.Replace(string(raw), `"rawLogRetained":false`, `"rawLogRetained":true`, 1)),
		"duplicate field":   []byte(strings.Replace(string(raw), `"status":"PASS"`, `"status":"PASS","status":"PASS"`, 1)),
		"unknown field":     []byte(strings.Replace(string(raw), `"status":"PASS"`, `"status":"PASS","endpoint":"private"`, 1)),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyOwnerVPSPreflight(changed, environmentDigest); err == nil {
				t.Fatal("invalid preflight evidence accepted")
			}
		})
	}
}

func validOwnerVPSPreflightRaw(environmentDigest string) []byte {
	return []byte(`{"schema":"kurdistan-phase17-owned-vps-preflight-v1","preflightId":"` + strings.Repeat("1", 32) + `","environmentSha256":"` + environmentDigest + `","status":"PASS","hostClass":"OWNER_CONTROLLED_VPS","os":"linux","arch":"amd64","systemd":true,"networkd":true,"nft":true,"unbound":true,"tun":true,"timeSynchronized":true,"hostClockToVps":true,"memory":true,"disk":true,"ipv4":true,"ipv6":false,"ipv6Global":false,"ipv6DefaultRoute":false,"ipv6Forwarding":false,"ipv6NftPolicy":false,"ipv6External":false,"sudo":true,"rawLogRetained":false}` + "\n")
}
