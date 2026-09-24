// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright 2026 Saro

package livecarrier

import (
	"testing"
	"time"

	"kurdistan/internal/product/runtimepolicy"
)

func TestResolveRuntimeAtSupportsV3WithoutWeakeningStrictV2(t *testing.T) {
	p := fixtureLiveCarrierPolicyV2(t)
	now := time.Now()
	if _, err := ResolveRuntimeAt(p, now); err != nil {
		t.Fatal(err)
	}
	p.SchemaVersion = 3
	p.Services = &runtimepolicy.ServicesV1{Version: 1, Update: &runtimepolicy.UpdateV1{
		URL: "https://updates.example/profile", ProfileID: "profiles.live", MaxArtifactBytes: 65536, TimeoutMillis: 1000, MinCheckIntervalSeconds: 60,
	}}
	var err error
	p.RelayAdmissionDigest, err = runtimepolicy.RelayAdmissionDigestV3At(p, now)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveV2At(p, now); err == nil {
		t.Fatal("strict V2 accepted V3")
	}
	a, err := ResolveRuntimeAt(p, now)
	if err != nil || !a.Networked || a.ALPN != "kurd/1" || a.EndpointCount != 1 {
		t.Fatalf("V3 carrier unavailable: %v", err)
	}
	for _, mutate := range []func(*runtimepolicy.PolicyV2){
		func(p *runtimepolicy.PolicyV2) { p.Services.Update.TimeoutMillis++ },
		func(p *runtimepolicy.PolicyV2) { p.SchemaVersion = 2 },
		func(p *runtimepolicy.PolicyV2) { p.SchemaVersion = 4 },
	} {
		changed := p.Clone()
		mutate(&changed)
		if a, err := ResolveRuntimeAt(changed, now); err == nil || a != (LiveAuthorityV2{}) {
			t.Fatal("unvalidated service authority resolved")
		}
	}
}
